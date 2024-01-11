package ch.migros.quantumproto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;
import java.util.Base64.Decoder;

import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.json.JSONObject;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ch.migros.quantumproto.util.AlgorithmNameUtils;
import ch.migros.quantumproto.util.CertificateUtils;
import ch.migros.quantumproto.util.JWTUtils;
import ch.migros.quantumproto.util.SignatureUtils;

/**
 * Defines a microservice called "JWT-Verifier" which receives JWTs via HTTP and
 * verifies the signature & certificate chain against the CA certificate.
 */
public class JWTVerifierApp {
    private static X509CertificateHolder cert;

    public static void main(String[] args) {
        System.out.println("I am a JWT Verifier!");

        Security.addProvider(new BouncyCastleProvider());

        // Download root certificate form CA
        try {
            cert = get_root_certificate();
        } catch (Exception e) {
            System.out.println("Certificate acquisition failed: " + e.getMessage());
            return;
        }

        System.out.println("I have the CA certificate");

        // Verify CA certificate
        try {
            assert CertificateUtils.checkCert(cert, cert);
        } catch (Exception e) {
            System.out.println("Certificate did not verify: " + e.getMessage());
            return;
        }

        System.out.println("The CA certificate is correctly self-signed");

        // Start HTTP server for verifying JWT's
        try {
            start_server();
        } catch (Exception e) {
            System.out.println("HTTPS Server Startup failed: " + e.getMessage());
            return;
        }

        System.out.println("I am ready to verify JWT's at jwt-verifier:80/jwt-verify/");
    }

    private static void start_server() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(80), 0);
        server.createContext("/jwt-verify/", new VerifyHandler(cert));
        server.setExecutor(null); // creates a default executor
        server.start();
    }

    private static X509CertificateHolder get_root_certificate() throws IOException {
        // Download root certificate
        URL url = new URL("http://cert-auth/cert-app/");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        if (connection == null)
            throw new IllegalStateException("Could not establish connection to cert-auth");

        if (connection.getResponseCode() != 200)
            throw new IllegalStateException("Received invalid response code: " + connection.getResponseCode());

        InputStream is = connection.getInputStream();
        byte[] certBytes = is.readAllBytes();
        is.close();
        connection.disconnect();

        return new X509CertificateHolder(certBytes);
    }

}

/**
 * HTTP request handler for a JWT verification endpoint.
 * Responds to any POST containing a JWT and certificate with a status code and
 * message depending on verification outcome. A successful verification is
 * accompanied by a security report summarizing the cryptographic components
 * used.
 */
class VerifyHandler implements HttpHandler {
    private X509CertificateHolder rootCert;

    public VerifyHandler(X509CertificateHolder rootCert) {
        this.rootCert = rootCert;
    }

    public void handle(HttpExchange t) throws IOException {
        // Catch healthcheck requests
        if (t.getRequestHeaders().containsKey("User-Agent")
                && t.getRequestHeaders().get("User-Agent").contains("Healthbot/1.0")) {
            t.sendResponseHeaders(200, -1);
            return;
        }

        try {
            System.out.println("Recieved verification request");
            InputStream is = t.getRequestBody();
            JSONObject reqJson = new JSONObject(new String(is.readAllBytes(), StandardCharsets.UTF_8));
            is.close();

            // Get JWT and cert
            Decoder dec = Base64.getUrlDecoder();

            String jwt = reqJson.getString("jwt");
            String certEncoded = reqJson.getString("cert");

            X509CertificateHolder cert = new X509CertificateHolder(dec.decode(certEncoded));

            // Verify chain
            try {
                if (!CertificateUtils.checkCert(cert, rootCert)) {
                    throw new IllegalArgumentException("Certificate is not valid");
                }
            } catch (Exception e) {
                System.out.println("Failure to verify client certificate: " + e.getMessage());
                e.printStackTrace();
                t.sendResponseHeaders(400, -1);
                return;
            }

            // Parse JWT
            String[] jwtParts = jwt.split("\\.");
            String tbs;
            JSONObject header;
            JSONObject payload;
            byte[] signature;
            String sigAlg;
            try {
                assert jwtParts.length == 3;
                header = new JSONObject(new String(dec.decode(jwtParts[0])));
                payload = new JSONObject(new String(dec.decode(jwtParts[1])));
                tbs = jwtParts[0] + "." + jwtParts[1];
                signature = dec.decode(jwtParts[2]);

                // Determine claimed signature algorithm
                sigAlg = JWTUtils.algToSigAlgName((String) header.get("alg"));

            } catch (IndexOutOfBoundsException e) {
                System.out.println("Unable to parse JWT: " + e.getMessage());
                t.sendResponseHeaders(400, -1);
                return;
            }

            // Verify signature
            try {
                ContentVerifier clientVerifier = SignatureUtils.getContentVerifier(cert, sigAlg);
                try (OutputStream os = clientVerifier.getOutputStream()) {
                    os.write(tbs.getBytes());
                }
                if (!clientVerifier.verify(signature))
                    throw new IllegalArgumentException("Signature is invalid for data");
            } catch (OperatorCreationException e) {
                System.out.println("Failure to verify JWT: " + e.getMessage());
                t.sendResponseHeaders(400, -1);
                return;
            }

            System.out.println("Verification succeeded.");

            // Short summary of security
            boolean rootIsHybrid = CertificateUtils.isHybridCert(rootCert);
            boolean clientHasCompositePublicKey = cert.getSubjectPublicKeyInfo().getAlgorithm()
                    .getAlgorithm().equals(MiscObjectIdentifiers.id_composite_key);
            boolean jwtIsComposite = AlgorithmNameUtils.isCompositeName(sigAlg);

            // Craft response
            String response = "I'm glad you got that signed :)\nYour header: " + header.toString()
                    + "\nYour payload: " + payload.toString()
                    + "\nSecurity report: "
                    + "\n  root cert is hybrid (and client hybrid-signed): " + rootIsHybrid
                    + "\n  client cert has composite key: " + clientHasCompositePublicKey
                    + "\n  jwt alg is composite: " + jwtIsComposite;
            t.getResponseHeaders().set("Content-Type", "text/plain");
            t.sendResponseHeaders(200, response.length());

            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        } catch (Exception e) {
            System.err.println("Exception during request handling");
            e.printStackTrace();
        }
    }
}