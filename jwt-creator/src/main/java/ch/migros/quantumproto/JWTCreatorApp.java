package ch.migros.quantumproto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.json.JSONObject;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

/**
 * Defines a microservice called "JWT-Creator" which generates a fresh key pair
 * for signing, submits a CSR to "Cert-Auth" (the CA) and signs any messages
 * received on its HTTP endpoint as a JWT.
 */
public class JWTCreatorApp {
    private static Map<String, X509CertificateHolder> certsSelf = new HashMap<>(2);
    private static X509CertificateHolder certTlsRoot;
    private static Map<String, KeyPair> keyPairs = new HashMap<>(2);

    public static void main(String[] args) {
        System.out.println("I am a JWT Creator!");

        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());

        // Download root certificate form CA
        try {
            certTlsRoot = get_root_certificate();
        } catch (Exception e) {
            System.out.println("Root certificate acquisition failed: " + e.getMessage());
            return;
        }

        System.out.println("I have the CA certificate");

        // Create new certificates, submit CSRs to CA
        try {
            get_signed_certificate("tls", "sign");
            get_signed_certificate("app", "sign-app");
        } catch (Exception e) {
            System.out.println("End-User certificate acquisition failed: " + e.getMessage());
            return;
        }

        System.out.println("I have my personal certificate, signed by the CA");

        // Start HTTPS server with this certificate
        try {
            start_server();
        } catch (Exception e) {
            System.out.println("HTTPS Server Startup failed: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        System.out.println("I am ready to sign any JWT at jwt-creator:443/jwt-create/");
    }

    private static X509CertificateHolder get_root_certificate() throws IOException {
        // Download root certificate
        URL url = new URL("http://cert-auth/cert/");
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

    /**
     * Requests a CA-signed certificate with a fresh RSA key pair.
     * To that end, a suitable CSR is submitted to the CA.
     * Saves the resulting key pair and certificate as part of static
     * {@code keyPair} and {@code certs} maps respectively.
     * 
     * @param mapKey       the key under which to save the results
     * @param signEndpoint CA endpoint to use for submitting the CSR
     * 
     * @throws IOException                        if HTTP connection to the CA fails
     * @throws OperatorCreationException          if CSR construction fails
     * @throws NoSuchProviderException            if key generation fails
     * @throws NoSuchAlgorithmException           if key generation fails
     * @throws InvalidAlgorithmParameterException if key generation fails
     */
    private static void get_signed_certificate(String mapKey, String signEndpoint)
            throws IOException, OperatorCreationException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // Parameters
        X500Name subject = new X500Name("CN=jwt-creator");

        // Generate RSA-3072 Key pair
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        gen.initialize(new RSAKeyGenParameterSpec(3072, BigInteger.valueOf(65537), null), new SecureRandom());

        KeyPair keyPair = gen.generateKeyPair();
        keyPairs.put(mapKey, keyPair);

        // Build CSR without extensions
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WITHRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject,
                keyPair.getPublic());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        // Submit CSR for signing
        URL url = new URL("http://cert-auth/" + signEndpoint + "/");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        if (connection == null)
            throw new IllegalStateException("Could not establish connection to cert-auth");

        connection.setRequestMethod("POST");
        connection.setDoOutput(true);

        try (OutputStream os = connection.getOutputStream()) {
            byte[] csrBytes = csr.getEncoded();
            os.write(csrBytes, 0, csrBytes.length);
        }

        if (connection.getResponseCode() != 200)
            throw new IllegalStateException("Received invalid response code: " + connection.getResponseCode());

        InputStream is = connection.getInputStream();
        byte[] certBytes = is.readAllBytes();
        is.close();
        connection.disconnect();

        X509CertificateHolder certSelf = new X509CertificateHolder(certBytes);
        certsSelf.put(mapKey, certSelf);

        // Print PEM certificate for debugging
        StringWriter sw = new StringWriter();
        PemObject po = new PemObject("CERTIFICATE", certSelf.getEncoded());
        PemWriter pw = new PemWriter(sw);
        pw.writeObject(po);
        pw.close();
        System.out.println("This is my '" + mapKey + "' certificate:");
        System.out.println(sw.toString());
    }

    private static void start_server()
            throws NoSuchAlgorithmException, NoSuchProviderException, IOException, KeyManagementException,
            CertificateException, KeyStoreException, InvalidKeySpecException, UnrecoverableKeyException {
        HttpsServer server = HttpsServer.create(new InetSocketAddress(443), 0);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");

        // initialise the keystore
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null);

        // Create Certificate Chain in proper format
        final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certLeaf = (X509Certificate) certFactory
                .generateCertificate(new ByteArrayInputStream(certsSelf.get("tls").getEncoded()));
        X509Certificate certCA = (X509Certificate) certFactory
                .generateCertificate(new ByteArrayInputStream(certTlsRoot.getEncoded()));
        final X509Certificate[] certChain = new X509Certificate[] { certLeaf, certCA };

        // Import private key, create a random password for the required protection of
        // the keystore
        String password = "";
        SecureRandom rand = new SecureRandom();
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < 20; i++) {
            password += alphabet.charAt(rand.nextInt(alphabet.length()));
        }
        ks.setKeyEntry("self-key", keyPairs.get("tls").getPrivate(), password.toCharArray(), certChain);

        // setup the key manager factory
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        kmf.init(ks, password.toCharArray());

        // setup the trust manager factory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        tmf.init(ks);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext));

        server.createContext("/jwt-create/", new CreateHandler(keyPairs.get("app"), certsSelf.get("app")));
        server.setExecutor(null); // creates a default executor
        server.start();
    }
}

/**
 * HTTP request handler for a JWT creation endpoint.
 * Responds to any POST with a JWT containing the request body, signed using the
 * key pair. The response is accompanied with the certificate provided in the
 * constructor.
 */
class CreateHandler implements HttpHandler {
    private KeyPair keyPair;
    private X509CertificateHolder cert;

    public CreateHandler(KeyPair keyPair, X509CertificateHolder cert) {
        this.keyPair = keyPair;
        this.cert = cert;
    }

    public void handle(HttpExchange t) throws IOException {
        // Catch healthcheck requests
        if (t.getRequestHeaders().containsKey("User-Agent")
                && t.getRequestHeaders().get("User-Agent").contains("Healthbot/1.0")) {
            t.sendResponseHeaders(200, -1);
            return;
        }

        try {
            System.out.println("Received creation request");

            InputStream is = t.getRequestBody();
            String message = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            is.close();

            if (message.length() == 0)
                message = "My favorite number is 42";

            // Create JWT
            JSONObject header = new JSONObject();
            header.put("alg", "RS256");
            header.put("typ", "JWT");

            JSONObject payload = new JSONObject();
            payload.put("sub", "anon"); // subject
            payload.put("iss", "jwt-creator"); // issuer
            payload.put("awesome", "yes");
            payload.put("msg", message);

            Encoder enc = Base64.getUrlEncoder().withoutPadding();
            String tbs = enc.encodeToString(header.toString().getBytes()) + "."
                    + enc.encodeToString(payload.toString().getBytes());

            // Sign JWT
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WITHRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keyPair.getPrivate());

            try (OutputStream os = signer.getOutputStream()) {
                os.write(tbs.getBytes());
            }
            byte[] sigBytes = signer.getSignature();

            System.out.println("Signed JWT");

            // Build JSON response
            String jwt = tbs + "." + enc.encodeToString(sigBytes);
            String certEncoded = enc.encodeToString(cert.getEncoded());

            JSONObject respJson = new JSONObject();
            respJson.put("jwt", jwt);
            respJson.put("cert", certEncoded);

            String response = respJson.toString();
            t.getResponseHeaders().add("Content-Type", "application/json");
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