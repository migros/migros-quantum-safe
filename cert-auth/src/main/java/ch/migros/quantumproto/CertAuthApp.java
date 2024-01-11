package ch.migros.quantumproto;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ch.migros.quantumproto.util.CertificateUtils;
import ch.migros.quantumproto.util.KeyGenUtils;

/**
 * Defines a microservice called "Cert-Auth" which creates a self-signed root
 * certificate, publishes it via an HTTP endpoint and accepts any CSRs on other
 * endpoints for signing using the root certificate.
 */
public class CertAuthApp {
    private static Map<String, KeyPair> keyPairs = new HashMap<>(2);
    private static Map<String, X509CertificateHolder> certs = new HashMap<>(2);

    private static String TLS_SIG_ALG;
    private static String APP_SIG_ALG;

    private static final String CONFIG_FILE_PATH = "/crypto_config.ini";

    static {
        // Load config file
        Properties configProps = new Properties();
        try {
            FileInputStream in = new FileInputStream(CONFIG_FILE_PATH);
            configProps.load(in);
            in.close();
        } catch (Exception e) {
            System.out.println("Error: could not load config.");
            e.printStackTrace();
        }

        // Extract algorithm identifiers from config
        TLS_SIG_ALG = configProps.getProperty("TLS_SIG_ALG");
        assert (TLS_SIG_ALG != null);
        APP_SIG_ALG = configProps.getProperty("APP_SIG_ALG");
        assert (APP_SIG_ALG != null);
    }

    public static void main(String[] args) throws InterruptedException {
        System.out.println("I am a CA!");

        Security.addProvider(new BouncyCastleProvider());

        // Create new root certificates
        try {
            create_root_certificate("tls", TLS_SIG_ALG);
            create_root_certificate("app", APP_SIG_ALG);
        } catch (Exception e) {
            System.out.println("Certificate creation failed: " + e.getMessage());
            return;
        }

        System.out.println("I created new root certificates");

        // Start HTTP server
        try {
            start_server();
        } catch (Exception e) {
            System.out.println("HTTP Server Startup failed: " + e.getMessage());
            return;
        }

        System.out.println("I am now serving my root certificates at cert-auth:80/cert and /cert-app");
        System.out.println("I am ready to sign any CSR over HTTP at cert-auth:80/sign and /sign-app");
    }

    /**
     * Creates a self-signed certificate with a fresh key pair
     * according to the configuration file.
     * Saves the resulting key pair and certificate as part of static
     * {@code keyPair} and {@code certs} maps respectively.
     * 
     * @param mapKey the key under which to save the results
     * @throws OperatorCreationException if certificate signing fails
     */
    private static void create_root_certificate(String mapKey, String sigAlg)
            throws OperatorCreationException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException {
        if (keyPairs.containsKey(mapKey))
            throw new IllegalStateException("Already created root certificate before");

        // Parameters
        X500Name issuerSubject = new X500Name("CN=cert-auth");
        LocalDateTime notBefore = LocalDateTime.now().minusDays(1);
        LocalDateTime notAfter = notBefore.plusDays(2);

        Date notBDate = Date.from(notBefore.atZone(ZoneId.of("Europe/Paris")).toInstant());
        Date notADate = Date.from(notAfter.atZone(ZoneId.of("Europe/Paris")).toInstant());

        // Generate Key pair
        KeyPair pair = KeyGenUtils.generateKeyPair(sigAlg);
        keyPairs.put(mapKey, pair);

        // Build self-signed certificate
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerSubject, BigInteger.ONE,
                notBDate, notADate, issuerSubject, pair.getPublic());
        X509CertificateHolder cert = CertificateUtils.signCert(builder, sigAlg, pair);
        certs.put(mapKey, cert);
    }

    private static void start_server() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(80), 0);
        server.createContext("/cert-app/", new CertHandler(certs.get("app")));
        server.createContext("/cert/", new CertHandler(certs.get("tls")));
        server.createContext("/sign-app/", new SignHandler(APP_SIG_ALG, keyPairs.get("app")));
        server.createContext("/sign/", new SignHandler(TLS_SIG_ALG, keyPairs.get("tls")));
        server.setExecutor(null); // creates a default executor
        server.start();
    }
}

/**
 * HTTP request handler for a certificate endpoint.
 * Responds to any request using the certificate provided in the constructor.
 */
class CertHandler implements HttpHandler {
    private X509CertificateHolder cert;

    public CertHandler(X509CertificateHolder cert) {
        this.cert = cert;
    }

    public void handle(HttpExchange t) throws IOException {
        // Don't care what's received (GET/POST, with body or not)
        // Reply with our certificate
        byte[] response = cert.getEncoded();
        t.getResponseHeaders().set("Content-Type", "application/octet-stream");
        t.sendResponseHeaders(200, response.length);

        OutputStream os = t.getResponseBody();
        os.write(response);
        os.close();
        t.close();
    }
}

/**
 * HTTP request handler for a signing endpoint.
 * Responds to any POST containing a CSR with a signed certificate using the key
 * pair and signature algorithm provided in the constructor.
 */
class SignHandler implements HttpHandler {
    private BigInteger serial;
    private KeyPair keyPair;
    private String sigAlg;

    public SignHandler(String sigAlg, KeyPair keyPair) {
        this.sigAlg = sigAlg;
        this.keyPair = keyPair;
        serial = BigInteger.TWO;
    }

    public void handle(HttpExchange t) throws IOException {
        try {

            if (!t.getRequestMethod().equals("POST")) {
                System.out.println("Received non-POST request: " + t.getRequestMethod());
                t.sendResponseHeaders(400, -1);
                return;
            }

            System.out.println("Received certificate signing request");

            // Not verified at all. In pracitce verification should include at least that
            // the request is allowed, signed correctly and contains reasonable parameters.
            PKCS10CertificationRequest csr;
            try (InputStream is = t.getRequestBody()) {
                byte[] csrBytes = is.readAllBytes();
                csr = new PKCS10CertificationRequest(csrBytes);
            }

            X500Name issuer = new X500Name("CN=cert-auth");
            LocalDateTime notBefore = LocalDateTime.now().minusHours(1);
            LocalDateTime notAfter = notBefore.plusHours(2);

            Date notBDate = Date.from(notBefore.atZone(ZoneId.of("UTC")).toInstant());
            Date notADate = Date.from(notAfter.atZone(ZoneId.of("UTC")).toInstant());

            serial = serial.add(BigInteger.ONE);
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, serial, notBDate,
                    notADate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

            // Parse requested extensions and add them
            Attribute[] attrList = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            System.out.println(attrList);
            for (Attribute attr : attrList) {
                for (ASN1Encodable attrVal : attr.getAttributeValues()) {
                    Extensions ext = Extensions.getInstance(attrVal);
                    for (ASN1ObjectIdentifier oid : ext.getExtensionOIDs()) {
                        builder.addExtension(ext.getExtension(oid));
                    }
                }
            }

            try {
                X509CertificateHolder certSigned = CertificateUtils.signCert(builder, sigAlg, keyPair);
                byte[] response = certSigned.getEncoded();
                t.getResponseHeaders().set("Content-Type", "application/octet-stream");
                t.sendResponseHeaders(200, response.length);

                OutputStream os = t.getResponseBody();
                os.write(response);
                os.close();

                System.out.println("Request fulfilled");
            } catch (OperatorCreationException | UnsupportedOperationException e) {
                throw new IOException("Error handling request", e);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}