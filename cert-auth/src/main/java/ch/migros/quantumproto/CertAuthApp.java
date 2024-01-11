package ch.migros.quantumproto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

/**
 * Defines a microservice called "Cert-Auth" which creates a self-signed root
 * certificate, publishes it via an HTTP endpoint and accepts any CSRs on other
 * endpoints for signing using the root certificate.
 */
public class CertAuthApp {
    private static Map<String, KeyPair> keyPairs = new HashMap<>(2);
    private static Map<String, X509CertificateHolder> certs = new HashMap<>(2);

    public static void main(String[] args) throws InterruptedException {
        System.out.println("I am a CA!");

        Security.addProvider(new BouncyCastleProvider());

        // Create new root certificates
        try {
            create_root_certificate("tls");
            create_root_certificate("app");
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
     * Creates a self-signed certificate with a fresh RSA key pair.
     * Saves the resulting key pair and certificate as part of static
     * {@code keyPair} and {@code certs} maps respectively.
     * 
     * @param mapKey the key under which to save the results
     * @throws OperatorCreationException if certificate signing fails
     */
    private static void create_root_certificate(String mapKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            OperatorCreationException {
        if (keyPairs.containsKey(mapKey))
            throw new IllegalStateException("Already created root certificate before");

        // Parameters
        X500Name issuerSubject = new X500Name("CN=cert-auth");
        LocalDateTime notBefore = LocalDateTime.now().minusDays(1);
        LocalDateTime notAfter = notBefore.plusDays(2);

        Date notBDate = Date.from(notBefore.atZone(ZoneId.of("Europe/Paris")).toInstant());
        Date notADate = Date.from(notAfter.atZone(ZoneId.of("Europe/Paris")).toInstant());

        // Generate RSA-3072 Key pair
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        gen.initialize(new RSAKeyGenParameterSpec(3072, BigInteger.valueOf(65537), null), new SecureRandom());

        KeyPair pair = gen.generateKeyPair();
        keyPairs.put(mapKey, pair);

        // Build self-signed certificate
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerSubject, BigInteger.ONE,
                notBDate, notADate, issuerSubject, pair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WITHRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(pair.getPrivate());
        X509CertificateHolder cert = builder.build(signer);
        certs.put(mapKey, cert);
    }

    private static void start_server() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(80), 0);
        server.createContext("/cert-app/", new CertHandler(certs.get("app")));
        server.createContext("/cert/", new CertHandler(certs.get("tls")));
        server.createContext("/sign-app/", new SignHandler(keyPairs.get("app")));
        server.createContext("/sign/", new SignHandler(keyPairs.get("tls")));
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

    public SignHandler(KeyPair keyPair) {
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
                ContentSigner signer = new JcaContentSignerBuilder("SHA256WITHRSA")
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(keyPair.getPrivate());
                X509CertificateHolder certSigned = builder.build(signer);
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