package ch.migros.quantumproto;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

/**
 * Defines a microservice called "JWT-Client" which presents the user with an
 * HTML webpage, accepting messages that are then submitted to JWT-Creator for
 * signing. The signed JWT is forwarded to the JWT-Verifier and its response is
 * reported to the user within the webpage.
 */
public class JWTClientApp {
    private static X509CertificateHolder certRoot;

    public static void main(String[] args) {
        System.out.println("I am a JWT Client!");

        Security.addProvider(new BouncyCastleJsseProvider());

        // Download root certificate form CA
        try {
            certRoot = get_root_certificate();
        } catch (Exception e) {
            System.out.println("Certificate acquisition failed: " + e.getMessage());
            return;
        }

        System.out.println("I have the CA certificate");

        // Setup web interface for interacting with services
        try {
            start_server();
        } catch (Exception e) {
            System.out.println("HTTPS Server Startup failed: " + e.getMessage());
            return;
        }

        System.out.println("I am ready to interact with the system at jwt-client:80/interact/");
    }

    private static void start_server() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(80), 0);
        server.createContext("/interact/", new InterfaceHandler());
        server.createContext("/run-interaction/", new InteractionHandler(certRoot));
        server.setExecutor(null); // creates a default executor
        server.start();
    }

    private static X509CertificateHolder get_root_certificate() throws IOException {
        // Download root certificate from CA
        URL url = new URL("http://10.2.0.7/cert/");
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
 * HTTP request handler for the main user interface of the protoype
 */
class InterfaceHandler implements HttpHandler {
    private final String HTML_STRING;

    public InterfaceHandler() throws IOException {
        // Read HTML page form resource file
        InputStream inputStream = InterfaceHandler.class.getResourceAsStream("/interact.html");

        StringBuilder resultStringBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = br.readLine()) != null) {
                resultStringBuilder.append(line).append("\n");
            }
        }
        inputStream.close();

        HTML_STRING = resultStringBuilder.toString();
    }

    public void handle(HttpExchange t) throws IOException {
        // Returns a website with a form for the message
        // Upon submission, JS calls /run-interaction/ and displays result
        byte[] respBytes = HTML_STRING.getBytes();
        t.getResponseHeaders().set("Content-Type", "text/html");
        t.sendResponseHeaders(200, respBytes.length);

        OutputStream os = t.getResponseBody();
        os.write(respBytes);
        os.close();
    }
}

/**
 * HTTP request handler simulating an execution of the prototype interactions.
 * Upon receiving a POST request, the message is forwarded to the JWT Creator,
 * whose JWT and certificate are sent to the JWT Verifier for verification.
 * The response from the JWT Verifier is then sent back as a response to the
 * original request.
 * 
 * The connection to the JWT Creator is protected using TLS.
 * The connection to the JWT Verifier is done via a VPN tunnel (due to the
 * network configuration).
 */
class InteractionHandler implements HttpHandler {
    private X509CertificateHolder certRoot;

    public InteractionHandler(X509CertificateHolder certRoot) {
        this.certRoot = certRoot;
    }

    public void handle(HttpExchange t) throws IOException {
        // expect POST requests
        if (!t.getRequestMethod().equals("POST")) {
            t.sendResponseHeaders(405, -1);
            return;
        }

        try {
            // Connects to other services and returns verification result
            String message = new String(t.getRequestBody().readAllBytes());
            if (message.startsWith("message=")) {
                message = message.substring(8);

                message = URLDecoder.decode(message, StandardCharsets.UTF_8.name());
            }

            System.out.println("Received interaction request with message: " + message);

            // Set up truststore with CA
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null);

            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certCA = (X509Certificate) certFactory
                    .generateCertificate(new ByteArrayInputStream(certRoot.getEncoded()));
            ks.setCertificateEntry("ca-root", certCA);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            tmf.init(ks);

            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());

            // Connect to JWT Creator: HTTPS
            URL url = new URL("https://jwt-creator/jwt-create/");
            HttpsURLConnection connectionTLS = (HttpsURLConnection) url.openConnection();

            if (connectionTLS == null)
                throw new IllegalStateException("Could not establish connection to jwt-creator");

            connectionTLS.setSSLSocketFactory(sslContext.getSocketFactory());

            connectionTLS.setRequestMethod("POST");
            connectionTLS.setDoOutput(true);
            System.out.println("About to connect to jwt-creator");

            OutputStream os = connectionTLS.getOutputStream();
            byte[] msgBytes = message.getBytes();
            os.write(msgBytes);
            os.close();

            System.out.println("Sent request to jwt-creator");

            if (connectionTLS.getResponseCode() != 200)
                throw new IllegalStateException(
                        "Received invalid response code from jwt-creator: " + connectionTLS.getResponseCode());

            String mime_type_tls = connectionTLS.getContentType();
            InputStream is = connectionTLS.getInputStream();
            byte[] jwtCertBytes = is.readAllBytes();
            is.close();
            connectionTLS.disconnect();

            // Cloud display JSON object (keys "jwt" and "cert") here
            System.out.println("This is the response I got: " + new String(jwtCertBytes));

            // Connect to JWT Verifier
            url = new URL("http://10.2.0.6/jwt-verify/");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            if (connection == null)
                throw new IllegalStateException("Could not establish connection to jwt-verifier");

            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", mime_type_tls);
            connection.setDoOutput(true);

            os = connection.getOutputStream();
            os.write(jwtCertBytes);
            os.close();

            if (connection.getResponseCode() != 200)
                throw new IllegalStateException(
                        "Received invalid response code from jwt-verifier: " + connection.getResponseCode());

            String mime_type = connection.getContentType();
            is = connection.getInputStream();
            byte[] respBytes = is.readAllBytes();
            is.close();
            connection.disconnect();

            // Should not fail but instead report error message
            t.getResponseHeaders().set("Content-Type", mime_type);
            t.sendResponseHeaders(200, respBytes.length);

            os = t.getResponseBody();
            os.write(respBytes);
            os.close();
        } catch (Exception e) {
            e.printStackTrace();

            // Should not fail but instead report error message
            String response = "Fatal error: " + e.getMessage();
            byte[] respBytes = response.getBytes();
            t.getResponseHeaders().set("Content-Type", "text/plain");
            t.sendResponseHeaders(500, respBytes.length);

            OutputStream os = t.getResponseBody();
            os.write(respBytes);
            os.close();
        }
    }
}