package ch.migros.quantumproto.hybrid;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

/**
 * Utility class to ease creation of hybrid certificates
 */
public class HybridCertificateBuilder {

    /**
     * Creates a CertificateBuilder with the given parameters. This can then be
     * provided with the signing key to create a certificate. The public key
     * provided here may be composite, nested or atomic.
     * 
     * @param issuer    X500Name representing the issuer of this certificate.
     * @param serial    the serial number for the certificate.
     * @param notBDate  Time before which the certificate is not valid.
     * @param notADate  Time after which the certificate is not valid.
     * @param subject   X500Name representing the subject of this certificate.
     * @param publicKey The (possibly nested) public key to be associated with the
     *                  certificate.
     * @return A corresponding CertificateBuilder
     * @throws CertIOException
     */
    public static JcaX509v3CertificateBuilder createBuilder(X500Name issuer, BigInteger serial, Date notBDate,
            Date notADate, X500Name subject, PublicKey publicKey) throws CertIOException {
        if (publicKey instanceof NestedPublicKey) {
            NestedPublicKey nestedKey = (NestedPublicKey) publicKey;
            PublicKey outerKey = nestedKey.getOuterPublicKey();
            PublicKey innerKey = nestedKey.getInnerPublicKey();
            SubjectPublicKeyInfo innerKeyInfo = SubjectPublicKeyInfo.getInstance(innerKey.getEncoded());

            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, notBDate, notADate,
                    subject, outerKey);
            builder.addExtension(Extension.subjectAltPublicKeyInfo, false, innerKeyInfo);
            return builder;
        } else {
            return new JcaX509v3CertificateBuilder(issuer, serial, notBDate, notADate, subject, publicKey);
        }
    }

}
