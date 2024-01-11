package ch.migros.quantumproto.util;

import java.security.cert.CertificateException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

/**
 * Utility class to support hybrid signatures and certificates
 * while being completely transparent to regular signatures
 * 
 * All signing and verification operations should use the methods implemented
 * here:
 * <ul>
 * <li>For signing, we provide the ContentSignerBuilder directly, only the
 * private key must be supplied
 * <li>For verification, we provide here a ContentVerifier for specific
 * algorithms. This requires knowledge of the algorithm used. To verify compound
 * structures (e.g. X.509 certificates), utility classes like
 * {@link CertificateUtils} should be used.
 * </ul>
 * 
 * Whenever we
 * 
 * @see <a href=
 *      "https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#signature-algorithms">https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#signature-algorithms</a>
 */

public class SignatureUtils {

    /**
     * Creates a ContentSignerBuilder for the given algorithm identifier. The
     * private key
     * can be provided to it when signing.
     * 
     * @param algorithmName The algorithm identifier, using syntax as described in
     *                      {@link AlgorithmNameUtils}
     * @return The resulting ContentSignerBuilder
     * @throws UnsupportedOperationException if a nested algorithm identifier is
     *                                       provided (callers should use
     *                                       {@link CertificateUtils} to sign
     *                                       certificates using nested schemes)
     */
    public static JcaContentSignerBuilder getContentSignerBuilder(String algorithmName)
            throws UnsupportedOperationException {
        return new JcaContentSignerBuilder(algorithmName).setProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    /**
     * Creates a ContentVerifier for the given algorithm identifier. The public key
     * is already provided to it from the given certificate.
     * 
     * @param cert          The certificate containing the public key
     * @param algorithmName The signing algorithm which will be verified
     * @return The resulting ContentVerifier
     * @throws OperatorCreationException if construction of the VerifierProvider
     *                                   fails
     * @throws CertificateException      if the certificate fails to parse
     * @throws IllegalArgumentException  if no suitable public key is found in the
     *                                   certificate
     */
    public static ContentVerifier getContentVerifier(X509CertificateHolder cert, String algorithmName)
            throws OperatorCreationException, CertificateException {
        return new JcaContentVerifierProviderBuilder().build(cert)
                .get(AlgorithmNameUtils.getSigAlgIdentifier(algorithmName));
    }

}
