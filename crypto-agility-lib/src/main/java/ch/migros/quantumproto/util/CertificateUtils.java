package ch.migros.quantumproto.util;

import java.io.IOException;
import java.security.KeyPair;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

public class CertificateUtils {

    /**
     * To create a CSR, we ask the user for the extensions they would like in their
     * certificate and we require their keyPair (which will be signed) as well as
     * the signature algorithm they would like to use
     * 
     * @param sigAlg     identifies how the CSR should be signed, should correspond
     *                   to type of {@code keyPair}
     * @param keyPair    holds public and private keys for which a certificate is
     *                   being requested
     * @param subject    is directly used in the CSR
     * @param extensions may be null if no extensions are requested
     * 
     * @return The resulting certificate signing request
     */
    public static PKCS10CertificationRequest createCertificationRequest(String sigAlg, KeyPair keyPair,
            X500Name subject, ExtensionsGenerator extensions)
            throws OperatorCreationException, UnsupportedOperationException, IOException {
        ContentSigner signer = SignatureUtils.getContentSignerBuilder(sigAlg).build(keyPair.getPrivate());
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject,
                keyPair.getPublic());
        if (extensions == null)
            extensions = new ExtensionsGenerator();
        // Add extensionRequests attribute
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
        return csrBuilder.build(signer);
    }

    /**
     * Takes a Certificate Builder and creates a finished certificate
     * 
     * @param builder holds the desired certificate content
     * @param sigAlg  what algorithm should be used to sign
     * @param keyPair keys to sign with
     */
    public static X509CertificateHolder signCert(X509v3CertificateBuilder builder, String sigAlg, KeyPair keyPair)
            throws OperatorCreationException, UnsupportedOperationException {
        ContentSigner signer = SignatureUtils.getContentSignerBuilder(sigAlg).build(keyPair.getPrivate());
        return builder.build(signer);
    }

    /**
     * Verifies that a certificate is correctly signed by the key presented in
     * another, trusted certificate
     * 
     * @param certToCheck The certificate under validation
     * @param parentCert  The trusted certificate whose key is claimed to have
     *                    signed {@code certToCheck}
     * @return True if and only if the signature is valid
     * @throws OperatorCreationException if the verifier cannot be built
     * @throws CertException             if verification fails for component
     *                                   signatures
     */
    public static boolean checkCert(X509CertificateHolder certToCheck, X509CertificateHolder parentCert)
            throws OperatorCreationException, CertException {
        // Extract parent key and build VerifierProvider
        SubjectPublicKeyInfo publicKey = parentCert.getSubjectPublicKeyInfo();
        ContentVerifierProvider vProv = new JcaContentVerifierProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(publicKey);

        return certToCheck.isSignatureValid(vProv);
    }

    /**
     * Extracts a suitable public key from a (possibly hybrid) certificate
     * 
     * @param cert     The certificate for extraction
     * @param sigAlgId The targeted signature algorithm
     * @return A suitable public key from the certificate
     * @throws IllegalArgumentException if the request cannot be resolved (uniquely
     *                                  or at all)
     */
    public static SubjectPublicKeyInfo extractPublicKeyForUseWith(X509CertificateHolder cert,
            AlgorithmIdentifier sigAlgId) {
        SubjectPublicKeyInfo publicKey = cert.getSubjectPublicKeyInfo();

        AlgorithmIdentifier keyAlgId = AlgorithmNameUtils.convertSigToKeyAlgId(sigAlgId);

        AlgorithmIdentifier regAlgId = publicKey.getAlgorithm();
        System.out.println("Trying to look for '" + keyAlgId.getAlgorithm() + "' in ['" + regAlgId.getAlgorithm()
                + "']");
        if (regAlgId.equals(keyAlgId)) {
            return publicKey;
        } else {
            throw new IllegalArgumentException("Algorithm '" + keyAlgId.getAlgorithm() + "' not found in certificate");
        }
    }
}
