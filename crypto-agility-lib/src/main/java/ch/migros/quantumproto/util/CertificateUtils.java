package ch.migros.quantumproto.util;

import java.io.IOException;
import java.security.KeyPair;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
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

import ch.migros.quantumproto.hybrid.NestedPrivateKey;
import ch.migros.quantumproto.hybrid.NestedPublicKey;

public class CertificateUtils {

    /**
     * To create a CSR, we ask the user for the extensions they would like in their
     * certificate and we require their keyPair (which will be signed) as well as
     * the signature algorithm they would like to use
     * 
     * NB: For hybrid applications, we will add the alternative public key (to be
     * used in addition to the regular one) as an extensionRequest attribute to the
     * CSR. This will result in a certificate with 'altSubjectPublicKeyInfo'
     * 
     * NB 2: How the CA chooses to sign such a request is left open
     * Also, this only makes sense if the key pair is used in fully hybrid
     * applications later on. For clients that only verify the regular 'signature'
     * Knowledge of the alternative key MUST NOT be assumed
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

        boolean useAltPublicKey = AlgorithmNameUtils.isNestedName(sigAlg);
        assert (keyPair.getPrivate() instanceof NestedPrivateKey == useAltPublicKey);
        assert (keyPair.getPublic() instanceof NestedPublicKey == useAltPublicKey);

        // Outer is used to sign CSR: Does not restrict usage of the public key at all
        // * Option A) Keep one signature, make it classical for compatibility
        // * Option B) Also introduce altSignature with the altPublicKey into the CSR
        // We choose B, as part of the signature's purpose is to verify key ownership
		if (extensions == null)
            extensions = new ExtensionsGenerator();
                
        if (useAltPublicKey) {
            String outerSigAlg = AlgorithmNameUtils.getNestedAlgorithmSpec(sigAlg).getOuterAlgorithmName();
            // String innerSigAlg =
            // AlgorithmNameUtils.getNestedAlgorithmSpec(sigAlg).getInnerAlgorithmName();

            NestedPrivateKey nestedPrivateKey = (NestedPrivateKey) keyPair.getPrivate();
            NestedPublicKey nestedPublicKey = (NestedPublicKey) keyPair.getPublic();

            ContentSigner outerSigner = SignatureUtils.getContentSignerBuilder(outerSigAlg)
                    .build(nestedPrivateKey.getOuterPrivateKey());
            // ContentSigner innerSigner =
            // SignatureUtils.getContentSignerBuilder(innerSigAlg)
            // .build(nestedPrivateKey.getInnerPrivateKey());

            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject,
                    nestedPublicKey.getOuterPublicKey());

            // Add subjectAltPublicKeyInfo extension
            SubjectAltPublicKeyInfo subjectAltPublicKeyInfo = SubjectAltPublicKeyInfo
                    .getInstance(nestedPublicKey.getInnerPublicKey().getEncoded());
            extensions.addExtension(
                    new Extension(Extension.subjectAltPublicKeyInfo, false, subjectAltPublicKeyInfo.getEncoded()));

            // Add extensionRequests attribute
            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());

            // Possibly add innerSigner signature as attribute.
            // Not part of RFC 2986 yet
            // Not for inlcusion in cert but to demonstrate knowledge of key
            return csrBuilder.build(outerSigner);
        } else {
            ContentSigner signer = SignatureUtils.getContentSignerBuilder(sigAlg).build(keyPair.getPrivate());
            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject,
                    keyPair.getPublic()); 
            // Add extensionRequests attribute
            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
            return csrBuilder.build(signer);
        }
    }

    /**
     * Takes a Certificate Builder and creates a finished certificate
     * Depending on sigAlg and keyPair, this certificate MAY contain altSignature
     * and altSignatureAlgorithm extensions.
     * 
     * @param builder holds the desired certificate content
     * @param sigAlg  what algorithm should be used to sign (may be a nested or
     *                compound name)
     * @param keyPair keys to sign with
     */
    public static X509CertificateHolder signCert(X509v3CertificateBuilder builder, String sigAlg, KeyPair keyPair)
            throws OperatorCreationException, UnsupportedOperationException {
        boolean useAltPublicKey = AlgorithmNameUtils.isNestedName(sigAlg);
        assert (keyPair.getPrivate() instanceof NestedPrivateKey == useAltPublicKey);
        assert (keyPair.getPublic() instanceof NestedPublicKey == useAltPublicKey);

        if (useAltPublicKey) {
            String outerSigAlg = AlgorithmNameUtils.getNestedAlgorithmSpec(sigAlg).getOuterAlgorithmName();
            String innerSigAlg = AlgorithmNameUtils.getNestedAlgorithmSpec(sigAlg).getInnerAlgorithmName();

            NestedPrivateKey nestedKey = (NestedPrivateKey) keyPair.getPrivate();

            ContentSigner outerSigner = SignatureUtils.getContentSignerBuilder(outerSigAlg)
                    .build(nestedKey.getOuterPrivateKey());
            ContentSigner innerSigner = SignatureUtils.getContentSignerBuilder(innerSigAlg)
                    .build(nestedKey.getInnerPrivateKey());
            return builder.build(outerSigner, false, innerSigner);
        } else {
            ContentSigner outerSigner = SignatureUtils.getContentSignerBuilder(sigAlg).build(keyPair.getPrivate());
            return builder.build(outerSigner);
        }
    }

    /**
     * Check to distinguish hybrid certificates from classical ones.
     * 
     * @param cert The certificate
     * @return True if and only if the given certificate holds a nested pair of
     *         public keys, i.e. is a (nested) hybrid certificate
     */
    public static boolean isHybridCert(X509CertificateHolder cert) {
        return extractAltPublicKey(cert) != null;
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
        // Extract regular key
        SubjectPublicKeyInfo publicKey = parentCert.getSubjectPublicKeyInfo();
        ContentVerifierProvider vProv = new JcaContentVerifierProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(publicKey);

        SubjectPublicKeyInfo altPublicKey = extractAltPublicKey(parentCert);
        if (altPublicKey != null) {
            // We have an altPublicKey in the parent certificate
            ContentVerifierProvider altVProv = new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(altPublicKey);
            return certToCheck.isSignatureValid(vProv) && certToCheck.isAlternativeSignatureValid(altVProv);
        } else {
            return certToCheck.isSignatureValid(vProv);
        }

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
        SubjectPublicKeyInfo altPublicKey = extractAltPublicKey(cert);

        if (altPublicKey == null)
            return publicKey;

        AlgorithmIdentifier keyAlgId = AlgorithmNameUtils.convertSigToKeyAlgId(sigAlgId);

        AlgorithmIdentifier regAlgId = publicKey.getAlgorithm();
        AlgorithmIdentifier altAlgId = altPublicKey.getAlgorithm();
        System.out.println("Trying to look for '" + keyAlgId.getAlgorithm() + "' between '" + regAlgId.getAlgorithm()
                + "' and '" + altAlgId + "'");
        if (regAlgId.equals(keyAlgId)) {
            if (altAlgId.equals(keyAlgId)) {
                throw new IllegalArgumentException("Ambiguous request for key");
            } else {
                return publicKey;
            }
        } else {
            if (altAlgId.equals(keyAlgId)) {
                return altPublicKey;
            } else {
                throw new IllegalArgumentException(
                        "Algorithm '" + keyAlgId.getAlgorithm() + "' not found in certificate");
            }
        }
    }

    /**
     * Extracts a suitable public key from a (possibly hybrid) certificate
     * 
     * @param cert          The certificate for extraction
     * @param algorithmName The targeted signature algorithm, using syntax as
     *                      described in {@link AlgorithmNameUtils}
     * @return A suitable public key from the certificate
     * @throws IllegalArgumentException if the request cannot be resolved (uniquely
     *                                  or at all)
     */
    public static SubjectPublicKeyInfo extractPublicKeyForUseWith(X509CertificateHolder cert, String algorithmName) {
        // Redundant check but nicer error message
        if (AlgorithmNameUtils.isNestedName(algorithmName))
            throw new UnsupportedOperationException("Cannot extract key for nested algorithm '" + algorithmName + "'");

        return extractPublicKeyForUseWith(cert, AlgorithmNameUtils.getSigAlgIdentifier(algorithmName));
    }

    /**
     * @param cert Certificate to extract AltPublicKey from
     * @return altSubjectPublicKeyInfo object or null if no such extension exists
     * @throws IOException
     */
    private static SubjectPublicKeyInfo extractAltPublicKey(X509CertificateHolder cert) {
        try {
            Extension altSubjectPublicKeyInfo = cert.getExtension(Extension.subjectAltPublicKeyInfo);
            if (altSubjectPublicKeyInfo != null) {
                return SubjectPublicKeyInfo.getInstance(altSubjectPublicKeyInfo.getExtnValue().getOctets());
            } else {
                return null;
            }
        } catch (Exception e) {
            throw new RuntimeException("Found alternative key but could not extract", e);
        }
    }

}
