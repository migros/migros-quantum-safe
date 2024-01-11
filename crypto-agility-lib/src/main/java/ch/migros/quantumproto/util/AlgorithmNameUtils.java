package ch.migros.quantumproto.util;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

/**
 * Utility class to help with handling signature names.
 * We build on top of JCA / BouncyCastle's algorithm names.
 * 
 * @see <a href="https://www.bouncycastle.org/specifications.html">BouncyCastle
 *      algorithm names</a>
 */
public class AlgorithmNameUtils {
    /**
     * Parses an algorithm identifier to an {@link AlgorithmIdentifier} description.
     * 
     * @param algorithmName The algorithm identifier
     * @return An {@link AlgorithmIdentifier} describing the requested scheme
     */
    public static AlgorithmIdentifier getSigAlgIdentifier(String algorithmName) {
        return new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmName);
    }

    /**
     * Deduces the required key type from a signature algorithm identifier.
     * 
     * @param algorithmName The signature algorithm identifier
     * @return A string describing the required key type, suitable for
     *         {@link java.security.KeyPairGenerator}
     * @throws UnsupportedOperationException if the signature algorithm is not one
     *                                       of the supported schemes
     */
    public static String mapSigToKeyAlgorithmName(String algorithmName) {
        if (algorithmName.contains("RSA")) {
            return "RSA";
        } else if (algorithmName.contains("ECDSA")) {
            return "EC";
        } else if (algorithmName.contains("FALCON")) {
            return "Falcon";
        } else if (algorithmName.contains("DILITHIUM")) {
            return "DILITHIUM";
        } else {
            throw new UnsupportedOperationException(
                    "Key algorithm for the signature algorithm '" + algorithmName + "' is not defined");
        }
    }

    /**
     * Deduces the required key type from a signature algorithm OID.
     * 
     * @param algorithmName The signature OID
     * @return An {@link AlgorithmIdentifier} describing the required key type
     * @throws UnsupportedOperationException if the signature algorithm is not one
     *                                       of the supported schemes
     */
    public static AlgorithmIdentifier convertSigToKeyAlgId(AlgorithmIdentifier sigAlgId) {
        // Found mostly with trial and error, not production-ready

        if (sigAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.sha256WithRSAEncryption)) {
            // SHA256WITHRSA
            return new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
        } else if (sigAlgId.getAlgorithm().equals(X9ObjectIdentifiers.ecdsa_with_SHA256)) {
            // SHA256WITHECDSA
            return new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey);
        } else if (sigAlgId.getAlgorithm().equals(BCObjectIdentifiers.falcon_1024)) {
            // FALCON-1024
            return new AlgorithmIdentifier(BCObjectIdentifiers.falcon_1024);
        } else if (sigAlgId.getAlgorithm().equals(BCObjectIdentifiers.dilithium5)) {
            // DILITHIUM5
            return new AlgorithmIdentifier(BCObjectIdentifiers.dilithium5);
        } else {
            throw new UnsupportedOperationException(
                    "Unkown signature algorithm identifier: " + sigAlgId.getAlgorithm());
        }
    }
}