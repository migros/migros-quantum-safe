package ch.migros.quantumproto.util;

import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.spec.CompositeAlgorithmSpec;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import ch.migros.quantumproto.hybrid.NestedAlgorithmSpec;

/**
 * Utility class to help with handling hybrid signature names.
 * We build on top of BouncyCastle's algorithm names.
 * 
 * We introduce two notations for variants of hybrid algorithms:
 * <ul>
 * <li>For composite signatures, we separate the components using "||"
 * <li>For nested signatures, we separate the components using ">>>" where the
 * left algorithm will be the outer signature (i.e. it also signs the signature
 * produced by the right algorithm)
 * </ul>
 * 
 * @see <a href="https://www.bouncycastle.org/specifications.html">BouncyCastle
 *      algorithm names</a>
 * @see <a href=
 *      "https://datatracker.ietf.org/doc/draft-ounsworth-pq-composite-sigs/">Composite
 *      Signatures</a>
 * @see <a href="https://eprint.iacr.org/2017/460.pdf">Nested Signatures (see
 *      Section 4.3)</a>
 */
public class AlgorithmNameUtils {
    private static final String COMPOSITE_DELIM = "||";
    private static final String NESTED_DELIM = ">>>";

    /**
     * Simple check to distinguish nested signature algorithm identifiers from
     * composite ones.
     * 
     * @param s The algorithm identifier, using syntax as described in
     *          {@link AlgorithmNameUtils}
     * @return True if and only if the given string appears to identify
     *         a composite signing algorithm.
     */
    public static boolean isCompositeName(String s) {
        return s.contains(COMPOSITE_DELIM);
    }

    /**
     * Simple check to distinguish nested signature algorithm identifiers from
     * composite ones.
     * 
     * @param s The algorithm identifier, using syntax as described in
     *          {@link AlgorithmNameUtils}
     * @return True if and only if the given string appears to identify
     *         a nested signing algorithm.
     */
    public static boolean isNestedName(String s) {
        return s.contains(NESTED_DELIM);
    }

    /**
     * Parses the given algorithm identifier and creates a
     * {@link CompositeAlgorithmSpec} containing the component algorithm names.
     * 
     * @param s The algorithm identifier, using syntax as described in
     *          {@link AlgorithmNameUtils}
     * @return A {@link CompositeAlgorithmSpec} whose algorithmNames contains the
     *         algorithms identified in the parameter s.
     */
    public static CompositeAlgorithmSpec getCompositeAlgorithmSpec(String s) {
        List<String> components = splitInTwo(s, COMPOSITE_DELIM);
        return new CompositeAlgorithmSpec.Builder().add(components.get(0)).add(components.get(1)).build();
    }

    /**
     * Parses the given algorithm identifier and creates a
     * {@link NestedAlgorithmSpec} containing the component algorithm names.
     * 
     * @param s The algorithm identifier, using syntax as described in
     *          {@link AlgorithmNameUtils}
     * @return A {@link NestedAlgorithmSpec} whose algorithmNames contains the
     *         algorithms identified in the parameter s.
     */
    public static NestedAlgorithmSpec getNestedAlgorithmSpec(String s) {
        List<String> components = splitInTwo(s, NESTED_DELIM);
        return new NestedAlgorithmSpec.Builder().setOuter(components.get(0)).setInner(components.get(1)).build();
    }

    /**
     * Combines two given algorithm identifers to a composite algorithm
     * 
     * @param comp1 The first component algorithm, using syntax as described in
     *              {@link AlgorithmNameUtils}
     * @param comp2 The second component algorithm, using syntax as described in
     *              {@link AlgorithmNameUtils}
     * @return An algorithm identifier describing the composite scheme as described
     *         in {@link AlgorithmNameUtils}
     */
    public static String createCompositeAlgorithm(String comp1, String comp2) {
        return comp1 + COMPOSITE_DELIM + comp2;
    }

    /**
     * Combines two given algorithm identifers to a composite algorithm
     * 
     * @param outer The outer component algorithm, using syntax as described in
     *              {@link AlgorithmNameUtils}
     * @param inner The inner component algorithm, using syntax as described in
     *              {@link AlgorithmNameUtils}
     * @return An algorithm identifier describing the nested scheme as described
     *         in {@link AlgorithmNameUtils}
     */
    public static String createNestedAlgorithm(String outer, String inner) {
        return outer + NESTED_DELIM + inner;
    }

    /**
     * Parses an atomic or composite algorithm identifier (using syntax as described
     * in {@link AlgorithmNameUtils}) to an {@link AlgorithmIdentifier} description.
     * 
     * @param algorithmName The algorithm identifier, using syntax as described in
     *                      {@link AlgorithmNameUtils}
     * @return An {@link AlgorithmIdentifier} describing the requested scheme
     * @throws UnsupportedOperationException if a nested algorithm is provided
     *                                       (callers should build the correct
     *                                       certificate directly)
     * @throws IllegalArgumentException      if no suitable algorithm is found in
     *                                       the crypto provider
     */
    public static AlgorithmIdentifier getSigAlgIdentifier(String algorithmName) {
        if (AlgorithmNameUtils.isCompositeName(algorithmName)) {
            // Adapted from JcaContentSignerBuilder
            CompositeAlgorithmSpec spec = AlgorithmNameUtils.getCompositeAlgorithmSpec(algorithmName);
            return new AlgorithmIdentifier(MiscObjectIdentifiers.id_alg_composite, createCompParams(spec));
        } else if (AlgorithmNameUtils.isNestedName(algorithmName)) {
            // Callers should use X.509 construction directly
            throw new UnsupportedOperationException("There is no algorithm identifier for nested algorithms");
        }
        return new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmName);
    }

    /**
     * Deduces the required key type from a signature algorithm identifier.
     * 
     * @param algorithmName The signature algorithm identifier (must not be
     *                      composite or
     *                      nested)
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

    /**
     * Adapted from {@link JcaContentSignerBuilder}, used to build a composite
     * {@link AlgorithmIdentifier}
     * 
     * @param compSpec Output from
     *                 {@link AlgorithmNameUtils#getCompositeAlgorithmSpec}
     * @return A {@link ASN1Sequence} describing the component algorithms
     */
    private static ASN1Sequence createCompParams(CompositeAlgorithmSpec compSpec) {
        SignatureAlgorithmIdentifierFinder algFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        ASN1EncodableVector v = new ASN1EncodableVector();

        List<String> algorithmNames = compSpec.getAlgorithmNames();
        List<AlgorithmParameterSpec> algorithmSpecs = compSpec.getParameterSpecs();

        for (int i = 0; i != algorithmNames.size(); i++) {
            AlgorithmParameterSpec sigSpec = algorithmSpecs.get(i);
            if (sigSpec == null) {
                v.add(algFinder.find(algorithmNames.get(i)));
                // Removed the following case as we never use RSA-PSS:
                // } else if (sigSpec instanceof PSSParameterSpec) {
                // v.add(createPSSParams((PSSParameterSpec) sigSpec));
            } else {
                throw new IllegalArgumentException("unrecognized parameterSpec");
            }
        }

        return new DERSequence(v);
    }

    /**
     * Splits the given algorithm identifier into its two component algorithms using
     * the provided delimiter.
     * 
     * @param s     The algorithm identifier
     * @param delim The delimiter
     * 
     * @return A list of the component algorithms
     * 
     * @throws IllegalArgumentException if not exactly 1 delimiter is found in the
     *                                  identifier
     */
    private static List<String> splitInTwo(String s, String delim) {
        List<String> list = new ArrayList<>();

        if (!s.contains(delim))
            throw new IllegalArgumentException("Found no delimiter (" + delim + ") in: '" + s + "'");

        String comp1 = s.substring(0, s.indexOf(delim));
        String comp2 = s.substring(s.indexOf(delim) + delim.length(), s.length());

        if (comp2.contains(delim))
            throw new IllegalArgumentException("Found more than one delimiter (" + delim + ") in: '" + s + "'");

        list.add(comp1);
        list.add(comp2);

        return list;
    }
}