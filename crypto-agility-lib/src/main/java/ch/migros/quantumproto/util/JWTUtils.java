package ch.migros.quantumproto.util;

import org.bouncycastle.jcajce.spec.CompositeAlgorithmSpec;

public class JWTUtils {

    /**
     * Converts some choices for the JWT "alg" header field defined here
     * https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
     * 
     * To their appropriate pendant in Java as defined in
     * https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#signature-algorithms
     * 
     * @param alg the algorithm identifier in JOSE notation (optionally including
     *            composite identifiers using the same delimiter as in
     *            {@link AlgorithmNameUtils})
     * @return An algorithm identifier using syntax as described in
     *         {@link AlgorithmNameUtils}
     * @throws UnsupportedOperationException If alg is not recognized
     */
    public static String algToSigAlgName(String alg) throws UnsupportedOperationException {
        if (AlgorithmNameUtils.isCompositeName(alg)) {
            CompositeAlgorithmSpec comps = AlgorithmNameUtils.getCompositeAlgorithmSpec(alg);
            String classical = comps.getAlgorithmNames().get(0);
            String quantumsafe = comps.getAlgorithmNames().get(1);

            return AlgorithmNameUtils.createCompositeAlgorithm(algToSigAlgName(classical),
                    algToSigAlgName(quantumsafe));
        } else if (AlgorithmNameUtils.isNestedName(alg)) {
            throw new UnsupportedOperationException("Nested JWT signatures are not supported.");
        }

        switch (alg) {
            case "RS256":
                return "SHA256WITHRSA";
            case "ES256":
                return "SHA256withECDSA";
            case "DILI5":
                return "DILITHIUM5";
            case "FAL10":
                return "FALCON-1024";
            default:
                throw new UnsupportedOperationException("Algorithm ID '" + alg + "' is not supported.");
        }
    }

}
