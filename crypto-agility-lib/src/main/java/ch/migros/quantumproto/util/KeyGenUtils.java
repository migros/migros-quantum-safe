package ch.migros.quantumproto.util;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

public class KeyGenUtils {

    /**
     * Creates a key pair for a given nested, composite or atomic algorithm
     * identifier
     * 
     * @param algorithmName The algorithm identifier, using syntax as described in
     *                      {@link AlgorithmNameUtils}
     * @return An freshly generated key pair suitable for further use with this
     *         algorithm
     * @throws NoSuchAlgorithmException           if the crypto provider does not
     *                                            support a required algorithm
     * @throws NoSuchProviderException            if the crypto provider does not
     *                                            exist
     * @throws InvalidAlgorithmParameterException if the key generation spec is not
     *                                            suitable
     */
    public static KeyPair generateKeyPair(String algorithmName)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // Map algorithmName for signatures to algorithmName for keyPairGenerator
        String keyAlgName = AlgorithmNameUtils.mapSigToKeyAlgorithmName(algorithmName);

        KeyPairGenerator gen = KeyPairGenerator.getInstance(keyAlgName, BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec keyGenSpec = KeyGenUtils.getKeyGenSpecForAlgorithm(keyAlgName);

        gen.initialize(keyGenSpec, new SecureRandom());

        return gen.generateKeyPair();
    }

    /**
     * When creating keys via the JCE, we need to provide an appropriate instance of
     * {@link java.security.spec.AlgorithmParameterSpec}. This class handles:
     * <ul>
     * <li>Figuring out which instance is appropriate
     * <li>Choosing suitable default parameters like key size or public exponent
     * </ul>
     * We don't provide a documentation of all supported algorithms as that would
     * change often. Please see the code.
     * 
     * @param algorithmName The algorithm name used in
     *                      {@link java.security.KeyPairGenerator#getInstance}.
     *                      Should be listed in:
     *                      https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keypairgenerator-algorithms
     * @return An appropriate non-null instance of
     *         {@link java.security.sepc.AlgorithmParameterSpec}
     * @throws UnsupportedOperationException If the algorithmName is not recognized
     */
    private static AlgorithmParameterSpec getKeyGenSpecForAlgorithm(String algorithmName)
            throws UnsupportedOperationException {
        switch (algorithmName) {
            case "RSA":
                return new RSAKeyGenParameterSpec(3072, BigInteger.valueOf(65537), null);
            case "EC":
                return new ECGenParameterSpec("secp256r1");
            case "Falcon":
                return FalconParameterSpec.falcon_1024;
            case "DILITHIUM":
                return DilithiumParameterSpec.dilithium5;
            default:
                throw new UnsupportedOperationException(
                        "Key generation for the algorithm '" + algorithmName + "' is not defined");
        }
    }

}
