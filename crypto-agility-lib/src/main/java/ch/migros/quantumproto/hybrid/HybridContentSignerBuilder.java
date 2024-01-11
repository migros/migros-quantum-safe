package ch.migros.quantumproto.hybrid;

import java.security.PrivateKey;

import org.bouncycastle.jcajce.spec.CompositeAlgorithmSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Wrapper for {@link JcaContentSignerBuilder}.
 * Does not change or check the constructor parameter {@link algorithmName}.
 * But intercepts calls to build() with nested keys to choose the correct key
 * from a {@link NestedPrivateKey}
 */
public class HybridContentSignerBuilder extends JcaContentSignerBuilder {
    // duplication of field in superclass because not visible
    private final String signatureAlgorithm;

    public HybridContentSignerBuilder(String algorithmName, CompositeAlgorithmSpec spec) {
        // Must only be used if spec is meaningful (RSA-PSS or Composite)
        super(algorithmName, spec);
        this.signatureAlgorithm = algorithmName;
    }

    public HybridContentSignerBuilder(String algorithmName) {
        super(algorithmName);
        this.signatureAlgorithm = algorithmName;
    }

    @Override
    public ContentSigner build(PrivateKey privateKey) throws OperatorCreationException {
        PrivateKey key = privateKey;

        if (privateKey instanceof NestedPrivateKey) {
            NestedPrivateKey nestedKey = (NestedPrivateKey) privateKey;
            NestedAlgorithmSpec spec = nestedKey.getAlgorithmSpec();

            if (spec.getOuterAlgorithmName().equals(signatureAlgorithm)) {
                if (spec.getInnerAlgorithmName().equals(signatureAlgorithm)) {
                    throw new RuntimeException("Ambiguous request for ContentSigner");
                } else {
                    key = nestedKey.getOuterPrivateKey();
                }
            } else {
                if (spec.getInnerAlgorithmName().equals(signatureAlgorithm)) {
                    key = nestedKey.getOuterPrivateKey();
                } else {
                    throw new IllegalArgumentException(
                            "Algorithm '" + signatureAlgorithm + "' not found in private key for '"
                                    + spec.getNestedAlgorithmName() + "'");
                }
            }
        }

        return super.build(key);
    }

}
