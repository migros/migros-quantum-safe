package ch.migros.quantumproto.hybrid;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import ch.migros.quantumproto.util.AlgorithmNameUtils;

/**
 * Holds algorithm names and parameters (if any) for two algorithms to be
 * used together in a nested, hybrid setting
 */
public class NestedAlgorithmSpec implements AlgorithmParameterSpec {
    public static class Builder {
        private String algorithmNameInner;
        private String algorithmNameOuter;
        private AlgorithmParameterSpec parameterSpecInner;
        private AlgorithmParameterSpec parameterSpecOuter;

        public Builder() {
        }

        public Builder setInner(String algorithmName) {
            return setInner(algorithmName, null);
        }

        public Builder setOuter(String algorithmName) {
            return setOuter(algorithmName, null);
        }

        public Builder setInner(String algorithmName, AlgorithmParameterSpec parameterSpec) {
            algorithmNameInner = algorithmName;
            parameterSpecInner = parameterSpec;

            return this;
        }

        public Builder setOuter(String algorithmName, AlgorithmParameterSpec parameterSpec) {
            algorithmNameOuter = algorithmName;
            parameterSpecOuter = parameterSpec;

            return this;
        }

        public NestedAlgorithmSpec build() {
            if (algorithmNameInner == null || algorithmNameOuter == null) {
                throw new IllegalStateException("cannot call build with <2 algorithm names added");
            }

            return new NestedAlgorithmSpec(this);
        }
    }

    private final String algorithmNameInner;
    private final String algorithmNameOuter;
    private final AlgorithmParameterSpec parameterSpecInner;
    private final AlgorithmParameterSpec parameterSpecOuter;

    public NestedAlgorithmSpec(Builder builder) {
        this.algorithmNameInner = builder.algorithmNameInner;
        this.algorithmNameOuter = builder.algorithmNameOuter;
        this.parameterSpecInner = builder.parameterSpecInner;
        this.parameterSpecOuter = builder.parameterSpecOuter;
    }

    public String getOuterAlgorithmName() {
        return algorithmNameOuter;
    }

    public String getInnerAlgorithmName() {
        return algorithmNameInner;
    }

    public AlgorithmParameterSpec getOuterParameterSpec() {
        return parameterSpecOuter;
    }

    public AlgorithmParameterSpec getInnerParameterSpec() {
        return parameterSpecInner;
    }

    public AlgorithmIdentifier getOuterAlgId() {
        return AlgorithmNameUtils.getSigAlgIdentifier(algorithmNameOuter);
    }

    public AlgorithmIdentifier getInnerAlgId() {
        return AlgorithmNameUtils.getSigAlgIdentifier(algorithmNameInner);
    }

    public String getNestedAlgorithmName() {
        return AlgorithmNameUtils.createNestedAlgorithm(algorithmNameOuter, algorithmNameInner);
    }
}
