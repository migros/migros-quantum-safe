package ch.migros.quantumproto.hybrid;

import java.security.PublicKey;
import java.util.Objects;

import org.bouncycastle.jcajce.CompositePublicKey;

/**
 * A nested public key class.
 * Adapted from {@link CompositePublicKey}
 */
public class NestedPublicKey
        implements PublicKey {
    private final PublicKey keyInner;
    private final PublicKey keyOuter;
    private final NestedAlgorithmSpec nestedAlgSpec;

    public NestedPublicKey(PublicKey keyOuter, PublicKey keyInner, NestedAlgorithmSpec nestedAlgSpec) {
        this.keyOuter = keyOuter;
        this.keyInner = keyInner;
        this.nestedAlgSpec = nestedAlgSpec;
    }

    public PublicKey getOuterPublicKey() {
        return keyOuter;
    }

    public PublicKey getInnerPublicKey() {
        return keyInner;
    }

    public String getAlgorithm() {
        return "Nested";
    }

    public NestedAlgorithmSpec getAlgorithmSpec() {
        return nestedAlgSpec;
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        throw new UnsupportedOperationException("unable to encode nested public key");
    }

    public int hashCode() {
        return Objects.hash(keyOuter, keyInner);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (o instanceof NestedPublicKey) {
            NestedPublicKey other = (NestedPublicKey) o;
            return keyOuter.equals(other.keyOuter) && keyInner.equals(other.keyInner);
        }

        return false;
    }
}
