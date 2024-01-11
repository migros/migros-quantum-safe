package ch.migros.quantumproto.hybrid;

import java.security.PrivateKey;
import java.util.Objects;

import org.bouncycastle.jcajce.CompositePrivateKey;

/**
 * A nested private key class.
 * Adapted from {@link CompositePrivateKey}
 */
public class NestedPrivateKey
        implements PrivateKey {
    private final PrivateKey keyInner;
    private final PrivateKey keyOuter;
    private final NestedAlgorithmSpec nestedAlgSpec;

    public NestedPrivateKey(PrivateKey keyOuter, PrivateKey keyInner, NestedAlgorithmSpec nestedAlgSpec) {
        this.keyOuter = keyOuter;
        this.keyInner = keyInner;
        this.nestedAlgSpec = nestedAlgSpec;
    }

    public PrivateKey getOuterPrivateKey() {
        return keyOuter;
    }

    public PrivateKey getInnerPrivateKey() {
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
        // throw new UnsupportedOperationException("unable to encode nested private
        // key");
        // Fall back to regular key if someone wants this.
        // This provides compatibility for TLS.
        return getOuterPrivateKey().getEncoded();
    }

    public int hashCode() {
        return Objects.hash(keyOuter, keyInner);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }

        if (o instanceof NestedPrivateKey) {
            NestedPrivateKey other = (NestedPrivateKey) o;
            return keyOuter.equals(other.keyOuter) && keyInner.equals(other.keyInner);
        }

        return false;
    }
}
