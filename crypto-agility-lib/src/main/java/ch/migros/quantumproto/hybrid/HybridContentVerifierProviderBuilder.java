package ch.migros.quantumproto.hybrid;

import java.security.cert.CertificateException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import ch.migros.quantumproto.util.CertificateUtils;

/**
 * Wrapper for {@link JcaContentVerifierProviderBuilder}.
 * Provides support for hybrid certificates (containing multiple public keys) by
 * selecting the correct key for the requested verification operation.
 * If multiple keys are needed, callers should employ multiple instances of this
 * class.
 */
public class HybridContentVerifierProviderBuilder extends JcaContentVerifierProviderBuilder {
    public HybridContentVerifierProviderBuilder() {
    }

    public ContentVerifierProvider build(X509CertificateHolder certHolder)
            throws OperatorCreationException, CertificateException {

        ContentVerifierProvider vProv = super.build(certHolder);

        if (!CertificateUtils.isHybridCert(certHolder))
            return vProv;

        final JcaContentVerifierProviderBuilder superBuilder = this;

        return new ContentVerifierProvider() {
            public boolean hasAssociatedCertificate() {
                return true;
            }

            public X509CertificateHolder getAssociatedCertificate() {
                return certHolder;
            }

            public ContentVerifier get(AlgorithmIdentifier algId)
                    throws OperatorCreationException {
                // Select correct key for this algorithm
                SubjectPublicKeyInfo key = CertificateUtils.extractPublicKeyForUseWith(certHolder, algId);

                return superBuilder.build(key).get(algId);
            }
        };
    }
}