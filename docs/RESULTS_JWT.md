# Results: Application-Layer / JWT
**Hybrid and fully migrated**

### Hybrid signatures
We encountered the following dilemma during the changeover:

JWTs are intended to sign cleartext payloads with an appended value  
I.e. we are not allowed to change the payload - this would possibly lead to errors for users inspecting the JWT content

Therefore, we have to sign a single value (header plus payload) and produce a single signature.

On the other hand, we want to handle X.509 certificates, for example, in such a way that the quantum-safe signature is a "non-critical extension".
This means that the existence of quantum-safe signatures should be obvious, but clients who do not know about them also ignore them.

This process would create two signatures - a quantum-safe one for normal content and a classical one for content (optionally plus this new extension).

### Solutions
Implementations now have (at least) two options:

**Composite Signatures**: Signatures are a concatenation of classical and quantum-safe signatures

* Here, we can provide a very similar interface to the one used today, complexity remains roughly the same
* However, we risk losing backwards-compatibility completely

**Nested**: Two signatures are produced, a quantum-safe one over the message and a classical one over both the message and the quantum-safe signature.

* There may be no predefined format for signatures and crypto libraries still offload the added complexity onto the developers
* However, this approach also allows for better backwards-compatibility

Our solution was to use composite signatures for JWTs, and nested ones for backwards-compatibility on the X.509 certificates.

Our crypto-agility library handled the complexity centrally to ease the burden for the developer:

```java
Library.signCert(certificate, "SHA256WITHRSA", keyPair); // classical
Library.signCert(certificate, "SHA256WITHRSA>>>DILITHIUM5", keyPair); // hybrid nested
```
