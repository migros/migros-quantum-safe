# Results: TLS
**Not completed, only prepared & currently classical**

To secure the TLS connection between jwt-client and jwt-creator several things have to happen:

* cert-auth must issue hybrid or quantum-secure certificates
* jwt-creator must understand and present these in the TLS stack
* jwt-client must validate these correctly in the TLS stack
* jwt-verifier must be able to validate them manually

We proceeded as follows:

1. Crypto agility: outsource as much conversion work as possible, as little hard coding as possible
   * A major problem was key generation, as some required parameters are defined in algorithm-specific classes
   * In the end, we solved this using a custom library that knows the relevant algorithms and sets default parameters
2. We extended the functionality of our library to provide verification options for jwt-verifier
   * Each construction of a KeyPair, Verifier or Signer object should only take place via the library

However, we cannot currently solve the thrid and fourth points from the initial list. Our approach establishes TLS connections using JSSE (Java Secure Socket Extension) providers, and while Bouncy Castle offers its own implementation (BCJSSE), even the latest version (176b02 at the time of development) does not support quantum-safe algorithms.

However, we have changed our TLS connections so that they are explicitly based on BCJSSE, so that this functionality can be added with future versions of BouncyCastle if necessary

In later steps, we were able to generate hybrid certificates with our library. These are currently only recognized by our stack as classic certificates and are used accordingly. This demonstrates the potential for backwards-compatibility.

In the future, we could update the TLS stack without further changes to the certificates to establish quantum-safe TLS connections.
