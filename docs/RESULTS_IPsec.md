# Results: IPsec Tunnel
**Not hybrid, just quantum-safe**

The migration with IPsec worked very easily. This is because StrongSwan as an IPsec provider and OpenSSL both offer very good support for the leading library with quantum-secure algorithms, liboqs.

liboqs was created as part of the "Open Quantum Safe" project, see [here](https://openquantumsafe.org/). The project provides OpenSSL and OpenSSH forks, as well as a "provider" for OpenSSL which we have used here.

Specifically, the migration consisted of several steps. Steps 1 & 2 must take place before 3 or 4, other than that there is no predetermined sequence (e.g. 2, 1, 4, 3 would also be conceivable).

1. Preparation in openssl-gen
   * Crypto Agility introduced (via configuration file)
   * Installation OpenSSL provider, "oqs-provider"
2. Preparation in gateways
   * Install liboqs and recompile StrongSwan
3. Updating the certificates
   * Since the gateways with liboqs understand the new certificates, there is no service interruption here
   * However, the key exchange remains classical
4. Update of the key exchange via proposals

NB: In this use case, the certificates are not hybrid, but only equipped with the new algorithms.  
Both systems (OpenSSL with oqs-provider and liboqs in StrongSwan) currently do not support hybrid certificates due to the lack of X.509 standards for this.  
We assume that this will be rectified in the future as soon as appropriate standards are available.
