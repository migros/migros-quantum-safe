#!/bin/sh
LONG_TERM_SIG=rsa
END_USER_SIG=ed25519

PROV_ARGS="-provider-path /oqs-provider/_build/oqsprov -provider oqsprovider"

echo "The following providers are present:"
openssl list -providers $PROV_ARGS

cd /
# Create CA key and self-signed certificate
openssl req -x509 -new -newkey $LONG_TERM_SIG -keyout caKey.pem -out caCert.pem --outform PEM -nodes -subj "/C=CH/O=Cyber/CN=Cyber Root CA" -days 3652 $PROV_ARGS

# Create end user key and CSR
openssl req -new -newkey $END_USER_SIG -keyout moonKey.pem -out moonCert.csr -nodes -subj "/emailAddress=moon@strongswan.org/C=CH/O=Cyber/CN=moon.strongswan.org" $PROV_ARGS
openssl req -new -newkey $END_USER_SIG -keyout carolKey.pem -out carolCert.csr -nodes -subj "/emailAddress=carol@strongswan.org/C=CH/O=Cyber/CN=carol.strongswan.org" $PROV_ARGS

# Sign CSR by CA
openssl x509 -req -in moonCert.csr -out moonCert.pem -CA caCert.pem -CAkey caKey.pem --outform PEM -CAcreateserial -days 365 -extfile v3.ext $PROV_ARGS
openssl x509 -req -in carolCert.csr -out carolCert.pem -CA caCert.pem -CAkey caKey.pem --outform PEM -CAcreateserial -days 365 -extfile v3.ext $PROV_ARGS

echo "Generated all keys/certs"

# Create necessary folders if needed
for folder in "/mnt/strongswan/carol/etc-swanctl" "/mnt/strongswan/moon/etc-swanctl"; do
    cd $folder
    for dir in "pkcs8 x509 x509ca"; do
        mkdir -p $dir
    done
done
cd /

# Move results to child containers. caKey.pem is lost because not needed.
cp carolKey.pem /mnt/strongswan/carol/etc-swanctl/pkcs8/carolKey.pem
cp carolCert.pem /mnt/strongswan/carol/etc-swanctl/x509/carolCert.pem
cp caCert.pem /mnt/strongswan/carol/etc-swanctl/x509ca/caCert.pem

cp moonKey.pem /mnt/strongswan/moon/etc-swanctl/pkcs8/moonKey.pem
cp moonCert.pem /mnt/strongswan/moon/etc-swanctl/x509/moonCert.pem
cp caCert.pem /mnt/strongswan/moon/etc-swanctl/x509ca/caCert.pem

echo "Successfully copied all keys/certs"