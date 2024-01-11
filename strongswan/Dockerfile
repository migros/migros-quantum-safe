FROM alpine:3.17
ENV VERSION="6.0.0beta5"
ENV DEV_PACKAGES_VERSIONLESS="wget unzip bzip2 make gcc openssl-dev cmake samurai musl-dev linux-headers"

RUN \
    # install packages
    apk add --no-cache iproute2 iputils nano curl $DEV_PACKAGES_VERSIONLESS

RUN \
    # download and build strongSwan IKEv2 daemon
    mkdir /strongswan-build && \
    cd /strongswan-build && \
    wget https://download.strongswan.org/strongswan-$VERSION.tar.bz2 && \
    tar xfj strongswan-$VERSION.tar.bz2 && \
    cd strongswan-$VERSION && \
    ./configure --prefix=/usr --sysconfdir=/etc --disable-ikev1       \
    --enable-silent-rules && \
    make all && make install && \
    cd / && rm -R strongswan-build && \
    ln -s /usr/libexec/ipsec/charon charon

RUN \
    # clean up
    apk del $DEV_PACKAGES_VERSIONLESS

# Expose IKE and NAT-T ports
EXPOSE 500 4500

ENTRYPOINT ["./charon"]