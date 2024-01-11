FROM alpine:3.17
ENV VERSION="6.0.0beta5"
ENV LIBOQS_VERSION="0.8.0"
ENV DEV_PACKAGES_VERSIONLESS="wget unzip bzip2 make gcc openssl-dev cmake samurai musl-dev linux-headers"

RUN \
    # install packages
    apk add --no-cache iproute2 iputils nano curl $DEV_PACKAGES_VERSIONLESS

RUN \
    # download and build liboqs
    mkdir /liboqs && \
    cd /liboqs && \
    wget https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$LIBOQS_VERSION.zip && \
    unzip $LIBOQS_VERSION.zip && \
    cd liboqs-$LIBOQS_VERSION && \
    mkdir build && cd build && \
    cmake -GNinja -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON .. && \
    ninja && ninja install && \
    cd / && rm -R /liboqs

RUN \
    # download and build strongSwan IKEv2 daemon
    mkdir /strongswan-build && \
    cd /strongswan-build && \
    wget https://download.strongswan.org/strongswan-$VERSION.tar.bz2 && \
    tar xfj strongswan-$VERSION.tar.bz2 && \
    cd strongswan-$VERSION && \
    ./configure --prefix=/usr --sysconfdir=/etc --disable-ikev1       \
    --enable-frodo --enable-oqs --enable-silent-rules && \
    make all && make install && \
    cd / && rm -R strongswan-build && \
    ln -s /usr/libexec/ipsec/charon charon

RUN \
    # clean up
    apk del $DEV_PACKAGES_VERSIONLESS

# Expose IKE and NAT-T ports
EXPOSE 500 4500

ENTRYPOINT ["./charon"]