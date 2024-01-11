FROM debian:12

# To fix hash sum mismatches during apt install
RUN rm -rf /var/lib/apt/lists/* && \
    apt-get clean && \
    apt-get update -o Acquire::CompressionTypes::Order::=gz

RUN echo "Acquire::http::Pipeline-Depth 0;" > /etc/apt/apt.conf.d/99custom && \
    echo "Acquire::http::No-Cache true;" >> /etc/apt/apt.conf.d/99custom && \
    echo "Acquire::BrokenProxy    true;" >> /etc/apt/apt.conf.d/99custom

RUN apt update && apt install -y \
    build-essential git cmake ninja-build \
    openssl libssl-dev \
    python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Downloads and installs oqs-provider
RUN git clone -b 0.5.1 --depth 1 https://github.com/open-quantum-safe/oqs-provider.git

RUN python3 -m venv venv
RUN . venv/bin/activate && pip install jinja2 pyyaml tabulate

#COPY fullbuild.sh /oqs-provider/scripts/fullbuild.sh
ENV LIBOQS_BRANCH=0.8.0
ENV OPENSSL_INSTALL=openssl

RUN . venv/bin/activate && \
    cd oqs-provider && \
    /bin/bash scripts/fullbuild.sh && \
    cmake --install _build

# Copy configurations
COPY openssl.cnf /etc/ssl/openssl.cnf
COPY v3.ext /v3.ext

# Copy runnable script for certificate generation
COPY gen_certs.sh /gen_certs.sh

ENTRYPOINT [ "./gen_certs.sh" ]