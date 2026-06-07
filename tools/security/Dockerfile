FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        dnsutils \
        git \
        httpie \
        iputils-ping \
        jq \
        make \
        netcat-openbsd \
        nodejs \
        npm \
        openssl \
        python3 \
        python3-pip \
        python3-venv \
        ripgrep \
        wget \
    && npm install -g jwt-cli \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

CMD ["/bin/bash"]
