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
        file \
        make \
        maven \
        netcat-openbsd \
        nodejs \
        npm \
        openjdk-17-jdk-headless \
        openssl \
        procps \
        python3 \
        python3-pip \
        python3-venv \
        ripgrep \
        tar \
        tree \
        unzip \
        wget \
    && python3 -m pip install --no-cache-dir --break-system-packages \
        bandit \
        pip-audit \
        semgrep \
    && npm install -g \
        corepack@0.29.4 \
        jwt-cli \
    && corepack enable \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

CMD ["/bin/bash"]
