FROM golang:1.25-bookworm AS katana-builder

RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/SharokhAtaie/extractify@latest

FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        chromium \
        dirb \
        fonts-liberation \
        nodejs \
        npm \
    && rm -rf /var/lib/apt/lists/*

COPY --from=katana-builder /go/bin/katana /usr/local/bin/katana
COPY --from=katana-builder /go/bin/extractify /usr/local/bin/extractify
COPY tools/discovery/katana-form-config.yaml /root/.config/katana/form-config.yaml
COPY tools/discovery/js-endpoint-extractor/package.json /opt/js-endpoint-extractor/package.json
RUN cd /opt/js-endpoint-extractor && npm install --omit=dev
COPY tools/discovery/js-endpoint-extractor/js-endpoint-extractor.mjs /opt/js-endpoint-extractor/js-endpoint-extractor.mjs
RUN chmod +x /opt/js-endpoint-extractor/js-endpoint-extractor.mjs \
    && ln -s /opt/js-endpoint-extractor/js-endpoint-extractor.mjs /usr/local/bin/js-endpoint-extractor

WORKDIR /work

CMD ["/bin/bash"]
