FROM golang:1.25-bookworm AS katana-builder

RUN go install github.com/projectdiscovery/katana/cmd/katana@latest

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=katana-builder /go/bin/katana /usr/local/bin/katana

WORKDIR /work

CMD ["/bin/bash"]
