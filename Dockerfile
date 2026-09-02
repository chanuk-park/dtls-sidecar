# n4dtls as a container image. This is the primary artifact: the sidecar is meant to run as
# a container in the network function's pod, where it shares that pod's network namespace
# and is attested by SPIRE as the pod itself.
#
# Multi-stage so the image builds from a clone with no prior steps:
#   docker build -t ghcr.io/chanuk-park/dtls-sidecar:latest .

FROM golang:1.24-bookworm AS build
# The NFQUEUE binding is cgo, so the build needs the library headers.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libnetfilter-queue-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Dependencies first so a source-only change does not re-download them.
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/n4dtls ./cmd/n4dtls

FROM debian:bookworm-slim
# libnetfilter-queue for the capture binding, iptables to install the capture rule in the
# pod's network namespace, iproute2 for diagnosis. Nothing else: the sidecar needs no access
# to anything of the network function's.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libnetfilter-queue1 iptables iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/n4dtls /usr/local/bin/n4dtls

# Requires CAP_NET_ADMIN and /dev/net/tun; see deploy/README.md.
ENTRYPOINT ["/usr/local/bin/n4dtls"]
