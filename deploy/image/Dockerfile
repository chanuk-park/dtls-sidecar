# The arm-B sidecar as a pod container. It needs libnetfilter_queue (the NFQUEUE binding is
# cgo) and iptables to install its own capture rule; nothing else. Running inside the NF's
# pod means it shares that pod's network namespace, so there is no nsenter and no host
# access, and SPIRE's k8s workload attestor resolves it to the pod's own identity -- the
# same arrangement Envoy has with SPIRE.
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends libnetfilter-queue1 iptables iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY n4dtls /usr/local/bin/n4dtls
ENTRYPOINT ["/usr/local/bin/n4dtls"]
