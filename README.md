# n4dtls — SPIFFE/SPIRE mutual-auth DTLS for 5G N4 (PFCP), without modifying the NF

`n4dtls` puts mutually-authenticated DTLS on the **N4 interface** between a 5G SMF and UPF.
Both ends present an **X509-SVID issued by SPIRE** and authorize each other by SPIFFE ID.

The network function is not modified: no image change, no configuration change, no command
change, and the PFCP payload is never rewritten. The sidecar intercepts the NF's own egress
PFCP, carries each packet whole inside a DTLS record, and reinjects it on the far side.

```
        SMF pod                                            UPF pod
 ┌───────────────────────┐                        ┌───────────────────────┐
 │  SMF (unmodified)     │                        │  UPF (unmodified)     │
 │      │ PFCP 8805      │                        │      ▲ PFCP 8805      │
 │      ▼                │                        │      │                │
 │  ┌─────────┐  NFQUEUE │                        │  ┌─────────┐  TUN     │
 │  │ n4dtls  │◄─────────┤                        │  │ n4dtls  ├─────────►│
 │  └────┬────┘          │                        │  └────▲────┘          │
 └───────┼───────────────┘                        └───────┼───────────────┘
         │        DTLS 8806, X509-SVID mutual auth        │
         └───────────────────────────────────────────────►┘
```

## Why not a terminating proxy

PFCP carries IP addresses *inside* its payload (F-SEID, Node ID). A proxy that terminates
and re-originates changes the outer addresses, and cores that correlate on them stop
matching sessions. `n4dtls` therefore treats the captured IP packet as an **opaque blob**:
the original L3 header is restored byte-for-byte on the far side, so the question of which
address a core correlates on never arises.

## Identity

The credential is always an X509-SVID fetched from SPIRE — never a PSK, never a static
certificate — and the peer is verified against SPIRE's trust bundle *and* authorized by its
exact SPIFFE ID. SVIDs and bundles are streamed, and the current one is served at each
handshake, so rotation is picked up without a restart (the same arrangement Envoy has with
SPIRE's SDS).

Two deployment shapes, differing only in how the sidecar itself is attested:

| | **in-pod** (default) | **host + delegated** |
|---|---|---|
| where it runs | a container in the NF's pod | a systemd unit on the node |
| network namespace | shared with the NF | entered with `nsenter` |
| SPIRE selectors | `k8s:ns` + `k8s:sa` + `k8s:container-name` | `unix:path` + `unix:sha256` |
| SPIRE API | Workload API | Delegated Identity API |
| pod spec | a container is added (NF pods restart) | untouched, no restart |

**in-pod is the stronger binding**: the identity is tied to that namespace, service account
and container, so a process elsewhere on the node cannot obtain it by running a copy of the
NF binary. Use `host + delegated` when the pod spec must not change at all.

## Quickstart

The sidecar runs as a **container in the SMF and UPF pods**, and SPIRE runs in the cluster.

```sh
# 1. build and make the image available to every node that runs an NF
docker build -t ghcr.io/chanuk-park/dtls-sidecar:latest .

# 2. SPIRE in-cluster: server (StatefulSet) + agent (DaemonSet) + one identity per NF
#    edit deploy/k8s/spire/13-registrar-config.yaml for your namespace/service accounts
kubectl apply -f deploy/k8s/spire/

# 3. add the sidecar to the network functions -- UPF first (it listens), then SMF (it dials)
#    edit the two patches for your addresses and trust domain
kubectl -n core patch deploy oai-upf --patch-file deploy/k8s/sidecar/upf-patch.yaml
kubectl -n core patch deploy oai-smf --patch-file deploy/k8s/sidecar/smf-patch.yaml

# 4. check it
kubectl -n core logs deploy/oai-smf -c n4dtls | grep ARMB-STATE
./deploy/n4dtls-verify.sh          # 11 checks, exit 0 only if all pass
```

`deploy/k8s/README.md` is the full guide. If the pod spec must not change at all, there is a
host-sidecar variant driven by shell scripts — see `deploy/README.md`.

`deploy/k8s/README.md` covers the Kubernetes deployment; `deploy/README.md` documents the
script-driven host variant. `docs/design.md` explains how capture,
encapsulation and reinjection work and why each choice was made. `docs/troubleshooting.md`
lists the failure modes that are easy to hit and how to recognise them.

## What it does and does not give you

**Does:** confidentiality and integrity for N4, with both ends cryptographically identified
by SPIRE and authorized by SPIFFE ID; automatic rotation; no NF modification.

**Does not:** distinguish *which instance* of an identity is speaking. Anything SPIRE issues
the identity to can use the tunnel — with `k8s` selectors that means anything in that pod,
with `unix` selectors anything running that binary on that node. If you need admission tied
to a specific execution rather than to an identity, this is not that control.

## Requirements

Linux with `libnetfilter_queue` and `/dev/net/tun`; `CAP_NET_ADMIN`; a SPIRE deployment
(the bootstrap script can stand one up); Kubernetes with `kubectl` for the deploy scripts.
DTLS is 1.2 (`pion/dtls` v3).

## Licence

Apache-2.0. See `LICENSE`.
