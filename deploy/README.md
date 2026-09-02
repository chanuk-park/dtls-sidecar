# Deploying n4dtls

Four scripts. They discover the deployment themselves — pod names, host nodes, container
PIDs, the UPF's N4 address — so nothing here is tied to one cluster.

```
spire-bootstrap.sh   SPIRE server + per-node agents + one identity per NF
n4dtls-inject.sh     in-pod:  add/remove the sidecar container in the NF's pod
n4dtls-deploy.sh     host:    start/stop the sidecar as a systemd unit on each node
n4dtls-verify.sh     11 checks against a running deployment
```

`spire-bootstrap.sh` writes `deploy.env`; the other scripts read it. It is environment
specific and git-ignored.

---

## 1. spire-bootstrap.sh

```sh
./spire-bootstrap.sh --smf-node <ip> --upf-node <ip> \
    [--trust-domain 5gc.example.com] [--version 1.11.2] [--host-sidecar]
```

Downloads SPIRE (once, cached in `/tmp/spire-dl`), runs a server on this host, starts one
agent per NF node, and creates **a distinct registration entry per NF** —
`…/ns/core/nf/smf` and `…/ns/core/nf/upf`. Distinct identities are the point: each sidecar
authorizes the *other's* SPIFFE ID, which is mutual authentication rather than two ends
sharing one credential.

Selectors depend on the mode:

* **in-pod (default)** — `k8s:ns:<ns> k8s:sa:<sa> k8s:container-name:n4dtls`. Needs the k8s
  workload attestor, which asks the kubelet which pod owns a PID. The script binds the
  built-in `system:kubelet-api-admin` ClusterRole to `system:nodes`, because a node's own
  kubelet client certificate authenticates as `system:node:<name>` and is **not** granted
  `nodes/proxy` by default (without this the attestor gets `403 Forbidden`).
* **`--host-sidecar`** — `unix:path:<nf binary> unix:sha256:<hash>`, read from the running
  NF process, plus a delegate entry authorizing use of the Delegated Identity API.

Environment overrides: `KUBELET_CERT`, `KUBELET_KEY` (default: the k3s node paths),
`NF_NAMESPACE` (default `core`), `SPIRE_CACHE`, `SPIRE_RUN`, `SIDECAR_NAME`.

The verification step asserts the property that matters in both modes: **a plain root
process on the node does not receive the NF's identity.** If it does, the selectors are not
binding the identity to the workload and everything downstream is theatre.

## 2a. n4dtls-inject.sh — in-pod (the Envoy arrangement)

```sh
./n4dtls-inject.sh up   [--namespace core] [--smf-deploy D] [--upf-deploy D] [--mtu 1200]
./n4dtls-inject.sh down
./n4dtls-inject.sh status
```

Patches the SMF/UPF Deployments with an `n4dtls` container. The NF container is untouched —
only the pod gains a second container, which shares the pod's network namespace (no
`nsenter`, no host access) and is attested by SPIRE as the pod itself.

Build the image first:

```sh
CGO_ENABLED=1 go build -o deploy/image/n4dtls ./cmd/n4dtls
docker build -t cirrus/n4dtls:armb deploy/image
# make it available to the kubelet on every NF node, e.g. for k3s:
docker save cirrus/n4dtls:armb -o /tmp/n4dtls.tar && sudo k3s ctr images import /tmp/n4dtls.tar
```

Override the image with `N4DTLS_IMAGE`.

`down` removes the sidecar **by name**, not by index: a strategic-merge patch does not
necessarily append, so a hardcoded index can point at the network function itself.

Adding a container edits the Deployment, so the NF pods restart. That is a deployment
change, not a change to the network function.

## 2b. n4dtls-deploy.sh — host sidecar (no pod spec change)

```sh
./n4dtls-deploy.sh up   [--smf-pod N] [--upf-pod N] [--upf-n4 IP] [--namespace core] [--mtu 1200]
./n4dtls-deploy.sh down
./n4dtls-deploy.sh status
```

Resolves each NF container's host node and PID via kubectl+crictl, learns the UPF's N4
address **by watching one PFCP packet leave the SMF** (true by construction on any
deployment; `--upf-n4` overrides when nothing is flowing), copies the binary to each node
and runs it under systemd inside the NF's network namespace.

Requires passwordless ssh+sudo to the NF nodes and `crictl` on them.

## 3. Ordering — why the sidecar starts before it captures

Both scripts start the **UPF side first** (it only listens) and then the SMF side (which
dials). Each sidecar installs its NFQUEUE capture rule **only after the DTLS session is
established**. Queueing the NF's PFCP with nowhere to send it drops heartbeats, and a PFCP
association dies after two missed heartbeats — so the gap between "rule installed" and
"tunnel ready" has to be zero.

For the same reason, capture matches **both directions** (`--dport 8805` *and*
`--sport 8805`): a core that sends from an ephemeral source port receives its responses on
that port, so matching only `--dport` tunnels requests while leaking responses in plaintext.

## 4. n4dtls-verify.sh

```sh
./n4dtls-verify.sh [--namespace core] [--smf-pod N] [--upf-pod N] [--skip-ue]
```

Detects whether the sidecar is in-pod or on the host and reads its log accordingly. Checks,
each PASS/FAIL with the evidence it used:

1. mutual-auth DTLS session up · the two ends present **different** SPIFFE IDs
2. only DTLS on the N4 link · **no plaintext PFCP** on the wire
3. the tunnel carries traffic **both ways** (catches responses leaking in plaintext)
4. the PFCP association survived · heartbeats still running
5. the NF was not modified
6. a real UE PDU session exists and its data plane works

Exit code 0 only if everything passed.

## Tuning

`--mtu` (default 1200) bounds the DTLS record. Lower the N4 link MTU to match if PFCP
messages approach it, so nothing fragments — a fragmented PFCP message is an artefact of the
sidecar, not a property of the core.

The NFQUEUE depth is 2048 and the sender's write deadline is 500 ms. Both are hang guards:
if the tunnel cannot carry a packet the original is **dropped**, never emitted in plaintext.
