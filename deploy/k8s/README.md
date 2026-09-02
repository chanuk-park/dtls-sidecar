# Kubernetes deployment

Everything runs in the cluster: SPIRE issues the identities, and `n4dtls` runs as a
**sidecar container in the SMF and UPF pods**. Nothing is installed on the nodes and no
shell scripts are involved.

```
spire/    SPIRE server (StatefulSet) + agent (DaemonSet) + per-NF registration
sidecar/  the patches that add the n4dtls container to the SMF and UPF Deployments
```

## 1. Identity infrastructure

```sh
kubectl apply -f deploy/k8s/spire/
kubectl -n spire rollout status statefulset/spire-server
kubectl -n spire rollout status daemonset/spire-agent
```

* **server** — StatefulSet with a PVC. Node attestation is `k8s_psat`: agents authenticate
  with a projected service-account token, so there are no join tokens to distribute and an
  agent restart re-attests by itself.
* **registrar / bundle-publisher** — sidecars in the server pod. The registrar creates one
  entry per network function; the publisher writes the trust bundle to a ConfigMap the
  agents bootstrap from. Both are in the server pod because they need the server's socket,
  and an `emptyDir` cannot be shared across pods.
* **agent** — DaemonSet, `hostPID` + `hostNetwork` (it resolves caller PIDs and talks to
  the kubelet). Its Workload API socket is a `hostPath`, which is how one agent per node
  serves every pod on that node. `nodes/proxy` is granted in RBAC — without it the k8s
  workload attestor gets `403 Forbidden`.

Point it at your core before applying, in `spire/13-registrar-config.yaml`:

```yaml
TRUST_DOMAIN: "5gc.example.com"
NF_NAMESPACE: "core"
SMF_SERVICE_ACCOUNT: "oai-smf"
UPF_SERVICE_ACCOUNT: "oai-upf"
SIDECAR_CONTAINER: "n4dtls"
```

The entries select on `k8s:ns` + `k8s:sa` + `k8s:container-name`, so the SVID is issued
because the requester is *that container in that pod* — not because it happens to be root
on the node.

## 2. The sidecar, in the NF pods

The image must be pullable on every node that runs an NF:

```sh
docker build -t ghcr.io/chanuk-park/dtls-sidecar:latest .
# or, for a local registry-less cluster (k3s):
docker save ghcr.io/chanuk-park/dtls-sidecar:latest -o /tmp/n4dtls.tar
sudo k3s ctr images import /tmp/n4dtls.tar        # on every NF node
```

Edit the two patches for your addresses and trust domain, then apply **UPF first** — it
only listens; the SMF side dials it:

```sh
kubectl -n core patch deploy oai-upf --patch-file deploy/k8s/sidecar/upf-patch.yaml
kubectl -n core patch deploy oai-smf --patch-file deploy/k8s/sidecar/smf-patch.yaml
```

`-peer` on the SMF side is the address the UPF's PFCP socket is bound to. Read it from the
running UPF rather than guessing — a UPF usually has several addresses (N3, N4, N6):

```sh
kubectl -n core exec deploy/oai-upf -c upf -- ss -lnup | grep 8805
```

The NF container is not mentioned in either patch, so its image, configuration and command
are untouched. The pod simply gains a second container that shares its network namespace.

Removing it:

```sh
# find the sidecar's index -- a strategic-merge patch does not necessarily append, so a
# hardcoded index can point at the network function itself
kubectl -n core get deploy oai-smf -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{"\n"}{end}'
kubectl -n core patch deploy oai-smf --type=json \
  -p '[{"op":"remove","path":"/spec/template/spec/containers/<index>"}]'
```

## 3. Check it

```sh
kubectl -n core logs deploy/oai-smf -c n4dtls | grep ARMB-STATE
```

```
ARMB-STATE component=n4dtls role=client self=spiffe://…/ns/core/nf/smf
  peer_id=spiffe://…/ns/core/nf/upf identity=workload
  auth=x509-svid+mutual cipher=0xc02b handshakes=1 fail=drop payload=untouched
```

`self` must be the **NF's** identity and different from `peer_id`; `handshakes=1` means one
handshake for the life of the session, not one per message. `deploy/n4dtls-verify.sh` runs
this and ten other checks, including that no plaintext PFCP remains on the wire.

## Ordering, and why it matters

Apply the UPF patch first and let its pod come up before the SMF patch. Each sidecar
installs its capture rule **only after its DTLS session is established** — PFCP queued with
nowhere to go is PFCP dropped, and a PFCP association dies after two missed heartbeats.

Adding a container restarts the NF pods. On a core that only associates at startup, bring
them back in dependency order (NRF, then SMF, then UPF) if the association does not settle.
