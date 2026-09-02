# Kubernetes deployment

Everything runs in the cluster: SPIRE issues the identities, and `n4dtls` runs as a
**sidecar container in the SMF and UPF pods**. Nothing is installed on the nodes and no
shell scripts are involved.

```
spire/    SPIRE server (StatefulSet) + agent (DaemonSet) + per-NF registration
sidecar/  the patches that add the n4dtls container to the SMF and UPF Deployments
```

## 1. Identity — use the SPIRE you already have

If a SPIRE agent is already running on your nodes, **use it**. That is what a SPIFFE workload
does: it mounts the node agent's Workload API socket and receives an SVID because an entry
exists for it. Do not apply a second SPIRE alongside one that is running — `kubectl apply`
overwrites same-named ConfigMaps and DaemonSets and will take the existing one down.

Read the three facts you need from the running install:

```sh
kubectl -n <spire-ns> get cm spire-agent -o jsonpath='{.data.agent\.conf}' \
  | grep -E 'trust_domain|socket_path|cluster'
kubectl -n <spire-ns> get ds spire-agent \
  -o jsonpath='{range .spec.template.spec.volumes[*]}{.name}: {.hostPath.path}{"\n"}{end}'
```

You need an agent on **every node that runs an NF**. An agent DaemonSet pinned to a subset of
nodes will leave the sidecar on the other nodes without an identity:

```sh
kubectl -n <spire-ns> get ds spire-agent -o jsonpath='{.spec.template.spec.nodeSelector}'
```

Then create one entry per NF. Parent them to a **node alias**, not to a specific agent: an
agent's SPIFFE ID contains its node UID, so an entry parented to one agent only works on
that node.

```sh
TD=<your trust domain>; CLUSTER=<your k8s_psat cluster name>
S=/opt/spire/bin/spire-server

# a parent every agent in the cluster satisfies
kubectl -n <spire-ns> exec deploy/spire-server -- $S entry create -node \
  -parentID "spiffe://$TD/spire/server" \
  -spiffeID "spiffe://$TD/k8s/$CLUSTER/node" \
  -selector "k8s_psat:cluster:$CLUSTER"

# one identity per NF, bound to the SIDECAR container in that NF's pod
for nf in smf upf; do
  kubectl -n <spire-ns> exec deploy/spire-server -- $S entry create \
    -parentID "spiffe://$TD/k8s/$CLUSTER/node" \
    -spiffeID "spiffe://$TD/ns/core/nf/$nf" \
    -selector "k8s:ns:core" -selector "k8s:sa:oai-$nf" \
    -selector "k8s:container-name:n4dtls" -x509SVIDTTL 3600
done
```

`k8s:container-name:n4dtls` is what separates the sidecar's identity from any entry the NF
itself already has. A workload can match several entries, so the sidecar is told which one to
present with `-identity`.

### If you have no SPIRE at all

`deploy/k8s/spire/` stands one up in its own namespace (`n4dtls-spire`, cluster-scoped names
prefixed to match) so it cannot collide with anything. It is a starting point, not a
production SPIRE.

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
