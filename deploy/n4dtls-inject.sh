#!/usr/bin/env bash
# Inject (or remove) the arm-B sidecar as a container in the NF's own pod -- the Envoy
# arrangement. The NF container is not touched: no image change, no config change, no
# command change. Only the pod gains a second container, which shares the pod's network
# namespace and is therefore attested by SPIRE's k8s workload attestor as the pod itself.
#
#   ./n4dtls-inject.sh up   [--namespace core] [--smf-deploy D] [--upf-deploy D] [--mtu 1200]
#   ./n4dtls-inject.sh down
#
# Adding a container edits the Deployment, so the NF pods restart. That is a deployment
# change, not a change to the network function.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="core"; MTU=1200; SMF_D=""; UPF_D=""
IMAGE="${N4DTLS_IMAGE:-ghcr.io/chanuk-park/dtls-sidecar:latest}"
SIDECAR="n4dtls"
DTLS_PORT=8806; DPORT=8805; SMF_Q=62; UPF_Q=61

CMD="${1:-}"; shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --namespace|-n) NS="$2"; shift 2;;
    --smf-deploy) SMF_D="$2"; shift 2;;
    --upf-deploy) UPF_D="$2"; shift 2;;
    --mtu) MTU="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -f "$HERE/deploy.env" ] || { echo "deploy.env missing -- run spire-bootstrap.sh first" >&2; exit 2; }
# shellcheck disable=SC1091
. "$HERE/deploy.env"
k() { kubectl -n "$NS" "$@"; }

discover() {
  [ -n "$SMF_D" ] || SMF_D=$(k get deploy --no-headers 2>/dev/null | grep -iE 'smf' | awk '{print $1}' | head -1)
  [ -n "$UPF_D" ] || UPF_D=$(k get deploy --no-headers 2>/dev/null | grep -iE 'upf' | awk '{print $1}' | head -1)
  [ -n "$SMF_D" ] && [ -n "$UPF_D" ] || { echo "could not find SMF/UPF deployments in ns=$NS" >&2; exit 1; }
  SPIRE_DIR="$(dirname "${SPIRE_SOCKET#unix://}")"
  SPIRE_SOCK_NAME="$(basename "${SPIRE_SOCKET#unix://}")"
}

# patch <deploy> <role> <peer-id> <self-id> <queue> <extra-args...>
patch_deploy() {
  local dep="$1" role="$2" peer_id="$3" self_id="$4" q="$5"; shift 5
  local args=("-role" "$role" "-peer-id" "$peer_id" "-identity" "$self_id"
              "-nfqueue" "$q" "-tun" "n4dtls0" "-install-nfq-rule"
              "-dport" "$DPORT" "-mtu" "$MTU" "$@")
  local args_json; args_json=$(printf '%s\n' "${args[@]}" | python3 -c 'import json,sys; print(json.dumps([l.rstrip("\n") for l in sys.stdin]))')
  # The sidecar needs NET_ADMIN (iptables/NFQUEUE/TUN in the pod netns), /dev/net/tun, and
  # the SPIRE agent socket. It gets nothing of the NF's.
  k patch deploy "$dep" --type=strategic -p "$(cat <<JSON
{"spec":{"template":{"spec":{
  "containers":[{
    "name":"$SIDECAR",
    "image":"$IMAGE",
    "imagePullPolicy":"IfNotPresent",
    "args":$args_json,
    "env":[{"name":"CIRRUS_SPIRE_SOCKET","value":"unix:///run/spire/sockets/$SPIRE_SOCK_NAME"}],
    "securityContext":{"privileged":true,"capabilities":{"add":["NET_ADMIN","NET_RAW"]}},
    "volumeMounts":[
      {"name":"spire-agent-socket","mountPath":"/run/spire/sockets","readOnly":true},
      {"name":"dev-net-tun","mountPath":"/dev/net/tun"}
    ]
  }],
  "volumes":[
    {"name":"spire-agent-socket","hostPath":{"path":"$SPIRE_DIR","type":"Directory"}},
    {"name":"dev-net-tun","hostPath":{"path":"/dev/net/tun","type":"CharDevice"}}
  ]
}}}}
JSON
)" >/dev/null
  echo "   injected $SIDECAR into $dep ($role)"
}

up() {
  discover
  echo "namespace=$NS  smf=$SMF_D  upf=$UPF_D  image=$IMAGE"
  echo "spire socket dir on host: $SPIRE_DIR (mounted read-only into the pods)"
  # The UPF listens; the SMF dials it. The SMF needs the UPF's N4 address, which is the
  # address the UPF's PFCP socket is on -- read it from the running UPF.
  local upf_pod upf_n4
  upf_pod=$(k get pod --no-headers 2>/dev/null | awk '$3=="Running"' | grep -iE 'upf' | awk '{print $1}' | head -1)
  # Read it from the UPF's own socket table. /proc/net/udp is unambiguous (ss column order
  # differs between listening and connected sockets, and the local address is what we want):
  # local_address is hex, little-endian per byte, port in hex after the colon.
  upf_n4=$(k exec "$upf_pod" -c "$(k get pod "$upf_pod" -o jsonpath='{.spec.containers[0].name}')" -- \
             sh -c 'cat /proc/net/udp' 2>/dev/null | python3 -c '
import sys
port_hex = format('"$DPORT"', "04X")
for line in sys.stdin:
    f = line.split()
    if len(f) < 2 or ":" not in f[1]:
        continue
    addr, port = f[1].split(":")
    if port != port_hex:
        continue
    b = [int(addr[i:i+2], 16) for i in (6, 4, 2, 0)]
    ip = ".".join(str(x) for x in b)
    if ip != "0.0.0.0":
        print(ip); break
' 2>/dev/null | head -1)
  [ -n "$upf_n4" ] || { echo "could not read the UPF N4 address from $upf_pod" >&2; exit 1; }
  echo "upf n4=$upf_n4"

  patch_deploy "$UPF_D" server "$SMF_SPIFFE_ID" "$UPF_SPIFFE_ID" "$UPF_Q" -listen "0.0.0.0:$DTLS_PORT"
  patch_deploy "$SMF_D" client "$UPF_SPIFFE_ID" "$SMF_SPIFFE_ID" "$SMF_Q" -peer "$upf_n4:$DTLS_PORT"
  echo "-- waiting for the NF pods to come back with the sidecar --"
  k rollout status deploy "$UPF_D" --timeout=180s | tail -1
  k rollout status deploy "$SMF_D" --timeout=180s | tail -1
  status
}

down() {
  discover
  for d in "$SMF_D" "$UPF_D"; do
    # Remove by INDEX OF THE SIDECAR, found by name. A strategic-merge patch does not
    # necessarily append, so a hardcoded index can point at the network function itself.
    local idx
    idx=$(k get deploy "$d" -o json 2>/dev/null | python3 -c '
import json,sys
spec = json.load(sys.stdin)["spec"]["template"]["spec"]["containers"]
for i, c in enumerate(spec):
    if c.get("name") == "'"$SIDECAR"'":
        print(i); break
' 2>/dev/null)
    if [ -z "$idx" ]; then echo "   $d had no sidecar"; continue; fi
    k patch deploy "$d" --type=json -p "[{\"op\":\"remove\",\"path\":\"/spec/template/spec/containers/$idx\"}]" >/dev/null 2>&1 \
      && echo "   removed $SIDECAR from $d (was container index $idx)" || echo "   could not remove the sidecar from $d"
  done
  k rollout status deploy "$UPF_D" --timeout=180s 2>/dev/null | tail -1
  k rollout status deploy "$SMF_D" --timeout=180s 2>/dev/null | tail -1
  echo "-- N4 is back in plaintext; the NF containers were never modified --"
}

status() {
  [ -n "${SMF_D:-}" ] || discover
  for d in "$SMF_D" "$UPF_D"; do
    local pod; pod=$(k get pod --no-headers 2>/dev/null | awk '$3~/Running/' | grep "^${d}-" | awk '{print $1}' | head -1)
    [ -n "$pod" ] || { echo "   $d: no running pod"; continue; }
    echo "-- $pod --"
    k logs "$pod" -c "$SIDECAR" --tail=200 2>/dev/null \
      | grep -oE 'self=[^ ]+ peer_id=[^ ]+ identity=[a-z]+|DTLS session up.*|captured=[0-9]+ sent=[0-9]+ recv=[0-9]+ injected=[0-9]+|FATAL.*' \
      | tail -3 | sed 's/^/     /'
  done
}

case "$CMD" in
  up) up;;
  down) down;;
  status) status;;
  *) echo "usage: $0 {up|down|status} [--namespace core] [--smf-deploy D] [--upf-deploy D] [--mtu 1200]" >&2; exit 2;;
esac
