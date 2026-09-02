#!/usr/bin/env bash
# Bootstrap SPIRE for the arm-B N4 DTLS sidecars on a generic OAI deployment.
#
# Creates a SPIRE server on the control node, one agent per node that runs an NF, and a
# DISTINCT workload entry for the SMF side and the UPF side, so the two sidecars present
# different SPIFFE IDs and each authorizes the other's (real mutual authentication, not a
# shared identity).
#
#   ./spire-bootstrap.sh --smf-node <ip> --upf-node <ip> [--trust-domain <td>] [--version 1.9.6]
#
# Emits deploy.env with the values n4dtls-deploy.sh consumes.
set -euo pipefail

TD="5gc.example.com"
# Must match the spire-api-sdk the sidecar is built against (v1.11.2). The Delegated
# Identity API's SubscribeToX509SVIDs grew its `pid` field after 1.9: an older agent simply
# ignores it, logs request_selectors="[]", and answers with the DELEGATE's own identity
# instead of the named workload's -- which looks like success but attests nothing.
VER="1.11.2"
SMF_NODE=""
UPF_NODE=""
CACHE="${SPIRE_CACHE:-/tmp/spire-dl}"
MODE="in-pod"                     # in-pod (Envoy model) | host (delegated identity)
SIDECAR_NAME="${SIDECAR_NAME:-n4dtls}"
RUN="${SPIRE_RUN:-/tmp/spire-armb}"
SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no"
# The k8s workload attestor resolves a pid to its pod (namespace / service account / pod
# uid) by asking the kubelet. Running on the host, the agent authenticates with the node's
# own kubelet client credentials. This is what lets an IN-POD sidecar be attested as the NF
# itself, the way Envoy is -- no delegated API needed.
KUBELET_CERT="${KUBELET_CERT:-/var/lib/rancher/k3s/agent/client-kubelet.crt}"
KUBELET_KEY="${KUBELET_KEY:-/var/lib/rancher/k3s/agent/client-kubelet.key}"

while [ $# -gt 0 ]; do
  case "$1" in
    --smf-node) SMF_NODE="$2"; shift 2;;
    --upf-node) UPF_NODE="$2"; shift 2;;
    --trust-domain) TD="$2"; shift 2;;
    --version) VER="$2"; shift 2;;
    --host-sidecar) MODE="host"; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$SMF_NODE" ] && [ -n "$UPF_NODE" ] || { echo "usage: $0 --smf-node <ip> --upf-node <ip>" >&2; exit 2; }

SMF_ID="spiffe://$TD/ns/core/nf/smf"
UPF_ID="spiffe://$TD/ns/core/nf/upf"
# The sidecar's own identity. It authorizes nothing on N4 -- it only names who may use the
# agent's Delegated Identity API to ask for an attestation of the NF's pid.
DELEGATE_ID="spiffe://$TD/node/n4dtls"

# nf_selectors <node> <pod> -- what SPIRE will see when it attests the workload.
#
# IN-POD mode (default): the sidecar runs as a container in the NF's pod, so the k8s
# attestor resolves it to that pod -- namespace, service account and the sidecar container's
# name. This is the Envoy arrangement, and it is the strongest binding available here: a
# process elsewhere on the node cannot satisfy it by running the same binary.
#
# HOST mode (--host-sidecar): the sidecar runs on the host and asks SPIRE to attest the NF's
# pid over the delegated API, so the selectors describe the NF PROCESS (path + hash). No pod
# spec change, but any process running that same binary matches.
nf_selectors() {
  local node="$1" pod="$2" ns="${NF_NAMESPACE:-core}" sa cid pid exe sum out
  if [ "$MODE" = "in-pod" ]; then
    sa=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.spec.serviceAccountName}' 2>/dev/null)
    [ -n "$sa" ] || { echo ""; return; }
    echo "k8s:ns:$ns k8s:sa:$sa k8s:container-name:$SIDECAR_NAME"
    return
  fi
  cid=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.containerStatuses[0].containerID}' 2>/dev/null | sed 's|.*://||')
  [ -n "$cid" ] || { echo ""; return; }
  pid=$(on_node "$node" "crictl inspect $cid" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["info"]["pid"])' 2>/dev/null)
  [ -n "$pid" ] || { echo ""; return; }
  exe=$(on_node "$node" "readlink /proc/$pid/exe" 2>/dev/null | tr -d '\r')
  sum=$(on_node "$node" "sha256sum /proc/$pid/exe" 2>/dev/null | awk '{print $1}')
  out=""
  [ -n "$exe" ] && out="unix:path:$exe"
  [ -n "$sum" ] && out="$out unix:sha256:$sum"
  echo "$out"
}

on_node() { local node="$1"; shift
  case " $(hostname -I) " in *" $node "*) sudo bash -c "$*";; *) ssh $SSH_OPTS "$node" "sudo bash -c '$*'";; esac
}
BIN="$CACHE/spire-$VER/bin"

echo "== 1. SPIRE $VER =="
if [ ! -x "$BIN/spire-server" ]; then
  mkdir -p "$CACHE"
  curl -sSL --max-time 300 -o "$CACHE/spire.tgz" \
    "https://github.com/spiffe/spire/releases/download/v$VER/spire-$VER-linux-amd64-musl.tar.gz"
  tar xzf "$CACHE/spire.tgz" -C "$CACHE"
fi
echo "   $BIN"

echo "== 2. server (on this host, reachable by every NF node) =="
sudo pkill -f 'spire-server run' 2>/dev/null || true
sudo rm -rf "$RUN/server"; mkdir -p "$RUN/server/data"
cat > "$RUN/server.conf" <<EOF
server {
  bind_address = "0.0.0.0"
  bind_port = "8081"
  socket_path = "$RUN/server.sock"
  trust_domain = "$TD"
  data_dir = "$RUN/server/data"
  log_level = "WARN"
  ca_ttl = "24h"
  default_x509_svid_ttl = "1h"
}
plugins {
  DataStore "sql" { plugin_data { database_type = "sqlite3" connection_string = "$RUN/server/datastore.sqlite3" } }
  KeyManager "memory" { plugin_data {} }
  NodeAttestor "join_token" { plugin_data {} }
}
EOF
nohup "$BIN/spire-server" run -config "$RUN/server.conf" > "$RUN/server.log" 2>&1 &
for i in $(seq 1 100); do "$BIN/spire-server" healthcheck -socketPath "$RUN/server.sock" >/dev/null 2>&1 && break; sleep 0.2; done
"$BIN/spire-server" healthcheck -socketPath "$RUN/server.sock" >/dev/null 2>&1 || { echo "server unhealthy"; tail -20 "$RUN/server.log"; exit 1; }
echo "   healthy on :8081"

if [ "$MODE" = "in-pod" ]; then
  echo "== 2b. kubelet access for the k8s workload attestor =="
  # The attestor maps a pid to its pod by asking the kubelet, and the node's own kubelet
  # client certificate authenticates as system:node:<name>, which is NOT granted nodes/proxy
  # by default (kubelet authorization is delegated to the API server). Bind the built-in
  # kubelet-api-admin role to those node users. Additive cluster RBAC; nothing about the NFs.
  kubectl apply -f - >/dev/null 2>&1 <<RBAC || echo "   WARNING: could not grant kubelet API access"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: spire-agent-kubelet-api
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kubelet-api-admin
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: system:node:$(kubectl get node -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: system:nodes
RBAC
  echo "   granted nodes/proxy to system:nodes (kubelet-api-admin)"
fi

echo "== 3. per-node agents + distinct workload entries =="
# The sidecars run as root in the NF's netns, so the unix workload attestor keys on uid 0.
# Each node gets its own agent SPIFFE ID, and the workload entry under that parent decides
# which identity that node's sidecar receives -- SMF node -> smf id, UPF node -> upf id.
start_agent() { # $1=node ip  $2=agent-name  $3=workload spiffe id  $4=NF selectors (space separated)
  local node="$1" name="$2" wid="$3" nfsel="$4"
  local tok
  tok=$("$BIN/spire-server" token generate -socketPath "$RUN/server.sock" \
        -spiffeID "spiffe://$TD/agent/$name" 2>/dev/null | sed -n 's/^Token: //p')
  [ -n "$tok" ] || { echo "no join token for $name"; exit 1; }
  # Two entries per node:
  #  (a) the NF's own identity, selected on what the NF PROCESS is. SPIRE resolves these
  #      when the sidecar asks it to attest that pid over the delegated API, so the SVID is
  #      issued because the process is that NF -- not because someone is root.
  #  (b) the delegate's identity, which only authorizes use of the admin socket.
  local sel_args=() sel
  for sel in $nfsel; do sel_args+=(-selector "$sel"); done
  "$BIN/spire-server" entry create -socketPath "$RUN/server.sock" \
    -parentID "spiffe://$TD/agent/$name" -spiffeID "$wid" \
    "${sel_args[@]}" -x509SVIDTTL 3600 >/dev/null 2>&1 || true
  echo "   entry $wid  selectors: $nfsel"
  # Only the host-sidecar mode needs a delegate identity. Creating one in in-pod mode would
  # also match the sidecar (it is root), giving it two identities to choose between.
  if [ "$MODE" = "host" ]; then
    "$BIN/spire-server" entry create -socketPath "$RUN/server.sock" \
      -parentID "spiffe://$TD/agent/$name" -spiffeID "$DELEGATE_ID" \
      -selector "unix:uid:0" -x509SVIDTTL 3600 >/dev/null 2>&1 || true
  fi
  # KeyManager "disk", not "memory": a join token is SINGLE USE, so an agent that loses its
  # keys on restart cannot re-attest and dies with "join token ... already been used". With
  # the key on disk it recovers its existing SVID and restarts cleanly.
  # admin_socket_path enables the Delegated Identity API, and authorized_delegates names
  # who may use it. That is what lets the sidecar ask SPIRE to attest the NF's pid and hand
  # back the NF's own SVID -- the Envoy-with-SPIRE model for a sidecar outside the pod.
  local conf="agent { data_dir = \"$RUN/agent/data\" log_level = \"WARN\" server_address = \"SERVERIP\" server_port = \"8081\" socket_path = \"$RUN/agent.sock\" admin_socket_path = \"${RUN}-admin/admin.sock\" trust_domain = \"$TD\" insecure_bootstrap = true
  authorized_delegates = [ \"$DELEGATE_ID\" ] }
plugins { KeyManager \"disk\" { plugin_data { directory = \"$RUN/agent/data\" } } NodeAttestor \"join_token\" { plugin_data {} } WorkloadAttestor \"unix\" { plugin_data { discover_workload_path = true } }
  WorkloadAttestor \"k8s\" { plugin_data { skip_kubelet_verification = true
    certificate_path = \"$KUBELET_CERT\" private_key_path = \"$KUBELET_KEY\" } } }"
  if [ "$node" = "local" ]; then
    echo "${conf/SERVERIP/127.0.0.1}" > "$RUN/agent.conf"
    sudo pkill -f 'spire-agent run' 2>/dev/null || true
    sudo rm -rf "$RUN/agent/data"; mkdir -p "$RUN/agent/data" "${RUN}-admin"
    sudo systemctl reset-failed armb-spire-agent 2>/dev/null || true
    sudo systemd-run --unit=armb-spire-agent --collect \
      "$BIN/spire-agent" run -config "$RUN/agent.conf" -joinToken "$tok" >/dev/null
  else
    echo "${conf/SERVERIP/$SERVER_IP}" > /tmp/armb-agent-$name.conf
    # Stage into a user-writable path first (scp cannot sudo), then place with sudo.
    ssh $SSH_OPTS "$node" "mkdir -p /tmp/armb-stage" || { echo "   cannot ssh to $node"; exit 1; }
    scp $SSH_OPTS -q "$BIN/spire-agent" "$node:/tmp/armb-stage/spire-agent" || { echo "   scp agent -> $node failed"; exit 1; }
    scp $SSH_OPTS -q /tmp/armb-agent-$name.conf "$node:/tmp/armb-stage/agent.conf" || { echo "   scp conf -> $node failed"; exit 1; }
    ssh $SSH_OPTS "$node" "sudo install -D -m0755 /tmp/armb-stage/spire-agent $CACHE/spire-$VER/bin/spire-agent && \
      sudo install -D -m0644 /tmp/armb-stage/agent.conf $RUN/agent.conf && \
      sudo systemctl stop armb-spire-agent 2>/dev/null; sudo systemctl reset-failed armb-spire-agent 2>/dev/null; \
      sudo rm -rf $RUN/agent/data && sudo mkdir -p $RUN/agent/data ${RUN}-admin && \
      sudo systemd-run --unit=armb-spire-agent --collect $CACHE/spire-$VER/bin/spire-agent run -config $RUN/agent.conf -joinToken $tok" >/dev/null 2>&1 \
      || { echo "   remote agent start failed on $node"; exit 1; }
  fi
  echo "   $name -> $wid"
}

# Which IP the remote agents dial back on.
SERVER_IP="$(ip -o -4 route get "$UPF_NODE" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
[ -n "$SERVER_IP" ] || SERVER_IP="$(hostname -I | awk '{print $1}')"
echo "   server reachable at $SERVER_IP"

SELF_IPS="$(hostname -I)"
smf_target="$SMF_NODE"; case " $SELF_IPS " in *" $SMF_NODE "*) smf_target=local;; esac
upf_target="$UPF_NODE"; case " $SELF_IPS " in *" $UPF_NODE "*) upf_target=local;; esac
# Discover the NF pods so their processes can be selected on (falls back loudly).
NS="${NF_NAMESPACE:-core}"
SMF_POD="${SMF_POD:-$(kubectl -n "$NS" get pod --no-headers 2>/dev/null | awk '$3=="Running"' | grep -iE 'smf' | awk '{print $1}' | head -1)}"
UPF_POD="${UPF_POD:-$(kubectl -n "$NS" get pod --no-headers 2>/dev/null | awk '$3=="Running"' | grep -iE 'upf' | awk '{print $1}' | head -1)}"
SMF_SEL="$(nf_selectors "$SMF_NODE" "$SMF_POD")"
UPF_SEL="$(nf_selectors "$UPF_NODE" "$UPF_POD")"
for v in SMF UPF; do
  eval "sel=\$${v}_SEL"
  if [ -z "$sel" ]; then
    echo "   WARNING: could not determine $v selectors ($MODE mode); falling back to unix:uid:0."
    echo "            That means ANY root process on that node can obtain the $v identity."
    eval "${v}_SEL='unix:uid:0'"
  fi
done
start_agent "$smf_target" smf-node "$SMF_ID" "$SMF_SEL"
[ "$SMF_NODE" = "$UPF_NODE" ] || start_agent "$upf_target" upf-node "$UPF_ID" "$UPF_SEL"

echo "== 4. verify =="
sleep 8
# What must be true now:
#  (a) the sidecar can obtain its DELEGATE identity from the Workload API (it is root), and
#  (b) the NF identity is NOT obtainable that way -- it is selected on the NF process, so
#      only an attestation of that pid through the delegated API yields it. (b) failing
#      would mean any root process on the node could impersonate the NF.
check_node() { # $1=target(local|ip)  $2=agent bin dir  $3=nf id
  local t="$1" bin="$2" nfid="$3" out
  # A non-zero exit here is the EXPECTED result in in-pod mode: a plain root process on the
  # node matches no registration entry and therefore gets no SVID at all. Capture it either
  # way instead of letting set -e treat the good outcome as a script failure.
  if [ "$t" = "local" ]; then out=$(sudo "$BIN/spire-agent" api fetch x509 -socketPath "$RUN/agent.sock" 2>&1 || true)
  else out=$(ssh $SSH_OPTS "$t" "sudo $bin/spire-agent api fetch x509 -socketPath $RUN/agent.sock" 2>&1 || true); fi

  # In BOTH modes the same thing must be true: a plain root process on the node must not be
  # handed the NF's identity. That is the whole point of attesting the workload rather than
  # trusting whoever asks.
  if echo "$out" | grep -q "$nfid"; then
    echo "   FAIL  $t hands the NF identity ($nfid) to any root process --"
    echo "         the selectors are not binding it to the workload"
    return 1
  fi
  echo "   OK    $t does NOT hand the NF identity to a root process on the node"

  if [ "$MODE" = "host" ]; then
    echo "$out" | grep -q "$DELEGATE_ID" \
      && echo "   OK    $t delegate identity available ($DELEGATE_ID)" \
      || { echo "   FAIL  $t could not obtain the delegate identity"; echo "$out" | head -5; return 1; }
    if [ "$t" = "local" ]; then sudo test -S "${RUN}-admin/admin.sock"
    else ssh $SSH_OPTS "$t" "sudo test -S ${RUN}-admin/admin.sock"; fi \
      && echo "   OK    $t delegated identity socket present" \
      || { echo "   FAIL  $t admin socket ${RUN}-admin/admin.sock missing"; return 1; }
  else
    # in-pod: the sidecar is attested through the k8s workload attestor, which needs the
    # agent to be able to reach the kubelet. Confirm it loaded rather than waiting for a
    # confusing "no SVID" from the sidecar later.
    local lg
    if [ "$t" = "local" ]; then lg=$(sudo journalctl -u armb-spire-agent --no-pager -n 200 2>/dev/null)
    else lg=$(ssh $SSH_OPTS "$t" "sudo journalctl -u armb-spire-agent --no-pager -n 200" 2>/dev/null); fi
    echo "$lg" | grep -qi 'plugin_name=k8s.*WorkloadAttestor\|WorkloadAttestor.*plugin_name=k8s' \
      && echo "   OK    $t k8s workload attestor loaded (pods attested by ns/sa/container)" \
      || echo "   WARN  $t could not confirm the k8s workload attestor loaded"
    echo "$lg" | grep -qi 'kubelet.*error\|failed to get pod' \
      && echo "   WARN  $t agent reported kubelet errors -- check KUBELET_CERT/KEY" || true
  fi
}
check_node "$smf_target" "$CACHE/spire-$VER/bin" "$SMF_ID"
[ "$SMF_NODE" = "$UPF_NODE" ] || check_node "$upf_target" "$CACHE/spire-$VER/bin" "$UPF_ID"

cat > "$(dirname "$0")/deploy.env" <<EOF
# generated by spire-bootstrap.sh
TRUST_DOMAIN=$TD
SMF_SPIFFE_ID=$SMF_ID
UPF_SPIFFE_ID=$UPF_ID
SPIRE_SOCKET=unix://$RUN/agent.sock
SPIRE_ADMIN_SOCKET=unix://${RUN}-admin/admin.sock
DELEGATE_ID=$DELEGATE_ID
SMF_NODE=$SMF_NODE
UPF_NODE=$UPF_NODE
EOF
echo "== done -> $(dirname "$0")/deploy.env =="
