#!/usr/bin/env bash
# Deploy (or remove) the arm-B N4 DTLS sidecars on a generic OAI deployment.
#
#   ./n4dtls-deploy.sh up      [--smf-pod <name>] [--upf-pod <name>] [--namespace core] [--mtu 1200]
#   ./n4dtls-deploy.sh down
#   ./n4dtls-deploy.sh status
#
# Discovers the SMF/UPF pods, their host node, container PID and N4 address by itself; the
# NF is never modified. Requires deploy.env from spire-bootstrap.sh, the n4dtls binary, and
# kubectl+crictl+ssh access to the NF nodes.
#
# Order matters and is enforced: the UPF side (DTLS server) starts first and only LISTENS;
# the SMF side dials it; each sidecar installs its capture rule ONLY after the session is
# up, so the NF's PFCP is never queued with nowhere to go (that gap tears down a live
# PFCP association).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="core"; MTU=1200; SMF_POD=""; UPF_POD=""; UPF_N4=""; DISCOVER_WAIT=20
BIN_SRC="${N4DTLS_BIN:-$HERE/../n4dtls}"
REMOTE_BIN=/tmp/n4dtls
SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no"
SMF_Q=62; UPF_Q=61; DPORT=8805; DTLS_PORT=8806

CMD="${1:-}"; shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --smf-pod) SMF_POD="$2"; shift 2;;
    --upf-pod) UPF_POD="$2"; shift 2;;
    --namespace|-n) NS="$2"; shift 2;;
    --mtu) MTU="$2"; shift 2;;
    --upf-n4) UPF_N4="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -f "$HERE/deploy.env" ] || { echo "deploy.env missing — run spire-bootstrap.sh first" >&2; exit 2; }
# shellcheck disable=SC1091
. "$HERE/deploy.env"

k() { kubectl -n "$NS" "$@"; }
# run a command on a node: locally if it is this host, over ssh otherwise
on() { local node="$1"; shift
  case " $(hostname -I) " in *" $node "*) sudo bash -c "$*";; *) ssh $SSH_OPTS "$node" "sudo bash -c '$*'";; esac
}

discover() {
  [ -n "$SMF_POD" ] || SMF_POD=$(k get pod --no-headers 2>/dev/null | awk '$3=="Running"' | grep -iE 'smf' | awk '{print $1}' | head -1)
  [ -n "$UPF_POD" ] || UPF_POD=$(k get pod --no-headers 2>/dev/null | awk '$3=="Running"' | grep -iE 'upf' | awk '{print $1}' | head -1)
  [ -n "$SMF_POD" ] && [ -n "$UPF_POD" ] || { echo "could not find SMF/UPF pods in ns=$NS (use --smf-pod/--upf-pod)" >&2; exit 1; }
  SMF_NODE_NAME=$(k get pod "$SMF_POD" -o jsonpath='{.spec.nodeName}')
  UPF_NODE_NAME=$(k get pod "$UPF_POD" -o jsonpath='{.spec.nodeName}')
  SMF_HOST=$(kubectl get node "$SMF_NODE_NAME" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
  UPF_HOST=$(kubectl get node "$UPF_NODE_NAME" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
  SMF_CID=$(k get pod "$SMF_POD" -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's|.*://||')
  UPF_CID=$(k get pod "$UPF_POD" -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's|.*://||')
  SMF_PID=$(on "$SMF_HOST" "crictl inspect $SMF_CID" | python3 -c 'import json,sys;print(json.load(sys.stdin)["info"]["pid"])')
  UPF_PID=$(on "$UPF_HOST" "crictl inspect $UPF_CID" | python3 -c 'import json,sys;print(json.load(sys.stdin)["info"]["pid"])')
  # The UPF's N4 address must be the one the SMF ACTUALLY sends PFCP to. A UPF usually has
  # several addresses (N3, N4, N6...), so "first non-eth0 interface" can name the wrong one.
  # Observe it instead: watch the SMF's own egress for one PFCP packet and take its
  # destination. That is true by construction, whatever the deployment looks like.
  # (--upf-n4 overrides this if the association is down and nothing can be observed.)
  if [ -z "$UPF_N4" ]; then
    UPF_N4=$(on "$SMF_HOST" "timeout ${DISCOVER_WAIT}s nsenter -t $SMF_PID -n tcpdump -i any -nn -c 1 udp and dst port $DPORT 2>/dev/null" \
             | grep -oE "> [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\\.$DPORT" | head -1 \
             | sed "s/^> //; s/\\.$DPORT\$//") || true
  fi
  if [ -z "$UPF_N4" ]; then
    UPF_N4=$(on "$UPF_HOST" "nsenter -t $UPF_PID -n ip -o -4 addr show 2>/dev/null" \
      | awk '{print $2, $4}' | grep -viE '^(lo|eth0) ' | awk '{print $2}' | cut -d/ -f1 | head -1)
    echo "   note: no PFCP seen in ${DISCOVER_WAIT}s; guessed UPF N4 = $UPF_N4 from its interfaces."
    echo "         If that is not the PFCP address, pass --upf-n4 <ip>."
  fi
  [ -n "$UPF_N4" ] || { echo "could not determine the UPF N4 address" >&2; exit 1; }
}

push_bin() { # place the sidecar on a node, ALWAYS refreshing it
  # Skipping the copy when a binary is already there silently runs a stale build -- which
  # shows up as flag-parsing failures the moment the sidecar grows an option.
  local node="$1"
  case " $(hostname -I) " in
    *" $node "*) sudo install -m0755 "$BIN_SRC" "$REMOTE_BIN";;
    *) scp $SSH_OPTS -q "$BIN_SRC" "$node:/tmp/n4dtls.new"; on "$node" "install -m0755 /tmp/n4dtls.new $REMOTE_BIN && rm -f /tmp/n4dtls.new";;
  esac
}

up() {
  [ -x "$BIN_SRC" ] || { echo "n4dtls binary not found at $BIN_SRC (build: CGO_ENABLED=1 go build -o n4dtls ./cmd/n4dtls)" >&2; exit 2; }
  discover
  echo "SMF $SMF_POD @ $SMF_NODE_NAME($SMF_HOST) pid=$SMF_PID"
  echo "UPF $UPF_POD @ $UPF_NODE_NAME($UPF_HOST) pid=$UPF_PID n4=$UPF_N4"
  push_bin "$SMF_HOST"; push_bin "$UPF_HOST"

  echo "-- UPF side (DTLS server; listens, no capture yet) --"
  on "$UPF_HOST" "systemctl reset-failed armb-upf 2>/dev/null; systemctl stop armb-upf 2>/dev/null; \
    systemd-run --unit=armb-upf --collect /usr/bin/nsenter -t $UPF_PID -n env CIRRUS_SPIRE_SOCKET=$SPIRE_SOCKET \
    $REMOTE_BIN -role server -listen 0.0.0.0:$DTLS_PORT -peer-id $SMF_SPIFFE_ID \
    ${SPIRE_ADMIN_SOCKET:+-delegated-socket $SPIRE_ADMIN_SOCKET -workload-pid $UPF_PID -identity $UPF_SPIFFE_ID} \
    -nfqueue $UPF_Q -tun n4dtls0 -install-nfq-rule -dport $DPORT -mtu $MTU" >/dev/null
  sleep 3

  echo "-- SMF side (DTLS client; dials, then both install capture) --"
  on "$SMF_HOST" "systemctl reset-failed armb-smf 2>/dev/null; systemctl stop armb-smf 2>/dev/null; \
    systemd-run --unit=armb-smf --collect /usr/bin/nsenter -t $SMF_PID -n env CIRRUS_SPIRE_SOCKET=$SPIRE_SOCKET \
    $REMOTE_BIN -role client -peer $UPF_N4:$DTLS_PORT -peer-id $UPF_SPIFFE_ID \
    ${SPIRE_ADMIN_SOCKET:+-delegated-socket $SPIRE_ADMIN_SOCKET -workload-pid $SMF_PID -identity $SMF_SPIFFE_ID} \
    -nfqueue $SMF_Q -tun n4dtls0 -install-nfq-rule -dport $DPORT -mtu $MTU" >/dev/null
  sleep 5
  status
}

down() {
  discover
  echo "-- stopping sidecars --"
  on "$SMF_HOST" "systemctl stop armb-smf 2>/dev/null; systemctl kill -s SIGKILL armb-smf 2>/dev/null; systemctl reset-failed armb-smf 2>/dev/null" || true
  on "$UPF_HOST" "systemctl stop armb-upf 2>/dev/null; systemctl kill -s SIGKILL armb-upf 2>/dev/null; systemctl reset-failed armb-upf 2>/dev/null" || true
  sleep 2
  echo "-- removing any leftover rules / tun (idempotent) --"
  for spec in "$SMF_HOST:$SMF_PID:$SMF_Q" "$UPF_HOST:$UPF_PID:$UPF_Q"; do
    local host="${spec%%:*}" rest="${spec#*:}"; local pid="${rest%%:*}" q="${rest#*:}"
    on "$host" "nsenter -t $pid -n iptables -t mangle -D OUTPUT -p udp --dport $DPORT -j NFQUEUE --queue-num $q --queue-bypass 2>/dev/null; \
                nsenter -t $pid -n iptables -t mangle -D OUTPUT -p udp --sport $DPORT -j NFQUEUE --queue-num $q --queue-bypass 2>/dev/null; \
                nsenter -t $pid -n iptables -t mangle -D OUTPUT -m mark --mark 20020 -j ACCEPT 2>/dev/null; \
                nsenter -t $pid -n ip link del n4dtls0 2>/dev/null; true"
  done
  echo "-- N4 is back in plaintext; the NF was never modified --"
}

status() {
  [ -n "${SMF_PID:-}" ] || discover
  echo "-- units --"
  echo "   smf: $(on "$SMF_HOST" 'systemctl is-active armb-smf' 2>/dev/null || echo inactive)"
  echo "   upf: $(on "$UPF_HOST" 'systemctl is-active armb-upf' 2>/dev/null || echo inactive)"
  echo "-- session --"
  on "$SMF_HOST" "journalctl -u armb-smf --no-pager 2>/dev/null | grep -oE 'DTLS session up.*|auth=[^ ]+ cipher=[^ ]+ handshakes=[0-9]+|FATAL.*' | tail -2" 2>/dev/null | sed 's/^/   /'
  echo "-- counters (captured=intercepted, sent/recv=tunneled, injected=reinjected) --"
  echo "   smf: $(on "$SMF_HOST" "journalctl -u armb-smf --no-pager 2>/dev/null | grep -oE 'captured=[0-9]+ sent=[0-9]+ recv=[0-9]+ injected=[0-9]+ drop_verdict=[0-9]+' | tail -1" 2>/dev/null)"
  echo "   upf: $(on "$UPF_HOST" "journalctl -u armb-upf --no-pager 2>/dev/null | grep -oE 'captured=[0-9]+ sent=[0-9]+ recv=[0-9]+ injected=[0-9]+ drop_verdict=[0-9]+' | tail -1" 2>/dev/null)"
}

case "$CMD" in
  up) up;;
  down) down;;
  status) status;;
  *) echo "usage: $0 {up|down|status} [--smf-pod N] [--upf-pod N] [--upf-n4 IP] [--namespace core] [--mtu 1200]" >&2; exit 2;;
esac
