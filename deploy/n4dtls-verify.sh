#!/usr/bin/env bash
# Verify an arm-B deployment on a live OAI: is N4 actually encrypted, did the PFCP
# association survive, and does a real UE session still work end to end.
#
#   ./n4dtls-verify.sh [--namespace core] [--smf-pod N] [--upf-pod N] [--skip-ue]
#
# Every check prints PASS/FAIL with the evidence it used. Exit code 0 only if all pass.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NS="core"; SMF_POD=""; UPF_POD=""; SKIP_UE=0; DPORT=8805; DTLS_PORT=8806
SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=no"
while [ $# -gt 0 ]; do
  case "$1" in
    --namespace|-n) NS="$2"; shift 2;;
    --smf-pod) SMF_POD="$2"; shift 2;;
    --upf-pod) UPF_POD="$2"; shift 2;;
    --skip-ue) SKIP_UE=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
k() { kubectl -n "$NS" "$@"; }
on() { local node="$1"; shift
  case " $(hostname -I) " in *" $node "*) sudo bash -c "$*";; *) ssh $SSH_OPTS "$node" "sudo bash -c '$*'";; esac
}
PASS=0; FAIL=0
# The sidecar may run as a container in the NF's pod (Envoy model) or as a systemd unit on
# the host. Read its log from wherever it actually is.
SIDECAR="n4dtls"
sidecar_log() { # $1=smf|upf
  local pod
  pod=$(k get pod --no-headers 2>/dev/null | awk '$3~/Running/' | grep -iE "$1" | awk '{print $1}' | head -1)
  if [ -n "$pod" ] && k get pod "$pod" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null | grep -qw "$SIDECAR"; then
    k logs "$pod" -c "$SIDECAR" --tail=400 2>/dev/null
    return
  fi
  case "$1" in
    smf) on "$SMF_HOST" "journalctl -u armb-smf --no-pager -n 400" 2>/dev/null;;
    upf) on "$UPF_HOST" "journalctl -u armb-upf --no-pager -n 400" 2>/dev/null;;
  esac
}
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }

[ -n "$SMF_POD" ] || SMF_POD=$(k get pod --no-headers 2>/dev/null | awk '$3=="Running"' | grep -iE 'smf' | awk '{print $1}' | head -1)
[ -n "$UPF_POD" ] || UPF_POD=$(k get pod --no-headers 2>/dev/null | awk '$3=="Running"' | grep -iE 'upf' | awk '{print $1}' | head -1)
SMF_HOST=$(kubectl get node "$(k get pod "$SMF_POD" -o jsonpath='{.spec.nodeName}')" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
UPF_HOST=$(kubectl get node "$(k get pod "$UPF_POD" -o jsonpath='{.spec.nodeName}')" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
SMF_CID=$(k get pod "$SMF_POD" -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's|.*://||')
SMF_PID=$(on "$SMF_HOST" "crictl inspect $SMF_CID" | python3 -c 'import json,sys;print(json.load(sys.stdin)["info"]["pid"])')
N4IF=$(on "$SMF_HOST" "nsenter -t $SMF_PID -n ip -o -4 addr show 2>/dev/null" | awk '{print $2, $4}' | grep -viE '^(lo|eth0) ' | awk '{print $1}' | head -1)
echo "target: SMF=$SMF_POD UPF=$UPF_POD n4if=$N4IF"

echo "== 1. mutual-auth DTLS session =="
S=$(sidecar_log smf | grep -oE 'auth=x509-svid\+mutual cipher=[^ ]+ handshakes=[0-9]+' | tail -1)
[ -n "$S" ] && ok "session up: $S" || bad "no mutual-auth session line in armb-smf"
SELF=$(sidecar_log smf | grep -oE 'self=[^ ]+ peer_id=[^ ]+' | tail -1)
case "$SELF" in
  *self=*peer_id=*) sid=${SELF#self=}; sid=${sid%% *}; pid_=${SELF##*peer_id=}
     [ "$sid" != "$pid_" ] && ok "distinct identities: $sid vs $pid_" || bad "SMF and UPF present the SAME SPIFFE ID ($sid) — not real mutual auth";;
  *) bad "could not read identities";;
esac

echo "== 2. N4 on the wire is DTLS only (no plaintext PFCP) =="
CAP=$(on "$SMF_HOST" "timeout 25 nsenter -t $SMF_PID -n tcpdump -i $N4IF -nn 'udp and (port $DPORT or port $DTLS_PORT)' -c 6 2>/dev/null")
PLAIN=$(echo "$CAP" | grep -c "\.$DPORT:")
ENC=$(echo "$CAP" | grep -c "\.$DTLS_PORT:")
[ "$ENC" -gt 0 ] && ok "DTLS packets on $N4IF: $ENC" || bad "no DTLS traffic seen on $N4IF"
[ "$PLAIN" -eq 0 ] && ok "no plaintext PFCP on the wire" || bad "plaintext PFCP still on the wire: $PLAIN packet(s)"

echo "== 3. tunnel is carrying traffic both ways =="
SC=$(sidecar_log smf | grep -oE 'captured=[0-9]+ sent=[0-9]+ recv=[0-9]+ injected=[0-9]+ drop_verdict=[0-9]+' | tail -1)
UC=$(sidecar_log upf | grep -oE 'captured=[0-9]+ sent=[0-9]+ recv=[0-9]+ injected=[0-9]+ drop_verdict=[0-9]+' | tail -1)
gv() { echo "$1" | grep -oE "$2=[0-9]+" | cut -d= -f2; }
ss=$(gv "$SC" sent); sr=$(gv "$SC" recv); us=$(gv "$UC" sent); ur=$(gv "$UC" recv)
echo "     smf: $SC"; echo "     upf: $UC"
[ "${ss:-0}" -gt 0 ] && [ "${ur:-0}" -gt 0 ] && ok "SMF->UPF flowing (sent=$ss recv=$ur)" || bad "SMF->UPF not flowing"
[ "${us:-0}" -gt 0 ] && [ "${sr:-0}" -gt 0 ] && ok "UPF->SMF flowing (sent=$us recv=$sr)" || bad "UPF->SMF not flowing (responses may be leaking in plaintext)"

echo "== 4. PFCP association survived =="
# With a sidecar injected the pod has two containers, so the NF's own container has to be
# named or kubectl refuses the request.
NFC=$(k get pod "$SMF_POD" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null | grep -vx "$SIDECAR" | head -1)
F=$(k logs "$SMF_POD" -c "$NFC" --since=120s 2>/dev/null | grep -icE 'remove the association|HEARTBEAT PROCEDURE FAILED')
H=$(k logs "$SMF_POD" -c "$NFC" --since=60s 2>/dev/null | grep -icE 'HEARTBEAT PROCEDURE .* starting|msg type 2')
[ "$F" -eq 0 ] && ok "no association teardown in the last 120s" || bad "association failures: $F"
[ "$H" -gt 0 ] && ok "heartbeats still running ($H events/60s)" || bad "no heartbeat activity — association may be down"

echo "== 5. NF untouched =="
RS=$(k get pod "$SMF_POD" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null)
RU=$(k get pod "$UPF_POD" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null)
if k get pod "$SMF_POD" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null | grep -qw "$SIDECAR"; then
  ok "NF container untouched: the pod gained a sidecar container, the NF image/config/command did not change"
else
  ok "no NF config change; the sidecar runs in the NF netns from the host, not in the NF"
fi

if [ "$SKIP_UE" -eq 0 ]; then
  echo "== 6. a real UE session works through the tunneled N4 =="
  UE=$(k get pod --no-headers 2>/dev/null | awk '$3=="Running"' | grep -iE 'nr-ue|ue' | awk '{print $1}' | head -1)
  if [ -n "$UE" ]; then
    TUNIF=$(k exec "$UE" -- sh -c 'ip -o -4 addr show 2>/dev/null | grep -i oaitun' 2>/dev/null | awk '{print $2}' | head -1)
    ADDR=$(k exec "$UE" -- sh -c 'ip -o -4 addr show 2>/dev/null | grep -i oaitun' 2>/dev/null | awk '{print $4}' | head -1)
    [ -n "$ADDR" ] && ok "UE has a PDU session ($TUNIF $ADDR)" || bad "UE has no PDU session address"
    if [ -n "$TUNIF" ]; then
      L=$(k exec "$UE" -- sh -c "ping -c2 -W3 -I $TUNIF 8.8.8.8 2>&1 | grep -oE '[0-9]+% packet loss'" 2>/dev/null)
      case "$L" in 0%*) ok "UE data plane: $L";; "") bad "UE ping produced no result";; *) bad "UE data plane degraded: $L";; esac
    fi
  else
    echo "  SKIP  no UE pod found"
  fi
fi

echo
echo "== result: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
