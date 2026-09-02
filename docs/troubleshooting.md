# Troubleshooting

Every entry here was hit for real. Each gives the symptom first, because that is what you
have when it happens.

## SPIRE

**`certificate signed by unknown authority` on every handshake**
`InsecureSkipVerify` is `false`. It must be `true` for SPIFFE authentication — see
`docs/design.md`. The verification that matters is in `VerifyPeerCertificate`.

**`admin socket cannot be in the same directory or a subdirectory as that containing the
Workload API socket`**
SPIRE refuses an `admin_socket_path` under the Workload API socket's directory *and any
subdirectory of it*. Use a sibling path (`/tmp/spire-run` + `/tmp/spire-run-admin`).

**Registration entries with `unix:path` / `unix:sha256` never match**
The unix workload attestor emits only uid/gid unless it is configured with
`discover_workload_path = true`.

**Agent dies on restart: `join token does not exist or has already been used`**
Join tokens are single-use. With `KeyManager "memory"` the agent loses its keys on restart,
tries to re-attest with the same token, and exits. Use `KeyManager "disk"` so it can recover
its existing SVID.

**k8s workload attestor: `403 Forbidden (user=system:node:<name>, ... nodes/proxy)`**
The attestor asks the kubelet which pod owns a PID. A node's own kubelet client certificate
authenticates as `system:node:<name>`, which is not granted `nodes/proxy`. Bind the built-in
`system:kubelet-api-admin` ClusterRole to `system:nodes` (the bootstrap script does this).

**The sidecar gets the wrong identity, peer rejects with `unexpected ID`**
The Workload API returns a *set*. Pass `-identity <spiffe-id>` so the right one is selected.

**Delegated mode: `no SVID for pid N`, and the agent logs `request_selectors="[]"`**
The `pid` field of `SubscribeToX509SVIDs` postdates SPIRE 1.9. An older agent ignores it and
answers with the *delegate's* identity — which looks like success while attesting nothing.
Run an agent matching your `spire-api-sdk` (1.11.x with sdk v1.11.2).

## Datapath

**After a peer restart the tunnel never recovers: `sent` climbs, `recv` stays 0, and the
peer sidecar shows only its listen line**
A DTLS session over UDP does not fail loudly when the far side goes away — writes still
succeed locally and reads simply never return — so an error-driven supervisor never wakes.
The sidecar now infers it: if datagrams have been sent and nothing has come back for longer
than `deadAfter` (20s, comfortably above the PFCP heartbeat interval), the session is treated
as lost and re-established. If you are on an older build, restart the CLIENT side (the one
with `-peer`) to force a fresh handshake.

Related operational note: bring the **server side up first**. The client dials on startup, so
starting it against a peer that is about to restart leaves it attached to a session that is
about to die.


**One direction flows, the other does not: `captured` climbs on one sidecar, stays 0 on the
other, and plaintext PFCP is still on the wire**
Stale conntrack. nat rules run only for the first packet of a connection, and the redirect
rules are installed *after* the DTLS session is up, so an NF that was already talking has an
ASSURED conntrack entry for the N4 flow. Its replies count as that flow's reply direction,
skip nat OUTPUT entirely, and leave unencrypted -- while the request direction looks healthy.
NOTRACK does not fix this: it governs new packets, not state that already exists. The
sidecar flushes conntrack for the intercepted port after installing its rules; if
`conntrack` is missing from the image it says so loudly. Confirm with:

```sh
conntrack -L -p udp 2>/dev/null | grep 8805      # should be empty or freshly created
iptables -t nat -L OUTPUT -v -n | grep REDIRECT  # counters must be non-zero on BOTH sides
```


**Packets are tunneled and injected but never reach the peer NF**
`rp_filter`. The effective value is `max(conf/all, conf/<iface>)`, so setting only the tun's
knob does nothing under a strict `conf/all`, and loose mode (2) is also insufficient. Both
must be 0 in that network namespace. The sidecar sets and logs them.

**Requests are encrypted, responses appear in plaintext on the wire**
Capture is matching only `--dport 8805`. A core sending from an ephemeral source port gets
responses carrying **source** 8805. Match both directions.

**The injected packet arrives on the tun (visible in tcpdump) but the socket never reads it**
The NF's socket is pinned with `SO_BINDTODEVICE`. TUN injection delivers to address-bound
sockets, not device-bound ones. Check with `ss -lnup` / `/proc/net/udp`; a device-bound core
needs an eBPF tc-ingress redirect instead.

**Sidecar crashes with `SIGSEGV ... signal arrived during cgo execution`**
Concurrent use of the libnetfilter_queue handle. All verdicts must go through one mutex.

## PFCP association

**The association dies seconds after the sidecar starts**
The capture rule went in before the DTLS session was up, so PFCP was queued with nowhere to
go and heartbeats were dropped; two missed heartbeats tear the association down. Install the
rule only after the session is established (both deploy scripts do).

**`already exists on pending associations` in a loop, no heartbeats, no UE sessions**
Not caused by the tunnel — verify by removing the sidecars entirely; if it reproduces, it is
the core. Seen on OAI after a simultaneous SMF+UPF restart. Recovery order: NRF, then SMF,
then UPF.

**After the association drops, the SMF never retries**
Some cores with a statically configured UPF do not re-attempt association. Restarting the UPF
is what makes the SMF re-associate.

## Kubernetes

**`down` deleted the network function**
A strategic-merge patch does not necessarily *append* — the sidecar can land at container
index 0. Remove it by name, never by a hardcoded index. (Fixed here; noted because it is easy
to reintroduce.)

**`kubectl logs <pod>` fails with "a container name must be specified"**
The pod has two containers now. Name the one you want: `-c n4dtls` for the sidecar, `-c <nf>`
for the network function.

**The sidecar runs an old build**
A deploy that copies the binary only when one is absent silently keeps a stale build; the
symptom is flag-parsing failure the moment the sidecar gains an option. Always refresh, and
for in-pod remember the image must be re-imported on every node.
