# Design

## The constraint

Put DTLS on N4 without touching the network function. "Without touching" means: the NF's
image, configuration and command line are unchanged, and **the PFCP payload is never
rewritten**.

That last part rules out the obvious approach. A terminating proxy re-originates traffic
under its own addresses, but PFCP carries IP addresses *inside* its payload — F-SEID and
Node ID — so the outer addresses and the IEs disagree, and a core that correlates on the
outer address stops matching its own sessions. Implementations differ on which they use, and
the standard is not decisive in practice, so the design refuses to depend on the answer:
preserve the whole packet and the question never arises.

## Capture → encapsulate → reinject

**Capture.** An iptables rule in the NF's network namespace sends egress PFCP to an NFQUEUE:

```
-t mangle -A OUTPUT -p udp --dport 8805 -j NFQUEUE --queue-num N --queue-bypass
-t mangle -A OUTPUT -p udp --sport 8805 -j NFQUEUE --queue-num N --queue-bypass
```

Both directions are matched. A request has destination port 8805, but a core that sends from
an *ephemeral* source port receives its responses addressed to that port — those carry
**source** 8805. Matching only `--dport` encrypts requests and leaks responses.

**Encapsulate.** The captured L3 packet is written whole as one DTLS record, and the original
is given `NF_DROP`, so the plaintext never leaves the host. If the tunnel cannot take it, the
original is still dropped — failing closed, never falling back to plaintext.

**Reinject.** Packets arriving from the peer are written to a **TUN device**. The kernel
receives them on that interface's input path with the original L3 header intact, so the NF
sees N4 exactly as if it had arrived over the wire. TUN was chosen over the alternatives
because it does not traverse the OUTPUT chain, so an injected packet cannot be recaptured by
our own rule — there is no loop to guard against.

Two things reliably break reinjection and both are handled explicitly:

* **rp_filter.** An injected packet is *peer-sourced*: its source address routes out of the
  real N4 interface, not the tun, so reverse-path filtering drops it. The effective value is
  `max(conf/all, conf/<iface>)`, so setting only the tun's knob does nothing when `conf/all`
  is strict — and loose mode (2) is *also* insufficient here. The sidecar sets `conf/all` and
  the tun to 0 in its own network namespace and logs both.
* **SO_BINDTODEVICE.** TUN injection reaches a socket bound to an address, but **not** one
  pinned to a device. Cores that bind their PFCP socket to an address (the common case) work;
  one that pins it to an interface would need an eBPF tc-ingress redirect instead.

## Identity

The credential is an X509-SVID from SPIRE. The peer is verified against SPIRE's trust bundle
and authorized by its exact SPIFFE ID. No PSK — a pre-shared key has neither chain nor
signature verification, so a PSK benchmark answers a different question than "what does
SPIFFE/SPIRE cost".

**`InsecureSkipVerify` must be `true`.** This is not a weakening. It disables only the default
hostname / system-root-pool check, which is meaningless for SPIFFE (a SPIFFE ID is not a DNS
name and SVIDs do not chain to public roots), and it is *replaced* by `VerifyPeerCertificate`
doing full chain verification against the live SPIRE bundle plus SPIFFE-ID authorization.
This is exactly what go-spiffe's own `tlsconfig.MTLS*Config` sets. With it `false`, every
handshake fails `certificate signed by unknown authority`.

**Rotation.** Both the SVID and the bundle are streamed, and the certificate is served through
`GetCertificate`/`GetClientCertificate` — read at each handshake rather than frozen into the
config — so a rotated SVID is presented from the next handshake on. A session supervisor
re-establishes the tunnel when the SVID genuinely changes, and when the tunnel breaks. The
same mechanism covers both because both have the same answer: dial again with whatever SVID
is current.

Rotation is signalled only when the **leaf certificate actually changes**. SPIRE re-sends the
whole SVID set on every cache change, so treating each message as a rotation tears the session
down hundreds of times for nothing.

**Which identity.** SPIRE hands back a *set* of SVIDs — a workload can match several entries.
Taking the first presents an arbitrary identity, and the peer rejects the handshake with
`unexpected ID`. The sidecar is told which SPIFFE ID to present (`-identity`) and selects it.

### Two attestation shapes

*In-pod* is the Envoy arrangement: the sidecar is a container in the NF's pod, so the k8s
workload attestor resolves it to that pod and the plain Workload API returns the pod's own
identity (`k8s:ns`, `k8s:sa`, `k8s:container-name`).

*Host + delegated* is for when the pod spec must not change. The Workload API attests its
*caller*, so calling it from the host returns the sidecar's own identity — only as strong as
whatever selectors that entry has. SPIRE's **Delegated Identity API** closes the gap: an
authorized delegate names a PID and SPIRE performs its own attestation of that process, so
the certificate presented on N4 is the identity SPIRE issues for the NF itself.

The two are not equivalent. `unix:path`+`unix:sha256` binds the identity to *a process running
that binary*; anything on the node running a copy satisfies it. The k8s selectors bind it to a
namespace, service account and container. Neither binds it to a specific *execution* — if that
is what you need, this is not the control that provides it.

## Failing closed

Every refusal drops the original packet rather than emitting it in plaintext: a full queue, a
write that times out, a tunnel that is down between sessions. The cost of that choice is a
gap in forwarding; the cost of the alternative is silently unprotected N4.

## Hot path

Per captured packet the sidecar does one copy out of C memory (unavoidable: the NFQUEUE
buffer dies with the callback) and one DTLS record write. The copy destination comes from a
pool rather than a fresh allocation, and the write deadline — a hang guard, not a per-message
SLA — is refreshed on a coarse schedule instead of per packet, because pion's
`SetWriteDeadline` takes a mutex and resets a runtime timer on every call. Benchmarks are in
`cmd/n4dtls/bench_test.go`.

The NFQUEUE verdict path is serialized by a mutex: libnetfilter_queue's queue handle is not
thread-safe, and calling `nfq_set_verdict()` concurrently with the receive loop segfaults
inside libnfnetlink under live traffic.
