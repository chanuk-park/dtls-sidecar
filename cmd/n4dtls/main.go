// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

//go:build linux && cgo

// n4dtls is the arm-B sidecar: it puts SPIRE-issued, mutually-authenticated DTLS on the
// Multus N4 link WITHOUT modifying the NF. It is symmetric — the same binary runs beside
// the SMF and beside the UPF. On each side it captures the NF's egress PFCP with the SAME
// NFQUEUE machinery arm A uses (§2 D1), ships the WHOLE IP packet as an opaque blob over an
// established DTLS session (§2 D2 — no terminating proxy, the PFCP payload and its F-SEID /
// Node ID IEs are never touched), and reinjects packets received from the peer on the local
// input path via a TUN device. The credential is an X509-SVID from the SPIRE Workload API;
// the peer is authorized by its SPIFFE ID (§2 D3). No PSK, no static cert, no skip-verify.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	dtls "github.com/pion/dtls/v3"
)

var (
	nCaptured, nSent, nRecv, nInjected, nDropVerdict, nHandshake atomic.Int64
)

func main() {
	role := flag.String("role", "", "client|server (which side dials the DTLS session; the pair must differ)")
	peer := flag.String("peer", "", "peer agent DTLS address host:port (role=client)")
	listen := flag.String("listen", "0.0.0.0:8806", "DTLS listen address (role=server)")
	spiffeSock := flag.String("spiffe-socket", os.Getenv("CIRRUS_SPIRE_SOCKET"), "SPIRE Workload API socket (unix:///...)")
	delegatedSock := flag.String("delegated-socket", os.Getenv("CIRRUS_SPIRE_DELEGATED_SOCKET"),
		"SPIRE agent Delegated Identity (admin) socket. With -workload-pid, SPIRE attests the "+
			"NF process itself and this sidecar presents the NF's identity -- the Envoy-with-SPIRE "+
			"model for a sidecar that cannot live inside the pod. Without it the Workload API "+
			"attests this process instead, which is only as strong as its own selectors.")
	workloadPID := flag.Int("workload-pid", 0, "pid of the NF to have SPIRE attest (needs -delegated-socket)")
	selfID := flag.String("identity", "", "SPIFFE ID this sidecar must present. SPIRE hands a "+
		"delegate every SVID it may see, including its own, so the one to use has to be named.")
	peerID := flag.String("peer-id", "", "expected peer SPIFFE ID (AuthorizeID) — mutual auth")
	queueNum := flag.Int("nfqueue", 42, "NFQUEUE number for captured egress PFCP (must match the iptables rule; §D1 same as arm A)")
	dport := flag.Int("dport", 8805, "PFCP UDP port captured on OUTPUT")
	tunName := flag.String("tun", "n4dtls0", "TUN device used to reinject peer packets")
	mark := flag.Int("mark", 0x4e34, "fwmark for injected packets / the accept-before-queue rule (loop guard)")
	mtu := flag.Int("mtu", 1200, "DTLS MTU (§D4: Multus MTU must be lowered to match so PFCP never fragments)")
	mode := flag.String("mode", "socket", "datapath: socket (proxy, like Envoy: REDIRECT into a "+
		"socket, deliver transparently -- no NFQUEUE, no TUN, no cgo) | nfqueue (packet capture "+
		"with deferred verdicts; only needed to share an interception path with a capture-based gate)")
	listenProxy := flag.String("proxy-listen", "0.0.0.0:18805", "socket mode: where the REDIRECT rule lands datagrams")
	peerN4 := flag.String("peer-n4", "", "socket mode, CP side: the far network function's N4 address host:port. "+
		"Leave empty on the UP side, where replies go back to whoever the CP last sent from.")
	redirectPeerFlag := flag.String("redirect-peer", "", "the far network function's N4 ADDRESS "+
		"(no port). Adds a rule that redirects everything the local NF sends to it, whatever "+
		"ports are involved -- necessary for cores that answer from an ephemeral socket instead "+
		"of from the PFCP port, whose replies otherwise escape the port-matched rules and leave "+
		"in plaintext. Set it on BOTH sides: on the CP name the UP's N4 address and vice versa.")
	localNF := flag.String("local-nf", "", "socket mode: this side's network function N4 address (delivery target)")
	installRules := flag.Bool("install-nfq-rule", false, "install the mangle OUTPUT accept-mark + NFQUEUE rules and remove them on exit")
	flag.Parse()

	if *role != "client" && *role != "server" {
		die("-role must be client or server")
	}
	if *role == "client" && *peer == "" {
		die("-role client needs -peer host:port")
	}
	if *peerID == "" {
		die("-peer-id (the peer's SPIFFE ID) is required for mutual auth")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 1. SPIRE identity -> DTLS config.
	id, err := loadIdentity(ctx, *spiffeSock, *delegatedSock, *workloadPID, *selfID, *peerID, *role == "server", *mtu)
	if err != nil {
		die("identity: " + err.Error())
	}
	defer id.close()

	socketMode := *mode == "socket"

	// 2. Reinjection device -- only the capture datapath needs one. In socket mode delivery
	// is a transparent UDP send, so there is no tun, no rp_filter to relax and no risk of
	// recapturing our own injection.
	var tun *tunDev
	if !socketMode {
		tun, err = openTUN(*tunName)
		if err != nil {
			die("tun: " + err.Error())
		}
		defer tun.close()
	}

	// 3. Establish the DTLS session FIRST. The capture rule is installed only AFTER the
	// tunnel is up (below), so we never drop the NF's PFCP into a queue with nowhere to
	// go — that gap is what tore down a live association in testing (heartbeats dropped
	// while the peer sidecar was still handshaking).
	conn, err := connect(ctx, id, *role, *peer, *listen)
	if err != nil {
		die("dtls: " + err.Error())
	}
	nHandshake.Add(1)
	defer conn.Close()

	// 4. Tunnel is up: NOW start intercepting.
	var px *proxy
	if socketMode {
		lp, perr := netip.ParseAddrPort(*listenProxy)
		if perr != nil {
			die("-proxy-listen: " + perr.Error())
		}
		var pn netip.AddrPort
		if *peerN4 != "" {
			if pn, perr = netip.ParseAddrPort(*peerN4); perr != nil {
				die("-peer-n4: " + perr.Error())
			}
		}
		var ln netip.Addr
		if *localNF != "" {
			if ln, perr = netip.ParseAddr(*localNF); perr != nil {
				die("-local-nf: " + perr.Error())
			}
		}
		redirectPeer = *redirectPeerFlag
		if px, err = newProxy(lp, pn, ln); err != nil {
			die("proxy: " + err.Error())
		}
		relaxRPFilter("lo")
		defer px.close()
		if *installRules {
			if err := installRedirectRules(*dport, int(lp.Port())); err != nil {
				die("install rules: " + err.Error())
			}
			defer removeRedirectRules(*dport, int(lp.Port()))
		}
	} else {
		if *installRules {
			if err := installNfqRules(*queueNum, *dport, *mark); err != nil {
				die("install rules: " + err.Error())
			}
			defer removeNfqRules(*queueNum, *dport, *mark)
		}
		fd, ferr := nfqStart(*queueNum)
		if ferr != nil {
			die("nfqueue: " + ferr.Error())
		}
		defer nfqStop()
		go nfqRunLoop(fd)
	}

	fmt.Fprintf(os.Stderr,
		"ARMB-STATE component=n4dtls role=%s mode=%s self=%s peer_id=%s identity=%s attested_pid=%d "+
			"nfqueue=%d dport=%d tun=%s mtu=%d mark=%#x auth=x509-svid+mutual cipher=%s "+
			"handshakes=%d rotation=live fail=drop payload=untouched\n",
		*role, *mode, id.spiffe, *peerID, id.mode, *workloadPID, *queueNum, *dport, *tunName, *mtu, *mark,
		fmt.Sprintf("%#x(negotiated=offered)", uint16(id.cfg.CipherSuites[0])), nHandshake.Load())

	// 5. Keep the session alive for the life of the sidecar. Envoy re-establishes its
	// connections when SDS hands it a new certificate and when a connection drops; the same
	// two events are handled here by one supervisor. Without it a rotation would leave the
	// session running on a credential SPIRE has already replaced, and a dropped tunnel would
	// leave the capture rule in place with nowhere to send PFCP -- which silently kills the
	// N4 association.
	h := &connHolder{}
	h.set(conn)
	go superviseSession(ctx, h, id, *role, *peer, *listen)

	// 6/7. Sender and receiver, per datapath.
	if socketMode {
		go proxySender(ctx, h, px)
		go proxyReceiver(ctx, h, px)
	} else {
		go senderLoop(h)
		go receiverLoop(ctx, h, tun)
	}

	// periodic counters (I5 raw counts; I8 params already logged above)
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "n4dtls: shutting down (captured=%d sent=%d recv=%d injected=%d drop=%d)\n",
				nCaptured.Load(), nSent.Load(), nRecv.Load(), nInjected.Load(), nDropVerdict.Load())
			return
		case <-tick.C:
			fmt.Fprintf(os.Stderr, "n4dtls: captured=%d sent=%d recv=%d injected=%d drop_verdict=%d handshakes=%d\n",
				nCaptured.Load(), nSent.Load(), nRecv.Load(), nInjected.Load(), nDropVerdict.Load(), nHandshake.Load())
		}
	}
}

// senderLoop pulls each captured egress PFCP packet (a full L3 IP packet from the shared
// NFQUEUE) and writes it verbatim as one DTLS record, then DROPs the original so the
// plaintext never leaves the host. One packet = one record; DTLS preserves the boundary.
func senderLoop(h *connHolder) {
	// The write deadline is a hang guard, not a per-message SLA, so it is refreshed on a
	// coarse schedule instead of per packet: pion's SetWriteDeadline takes a mutex and
	// stops/resets a runtime timer on every call, which is real per-packet cost for a
	// bound that only has to be "roughly half a second". Refreshing when less than half
	// the budget remains keeps every write bounded by writeBudget at worst.
	const writeBudget = 500 * time.Millisecond
	var deadlineAt time.Time
	var lastConn *dtls.Conn
	for pk := range nfqCh {
		nCaptured.Add(1)
		conn := h.get() // may be a replacement after a rotation or a reconnect
		if conn == nil {
			nfqSetVerdict(pk.id, false)
			nDropVerdict.Add(1)
			releasePkt(pk)
			continue
		}
		if conn != lastConn { // fresh connection: its deadline has not been set yet
			lastConn, deadlineAt = conn, time.Time{}
		}
		if now := time.Now(); now.Add(writeBudget / 2).After(deadlineAt) {
			deadlineAt = now.Add(writeBudget)
			_ = conn.SetWriteDeadline(deadlineAt)
		}
		_, err := conn.Write(pk.data)
		releasePkt(pk) // payload is copied into the DTLS record; recycle the buffer
		if err != nil {
			// fail-closed: if the tunnel cannot carry it, DROP (never emit plaintext).
			nfqSetVerdict(pk.id, false)
			nDropVerdict.Add(1)
			logf("dtls write failed, dropped original: %v", err)
			h.fail(conn) // ask the supervisor for a new session
			continue
		}
		nSent.Add(1)
		nfqSetVerdict(pk.id, false) // NF_DROP — the DTLS record carries it now
		nDropVerdict.Add(1)
	}
}

// receiverLoop reads DTLS records (each a whole IP packet from the peer NF) and reinjects
// them on the local input path. The restored packet keeps the peer NF's real source, so
// the local NF sees N4 exactly as if it arrived over the wire.
func receiverLoop(ctx context.Context, h *connHolder, tun *tunDev) {
	buf := make([]byte, 65535)
	lastRecv := time.Now()
	sentAtLastRecv := nSent.Load()
	for {
		if ctx.Err() != nil {
			return
		}
		conn := h.get()
		if conn == nil {
			time.Sleep(100 * time.Millisecond)
			lastRecv, sentAtLastRecv = time.Now(), nSent.Load()
			continue
		}
		// Same liveness rule as the socket datapath: a dead UDP peer produces neither a
		// write error nor a read error, so a one-way session has to be inferred.
		_ = conn.SetReadDeadline(time.Now().Add(livenessPoll))
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if isTimeout(err) {
				if nSent.Load() > sentAtLastRecv && time.Since(lastRecv) > deadAfter {
					logf("no reply for %s while %d packet(s) were sent -- re-establishing",
						time.Since(lastRecv).Round(time.Second), nSent.Load()-sentAtLastRecv)
					h.fail(conn)
					lastRecv, sentAtLastRecv = time.Now(), nSent.Load()
				}
				continue
			}
			logf("dtls read failed: %v", err)
			h.fail(conn) // the supervisor rebuilds; do not abandon the receive path
			continue
		}
		lastRecv, sentAtLastRecv = time.Now(), nSent.Load()
		if n == 0 {
			continue
		}
		nRecv.Add(1)
		if _, err := tun.inject(buf[:n]); err != nil {
			logf("tun inject failed: %v", err)
			continue
		}
		nInjected.Add(1)
	}
}

// connect establishes the one DTLS session. The client retries the dial (the peer's
// listener may not be up yet); the server accepts a single peer.
var serverListener net.Listener

func connect(ctx context.Context, id *identity, role, peer, listen string) (*dtls.Conn, error) {
	if role == "server" {
		// The listener is created once and kept: re-establishing a session must not try to
		// rebind the port (it would fail EADDRINUSE), and the peer reconnects to the same
		// endpoint. Accept simply yields the next session.
		if serverListener == nil {
			laddr, err := net.ResolveUDPAddr("udp", listen)
			if err != nil {
				return nil, err
			}
			l, err := dtls.Listen("udp", laddr, id.cfg)
			if err != nil {
				return nil, err
			}
			serverListener = l
			logf("listening for peer DTLS on %s", listen)
		}
		c, err := serverListener.Accept()
		if err != nil {
			return nil, err
		}
		return c.(*dtls.Conn), nil
	}
	raddr, err := net.ResolveUDPAddr("udp", peer)
	if err != nil {
		return nil, err
	}
	for {
		c, err := dtls.Dial("udp", raddr, id.cfg)
		if err == nil {
			logf("DTLS session up to %s", peer)
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
			logf("dial %s failed (%v), retrying", peer, err)
		}
	}
}


// installNfqRules mirrors arm A's interception exactly (§D1): capture egress PFCP into the
// same queue. The accept-mark rule in front is the loop guard for injection primitive C and
// is harmless for the TUN path (injected packets never traverse OUTPUT). All in mangle.
func installNfqRules(queueNum, dport, mark int) error {
	// Capture PFCP in BOTH directions: a request has dst port 8805, but a core that sends
	// from an ephemeral source port (OAI's SMF does) gets responses addressed to that
	// ephemeral port -- those carry SRC port 8805, not dst. Matching only --dport would
	// tunnel requests while leaking responses in plaintext (verified on live OAI). Match
	// either.
	rules := [][]string{
		{"-t", "mangle", "-I", "OUTPUT", "1", "-m", "mark", "--mark", fmt.Sprintf("%d", mark), "-j", "ACCEPT"},
		{"-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", fmt.Sprintf("%d", dport), "-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", queueNum), "--queue-bypass"},
		{"-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--sport", fmt.Sprintf("%d", dport), "-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", queueNum), "--queue-bypass"},
	}
	for _, r := range rules {
		if out, err := exec.Command("iptables", r...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %v: %v (%s)", r, err, out)
		}
		fmt.Fprintf(os.Stderr, "n4dtls: installed iptables %v\n", r)
	}
	return nil
}

func removeNfqRules(queueNum, dport, mark int) {
	rules := [][]string{
		{"-t", "mangle", "-D", "OUTPUT", "-m", "mark", "--mark", fmt.Sprintf("%d", mark), "-j", "ACCEPT"},
		{"-t", "mangle", "-D", "OUTPUT", "-p", "udp", "--dport", fmt.Sprintf("%d", dport), "-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", queueNum), "--queue-bypass"},
		{"-t", "mangle", "-D", "OUTPUT", "-p", "udp", "--sport", fmt.Sprintf("%d", dport), "-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", queueNum), "--queue-bypass"},
	}
	for _, r := range rules {
		exec.Command("iptables", r...).Run()
	}
}

// logf is the one place sidecar diagnostics are written, so every component reports the
// same way regardless of which goroutine it runs on.
func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "n4dtls: "+format+"\n", a...)
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "n4dtls: FATAL "+msg)
	os.Exit(1)
}
