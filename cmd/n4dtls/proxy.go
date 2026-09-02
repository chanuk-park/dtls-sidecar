// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

//go:build linux

package main

// Socket-mode datapath: the sidecar is a proxy.
//
//	SMF N4 ──▶ sidecar ══DTLS══▶ sidecar ──▶ UPF N4
//
// This is how Envoy is placed: traffic is redirected into the sidecar's socket by iptables,
// the sidecar forwards it, and the far side delivers it. It is not packet capture -- no
// NFQUEUE, no verdicts, no TUN device, no cgo -- so a datagram costs a read and a write
// instead of a round trip through netlink and back into the kernel.
//
// Interception. TPROXY preserves the original destination but is only valid in mangle
// PREROUTING, and PFCP from the NF is LOCALLY GENERATED, so it never passes there. The
// remaining transparent option for locally generated traffic is a nat OUTPUT REDIRECT, which
// is what Istio uses outbound -- but it rewrites the destination, and SO_ORIGINAL_DST does
// not work for UDP. So the destination is not recovered from the kernel; it is known:
//
//   * on the CP side the destination is the UP function's N4 address, which is configuration
//     (-peer-n4), and
//   * on the UP side the destination is whoever the CP last sent from, which this sidecar
//     knows because it delivered that datagram itself.
//
// TS 29.244 §5.8.1 makes the second one exact rather than a guess: "Only one PFCP association
// shall be setup between a given pair of CP and UP functions", so there is one flow to track.
//
// Delivery. The far side sends with IP_TRANSPARENT and the ORIGINAL source address, so the
// network function receives the datagram from its real peer. The PFCP payload is copied
// verbatim: F-SEID and Node ID never see a rewritten address, which is the failure mode a
// terminating proxy has on PFCP.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// frame is what crosses the DTLS session: the 4-tuple the datagram had before interception,
// then the payload untouched.
//
//	0      4        6      10       12
//	| srcIP | srcPort | dstIP | dstPort | payload... |
const frameHeaderLen = 12

// proxyMark tags datagrams this sidecar delivers, so the redirect rules skip them.
const proxyMark = 0x4e35

func encodeFrame(dst []byte, src, to netip.AddrPort, payload []byte) []byte {
	buf := dst[:0]
	s4, d4 := src.Addr().As4(), to.Addr().As4()
	buf = append(buf, s4[:]...)
	buf = binary.BigEndian.AppendUint16(buf, src.Port())
	buf = append(buf, d4[:]...)
	buf = binary.BigEndian.AppendUint16(buf, to.Port())
	return append(buf, payload...)
}

func decodeFrame(b []byte) (src, dst netip.AddrPort, payload []byte, err error) {
	if len(b) < frameHeaderLen {
		return src, dst, nil, fmt.Errorf("short frame: %d bytes", len(b))
	}
	src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[0:4])), binary.BigEndian.Uint16(b[4:6]))
	dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[6:10])), binary.BigEndian.Uint16(b[10:12]))
	return src, dst, b[frameHeaderLen:], nil
}

// proxy is one side of the pair.
type proxy struct {
	listen   netip.AddrPort // where REDIRECT lands datagrams
	peerN4   netip.AddrPort // the far network function's N4 address (empty on the UP side)
	localNF  netip.Addr     // this side's network function address, used as the delivery target
	conn     *net.UDPConn

	mu       sync.Mutex
	lastFrom netip.AddrPort // the far NF endpoint we last delivered from; replies go back to it
}

func newProxy(listen, peerN4 netip.AddrPort, localNF netip.Addr) (*proxy, error) {
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(listen))
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", listen, err)
	}
	return &proxy{listen: listen, peerN4: peerN4, localNF: localNF, conn: c}, nil
}

// capture reads one redirected datagram and reports the 4-tuple it originally had.
func (p *proxy) capture(buf []byte) (src, dst netip.AddrPort, payload []byte, err error) {
	n, from, err := p.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return src, dst, nil, err
	}
	src = from
	if p.peerN4.IsValid() {
		dst = p.peerN4 // CP side: the destination is the configured peer
	} else {
		p.mu.Lock()
		dst = p.lastFrom // UP side: reply to whoever we last delivered from
		p.mu.Unlock()
		if !dst.IsValid() {
			return src, dst, nil, fmt.Errorf("no peer endpoint known yet; dropping a reply with nowhere to go")
		}
	}
	return src, dst, buf[:n], nil
}

// deliver sends payload to the local network function as though it came from src. The socket
// is transparent so the spoofed source is allowed, and it is created per datagram: PFCP on N4
// is a handful of messages a second, and a fresh socket keeps the source exact without a
// table of bound ports to reconcile.
func (p *proxy) deliver(src, dst netip.AddrPort, payload []byte) error {
	p.mu.Lock()
	p.lastFrom = src
	p.mu.Unlock()

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)
	// IP_TRANSPARENT is what lets us bind a source address that is not ours -- the network
	// function must see its real peer, not this sidecar.
	if err := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return fmt.Errorf("IP_TRANSPARENT (needs CAP_NET_ADMIN): %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("SO_REUSEADDR: %w", err)
	}
	// Mark it so the redirect rules let it out instead of looping it back to us.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, proxyMark); err != nil {
		return fmt.Errorf("SO_MARK: %w", err)
	}
	sa4 := &unix.SockaddrInet4{Port: int(src.Port()), Addr: src.Addr().As4()}
	if err := unix.Bind(fd, sa4); err != nil {
		return fmt.Errorf("bind %s: %w", src, err)
	}
	to := &unix.SockaddrInet4{Port: int(dst.Port()), Addr: dst.Addr().As4()}
	if err := unix.Sendto(fd, payload, 0, to); err != nil {
		return fmt.Errorf("sendto %s: %w", dst, err)
	}
	return nil
}

func (p *proxy) close() {
	if p != nil && p.conn != nil {
		p.conn.Close()
	}
}

var _ = syscall.AF_INET // keep syscall referenced for build parity across toolchains

// --- iptables: the Envoy-style outbound redirect --------------------------------------------

// installRedirectRules sends the network function's PFCP into this sidecar's socket. This is
// the outbound half of what istio-iptables does, with two differences: it is UDP, and it
// matches the reply direction too.
//
//	--dport 8805  the CP function's requests
//	--sport 8805  the UP function's replies, which are addressed to the CP's ephemeral port
//
// The sidecar's own traffic is exempted by owner match, or it would redirect its own delivery
// back into itself.
func installRedirectRules(dport, toPort int) error {
	for _, r := range redirectRuleSet("-A", dport, toPort) {
		if out, err := exec.Command("iptables", r...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %v: %v (%s)", r, err, out)
		}
		logf("installed iptables %v", r)
	}
	return nil
}

func removeRedirectRules(dport, toPort int) {
	for _, r := range redirectRuleSet("-D", dport, toPort) {
		exec.Command("iptables", r...).Run()
	}
}

func redirectRuleSet(op string, dport, toPort int) [][]string {
	p, t := fmt.Sprintf("%d", dport), fmt.Sprintf("%d", toPort)
	// Exempt our own delivery by FWMARK, not by uid: the network function usually runs as
	// root too, so a uid-owner exemption exempts the very traffic we are here to intercept
	// (observed: every datagram bypassed the proxy and went straight out).
	mk := fmt.Sprintf("%#x", proxyMark)
	return [][]string{
		// NOTRACK on what we deliver. nat rules only run for the FIRST packet of a
		// connection, so if our delivered datagram creates conntrack state, the network
		// function's REPLY counts as that flow's reply direction and skips nat OUTPUT
		// entirely -- it leaves in plaintext by the direct route (observed: the reply never
		// reached the proxy). Untracked delivery keeps each direction independent.
		{"-t", "raw", op, "OUTPUT", "-p", "udp", "-m", "mark", "--mark", mk, "-j", "NOTRACK"},
		{"-t", "nat", op, "OUTPUT", "-p", "udp", "-m", "mark", "--mark", mk, "-j", "RETURN"},
		{"-t", "nat", op, "OUTPUT", "-p", "udp", "--dport", p, "-j", "REDIRECT", "--to-ports", t},
		{"-t", "nat", op, "OUTPUT", "-p", "udp", "--sport", p, "-j", "REDIRECT", "--to-ports", t},
	}
}

// --- datapath loops -------------------------------------------------------------------------

// proxySender: read a redirected datagram, put its 4-tuple and payload on the DTLS session.
func proxySender(ctx context.Context, h *connHolder, px *proxy) {
	buf := make([]byte, 65535)
	frame := make([]byte, 0, 65535+frameHeaderLen)
	for ctx.Err() == nil {
		src, dst, payload, err := px.capture(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logf("proxy capture: %v", err)
			continue
		}
		nCaptured.Add(1)
		conn := h.get()
		if conn == nil {
			nDropVerdict.Add(1) // fail closed: never fall back to plaintext
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write(encodeFrame(frame, src, dst, payload)); err != nil {
			logf("dtls write failed, dropped datagram: %v", err)
			nDropVerdict.Add(1)
			h.fail(conn)
			continue
		}
		nSent.Add(1)
	}
}

// proxyReceiver: take a frame off the DTLS session and deliver it to the local network
// function with the original source address.
func proxyReceiver(ctx context.Context, h *connHolder, px *proxy) {
	buf := make([]byte, 65535)
	for ctx.Err() == nil {
		conn := h.get()
		if conn == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logf("dtls read failed: %v", err)
			h.fail(conn)
			continue
		}
		src, dst, payload, derr := decodeFrame(buf[:n])
		if derr != nil {
			logf("proxy decode: %v", derr)
			continue
		}
		nRecv.Add(1)
		if err := px.deliver(src, dst, payload); err != nil {
			logf("proxy deliver %s -> %s: %v", src, dst, err)
			continue
		}
		nInjected.Add(1)
	}
}
