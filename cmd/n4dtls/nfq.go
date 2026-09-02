// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

//go:build linux && cgo

package main

// Minimal cgo binding to libnetfilter_queue with DEFERRED verdicts: the C callback
// hands each packet (id + IP payload) to Go and returns WITHOUT verdicting; the holdd
// engine sets the verdict later via SetVerdict(id, accept). One queue per process.

/*
#cgo pkg-config: libnetfilter_queue
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

extern int goNfqCB(int id, unsigned char *data, int len);

static int _cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
               struct nfq_data *nfa, void *cbdata) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    int id = ph ? ntohl(ph->packet_id) : 0;
    unsigned char *pkt = 0;
    int len = nfq_get_payload(nfa, &pkt);
    goNfqCB(id, pkt, len);   // hand to Go; DO NOT verdict here (deferred)
    return 0;
}

static struct nfq_handle  *g_h  = 0;
static struct nfq_q_handle *g_qh = 0;

static int nfq_start(int queue_num) {
    g_h = nfq_open();
    if (!g_h) return -1;
    nfq_unbind_pf(g_h, AF_INET);
    if (nfq_bind_pf(g_h, AF_INET) < 0) return -2;
    g_qh = nfq_create_queue(g_h, queue_num, &_cb, 0);
    if (!g_qh) return -3;
    if (nfq_set_mode(g_qh, NFQNL_COPY_PACKET, 0xffff) < 0) return -4;
    return nfq_fd(g_h);
}

static int nfq_loop(int fd) {
    char buf[65536] __attribute__((aligned));
    int rv;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(g_h, buf, rv);
    }
    return rv;
}

static int nfq_verdict(int id, int accept) {
    if (!g_qh) return -1;
    return nfq_set_verdict(g_qh, id, accept ? NF_ACCEPT : NF_DROP, 0, 0);
}

static void nfq_stop() {
    if (g_qh) nfq_destroy_queue(g_qh);
    if (g_h)  nfq_close(g_h);
}
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"
)

// nfqPacket is delivered from the C callback to the Go handler. buf is the pooled
// backing array (nil when the packet was too large to pool); release it with releasePkt
// once the payload has been consumed.
type nfqPacket struct {
	id   uint32
	data []byte // IP packet (L3; NFQUEUE on INPUT has no ethernet header)
	buf  *[]byte
}

var nfqCh chan nfqPacket

// nfqQueueDepth mirrors arm A's holdd MaxQueue.
var nfqQueueDepth = 2048

// Captured packets are copied out of C memory on every callback -- the C buffer is invalid
// once the callback returns, so the copy is unavoidable. The ALLOCATION is avoidable
// though, and C.GoBytes did one per packet. Pool the destination instead: PFCP on N4 never
// approaches this size (MTU is ~1400), so the pool covers every real packet and anything
// larger falls back to a plain allocation.
const pooledPacketSize = 2048

var pktPool = sync.Pool{New: func() any { b := make([]byte, pooledPacketSize); return &b }}

func getPktBuf(n int) (*[]byte, []byte) {
	if n > pooledPacketSize {
		return nil, make([]byte, n)
	}
	p := pktPool.Get().(*[]byte)
	return p, (*p)[:n]
}

// releasePkt returns a consumed packet's buffer to the pool. Safe to call on a packet whose
// payload was not pooled.
func releasePkt(pk nfqPacket) {
	if pk.buf != nil {
		pktPool.Put(pk.buf)
	}
}

//export goNfqCB
func goNfqCB(id C.int, data *C.uchar, length C.int) C.int {
	if length > 0 && data != nil {
		p, b := getPktBuf(int(length))
		copy(b, unsafe.Slice((*byte)(unsafe.Pointer(data)), int(length)))
		select {
		case nfqCh <- nfqPacket{id: uint32(id), data: b, buf: p}:
		default:
			// Go handler backpressured: DROP immediately (fail-closed) so we never
			// block the kernel recv loop.
			pktPool.Put(p)
			nfqSetVerdict(uint32(id), false)
		}
	} else {
		nfqSetVerdict(uint32(id), true)
	}
	return 0
}

func nfqStart(queueNum int) (int, error) {
	// Depth matches arm A's holdd MaxQueue (2048) so neither arm absorbs a burst the
	// other would have dropped -- the shallower 1024 used before handicapped this arm (D4).
	nfqCh = make(chan nfqPacket, nfqQueueDepth)
	fd := int(C.nfq_start(C.int(queueNum)))
	if fd < 0 {
		return 0, errors.New("nfq_start failed")
	}
	return fd, nil
}

func nfqRunLoop(fd int) { C.nfq_loop(C.int(fd)) }

// libnetfilter_queue's queue handle is NOT thread-safe: nfq_set_verdict() and the
// nfq_handle_packet() recv loop both touch it, and calling them concurrently segfaults
// inside libnfnetlink (observed on live OAI: SIGSEGV during cgo execution at this call
// while the C loop was reading). Every verdict therefore goes through one mutex, which
// the C callback's own drop path takes as well.
var verdictMu sync.Mutex

func nfqSetVerdict(id uint32, accept bool) {
	a := C.int(0)
	if accept {
		a = 1
	}
	verdictMu.Lock()
	C.nfq_verdict(C.int(id), a)
	verdictMu.Unlock()
}

func nfqStop() { C.nfq_stop() }
