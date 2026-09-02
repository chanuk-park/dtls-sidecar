// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ DKU

//go:build linux && cgo

package main

// Session supervision: keep exactly one live DTLS session, replace it when SPIRE rotates
// the SVID, and rebuild it when it breaks.
//
// This is the part of the Envoy/SPIRE model that a single startup handshake does not give
// you. Envoy is handed new certificates over SDS and brings connections onto them, and it
// re-establishes a connection that drops. Here the same two events -- rotation and loss --
// funnel into one supervisor, because both have the same answer: dial again with whatever
// SVID is current.
//
// The capture rule stays installed across a replacement. Captured PFCP waits in the
// NFQUEUE channel (depth 2048) for the moment a handshake takes, rather than being dropped:
// N4 heartbeats are seconds apart, so a sub-second gap costs nothing, whereas tearing the
// rule down and putting it back would expose the plaintext we are here to remove.

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	dtls "github.com/pion/dtls/v3"
)

// connHolder hands the current session to the sender and receiver, and lets either of them
// report the one they were using as broken without racing the supervisor.
type connHolder struct {
	mu   sync.RWMutex
	conn *dtls.Conn
	bad  chan *dtls.Conn // buffered(1): a connection reported as broken
}

func (h *connHolder) get() *dtls.Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.conn
}

func (h *connHolder) set(c *dtls.Conn) {
	h.mu.Lock()
	h.conn = c
	if h.bad == nil {
		h.bad = make(chan *dtls.Conn, 1)
	}
	h.mu.Unlock()
}

// fail reports c as unusable. Reporting a connection that has already been replaced is a
// no-op, so the sender and receiver can both call it for the same failure.
func (h *connHolder) fail(c *dtls.Conn) {
	h.mu.RLock()
	cur, ch := h.conn, h.bad
	h.mu.RUnlock()
	if c != cur || ch == nil {
		return
	}
	select {
	case ch <- c:
	default:
	}
}

// superviseSession replaces the session on rotation or failure until ctx ends.
func superviseSession(ctx context.Context, h *connHolder, id *identity, role, peer, listen string) {
	h.mu.RLock()
	bad := h.bad
	h.mu.RUnlock()

	for {
		var reason string
		select {
		case <-ctx.Done():
			return
		case <-id.src.rotations():
			reason = "SVID rotated"
		case c := <-bad:
			if c != h.get() {
				continue // already replaced by an earlier event
			}
			reason = "session lost"
		}

		old := h.get()
		logf("%s -- re-establishing the DTLS session (identity=%s)", reason, id.src.id())
		h.mu.Lock()
		h.conn = nil // sender fails closed for the moment this takes
		h.mu.Unlock()
		if old != nil {
			_ = old.Close()
		}

		conn, err := connect(ctx, id, role, peer, listen)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logf("re-establish failed: %v (retrying)", err)
			time.Sleep(2 * time.Second)
			// Put the failure back so the loop retries rather than waiting for a new event.
			select {
			case bad <- nil:
			default:
			}
			continue
		}
		atomic.AddInt64(&reHandshakes, 1)
		nHandshake.Add(1)
		h.set(conn)
		logf("DTLS session re-established (handshakes=%d, of which re-established=%d)",
			nHandshake.Load(), atomic.LoadInt64(&reHandshakes))
	}
}

var reHandshakes int64
