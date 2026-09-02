//go:build linux && cgo

package main

import (
	"testing"
	"time"

	"github.com/pion/transport/v4/deadline"
)

// The captured-packet path does one copy out of C memory (unavoidable: the C buffer dies
// when the callback returns) and used to do one heap allocation per packet as well
// (C.GoBytes). These benchmarks measure exactly that difference. The destination must
// ESCAPE -- in the real path it is handed to a channel -- or escape analysis stack-allocates
// it and the comparison measures nothing.
const benchPktLen = 200 // PFCP heartbeat/session messages are small

var sink []byte // forces the destination to escape, as the channel does in the real path

func BenchmarkPacketBufAlloc(b *testing.B) { // old behaviour: allocate per packet
	src := make([]byte, benchPktLen)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dst := make([]byte, benchPktLen)
		copy(dst, src)
		sink = dst
	}
}

func BenchmarkPacketBufPooled(b *testing.B) { // new behaviour: take from the pool
	src := make([]byte, benchPktLen)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p, dst := getPktBuf(benchPktLen)
		copy(dst, src)
		sink = dst
		releasePkt(nfqPacket{data: dst, buf: p})
	}
}

// The write deadline is a hang guard. pion's SetWriteDeadline takes a mutex and stops/resets
// a runtime timer on every call, so doing it per packet is real cost for a bound that only
// has to be roughly right. These measure per-packet Set vs the coarse refresh now in
// senderLoop (refresh only once less than half the budget remains).
const benchBudget = 500 * time.Millisecond

func BenchmarkDeadlinePerPacket(b *testing.B) { // old behaviour
	d := deadline.New()
	defer d.Set(time.Time{})
	for i := 0; i < b.N; i++ {
		d.Set(time.Now().Add(benchBudget))
	}
}

func BenchmarkDeadlineCoarse(b *testing.B) { // new behaviour
	d := deadline.New()
	defer d.Set(time.Time{})
	var deadlineAt time.Time
	for i := 0; i < b.N; i++ {
		if now := time.Now(); now.Add(benchBudget / 2).After(deadlineAt) {
			deadlineAt = now.Add(benchBudget)
			d.Set(deadlineAt)
		}
	}
}
