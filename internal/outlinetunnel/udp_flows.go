package outlinetunnel

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// MaxUDPFlows bounds the UDP flows one tunnel keeps open. Every flow holds
	// a socket and two goroutines, and any local process can start flows by
	// sending datagrams to a routed address, so an unbounded table would let it
	// exhaust the root helper's file descriptors.
	MaxUDPFlows = 256
	// udpBufSize is the read buffer of one flow direction. A datagram routed
	// through the MTU-sized utun is small; 16 KiB is generous and a fraction of
	// a full 64 KiB packet.
	udpBufSize = 16 << 10
)

// udpBufPool recycles flow buffers so short-lived flows (one per DNS query) do
// not each allocate their own.
var udpBufPool = sync.Pool{New: func() any {
	b := make([]byte, udpBufSize)
	return &b
}}

func getUDPBuf() *[]byte  { return udpBufPool.Get().(*[]byte) }
func putUDPBuf(b *[]byte) { udpBufPool.Put(b) }

// udpFlow is one UDP flow's lifecycle handle. Its sockets register as they are
// opened; closing the flow closes every one registered and any added later, so
// an eviction that lands before the sockets exist still takes effect.
type udpFlow struct {
	last atomic.Int64 // unix nanoseconds of the last datagram in either direction

	mu      sync.Mutex
	closed  bool
	closers []io.Closer
}

func newUDPFlow(now time.Time) *udpFlow {
	f := &udpFlow{}
	f.touch(now)
	return f
}

func (f *udpFlow) touch(now time.Time) { f.last.Store(now.UnixNano()) }

// add registers c; if the flow is already closed it closes c and returns false.
func (f *udpFlow) add(c io.Closer) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		_ = c.Close()
		return false
	}
	f.closers = append(f.closers, c)
	return true
}

// close closes every socket of the flow. It is idempotent.
func (f *udpFlow) close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	cs := f.closers
	f.closers = nil
	f.mu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}

// udpFlowTable holds a tunnel's live UDP flows up to a cap.
type udpFlowTable struct {
	mu    sync.Mutex
	max   int
	flows map[*udpFlow]struct{}
	// evictions counts flows closed to make room.
	evictions atomic.Uint64
}

func newUDPFlowTable(max int) *udpFlowTable {
	return &udpFlowTable{max: max, flows: make(map[*udpFlow]struct{})}
}

// admit registers f. When the table is full it first closes the least recently
// used flow, so a burst of new flows displaces the idlest ones instead of
// growing without bound.
func (t *udpFlowTable) admit(f *udpFlow) {
	t.mu.Lock()
	var victim *udpFlow
	if len(t.flows) >= t.max {
		for c := range t.flows {
			if victim == nil || c.last.Load() < victim.last.Load() {
				victim = c
			}
		}
		delete(t.flows, victim)
	}
	t.flows[f] = struct{}{}
	t.mu.Unlock()
	if victim != nil {
		t.evictions.Add(1)
		victim.close()
	}
}

func (t *udpFlowTable) remove(f *udpFlow) {
	t.mu.Lock()
	delete(t.flows, f)
	t.mu.Unlock()
}

func (t *udpFlowTable) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

// closeAll closes every flow; used when the tunnel stops.
func (t *udpFlowTable) closeAll() {
	t.mu.Lock()
	all := make([]*udpFlow, 0, len(t.flows))
	for f := range t.flows {
		all = append(all, f)
	}
	t.flows = make(map[*udpFlow]struct{})
	t.mu.Unlock()
	for _, f := range all {
		f.close()
	}
}
