package dnswatch

import (
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type flowRecorder struct {
	mu    sync.Mutex
	flows []Flow
}

func (r *flowRecorder) add(f Flow) {
	r.mu.Lock()
	r.flows = append(r.flows, f)
	r.mu.Unlock()
}

func (r *flowRecorder) all() []Flow {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Flow(nil), r.flows...)
}

// newTestWatcher returns a watcher whose local addresses and clock are fixed.
func newTestWatcher(locals ...string) (*Watcher, *flowRecorder, *time.Time) {
	rec := &flowRecorder{}
	clock := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	w := NewWatcher(func(Answer) {}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.SetFlowHandler(rec.add)
	w.now = func() time.Time { return clock }
	w.localAddrs = func() addrSet {
		set := addrSet{}
		for _, l := range locals {
			set[netip.MustParseAddr(l)] = struct{}{}
		}
		return set
	}
	w.refreshLocals()
	return w, rec, &clock
}

func TestWatcherKeepsOnlyOutboundFlows(t *testing.T) {
	w, rec, _ := newTestWatcher("10.0.0.2")

	out := ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagSYN, nil))
	in := ipv4Between("203.0.113.9", "10.0.0.2", 6, 0, 0, tcpSegment(22, flagSYN, nil))
	w.handleFrame(out, dltRaw, "en0")
	w.handleFrame(in, dltRaw, "en0")

	flows := rec.all()
	if len(flows) != 1 || flows[0].Dst != netip.MustParseAddr("93.184.216.34") || flows[0].Interface != "en0" || flows[0].Proto != ProtoTCP {
		t.Fatalf("flows = %+v, want only the outbound SYN on en0", flows)
	}
	if flows[0].Time.IsZero() {
		t.Error("a flow carries its capture time")
	}
}

func TestWatcherPicksUpNewLocalAddressesOnRescan(t *testing.T) {
	w, rec, _ := newTestWatcher("10.0.0.2")
	syn := ipv4Between("10.9.8.7", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagSYN, nil))

	w.handleFrame(syn, dltRaw, "utun4")
	if len(rec.all()) != 0 {
		t.Fatal("an address this Mac does not hold is not outbound")
	}
	w.localAddrs = func() addrSet { return addrSet{netip.MustParseAddr("10.9.8.7"): {}} }
	w.refreshLocals()
	w.handleFrame(syn, dltRaw, "utun4")
	if len(rec.all()) != 1 {
		t.Fatal("a tunnel address added on rescan must count as local")
	}
}

func TestWatcherDedupesUDPPerInterfaceDestinationAndPort(t *testing.T) {
	w, rec, clock := newTestWatcher("10.0.0.2")
	quic := func(dst string, port uint16) []byte {
		return ipv4Between("10.0.0.2", dst, 17, 0, 0, udpTo(port, quicInitial))
	}

	w.handleFrame(quic("93.184.216.34", 443), dltRaw, "en0")
	w.handleFrame(quic("93.184.216.34", 443), dltRaw, "en0") // same key: dropped
	w.handleFrame(quic("93.184.216.34", 443), dltRaw, "utun4")
	w.handleFrame(quic("93.184.216.35", 443), dltRaw, "en0")
	w.handleFrame(quic("93.184.216.34", 8443), dltRaw, "en0") // not QUIC's port: ignored
	if got := len(rec.all()); got != 3 {
		t.Fatalf("flows = %d, want 3 (interface and address each make a new key; only port 443 counts)", got)
	}

	*clock = clock.Add(59 * time.Second)
	w.handleFrame(quic("93.184.216.34", 443), dltRaw, "en0")
	if got := len(rec.all()); got != 3 {
		t.Fatalf("flows = %d, want the same key still suppressed at 59s", got)
	}
	*clock = clock.Add(2 * time.Second)
	w.handleFrame(quic("93.184.216.34", 443), dltRaw, "en0")
	if got := len(rec.all()); got != 4 {
		t.Fatalf("flows = %d, want the key reported again after 60s", got)
	}
}

func TestWatcherDoesNotDedupeTCP(t *testing.T) {
	w, rec, _ := newTestWatcher("10.0.0.2")
	syn := ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagSYN, nil))
	w.handleFrame(syn, dltRaw, "en0")
	w.handleFrame(syn, dltRaw, "en0")
	if got := len(rec.all()); got != 2 {
		t.Fatalf("flows = %d, want every SYN reported", got)
	}
}

func TestWatcherStopsReportingFlowsWhenDisabled(t *testing.T) {
	w, rec, _ := newTestWatcher("10.0.0.2")
	syn := ipv4Between("10.0.0.2", "93.184.216.34", 6, 0, 0, tcpSegment(443, flagSYN, nil))

	w.SetFlowsEnabled(false)
	w.handleFrame(syn, dltRaw, "en0")
	if len(rec.all()) != 0 {
		t.Fatal("a disabled watcher reports no flows")
	}
	w.SetFlowsEnabled(true)
	w.handleFrame(syn, dltRaw, "en0")
	if len(rec.all()) != 1 {
		t.Fatal("re-enabling resumes reporting")
	}
}

func TestWatcherStillReportsAnswersWhenFlowsAreOff(t *testing.T) {
	var got []Answer
	w := NewWatcher(func(a Answer) { got = append(got, a) }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.refreshLocals()
	frame := ipv4Between("1.1.1.1", "10.0.0.2", 17, 0, 0, udpDatagram(53, dnsReply(t, "a.example.com", 0, "93.184.216.34")))
	w.handleFrame(frame, dltRaw, "en0")
	if len(got) != 1 || got[0].Interface != "en0" {
		t.Fatalf("answers = %+v, want one on en0", got)
	}
}

func TestUDPDeduperStaysBounded(t *testing.T) {
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	d := newUDPDeduper(func() time.Time { return now }, time.Minute)
	for i := range maxUDPDedupEntries * 2 {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		d.first(Flow{Interface: "en0", Dst: addr, DstPort: 443})
	}
	if len(d.seen) > maxUDPDedupEntries {
		t.Fatalf("table has %d entries, want at most %d", len(d.seen), maxUDPDedupEntries)
	}
}
