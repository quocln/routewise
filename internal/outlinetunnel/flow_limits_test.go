package outlinetunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// tickClock is a clock that moves forward one second on every read, so flow
// recency is strictly ordered without sleeping.
func tickClock() func() time.Time {
	var n atomic.Int64
	base := time.Unix(1_800_000_000, 0)
	return func() time.Time { return base.Add(time.Duration(n.Add(1)) * time.Second) }
}

func udpRoundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 64)); err != nil {
		t.Fatalf("reply to %q: %v", msg, err)
	}
}

func TestUDPFlowCapClosesTheLeastRecentlyUsedFlow(t *testing.T) {
	h := startHarness(t, func(o *Options) {
		o.MaxUDPFlows = 3
		o.UDPIdleTimeout = time.Minute
		o.Now = tickClock()
	})
	open := func(dst string) net.Conn {
		c, err := h.host.dialUDP(netip.MustParseAddrPort(dst))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	c1 := open("198.51.100.51:5300")
	udpRoundTrip(t, c1, "a")
	c2 := open("198.51.100.52:5300")
	udpRoundTrip(t, c2, "b")
	c3 := open("198.51.100.53:5300")
	udpRoundTrip(t, c3, "c")
	waitFor(t, "three flows", func() bool { return h.tn.Stats().UDPFlows == 3 })

	// Flow 1 is used again, so flow 2 is now the least recently used.
	udpRoundTrip(t, c1, "a2")

	c4 := open("198.51.100.54:5300")
	udpRoundTrip(t, c4, "d")

	waitFor(t, "the LRU flow to be evicted", func() bool {
		h.dialer.mu.Lock()
		defer h.dialer.mu.Unlock()
		return len(h.dialer.pcs) == 4 && h.dialer.pcs[1].isClosed()
	})
	h.dialer.mu.Lock()
	for i, pc := range h.dialer.pcs {
		if i != 1 && pc.isClosed() {
			t.Errorf("flow %d was closed; only the least recently used (flow 1) should be", i)
		}
	}
	h.dialer.mu.Unlock()
	if got := h.tn.udp.size(); got != 3 {
		t.Errorf("flow table holds %d flows, want the cap of 3", got)
	}
	if got := h.tn.Stats().UDPEvictions; got != 1 {
		t.Errorf("evictions = %d, want 1", got)
	}
	waitFor(t, "live flow count to settle at the cap", func() bool { return h.tn.Stats().UDPFlows == 3 })
}

func TestUDPFlowTableNeverExceedsItsCapUnderABurst(t *testing.T) {
	table := newUDPFlowTable(8)
	var closed atomic.Int64
	base := time.Unix(1_800_000_000, 0)
	for i := 0; i < 100; i++ {
		f := newUDPFlow(base.Add(time.Duration(i) * time.Second))
		f.add(closerFunc(func() error { closed.Add(1); return nil }))
		table.admit(f)
		if table.size() > 8 {
			t.Fatalf("table grew to %d with a cap of 8", table.size())
		}
	}
	if closed.Load() != 92 {
		t.Errorf("closed %d flows, want 92 evictions", closed.Load())
	}
	// A flow evicted before its sockets exist still closes them when they arrive.
	late := newUDPFlow(base)
	late.close()
	var lateClosed atomic.Bool
	if late.add(closerFunc(func() error { lateClosed.Store(true); return nil })) || !lateClosed.Load() {
		t.Error("a socket added to an evicted flow must be closed at once")
	}
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func TestADNSFlowClosesAfterItsFirstReply(t *testing.T) {
	h := startHarness(t, func(o *Options) { o.UDPIdleTimeout = time.Minute })
	c, err := h.host.dialUDP(netip.MustParseAddrPort("198.51.100.60:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	udpRoundTrip(t, c, "query")
	waitFor(t, "the DNS flow to close after its reply", func() bool {
		h.dialer.mu.Lock()
		defer h.dialer.mu.Unlock()
		return h.tn.Stats().UDPFlows == 0 && h.tn.udp.size() == 0 && len(h.dialer.pcs) == 1 && h.dialer.pcs[0].isClosed()
	})
}

func TestUDPBuffersAreSmallAndPooled(t *testing.T) {
	if udpBufSize > 16<<10 {
		t.Errorf("udpBufSize = %d, want at most 16 KiB", udpBufSize)
	}
	b := getUDPBuf()
	if len(*b) != udpBufSize {
		t.Errorf("pooled buffer is %d bytes", len(*b))
	}
	putUDPBuf(b)
}

func TestAPanicInAFlowGoroutineDoesNotCrashTheTunnel(t *testing.T) {
	h := startHarness(t, nil)
	before := h.tn.live.Load()
	if !h.tn.spawn(func() { panic("hostile packet SECRETISH") }) {
		t.Fatal("spawn refused")
	}
	waitFor(t, "the goroutine to end", func() bool { return h.tn.live.Load() == before })
	got := h.tn.Stats().LastDialError
	if !strings.Contains(got, "internal error") || strings.Contains(got, "SECRETISH") {
		t.Errorf("recorded error = %q; want a generic internal error that does not echo the panic", got)
	}
	// The tunnel still forwards.
	c, err := h.host.dialUDP(netip.MustParseAddrPort("198.51.100.61:5300"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	udpRoundTrip(t, c, "still alive")
}

func TestRecordedErrorsAreRateLimitedInTheLog(t *testing.T) {
	var logs lockedBuffer
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	h := startHarness(t, func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(&logs, nil))
		o.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	for i := 0; i < 100; i++ {
		h.tn.recordError(errors.New("write utun: no buffer space"))
	}
	if n := strings.Count(logs.String(), "outline tunnel error"); n != 1 {
		t.Fatalf("%d warnings for a burst of 100 errors, want 1", n)
	}
	mu.Lock()
	now = now.Add(errLogInterval + time.Second)
	mu.Unlock()
	h.tn.recordError(errors.New("write utun: no buffer space"))
	out := logs.String()
	if n := strings.Count(out, "outline tunnel error"); n != 2 || !strings.Contains(out, "suppressed_since_last=99") {
		t.Fatalf("after the interval: %d warnings, want 2 with the held-back count 99:\n%s", n, out)
	}
	if got := h.tn.Stats().LastDialError; got != "write utun: no buffer space" {
		t.Errorf("the last error must still be recorded every time, got %q", got)
	}
}

func TestDialFailureLogsNoDestinationAtWarn(t *testing.T) {
	var logs lockedBuffer
	h := startHarness(t, func(o *Options) { o.Logger = slog.New(slog.NewTextHandler(&logs, nil)) })
	h.dialer.mu.Lock()
	h.dialer.dialErr = errors.New("server unreachable")
	h.dialer.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c, err := h.host.dialTCP(ctx, netip.MustParseAddrPort("198.51.100.62:443")); err == nil {
		c.Close()
	}
	waitFor(t, "the warning", func() bool { return strings.Contains(logs.String(), "outline tunnel error") })
	if strings.Contains(logs.String(), "198.51.100.62") || strings.Contains(h.tn.Stats().LastDialError, "198.51.100.62") {
		t.Errorf("the destination leaked into the warning or the recorded error:\n%s", logs.String())
	}
}

func TestTheUtunEventQueueIsDrained(t *testing.T) {
	h := startHarness(t, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			select {
			case h.dev.events <- tun.EventUp:
			case <-time.After(5 * time.Second):
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the device's event channel is not being read")
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// --- Probe ---

// dnsServer is a TCP DNS server for probe tests. mode picks its behaviour.
type dnsServer struct {
	addr  string
	mu    sync.Mutex
	query []byte
}

func startDNSServer(t *testing.T, mode string) *dnsServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &dnsServer{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				s.mu.Lock()
				s.query = q
				s.mu.Unlock()
				reply := append([]byte(nil), q...)
				reply[2] |= 0x80 // QR
				switch mode {
				case "hang":
					time.Sleep(5 * time.Second)
					return
				case "wrongid":
					reply[0] ^= 0xff
				case "notresponse":
					reply[2] &^= 0x80
				case "short":
					reply = reply[:5]
				case "servfail":
					reply[3] |= 2
				}
				_ = binary.Write(c, binary.BigEndian, uint16(len(reply)))
				_, _ = c.Write(reply)
			}()
		}
	}()
	return s
}

func probeHarness(t *testing.T, mode string) (*harness, *dnsServer, netip.AddrPort) {
	t.Helper()
	srv := startDNSServer(t, mode)
	h := startHarness(t, nil)
	h.dialer.tcpTarget = srv.addr
	return h, srv, netip.MustParseAddrPort("1.0.0.1:53")
}

func TestProbeSucceedsOnADNSReplyAndSendsARootNSQuery(t *testing.T) {
	for _, mode := range []string{"ok", "servfail"} {
		h, srv, dns := probeHarness(t, mode)
		if err := h.tn.Probe(context.Background(), dns); err != nil {
			t.Fatalf("%s: probe failed: %v", mode, err)
		}
		if got := h.dialer.dialed(); len(got) != 1 || got[0] != "1.0.0.1:53" {
			t.Errorf("%s: dialed %v, want the DNS server on port 53 through the dialer", mode, got)
		}
		srv.mu.Lock()
		q := srv.query
		srv.mu.Unlock()
		// ID(2) flags(2) qd=1 an/ns/ar=0, then the root name, type NS, class IN.
		if len(q) != 17 || binary.BigEndian.Uint16(q[4:]) != 1 || q[12] != 0 ||
			binary.BigEndian.Uint16(q[13:]) != 2 || binary.BigEndian.Uint16(q[15:]) != 1 {
			t.Errorf("%s: query is not a root NS query: % x", mode, q)
		}
	}
}

func TestProbeFailsWhenTheReplyIsWrongOrMissing(t *testing.T) {
	for _, mode := range []string{"wrongid", "notresponse", "short"} {
		h, _, dns := probeHarness(t, mode)
		if err := h.tn.Probe(context.Background(), dns); err == nil {
			t.Errorf("%s: probe passed on a bad reply", mode)
		}
	}
	h, _, dns := probeHarness(t, "hang")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := h.tn.Probe(ctx, dns); err == nil {
		t.Error("probe passed with no reply")
	}
	if time.Since(start) > 3*time.Second {
		t.Error("probe did not stop at its context deadline")
	}
}

func TestProbeFailsWhenTheServerCannotBeReachedAndNeverLeaksTheKey(t *testing.T) {
	h, _, dns := probeHarness(t, "ok")
	h.dialer.mu.Lock()
	h.dialer.dialErr = errors.New("connection refused")
	h.dialer.mu.Unlock()
	err := h.tn.Probe(context.Background(), dns)
	if err == nil {
		t.Fatal("probe passed with a dead server")
	}
	if strings.Contains(err.Error(), testKey.Password) {
		t.Errorf("probe error leaks the password: %v", err)
	}
}

func TestProbeStopsWhenTheTunnelStops(t *testing.T) {
	h, _, dns := probeHarness(t, "hang")
	errc := make(chan error, 1)
	go func() { errc <- h.tn.Probe(context.Background(), dns) }()
	time.Sleep(200 * time.Millisecond)
	_ = h.tn.Stop()
	select {
	case err := <-errc:
		if err == nil {
			t.Error("probe passed on a stopped tunnel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("probe kept running after Stop")
	}
}
