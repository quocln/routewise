package outlinetunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

var testKey = Key{Method: CipherChaCha20, Password: "pw", Host: "203.0.113.10", Port: 8388}

type harness struct {
	tn     *Tunnel
	dialer *fakeDialer
	host   *localHost
	dev    *pipeTun // tunnel side
	links  *recordLinks
}

// startHarness starts a Tunnel on an in-memory device and attaches a second
// stack as the local host. Packets flow host -> pipe -> tunnel stack ->
// forwarders -> fakeDialer.
func startHarness(t *testing.T, mutate func(*Options)) *harness {
	t.Helper()
	tunSide, hostSide := newPipeTunPair("utunTEST", "host")
	h := &harness{
		dialer: &fakeDialer{tcpTarget: startDestServer(t)},
		dev:    tunSide,
		links:  &recordLinks{},
	}
	opts := Options{
		Address:        netip.MustParseAddr("10.233.0.7"),
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Links:          h.links,
		Resolver:       fakeResolver{},
		NewDialer:      func(Key, netip.AddrPort) (Dialer, error) { return h.dialer, nil },
		CreateTUN:      func(int) (tun.Device, error) { return tunSide, nil },
		UDPIdleTimeout: 2 * time.Second,
	}
	if mutate != nil {
		mutate(&opts)
	}
	tn, err := Start(context.Background(), testKey, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = tn.Stop() })
	h.tn = tn
	h.host = newLocalHost(t, hostSide, netip.MustParseAddr("10.233.0.2"))
	return h
}

func TestTunnelSetup(t *testing.T) {
	h := startHarness(t, nil)
	if h.tn.Name() != "utunTEST" {
		t.Fatalf("Name = %q", h.tn.Name())
	}
	if h.tn.ServerAddr() != netip.MustParseAddrPort("203.0.113.10:8388") {
		t.Fatalf("ServerAddr = %v", h.tn.ServerAddr())
	}
	want := [][]string{
		{"addalias", "utunTEST", "10.233.0.7", "10.233.0.7"},
		{"up", "utunTEST"},
	}
	if len(h.links.calls) != len(want) {
		t.Fatalf("calls = %v", h.links.calls)
	}
	for i, c := range want {
		if strings.Join(h.links.calls[i], " ") != strings.Join(c, " ") {
			t.Fatalf("call %d = %v, want %v", i, h.links.calls[i], c)
		}
	}
	for _, c := range h.links.calls {
		if c[0] != "addalias" && c[0] != "up" {
			t.Fatalf("tunnel must not add routes: %v", c)
		}
	}
}

func TestTCPForwardedThroughDialer(t *testing.T) {
	h := startHarness(t, nil)
	dst := netip.MustParseAddrPort("198.51.100.20:8443")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := h.host.dialTCP(ctx, dst)
	if err != nil {
		t.Fatalf("dial through tunnel: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	// Half-close: the destination only answers after it sees EOF, and the
	// answer must still arrive on the read side.
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "got:hello" {
		t.Fatalf("got %q", got)
	}
	if d := h.dialer.dialed(); len(d) != 1 || d[0] != "198.51.100.20:8443" {
		t.Fatalf("dialed %v, want [198.51.100.20:8443]", d)
	}
	waitFor(t, "byte counters", func() bool {
		s := h.tn.Stats()
		return s.BytesOut == 5 && s.BytesIn == uint64(len("got:hello"))
	})
	waitFor(t, "tcp flows drained", func() bool { return h.tn.Stats().TCPFlows == 0 })
}

func TestTCPLargeTransfer(t *testing.T) {
	h := startHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := h.host.dialTCP(ctx, netip.MustParseAddrPort("198.51.100.21:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := []byte(strings.Repeat("0123456789abcdef", 64<<10)) // 1 MiB
	go func() {
		_, _ = c.Write(payload)
		_ = c.CloseWrite()
	}()
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(payload)+4 || string(got[4:]) != string(payload) {
		t.Fatalf("round trip mismatch: got %d bytes", len(got))
	}
}

func TestTCPDialFailureResetsAndRecordsError(t *testing.T) {
	h := startHarness(t, nil)
	h.dialer.mu.Lock()
	h.dialer.dialErr = errors.New("server unreachable")
	h.dialer.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c, err := h.host.dialTCP(ctx, netip.MustParseAddrPort("198.51.100.22:443")); err == nil {
		c.Close()
		t.Fatal("expected the connection to be refused")
	}
	waitFor(t, "dial error recorded", func() bool {
		s := h.tn.Stats()
		return strings.Contains(s.LastDialError, "server unreachable") && !s.LastDialErrorAt.IsZero()
	})
}

func TestUDPRoundTrip(t *testing.T) {
	h := startHarness(t, nil)
	dst := netip.MustParseAddrPort("198.51.100.30:5353")
	c, err := h.host.dialUDP(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, msg := range []string{"ping", "pong"} {
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read reply to %q: %v", msg, err)
		}
		if string(buf[:n]) != "echo:"+msg {
			t.Fatalf("reply = %q", buf[:n])
		}
	}
	h.dialer.mu.Lock()
	defer h.dialer.mu.Unlock()
	if len(h.dialer.pcs) != 1 {
		t.Fatalf("expected one flow for one (src,dst) pair, got %d", len(h.dialer.pcs))
	}
	if len(h.dialer.packets) != 2 || h.dialer.packets[0].to != "198.51.100.30:5353" {
		t.Fatalf("packets = %+v", h.dialer.packets)
	}
}

func TestUDPFlowsAreKeyedByDestination(t *testing.T) {
	h := startHarness(t, nil)
	for _, dst := range []string{"198.51.100.31:5300", "198.51.100.32:5300"} {
		c, err := h.host.dialUDP(netip.MustParseAddrPort(dst))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte("q"))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 16)); err != nil {
			t.Fatalf("%s: %v", dst, err)
		}
	}
	waitFor(t, "two flows", func() bool { return h.tn.Stats().UDPFlows == 2 })
}

func TestUDPFlowDroppedWhenIdle(t *testing.T) {
	h := startHarness(t, func(o *Options) { o.UDPIdleTimeout = 150 * time.Millisecond })
	c, err := h.host.dialUDP(netip.MustParseAddrPort("198.51.100.33:5300"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("q"))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle flow dropped", func() bool {
		h.dialer.mu.Lock()
		defer h.dialer.mu.Unlock()
		return h.tn.Stats().UDPFlows == 0 && len(h.dialer.pcs) == 1 && h.dialer.pcs[0].isClosed()
	})
}

func TestStopIsIdempotentConcurrentAndLeakFree(t *testing.T) {
	h := startHarness(t, nil)

	// Leave a live TCP and UDP flow behind so Stop has real work to do.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tc, err := h.host.dialTCP(ctx, netip.MustParseAddrPort("198.51.100.40:80"))
	if err != nil {
		t.Fatal(err)
	}
	uc, err := h.host.dialUDP(netip.MustParseAddrPort("198.51.100.41:5300"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = uc.Write([]byte("q"))
	_ = uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := uc.Read(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "flows live", func() bool { s := h.tn.Stats(); return s.TCPFlows == 1 && s.UDPFlows == 1 })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = h.tn.Stop() }()
	}
	wg.Wait()
	if err := h.tn.Stop(); err != nil {
		t.Fatalf("repeat Stop: %v", err)
	}
	if n := h.tn.live.Load(); n != 0 {
		t.Fatalf("%d tunnel goroutines still running after Stop", n)
	}
	if !h.dev.isClosed() {
		t.Fatal("tun device not closed")
	}
	if s := h.tn.Stats(); s.TCPFlows != 0 || s.UDPFlows != 0 {
		t.Fatalf("flows after Stop: %+v", s)
	}
	h.dialer.mu.Lock()
	for i, pc := range h.dialer.pcs {
		if !pc.isClosed() {
			t.Errorf("udp flow %d not closed", i)
		}
	}
	h.dialer.mu.Unlock()
	_ = tc.Close()
	_ = uc.Close()
}

// TestNoGoroutineLeakAfterStop starts and stops a whole tunnel plus host and
// checks the process goroutine count returns to its baseline.
func TestNoGoroutineLeakAfterStop(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	func() {
		tunSide, hostSide := newPipeTunPair("utunLEAK", "host")
		dialer := &fakeDialer{tcpTarget: startDestServer(t)}
		tn, err := Start(context.Background(), testKey, Options{
			Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			Links:     &recordLinks{},
			Resolver:  fakeResolver{},
			NewDialer: func(Key, netip.AddrPort) (Dialer, error) { return dialer, nil },
			CreateTUN: func(int) (tun.Device, error) { return tunSide, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		// Host side with explicit teardown (not t.Cleanup) so it is gone before the check.
		hostNS, herr := newNetStack(DefaultMTU, nil, nil)
		if herr != nil {
			t.Fatal(herr)
		}
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); pumpTunToStack(ctx, hostSide, hostNS.ep, func(error) {}) }()
		go func() { defer wg.Done(); pumpStackToTun(ctx, hostSide, hostNS.ep, func(error) {}) }()

		_ = tn.Stop()
		cancel()
		_ = hostSide.Close()
		hostNS.close()
		wg.Wait()
	}()

	waitFor(t, "goroutines back to baseline", func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= before+1 // +1: test-server accept loop started above
	})
}

func TestStartFailureTearsDown(t *testing.T) {
	t.Run("ifconfig fails", func(t *testing.T) {
		tunSide, _ := newPipeTunPair("utunFAIL", "host")
		_, err := Start(context.Background(), testKey, Options{
			Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			Links:     &recordLinks{err: errors.New("ifconfig failed")},
			Resolver:  fakeResolver{},
			NewDialer: func(Key, netip.AddrPort) (Dialer, error) { return &fakeDialer{}, nil },
			CreateTUN: func(int) (tun.Device, error) { return tunSide, nil },
		})
		if err == nil || !strings.Contains(err.Error(), "ifconfig") {
			t.Fatalf("err = %v", err)
		}
		if !tunSide.isClosed() {
			t.Fatal("utun leaked after failed Start")
		}
	})
	t.Run("resolve fails before creating a device", func(t *testing.T) {
		created := false
		k := testKey
		k.Host = "vpn.example.test"
		_, err := Start(context.Background(), k, Options{
			Resolver:  fakeResolver{},
			CreateTUN: func(int) (tun.Device, error) { created = true; return nil, errors.New("unreachable") },
		})
		if err == nil || created {
			t.Fatalf("err = %v, created = %v", err, created)
		}
	})
	t.Run("invalid options", func(t *testing.T) {
		for _, o := range []Options{
			{MTU: 100},
			{Address: netip.MustParseAddr("fd00::1")},
		} {
			if _, err := Start(context.Background(), testKey, o); err == nil {
				t.Errorf("expected error for %+v", o)
			}
		}
		if _, err := Start(context.Background(), Key{}, Options{}); err == nil {
			t.Error("expected error for empty key")
		}
	})
}

func TestResolveServerPrefersIPv4(t *testing.T) {
	k := testKey
	k.Host = "vpn.example.test"
	got, err := resolveServer(context.Background(), fakeResolver{addrs: []netip.Addr{
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.77"),
	}}, k)
	if err != nil || got != netip.MustParseAddrPort("192.0.2.77:8388") {
		t.Fatalf("got %v, %v", got, err)
	}
	got, err = resolveServer(context.Background(), fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("2001:db8::1")}}, k)
	if err != nil || !got.Addr().Is6() {
		t.Fatalf("v6 fallback: %v, %v", got, err)
	}
	if _, err = resolveServer(context.Background(), fakeResolver{}, k); err == nil {
		t.Fatal("expected resolver error")
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
