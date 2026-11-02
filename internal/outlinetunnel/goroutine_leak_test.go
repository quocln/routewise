package outlinetunnel

import (
	"context"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

// TestStopLeavesNoGoroutinesWithLiveFlowsAndProbe stops a tunnel that carries a
// TCP flow, a UDP flow and an unanswered probe, and checks every goroutine it
// started, including the per-flow relays and idle timers, is gone. The
// subtest's cleanups (host stack, destination server) run before t.Run
// returns, so the count is compared against a baseline taken before it.
func TestStopLeavesNoGoroutinesWithLiveFlowsAndProbe(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	t.Run("run", func(t *testing.T) {
		h := startHarness(t, func(o *Options) { o.UDPIdleTimeout = time.Minute })
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		tc, err := h.host.dialTCP(ctx, netip.MustParseAddrPort("198.51.100.50:80"))
		if err != nil {
			t.Fatal(err)
		}
		defer tc.Close()
		uc, err := h.host.dialUDP(netip.MustParseAddrPort("198.51.100.51:5300"))
		if err != nil {
			t.Fatal(err)
		}
		defer uc.Close()
		_, _ = uc.Write([]byte("q"))
		_ = uc.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := uc.Read(make([]byte, 16)); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "flows live", func() bool { s := h.tn.Stats(); return s.TCPFlows == 1 && s.UDPFlows == 1 })

		// The destination answers only after EOF, so the probe blocks on its reply.
		probeErr := make(chan error, 1)
		go func() { probeErr <- h.tn.Probe(context.Background(), netip.MustParseAddrPort("198.51.100.52:53")) }()
		waitFor(t, "probe dialed", func() bool { return len(h.dialer.dialed()) == 2 })

		if err := h.tn.Stop(); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		select {
		case err := <-probeErr:
			if err == nil {
				t.Error("probe succeeded on a stopped tunnel")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("probe still running after Stop")
		}
	})

	waitFor(t, "goroutines back to baseline", func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= before
	})
}
