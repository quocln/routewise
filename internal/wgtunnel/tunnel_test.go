package wgtunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/quocln/routewise/internal/tunnelnet"
)

// testConfig is a one-peer profile whose endpoint is an IP literal, so no
// lookup happens, on a loopback port nothing listens on.
func testConfig() Config {
	return Config{
		PrivateKey: Key{1},
		Addresses:  []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")},
		Peers: []Peer{{
			PublicKey:  Key{2},
			Endpoint:   Endpoint{Host: "127.0.0.1", Port: 9},
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
		}},
	}
}

func testOptions(links tunnelnet.Links, create func(int) (tun.Device, error)) Options {
	return Options{
		Links:     links,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		CreateTUN: create,
	}
}

// closeTrackingTUN signals when the device it wraps has been closed.
type closeTrackingTUN struct {
	tun.Device
	closed chan struct{}
	once   sync.Once
}

func (c *closeTrackingTUN) Close() error {
	err := c.Device.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not happen", what)
	}
}

func TestStartConfiguresDeviceAndStopClosesIt(t *testing.T) {
	ch := tuntest.NewChannelTUN()
	run := &fakeLinks{}
	var gotMTU int
	tn, err := Start(context.Background(), testConfig(), testOptions(run, func(mtu int) (tun.Device, error) {
		gotMTU = mtu
		return ch.TUN(), nil
	}))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(tn.Stop)

	if gotMTU != DefaultMTU {
		t.Errorf("mtu = %d, want %d", gotMTU, DefaultMTU)
	}
	if tn.Name() != "loopbackTun1" {
		t.Errorf("Name = %q", tn.Name())
	}
	want := []call{
		{"addalias", []string{"loopbackTun1", "10.8.0.2/32", "10.8.0.2"}},
		{"up", []string{"loopbackTun1"}},
	}
	if !reflect.DeepEqual(run.calls, want) {
		t.Errorf("calls = %v\nwant %v", run.calls, want)
	}
	st, err := tn.Stats()
	if err != nil || len(st.Peers) != 1 {
		t.Fatalf("Stats = %+v, %v", st, err)
	}
	if eps := tn.PeerEndpoints(); len(eps) != 1 || eps[0] != netip.MustParseAddrPort("127.0.0.1:9") {
		t.Errorf("PeerEndpoints = %v", eps)
	}

	select {
	case <-tn.Done():
		t.Fatal("Done closed before Stop")
	default:
	}
	tn.Stop()
	tn.Stop() // idempotent
	waitClosed(t, tn.Done(), "Done after Stop")
}

func TestStartUsesConfiguredMTU(t *testing.T) {
	cfg := testConfig()
	cfg.MTU = 1280
	ch := tuntest.NewChannelTUN()
	var gotMTU int
	tn, err := Start(context.Background(), cfg, testOptions(&fakeLinks{}, func(mtu int) (tun.Device, error) {
		gotMTU = mtu
		return ch.TUN(), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	tn.Stop()
	if gotMTU != 1280 {
		t.Errorf("mtu = %d", gotMTU)
	}
}

func TestStartTearsDownWhenAddressAssignmentFails(t *testing.T) {
	dev := &closeTrackingTUN{Device: tuntest.NewChannelTUN().TUN(), closed: make(chan struct{})}
	tn, err := Start(context.Background(), testConfig(), testOptions(&fakeLinks{failOn: 1}, func(int) (tun.Device, error) {
		return dev, nil
	}))
	if err == nil || tn != nil {
		t.Fatalf("Start = %v, %v; want error", tn, err)
	}
	if !strings.Contains(err.Error(), "assign addresses on loopbackTun1") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v", err)
	}
	// The device owns the tun once built, so the failed Start must have closed it.
	waitClosed(t, dev.closed, "tun close")
}

func TestStartCreatesNothingWhenResolveFails(t *testing.T) {
	cfg := testConfig()
	cfg.Peers[0].Endpoint = Endpoint{Host: "vpn.example.test", Port: 51820}
	var created atomic.Bool
	opts := testOptions(&fakeLinks{}, func(int) (tun.Device, error) {
		created.Store(true)
		return nil, errors.New("must not be called")
	})
	opts.Resolver = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	if _, err := Start(context.Background(), cfg, opts); err == nil || !strings.Contains(err.Error(), "no such host") {
		t.Fatalf("err = %v", err)
	}
	if created.Load() {
		t.Error("utun created although the endpoint did not resolve")
	}
}

func TestStartReportsCreateTUNFailure(t *testing.T) {
	run := &fakeLinks{}
	_, err := Start(context.Background(), testConfig(), testOptions(run, func(int) (tun.Device, error) {
		return nil, errors.New("operation not permitted")
	}))
	if err == nil || !strings.Contains(err.Error(), "create tunnel device: operation not permitted") {
		t.Fatalf("err = %v", err)
	}
	if len(run.calls) != 0 {
		t.Errorf("ran commands without a device: %v", run.calls)
	}
}

func TestStartHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Start(ctx, testConfig(), testOptions(&fakeLinks{}, nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestStopLeavesNoGoroutines(t *testing.T) {
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	for i := 0; i < 3; i++ {
		ch := tuntest.NewChannelTUN()
		tn, err := Start(context.Background(), testConfig(), testOptions(&fakeLinks{}, func(int) (tun.Device, error) {
			return ch.TUN(), nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		tn.Stop()
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		runtime.GC()
		if n := runtime.NumGoroutine(); n <= before {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("goroutines = %d after Stop, baseline %d", n, before)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
