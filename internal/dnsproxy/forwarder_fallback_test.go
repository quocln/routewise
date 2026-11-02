package dnsproxy

import (
	"net"
	"strconv"
	"testing"
)

// occupy binds a UDP socket on a free loopback port and returns the port.
func occupy(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	return port
}

func TestAttemptsOrderPrimaryFallbacksThenShared(t *testing.T) {
	f := NewAt("127.0.0.1:53", Config{FallbackHosts: []string{"127.0.0.53", "127.0.0.54"}})
	got := f.attempts()
	want := []listenAttempt{{addr: "127.0.0.1:53"}, {addr: "127.0.0.53:53"}, {addr: "127.0.0.54:53"}}
	if shareListener != nil {
		want = append(want, listenAttempt{addr: "127.0.0.1:53", shared: true})
	}
	if len(got) != len(want) {
		t.Fatalf("attempts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("attempt %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestAttemptsWithoutFallbacksIsPrimaryOnly(t *testing.T) {
	got := NewAt("127.0.0.1:53", Config{}).attempts()
	if len(got) != 1 || got[0].addr != "127.0.0.1:53" || got[0].shared {
		t.Errorf("attempts = %v, want only the primary address", got)
	}
}

func TestListenPortPerOS(t *testing.T) {
	if ListenPort < 1 || ListenPort > 65535 {
		t.Fatalf("ListenPort = %d", ListenPort)
	}
	if got := New(Config{}).Addr(); got != net.JoinHostPort(ListenHost, strconv.Itoa(ListenPort)) {
		t.Errorf("default address = %q", got)
	}
}

func TestStartListensOnFallbackWhenPrimaryIsTaken(t *testing.T) {
	probe, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback to stand in for a second loopback address")
	}
	probe.Close()

	port := occupy(t)
	f := NewAt("127.0.0.1:"+port, Config{FallbackHosts: []string{"::1"}})
	if err := f.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(f.Stop)
	if got, want := f.Addr(), "[::1]:"+port; got != want {
		t.Errorf("Addr = %q, want %q", got, want)
	}
}

func TestStartFailsWhenPrimaryIsTakenAndNoFallbacks(t *testing.T) {
	port := occupy(t)
	f := NewAt("127.0.0.1:"+port, Config{})
	if err := f.Start(); err == nil {
		f.Stop()
		t.Fatal("Start succeeded on a taken port")
	}
	if f.Running() {
		t.Error("Running after a failed Start")
	}
}
