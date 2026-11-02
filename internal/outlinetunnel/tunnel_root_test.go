//go:build darwin

package outlinetunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestTunnelLifecycleAsRoot creates a real utun and checks address assignment,
// that no route is added, and that Stop removes the interface. It needs root,
// so it only runs when ROUTEWISE_OUTLINE_ROOT_TEST=1.
func TestTunnelLifecycleAsRoot(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("ROUTEWISE_OUTLINE_ROOT_TEST") != "1" {
		t.Skip("needs root and ROUTEWISE_OUTLINE_ROOT_TEST=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	routesBefore := netstat(t, "-rn", "-f", "inet")
	addr := netip.MustParseAddr("10.233.250.1")
	tn, err := Start(ctx, Key{Method: CipherChaCha20, Password: "pw", Host: "192.0.2.1", Port: 8388}, Options{
		Address: addr,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = tn.Stop()
		}
	}()

	name := tn.Name()
	if !strings.HasPrefix(name, "utun") {
		t.Fatalf("Name = %q", name)
	}
	out, err := exec.Command("/sbin/ifconfig", name).CombinedOutput()
	if err != nil {
		t.Fatalf("ifconfig %s: %v: %s", name, err, out)
	}
	if !strings.Contains(string(out), "inet "+addr.String()) || !strings.Contains(string(out), "UP") {
		t.Fatalf("interface not configured:\n%s", out)
	}
	if routesAfter := netstat(t, "-rn", "-f", "inet"); strings.Contains(routesAfter, name) && !strings.Contains(routesBefore, name) {
		// The connected host route for the alias address is created by the
		// kernel; any route naming the utun beyond it would be ours.
		for _, line := range strings.Split(routesAfter, "\n") {
			if strings.Contains(line, name) && !strings.Contains(line, addr.String()) {
				t.Fatalf("unexpected route via %s: %s", name, line)
			}
		}
	}
	if st := tn.Stats(); st.TCPFlows != 0 || st.UDPFlows != 0 {
		t.Fatalf("fresh tunnel has flows: %+v", st)
	}

	if err := tn.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	stopped = true
	if err := tn.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatalf("%s still exists after Stop", name)
	}
}

func netstat(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("/usr/sbin/netstat", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("netstat: %v: %s", err, out)
	}
	return string(out)
}
