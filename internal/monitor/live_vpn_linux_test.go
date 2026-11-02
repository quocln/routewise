//go:build linux

package monitor

import (
	"os"
	"strings"
	"testing"
)

// TestLiveDetectionMatchesExpectedTunnels reads the real routes, rules and
// links of the namespace it runs in and compares the detected tunnels with
// ROUTEWISE_LIVE_VPN_EXPECT, a comma-separated list of "iface" or
// "iface=gateway" ("none" for no tunnel). Run it inside a dedicated network
// namespace (ip netns exec) that holds a simulated VPN; it is skipped
// otherwise.
func TestLiveDetectionMatchesExpectedTunnels(t *testing.T) {
	expect := os.Getenv("ROUTEWISE_LIVE_VPN_EXPECT")
	if expect == "" {
		t.Skip("set ROUTEWISE_LIVE_VPN_EXPECT inside a test network namespace")
	}

	m := NewVPNMonitor(0)
	got := m.findUTunInterfaces(nil)
	var gotText []string
	for _, tn := range got {
		s := tn.Interface
		if tn.Gateway.IsValid() {
			s += "=" + tn.Gateway.String()
		}
		gotText = append(gotText, s)
	}
	want := expect
	if want == "none" {
		want = ""
	}
	if strings.Join(gotText, ",") != want {
		t.Fatalf("detected %q, want %q", strings.Join(gotText, ","), want)
	}
}
