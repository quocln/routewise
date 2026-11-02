package daemon

import (
	"runtime"
	"testing"

	"github.com/quocln/routewise/internal/history"
)

func TestFlowVerdictNamesManagedTunnelsAndOtherTunnelFamilies(t *testing.T) {
	d, _, _, _ := newDNSTestDaemonWith(t, nil, "example.com")
	managed := testSession(wgIface, wireGuardPath)
	managed.client.Name = "WireGuard"
	d.sessions.add(managed)
	// The fake has no context or routes for Stop to tear down.
	defer d.sessions.remove(managed)

	for iface, want := range map[string]struct{ verdict, vpn string }{
		wgIface:             {history.VerdictVPN, "WireGuard"},
		otherUnmanagedIface: {history.VerdictOther, ""},
		"tun1":              {history.VerdictOther, ""},
		"tap0":              {history.VerdictOther, ""},
		"en0":               {history.VerdictDirect, ""},
		"bridge100":         {history.VerdictDirect, ""},
	} {
		if verdict, vpn := d.flowVerdict(iface); verdict != want.verdict || vpn != want.vpn {
			t.Errorf("flowVerdict(%q) = %q, %q; want %q, %q", iface, verdict, vpn, want.verdict, want.vpn)
		}
	}
	// Windows names IPsec adapters freely, so no alias marks one.
	if runtime.GOOS != "windows" {
		if verdict, _ := d.flowVerdict("ipsec0"); verdict != history.VerdictOther {
			t.Errorf("flowVerdict(ipsec0) = %q, want %q", verdict, history.VerdictOther)
		}
	}
}
