package ifacename

import (
	"testing"

	"github.com/quocln/routewise/internal/winnet"
)

func TestAdapterIsVPNTunnelUsesTheDriverNotTheName(t *testing.T) {
	adapters := []winnet.Adapter{
		{Alias: "work", Description: "WireGuard Tunnel", IfType: 53},
		{Alias: "Ethernet 2", Description: "AWS VPN Client TAP-Windows Adapter V9", IfType: 6},
		{Alias: "Ethernet", Description: "Intel(R) Ethernet Connection", IfType: 6},
	}
	for alias, want := range map[string]bool{"work": true, "ETHERNET 2": true, "Ethernet": false} {
		got, found := adapterIsVPNTunnel(adapters, alias)
		if !found || got != want {
			t.Errorf("adapterIsVPNTunnel(%q) = %v, %v; want %v, true", alias, got, found, want)
		}
	}
	if _, found := adapterIsVPNTunnel(adapters, "gone"); found {
		t.Error("an alias no adapter carries must not be found")
	}
}
