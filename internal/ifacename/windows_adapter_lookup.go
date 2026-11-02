package ifacename

import (
	"strings"

	"github.com/quocln/routewise/internal/winnet"
)

// adapterIsVPNTunnel reports whether the adapter whose friendly name is alias
// is a VPN tunnel by its driver and interface type. Names alone miss the
// official WireGuard client (it names the adapter after the config) and AWS VPN
// Client (its TAP adapter shows up as "Ethernet 2"). found is false when no
// adapter carries the alias, so the caller falls back to the name rules.
func adapterIsVPNTunnel(adapters []winnet.Adapter, alias string) (tunnel, found bool) {
	for _, a := range adapters {
		if strings.EqualFold(a.Alias, alias) {
			return a.IsVPNTunnel(), true
		}
	}
	return false, false
}
