package monitor

import (
	"net/netip"

	"github.com/quocln/routewise/internal/winnet"
)

// windowsRouteEntries turns a read of the Windows IPv4 route table into
// entries. Only routes of an operational, non-loopback adapter count, and a
// route the stack derived from an address (the interface's own address,
// subnet, broadcast and multicast) is never part of a tunnel. A tunnel
// adapter's default route is dropped when a non-tunnel default route ranks
// ahead of it, because Windows then never uses the tunnel's.
//
// Windows ranks routes by the route's own metric plus its interface's metric
// (Route.Effective), so that sum is what the comparison uses. wireguard-nt and
// the WireGuard client install the full tunnel as the on-link 0.0.0.0/1 and
// 128.0.0.0/1 pair, OpenVPN and the AWS client install the pair or a default
// through the tunnel's gateway; findVPNFromRoutes recognises each.
func windowsRouteEntries(routes []winnet.Route) []routeEntry {
	bestNonTunnelDefault := uint32(0)
	haveNonTunnelDefault := false
	for _, r := range routes {
		if r.Dest != defaultPrefix || !usableWindowsRoute(r) || r.Adapter.IsVPNTunnel() {
			continue
		}
		if e := r.Effective(); !haveNonTunnelDefault || e < bestNonTunnelDefault {
			bestNonTunnelDefault, haveNonTunnelDefault = e, true
		}
	}

	var entries []routeEntry
	for _, r := range routes {
		// Only the catch-all rows are read; the rest of a large table is skipped
		// before any adapter lookup.
		if !detectorDest(r.Dest.Masked()) || !usableWindowsRoute(r) {
			continue
		}
		tunnel := r.Adapter.IsVPNTunnel()
		if r.Dest == defaultPrefix && tunnel && haveNonTunnelDefault && bestNonTunnelDefault < r.Effective() {
			continue
		}
		entries = append(entries, routeEntry{
			Dest:    r.Dest.Masked(),
			Gateway: r.Gateway(),
			Iface:   r.Adapter.Alias,
			Tunnel:  tunnel,
		})
	}
	return entries
}

// usableWindowsRoute reports whether r is an IPv4 route a VPN could own: not
// derived from an address, on an adapter that is up and not the loopback.
func usableWindowsRoute(r winnet.Route) bool {
	if r.Protocol == winnet.ProtocolLocal || !r.Adapter.Up || r.Adapter.IsLoopback() {
		return false
	}
	return r.Dest.IsValid() && r.Dest.Addr().Is4() && r.Dest != netip.MustParsePrefix("255.255.255.255/32")
}
