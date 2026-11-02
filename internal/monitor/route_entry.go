package monitor

import "net/netip"

// routeEntry is one IPv4 route in the neutral form VPN detection works on. The
// OS-specific sources (netstat on macOS, netlink on Linux) fill it, so the
// full-tunnel rules above them are written once.
type routeEntry struct {
	// Dest is the destination prefix; the default route is 0.0.0.0/0.
	Dest netip.Prefix
	// Gateway is the next hop; invalid when the route points straight at the
	// interface (on-link).
	Gateway netip.Addr
	// Iface is the outgoing interface name.
	Iface string
	// Scoped marks an interface-scoped route (macOS RTF_IFSCOPE). Such a route
	// never overrides the default route, so it cannot make a full tunnel.
	Scoped bool
	// Tunnel is set by the source when Iface is a tunnel interface a VPN
	// client owns: a utun on macOS, a tun or WireGuard link on Linux.
	Tunnel bool
}

// detectorDest reports whether dest is a destination VPN detection reads: the
// default route and the two halves of it. A route table holds thousands of
// other rows, mostly RouteWise's own host routes, so every source filters with
// this before it builds an entry.
func detectorDest(dest netip.Prefix) bool {
	return dest == defaultPrefix || dest == lowerHalf || dest == upperHalf
}
