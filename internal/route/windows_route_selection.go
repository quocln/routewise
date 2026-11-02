package route

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/quocln/routewise/internal/winnet"
)

// The functions in this file decide over a read of the Windows route table and
// touch nothing, so they run and are tested on every platform. The Windows
// table (windows_table_logic.go) applies their answers through the IP Helper
// API.

var (
	defaultV4          = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	multicastV4        = netip.MustParsePrefix("224.0.0.0/4")
	limitedBroadcastV4 = netip.MustParsePrefix("255.255.255.255/32")
)

// usableV4 reports whether r is an IPv4 route that can carry traffic: its
// adapter is up and is not the loopback, and it is not a multicast or limited
// broadcast entry the stack keeps for itself.
func usableV4(r winnet.Route) bool {
	if !r.Dest.IsValid() || !r.Dest.Addr().Is4() || !r.Adapter.Up || r.Adapter.IsLoopback() {
		return false
	}
	if multicastV4.Contains(r.Dest.Addr()) {
		return false
	}
	return r.Dest != limitedBroadcastV4
}

// defaultRoutesOf returns the usable IPv4 default routes, the one Windows
// prefers first: Windows ranks by route metric plus interface metric, so that
// sum is the order, with the interface index breaking ties to stay stable.
func defaultRoutesOf(rs []winnet.Route) []winnet.Route {
	var out []winnet.Route
	for _, r := range rs {
		if usableV4(r) && r.Dest == defaultV4 {
			out = append(out, r)
		}
	}
	slices.SortStableFunc(out, func(a, b winnet.Route) int {
		if c := cmpUint32(a.Effective(), b.Effective()); c != 0 {
			return c
		}
		return cmpUint32(a.Adapter.Index, b.Adapter.Index)
	})
	return out
}

func cmpUint32(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// localGatewayOf mirrors the LAN gateway rule of the other platforms: the
// global default when it leads to a LAN, otherwise the best default whose
// adapter is not a VPN tunnel, preferring the adapter named prefer.
func localGatewayOf(rs []winnet.Route, prefer string) (netip.Addr, string, error) {
	defaults := defaultRoutesOf(rs)
	var firstErr error
	if len(defaults) == 0 {
		firstErr = fmt.Errorf("default route not found in route table")
	} else if gw := defaults[0].Gateway(); gw.IsValid() && !defaults[0].Adapter.IsVPNTunnel() {
		return gw, defaults[0].Adapter.Alias, nil
	}

	var firstGW netip.Addr
	var firstIface string
	for _, r := range defaults {
		gw := r.Gateway()
		if !gw.Is4() || r.Adapter.IsVPNTunnel() {
			continue
		}
		if prefer != "" && strings.EqualFold(r.Adapter.Alias, prefer) {
			return gw, r.Adapter.Alias, nil
		}
		if !firstGW.IsValid() {
			firstGW, firstIface = gw, r.Adapter.Alias
		}
	}
	if firstGW.IsValid() {
		return firstGW, firstIface, nil
	}
	if firstErr != nil {
		return netip.Addr{}, "", firstErr
	}
	return netip.Addr{}, "", fmt.Errorf("no LAN default route found")
}

// bestRouteTo returns the route Windows sends dest through: the longest
// matching prefix, then the lowest effective metric.
func bestRouteTo(rs []winnet.Route, dest netip.Addr) (winnet.Route, bool) {
	var best winnet.Route
	found := false
	for _, r := range rs {
		if !usableV4(r) || !r.Dest.Contains(dest) {
			continue
		}
		if !found || r.Dest.Bits() > best.Dest.Bits() ||
			(r.Dest.Bits() == best.Dest.Bits() && r.Effective() < best.Effective()) {
			best, found = r, true
		}
	}
	return best, found
}

// adapterForGateway finds the adapter whose connected network contains gw, the
// way the stack decides which interface a next hop is reachable on. The
// connected-subnet routes the stack derives from addresses (protocol Local,
// prefix /1 to /31) decide; an on-link route a VPN client added by hand is
// consulted only when there is none, and then only for a /8 or longer so a
// tunnel's on-link 0.0.0.0/1 does not claim every gateway.
func adapterForGateway(rs []winnet.Route, gw netip.Addr) (winnet.Adapter, bool) {
	pick := func(accept func(winnet.Route) bool) (winnet.Adapter, bool) {
		var best winnet.Route
		found := false
		for _, r := range rs {
			if !usableV4(r) || !r.OnLink() || !r.Dest.Contains(gw) || !accept(r) {
				continue
			}
			if !found || r.Dest.Bits() > best.Dest.Bits() ||
				(r.Dest.Bits() == best.Dest.Bits() && r.Effective() < best.Effective()) {
				best, found = r, true
			}
		}
		return best.Adapter, found
	}
	if a, ok := pick(func(r winnet.Route) bool {
		return r.Protocol == winnet.ProtocolLocal && r.Dest.Bits() >= 1 && r.Dest.Bits() <= 31
	}); ok {
		return a, true
	}
	return pick(func(r winnet.Route) bool { return r.Dest.Bits() >= 8 && r.Dest.Bits() <= 31 })
}

// adapterByAlias finds an adapter by friendly name, ignoring case.
func adapterByAlias(adapters []winnet.Adapter, alias string) (winnet.Adapter, bool) {
	for _, a := range adapters {
		if strings.EqualFold(a.Alias, alias) {
			return a, true
		}
	}
	return winnet.Adapter{}, false
}

// routesTo returns the routes for exactly prefix, any adapter.
func routesTo(rs []winnet.Route, prefix netip.Prefix) []winnet.Route {
	var out []winnet.Route
	for _, r := range rs {
		if r.Dest == prefix {
			out = append(out, r)
		}
	}
	return out
}

// routeOwnedBy reports whether r is the route of the owner a delete names: the
// interface when there is one, else the gateway; with neither, any route.
func routeOwnedBy(r winnet.Route, gateway netip.Addr, iface string) bool {
	switch {
	case iface != "":
		return strings.EqualFold(r.Adapter.Alias, iface)
	case gateway.IsValid():
		return sameNextHop(r.NextHop, gateway)
	}
	return true
}

// ownerGateway reads a gateway as the manager recorded it. Anything that is
// not a usable address (empty, "invalid IP", a link-layer form) names no owner.
func ownerGateway(raw string) netip.Addr {
	gw, err := netip.ParseAddr(raw)
	if err != nil || gw.IsUnspecified() {
		return netip.Addr{}
	}
	return gw
}

// sameNextHop compares two next hops, treating every on-link form as equal.
func sameNextHop(a, b netip.Addr) bool {
	aLink := !a.IsValid() || a.IsUnspecified()
	bLink := !b.IsValid() || b.IsUnspecified()
	if aLink || bLink {
		return aLink && bLink
	}
	return a.Unmap() == b.Unmap()
}

// routeKey identifies a route the way Windows does: interface, destination and
// next hop. The metric is not part of it, so two routes that differ only in
// metric cannot coexist.
type routeKey struct {
	index   uint32
	dest    netip.Prefix
	nextHop netip.Addr
}

func keyOf(r winnet.Route) routeKey {
	nh := r.NextHop.Unmap()
	if !nh.IsValid() || nh.IsUnspecified() {
		nh = netip.Addr{}
	}
	return routeKey{index: r.Adapter.Index, dest: r.Dest, nextHop: nh}
}

// metricAhead returns the route metric that makes a route on adapter rank just
// ahead of effective, so it takes over as the preferred route even if the one
// it replaces cannot be deleted. It floors at zero.
func metricAhead(effective uint32, a winnet.Adapter) uint32 {
	if effective <= a.Metric+1 {
		return 0
	}
	return effective - a.Metric - 1
}

// snapshotEntries converts routes to the notation the manager reads from the
// BSD table: "default", a bare address for a host route, a masked CIDR
// otherwise; an on-link route's gateway is "link#<index>".
func snapshotEntries(rs []winnet.Route) []RouteEntry {
	entries := make([]RouteEntry, 0, len(rs))
	for _, r := range rs {
		if !usableV4(r) {
			continue
		}
		e := RouteEntry{
			Destination: "default",
			Gateway:     fmt.Sprintf("link#%d", r.Adapter.Index),
			Flags:       "U",
			Interface:   r.Adapter.Alias,
		}
		if gw := r.Gateway(); gw.IsValid() {
			e.Gateway = gw.String()
			e.Flags += "G"
		}
		switch bits := r.Dest.Bits(); {
		case bits == 32:
			e.Destination = r.Dest.Addr().String()
			e.Flags += "H"
		case bits > 0:
			e.Destination = r.Dest.Masked().String()
		}
		entries = append(entries, e)
	}
	return entries
}
