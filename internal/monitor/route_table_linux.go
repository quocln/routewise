//go:build linux

package monitor

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/quocln/routewise/internal/ifacename"
)

// defaultRulePriority is where the kernel puts the lookup of the main table
// when no rule says otherwise.
const defaultRulePriority = 32766

// ownedRuleProtocol is the protocol RouteWise stamps on the policy rules it
// adds, which are not part of the system's own routing policy.
const ownedRuleProtocol = 0xf5

// fetchRouteTable is the production routeTable default: the IPv4 routes of the
// main table and of every table a broad policy rule sends traffic to ahead of
// the main table, read over netlink. Only the default route and its two halves
// are kept (see dumpDetectorRoutes).
func fetchRouteTable() ([]routeEntry, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	routes, err := dumpDetectorRoutes()
	if err != nil {
		return nil, err
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	return linuxRouteEntries(links, routes, rules), nil
}

// isTunnelLink reports whether l is a tunnel interface a VPN client owns.
func isTunnelLink(l netlink.Link) bool { return ifacename.IsTunnelLinkType(l.Type()) }

// linuxRouteEntries turns kernel routes into entries. Only unicast IPv4 routes
// with an output interface count, from the main table and the tables that
// policy rules consult first. A tunnel's default route is dropped when a
// non-tunnel default route of the same table has a lower metric, because the
// kernel then never uses the tunnel's.
func linuxRouteEntries(links []netlink.Link, routes []netlink.Route, rules []netlink.Rule) []routeEntry {
	names := make(map[int]string, len(links))
	tunnels := make(map[int]bool, len(links))
	for _, l := range links {
		a := l.Attrs()
		names[a.Index] = a.Name
		tunnels[a.Index] = isTunnelLink(l)
	}
	tables := consultedTables(rules)

	// bestNonTunnelDefault is the lowest metric of a non-tunnel default route
	// per table.
	bestNonTunnelDefault := make(map[int]int)
	for _, r := range routes {
		if !usableRoute(r, tables) || !isDefaultDst(r.Dst) || tunnels[r.LinkIndex] {
			continue
		}
		if best, ok := bestNonTunnelDefault[r.Table]; !ok || r.Priority < best {
			bestNonTunnelDefault[r.Table] = r.Priority
		}
	}

	var entries []routeEntry
	for _, r := range routes {
		if !usableRoute(r, tables) {
			continue
		}
		name, ok := names[r.LinkIndex]
		if !ok {
			continue
		}
		dest, ok := routeDest(r.Dst)
		if !ok || !detectorDest(dest) {
			continue
		}
		if dest.Bits() == 0 && tunnels[r.LinkIndex] {
			if best, ok := bestNonTunnelDefault[r.Table]; ok && best < r.Priority {
				continue
			}
		}
		var gateway netip.Addr
		if gw := r.Gw.To4(); gw != nil {
			gateway, _ = netip.AddrFromSlice(gw)
		}
		entries = append(entries, routeEntry{
			Dest:    dest,
			Gateway: gateway,
			Iface:   name,
			Tunnel:  tunnels[r.LinkIndex],
		})
	}
	return entries
}

// usableRoute reports whether r is a unicast route with an output interface in
// a considered table.
func usableRoute(r netlink.Route, tables map[int]bool) bool {
	table := r.Table
	if table == 0 {
		table = unix.RT_TABLE_MAIN
	}
	return r.Type == unix.RTN_UNICAST && r.LinkIndex != 0 && tables[table]
}

func isDefaultDst(dst *net.IPNet) bool {
	p, ok := routeDest(dst)
	return ok && p.Bits() == 0
}

// routeDest converts a route destination; nil is the default route.
func routeDest(dst *net.IPNet) (netip.Prefix, bool) {
	if dst == nil {
		return defaultPrefix, true
	}
	ip := dst.IP.To4()
	if ip == nil {
		return netip.Prefix{}, false
	}
	ones, bits := dst.Mask.Size()
	if bits != 32 {
		return netip.Prefix{}, false
	}
	addr, _ := netip.AddrFromSlice(ip)
	return netip.PrefixFrom(addr, ones), true
}

// consultedTables returns the routing tables the kernel reads before it would
// read the main table for ordinary outgoing traffic: main itself, and each
// table that a rule ahead of the main lookup sends all unmarked traffic to.
//
// wg-quick shows why: it puts the tunnel's default route in table 51820 and
// adds the rule "not fwmark 51820 lookup 51820" ahead of main, so the main
// table never shows the tunnel at all. A rule that only matches some sources,
// destinations, interfaces or marks selects a slice of traffic, not a full
// tunnel, and is ignored.
func consultedTables(rules []netlink.Rule) map[int]bool {
	mainPriority := defaultRulePriority
	for _, r := range rules {
		// Only a rule that sends all traffic to main ends the search. Rules
		// with a mark or other selector (Tailscale's "fwmark 0x80000/0xff0000
		// lookup main") pass the rest on, and RouteWise's own rule ahead of the
		// VPN's table (see ownedRuleProtocol) must not hide that table.
		if r.Table == unix.RT_TABLE_MAIN && r.SuppressPrefixlen < 0 && r.Priority >= 0 && r.Priority < mainPriority &&
			isBroadRule(r) && r.Protocol != ownedRuleProtocol {
			mainPriority = r.Priority
		}
	}

	tables := map[int]bool{unix.RT_TABLE_MAIN: true}
	for _, r := range rules {
		switch r.Table {
		case 0, unix.RT_TABLE_MAIN, unix.RT_TABLE_DEFAULT, unix.RT_TABLE_LOCAL:
			continue
		}
		// A rule that is not a table lookup (goto, blackhole, unreachable)
		// has no table, so the table check above already skipped it. The
		// action itself is not reported when listing rules.
		if r.Priority < 0 || r.Priority >= mainPriority {
			continue
		}
		if isBroadRule(r) {
			tables[r.Table] = true
		}
	}
	return tables
}

// isBroadRule reports whether r matches all traffic, or, when inverted around a
// firewall mark, all traffic that does not carry that mark.
func isBroadRule(r netlink.Rule) bool {
	if !isAnyPrefix(r.Src) || !isAnyPrefix(r.Dst) {
		return false
	}
	if r.IifName != "" || r.OifName != "" || r.Tos != 0 || r.IPProto != 0 ||
		r.Dport != nil || r.Sport != nil || r.UIDRange != nil {
		return false
	}
	if r.Mark != 0 {
		return r.Invert
	}
	return !r.Invert
}

func isAnyPrefix(n *net.IPNet) bool {
	if n == nil {
		return true
	}
	ones, _ := n.Mask.Size()
	return ones == 0
}
