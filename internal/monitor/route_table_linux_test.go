//go:build linux

package monitor

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func testLinks() []netlink.Link {
	return []netlink.Link{
		&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "eth0"}},
		&netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Index: 3, Name: "tun0"}},
		&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Index: 4, Name: "wg0"}},
		&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Index: 5, Name: "br0"}},
	}
}

func route(table, link, metric int, dst string, gw string) netlink.Route {
	r := netlink.Route{Table: table, LinkIndex: link, Priority: metric, Type: unix.RTN_UNICAST, Family: unix.AF_INET}
	if dst != "" {
		_, n, _ := net.ParseCIDR(dst)
		r.Dst = n
	}
	if gw != "" {
		r.Gw = net.ParseIP(gw)
	}
	return r
}

// ipRule builds a table-lookup rule as RuleList reports it: the rule's action
// is not filled in.
func ipRule(prio, table int, mod func(*netlink.Rule)) netlink.Rule {
	r := *netlink.NewRule()
	r.Priority, r.Table, r.Family = prio, table, unix.AF_INET
	if mod != nil {
		mod(&r)
	}
	return r
}

// defaultRules are the rules of a stock Linux install.
func defaultRules() []netlink.Rule {
	return []netlink.Rule{
		ipRule(0, unix.RT_TABLE_LOCAL, nil),
		ipRule(32766, unix.RT_TABLE_MAIN, nil),
		ipRule(32767, unix.RT_TABLE_DEFAULT, nil),
	}
}

func detect(t *testing.T, routes []netlink.Route, rules []netlink.Rule) []vpnMatch {
	t.Helper()
	return findVPNFromRoutes(linuxRouteEntries(testLinks(), routes, rules))
}

func TestLinuxOpenVPNDef1PairIsAFullTunnel(t *testing.T) {
	got := detect(t, []netlink.Route{
		route(254, 2, 100, "", "192.168.1.1"),
		route(254, 3, 0, "0.0.0.0/1", "10.8.0.5"),
		route(254, 3, 0, "128.0.0.0/1", "10.8.0.5"),
	}, defaultRules())
	want := []vpnMatch{{iface: "tun0", gateway: netip.MustParseAddr("10.8.0.5")}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestLinuxWireGuardDefaultInMainTable(t *testing.T) {
	got := detect(t, []netlink.Route{
		route(254, 2, 100, "", "192.168.1.1"),
		route(254, 4, 0, "", ""),
	}, defaultRules())
	if want := []vpnMatch{{iface: "wg0"}}; !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// wg-quick keeps the tunnel's default route out of the main table and routes
// everything but its own marked packets through table 51820.
func TestLinuxWgQuickPolicyRoutingIsAFullTunnel(t *testing.T) {
	rules := append(defaultRules(),
		ipRule(32764, unix.RT_TABLE_MAIN, func(r *netlink.Rule) { r.SuppressPrefixlen = 0 }),
		ipRule(32765, 51820, func(r *netlink.Rule) { r.Mark, r.Invert = 51820, true }),
	)
	got := detect(t, []netlink.Route{
		route(254, 2, 100, "", "192.168.1.1"),
		route(51820, 4, 0, "", ""),
	}, rules)
	if want := []vpnMatch{{iface: "wg0"}}; !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestLinuxRulesThatSelectOnlyPartOfTheTrafficAreIgnored(t *testing.T) {
	routes := []netlink.Route{
		route(254, 2, 100, "", "192.168.1.1"),
		route(100, 4, 0, "", ""),
	}
	partial := map[string]func(*netlink.Rule){
		"marked traffic only": func(r *netlink.Rule) { r.Mark = 100 },
		"one source":          func(r *netlink.Rule) { _, r.Src, _ = net.ParseCIDR("10.1.0.0/24") },
		"one destination":     func(r *netlink.Rule) { _, r.Dst, _ = net.ParseCIDR("10.1.0.0/24") },
		"one input interface": func(r *netlink.Rule) { r.IifName = "docker0" },
		"one uid range":       func(r *netlink.Rule) { r.UIDRange = netlink.NewRuleUIDRange(1000, 1000) },
	}
	for name, mod := range partial {
		t.Run(name, func(t *testing.T) {
			if got := detect(t, routes, append(defaultRules(), ipRule(100, 100, mod))); len(got) != 0 {
				t.Fatalf("got %+v, want no tunnel", got)
			}
		})
	}

	t.Run("after the main lookup", func(t *testing.T) {
		rules := append(defaultRules(), ipRule(32767-1+1, 100, nil))
		if got := detect(t, routes, rules); len(got) != 0 {
			t.Fatalf("got %+v, want no tunnel", got)
		}
	})
}

func TestLinuxTunnelDefaultWithWorseMetricIsNotInUse(t *testing.T) {
	got := detect(t, []netlink.Route{
		route(254, 2, 100, "", "192.168.1.1"),
		route(254, 3, 700, "", "10.8.0.5"),
	}, defaultRules())
	if len(got) != 0 {
		t.Fatalf("got %+v: the LAN default wins, the tunnel carries nothing", got)
	}

	got = detect(t, []netlink.Route{
		route(254, 2, 100, "", "192.168.1.1"),
		route(254, 3, 50, "", "10.8.0.5"),
	}, defaultRules())
	if len(got) != 1 || got[0].iface != "tun0" {
		t.Fatalf("got %+v, want tun0 (lower metric than the LAN default)", got)
	}
}

func TestLinuxOnlyTunnelLinkKindsQualify(t *testing.T) {
	got := detect(t, []netlink.Route{
		route(254, 2, 100, "", "192.168.1.1"),
		route(254, 5, 0, "0.0.0.0/1", ""),
		route(254, 5, 0, "128.0.0.0/1", ""),
	}, defaultRules())
	if len(got) != 0 {
		t.Fatalf("got %+v: a bridge is not a VPN tunnel", got)
	}
}

func TestLinuxNonUnicastAndOtherTablesAreSkipped(t *testing.T) {
	blackhole := route(254, 3, 0, "", "")
	blackhole.Type = unix.RTN_BLACKHOLE
	got := detect(t, []netlink.Route{
		blackhole,
		route(77, 4, 0, "", ""), // a table no rule consults
	}, defaultRules())
	if len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

func TestIsInterfaceUpLinuxLoopback(t *testing.T) {
	if !isInterfaceUp("lo") {
		t.Error("lo should be up")
	}
	if isInterfaceUp("rw-no-such-iface") {
		t.Error("a missing interface is not up")
	}
}

// Tailscale puts "fwmark 0x80000/0xff0000 lookup main" ahead of its own
// "lookup 52"; the marked rule is not the main lookup for ordinary traffic, so
// the exit node's default in table 52 is still seen.
func markedRule(r *netlink.Rule) {
	mask := uint32(0xff0000)
	r.Mark, r.Mask = 0x80000, &mask
}

func TestLinuxTailscaleExitNodeIsFoundBehindItsMarkedMainRule(t *testing.T) {
	rules := append(defaultRules(),
		ipRule(5210, unix.RT_TABLE_MAIN, markedRule),
		ipRule(5230, unix.RT_TABLE_DEFAULT, markedRule),
		ipRule(5270, 52, nil),
	)
	got := detect(t, []netlink.Route{
		route(254, 2, 100, "", "192.168.1.1"),
		route(52, 3, 0, "", ""),
	}, rules)
	if want := []vpnMatch{{iface: "tun0"}}; !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// RouteWise's own rule "lookup main" ahead of a policy-routed tunnel's table
// is not the system's main lookup: it must not hide the tunnel it was added for.
func TestLinuxOwnMainLookupRuleDoesNotHideTheTunnel(t *testing.T) {
	rules := append(defaultRules(),
		ipRule(32764, unix.RT_TABLE_MAIN, func(r *netlink.Rule) { r.SuppressPrefixlen = 0 }),
		ipRule(32765, 51820, func(r *netlink.Rule) { r.Mark, r.Invert = 51820, true }),
		ipRule(32764-1, unix.RT_TABLE_MAIN, func(r *netlink.Rule) { r.Protocol = ownedRuleProtocol }),
	)
	routes := []netlink.Route{route(254, 2, 100, "", "192.168.1.1"), route(51820, 4, 0, "", "")}
	if got, want := detect(t, routes, rules), []vpnMatch{{iface: "wg0"}}; !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	// The same rule from someone else is a real main lookup ahead of the tunnel.
	rules[len(rules)-1].Protocol = 0
	if got := detect(t, routes, rules); len(got) != 0 {
		t.Fatalf("a foreign main lookup ahead of the tunnel table must hide it, got %+v", got)
	}
}
