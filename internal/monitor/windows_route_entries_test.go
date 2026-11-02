package monitor

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/quocln/routewise/internal/winnet"
)

var (
	winEthernet = winnet.Adapter{Index: 5, Alias: "Ethernet", Description: "Intel(R) Ethernet Connection", IfType: 6, Up: true, Metric: 25}
	winTAP      = winnet.Adapter{Index: 12, Alias: "tap1", Description: "TAP-Windows Adapter V9", IfType: 6, Up: true, Metric: 1}
	winWintun   = winnet.Adapter{Index: 14, Alias: "wintun1", Description: "Wintun Userspace Tunnel", IfType: 53, Up: true, Metric: 0}
	winDCO      = winnet.Adapter{Index: 15, Alias: "ovpndco1", Description: "OpenVPN Data Channel Offload", IfType: 6, Up: true, Metric: 1}
	winLoopback = winnet.Adapter{Index: 1, Alias: "Loopback Pseudo-Interface 1", Description: "Software Loopback Interface 1", IfType: 24, Up: true, Metric: 75}
)

func winRoute(a winnet.Adapter, dest, hop string, metric, proto uint32) winnet.Route {
	r := winnet.Route{Adapter: a, Dest: netip.MustParsePrefix(dest), Metric: metric, Protocol: proto, NextHop: netip.IPv4Unspecified()}
	if hop != "" {
		r.NextHop = netip.MustParseAddr(hop)
	}
	return r
}

// The adapters above use aliases every OS's interface-name check accepts, since
// findVPNFromRoutes validates names with the build's own rules; the entry
// conversion is also checked with the aliases Windows really uses.
func winDetect(routes ...winnet.Route) []vpnMatch {
	return findVPNFromRoutes(windowsRouteEntries(routes))
}

func winLAN() []winnet.Route {
	return []winnet.Route{
		winRoute(winEthernet, "0.0.0.0/0", "192.168.1.1", 0, 16),
		winRoute(winEthernet, "192.168.1.0/24", "", 256, winnet.ProtocolLocal),
		winRoute(winLoopback, "127.0.0.0/8", "", 331, winnet.ProtocolLocal),
	}
}

func TestWindowsOpenVPNTapDef1PairIsAFullTunnel(t *testing.T) {
	got := winDetect(append(winLAN(),
		winRoute(winTAP, "10.8.0.0/24", "", 256, winnet.ProtocolLocal),
		winRoute(winTAP, "0.0.0.0/1", "10.8.0.1", 1, winnet.ProtocolNetMgmt),
		winRoute(winTAP, "128.0.0.0/1", "10.8.0.1", 1, winnet.ProtocolNetMgmt))...)
	want := []vpnMatch{{iface: winTAP.Alias, gateway: netip.MustParseAddr("10.8.0.1")}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestWindowsWireGuardOnLinkHalvesAreAFullTunnel(t *testing.T) {
	got := winDetect(append(winLAN(),
		winRoute(winWintun, "0.0.0.0/1", "", 0, winnet.ProtocolNetMgmt),
		winRoute(winWintun, "128.0.0.0/1", "", 0, winnet.ProtocolNetMgmt))...)
	if want := []vpnMatch{{iface: "wintun1"}}; !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestWindowsDCODefaultThroughGateway(t *testing.T) {
	got := winDetect(append(winLAN(), winRoute(winDCO, "0.0.0.0/0", "10.9.0.1", 1, winnet.ProtocolNetMgmt))...)
	want := []vpnMatch{{iface: winDCO.Alias, gateway: netip.MustParseAddr("10.9.0.1")}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestWindowsTunnelDefaultRankedBehindTheLANIsNotInUse(t *testing.T) {
	// LAN effective metric is 25; the tunnel's 600+1 loses, 0+1 wins.
	if got := winDetect(append(winLAN(), winRoute(winTAP, "0.0.0.0/0", "10.8.0.1", 600, winnet.ProtocolNetMgmt))...); len(got) != 0 {
		t.Fatalf("got %+v: the LAN default wins, the tunnel carries nothing", got)
	}
	got := winDetect(append(winLAN(), winRoute(winTAP, "0.0.0.0/0", "10.8.0.1", 0, winnet.ProtocolNetMgmt))...)
	if len(got) != 1 || got[0].iface != winTAP.Alias {
		t.Fatalf("got %+v, want the tunnel (effective metric 1 beats 25)", got)
	}
}

func TestWindowsOnlyTunnelAdaptersQualify(t *testing.T) {
	got := winDetect(append(winLAN(),
		winRoute(winEthernet, "0.0.0.0/1", "192.168.1.1", 0, winnet.ProtocolNetMgmt),
		winRoute(winEthernet, "128.0.0.0/1", "192.168.1.1", 0, winnet.ProtocolNetMgmt))...)
	if len(got) != 0 {
		t.Fatalf("got %+v: Ethernet is not a VPN tunnel", got)
	}
}

func TestWindowsDownAdaptersAndDerivedRoutesAreIgnored(t *testing.T) {
	down := winWintun
	down.Up = false
	got := winDetect(
		winRoute(down, "0.0.0.0/1", "", 0, winnet.ProtocolNetMgmt),
		winRoute(down, "128.0.0.0/1", "", 0, winnet.ProtocolNetMgmt),
		winRoute(winTAP, "0.0.0.0/0", "10.8.0.1", 0, winnet.ProtocolLocal),
	)
	if len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

func TestWindowsRouteEntriesAreMasked(t *testing.T) {
	entries := windowsRouteEntries([]winnet.Route{winRoute(winWintun, "0.1.2.3/1", "", 0, winnet.ProtocolNetMgmt)})
	if len(entries) != 1 || entries[0].Dest != netip.MustParsePrefix("0.0.0.0/1") || !entries[0].Tunnel || entries[0].Gateway.IsValid() {
		t.Fatalf("got %+v", entries)
	}
}

func TestWindowsRouteEntriesKeepTheRealAlias(t *testing.T) {
	dco := winnet.Adapter{Index: 15, Alias: "OpenVPN Data Channel Offload", Description: "OpenVPN Data Channel Offload", IfType: 6, Up: true}
	entries := windowsRouteEntries([]winnet.Route{
		winRoute(dco, "0.0.0.0/0", "10.9.0.1", 1, winnet.ProtocolNetMgmt),
		winRoute(winEthernet, "0.0.0.0/0", "192.168.1.1", 600, winnet.ProtocolNetMgmt),
	})
	want := []routeEntry{
		{Dest: defaultPrefix, Gateway: netip.MustParseAddr("10.9.0.1"), Iface: "OpenVPN Data Channel Offload", Tunnel: true},
		{Dest: defaultPrefix, Gateway: netip.MustParseAddr("192.168.1.1"), Iface: "Ethernet"},
	}
	if !slices.Equal(entries, want) {
		t.Fatalf("got %+v, want %+v", entries, want)
	}
}

// Only the catch-all rows reach detection: a tunnel's host and subnet routes
// are never turned into entries.
func TestWindowsRouteEntriesDropRowsDetectionDoesNotRead(t *testing.T) {
	entries := windowsRouteEntries([]winnet.Route{
		winRoute(winWintun, "10.1.2.3/32", "", 0, winnet.ProtocolNetMgmt),
		winRoute(winWintun, "10.0.0.0/8", "", 0, winnet.ProtocolNetMgmt),
		winRoute(winWintun, "0.0.0.0/1", "", 0, winnet.ProtocolNetMgmt),
	})
	if len(entries) != 1 || entries[0].Dest != lowerHalf {
		t.Fatalf("got %+v, want only 0.0.0.0/1", entries)
	}
}
