package monitor

import (
	"net/netip"
	"slices"
	"testing"
)

func TestParseNetstatDest(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"default", "0.0.0.0/0", true},
		{"0/1", "0.0.0.0/1", true},
		{"128.0/1", "128.0.0.0/1", true},
		{"128/1", "128.0.0.0/1", true},
		{"0.0.0.0/1", "0.0.0.0/1", true},
		{"192.168.1/24", "192.168.1.0/24", true},
		{"10.0.0.7", "10.0.0.7/32", true},
		{"link#12", "", false},
		{"ff02::/16", "", false},
		{"1.2.3.4.5/8", "", false},
		{"10.0.0.0/33", "", false},
	}
	for _, tt := range tests {
		got, ok := parseNetstatDest(tt.in)
		if ok != tt.ok || (ok && got != netip.MustParsePrefix(tt.want)) {
			t.Errorf("parseNetstatDest(%q) = %v, %v; want %s, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestParseNetstatRoutesKeepsScopedAndTunnelMarks(t *testing.T) {
	entries := parseNetstatRoutes([]byte(`Destination        Gateway            Flags        Netif
default            192.168.1.1        UGScIg       en0
default            link#18            UCSg         utun4
0/1                10.0.0.1           UGSc         ipsec0
`))
	want := []routeEntry{
		{Dest: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"), Iface: "en0", Scoped: true},
		{Dest: netip.MustParsePrefix("0.0.0.0/0"), Iface: "utun4", Tunnel: true},
		{Dest: netip.MustParsePrefix("0.0.0.0/1"), Gateway: netip.MustParseAddr("10.0.0.1"), Iface: "ipsec0"},
	}
	if !slices.Equal(entries, want) {
		t.Fatalf("entries = %+v, want %+v", entries, want)
	}
}

// TestFindVPNFromEntriesIgnoresNonTunnelInterfaces covers the shape a Linux
// source produces: entries without a scope, on interfaces the source did or
// did not mark as tunnels.
func TestFindVPNFromEntriesIgnoresNonTunnelInterfaces(t *testing.T) {
	p := netip.MustParsePrefix
	gw := netip.MustParseAddr("10.8.0.1")
	entries := []routeEntry{
		{Dest: p("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"), Iface: "eth0"},
		{Dest: p("0.0.0.0/1"), Gateway: gw, Iface: "tun0", Tunnel: true},
		{Dest: p("128.0.0.0/1"), Gateway: gw, Iface: "tun0", Tunnel: true},
		{Dest: p("0.0.0.0/0"), Iface: "wg0", Tunnel: true},
		{Dest: p("0.0.0.0/0"), Iface: "br0", Tunnel: false},
	}
	got := findVPNFromRoutes(entries)
	want := []vpnMatch{{iface: "tun0", gateway: gw}, {iface: "wg0"}}
	if !slices.Equal(got, want) {
		t.Fatalf("findVPNFromRoutes() = %+v, want %+v", got, want)
	}
}
