package dns

import (
	"net/netip"
	"reflect"
	"testing"
)

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// A typical workstation on a VPN: the LAN uplink and the global fallback, the
// VPN's tunnel with servers it published through update-systemd-resolved, and
// RouteWise's own link pointing at the local forwarder.
func resolvedFixture() ([]resolvedEntry, map[int]resolvedLink) {
	entries := []resolvedEntry{
		{ifindex: 0, addr: netip.MustParseAddr("9.9.9.9")},
		{ifindex: 2, addr: netip.MustParseAddr("192.168.1.1")},
		{ifindex: 7, addr: netip.MustParseAddr("10.8.0.2")},
		{ifindex: 7, addr: netip.MustParseAddr("10.8.0.3")},
		{ifindex: 9, addr: netip.MustParseAddr("127.0.0.1"), port: 53053},
	}
	links := map[int]resolvedLink{
		2: {name: "eth0", defaultRoute: true},
		7: {name: "tun0", defaultRoute: false, domains: []string{"~corp.example"}},
		9: {name: "rw-dns", defaultRoute: false, domains: []string{"~example.com"}},
	}
	return entries, links
}

func TestRenderResolvedConfigFeedsVPNNameserverSelection(t *testing.T) {
	entries, links := resolvedFixture()
	out := renderResolvedConfig(entries, links)

	if got, bound := SelectVPNNameservers(out, "tun0", FallbackOptions{}); !bound || !reflect.DeepEqual(got, addrs("10.8.0.2", "10.8.0.3")) {
		t.Errorf("tun0 nameservers = %v bound=%v, want the tunnel's servers bound", got, bound)
	}
	if got, bound := SelectVPNNameservers(out, "eth0", FallbackOptions{}); !bound || !reflect.DeepEqual(got, addrs("192.168.1.1")) {
		t.Errorf("eth0 nameservers = %v bound=%v", got, bound)
	}
	if got, bound := SelectVPNNameservers(out, "wg0", FallbackOptions{}); bound || got != nil {
		t.Errorf("wg0 nameservers = %v bound=%v, want none without the guess", got, bound)
	}
}

func TestRenderResolvedConfigNeverOffersTheForwarderOrTheStub(t *testing.T) {
	entries, links := resolvedFixture()
	entries = append(entries,
		resolvedEntry{ifindex: 2, addr: netip.MustParseAddr("127.0.0.53")},
		resolvedEntry{ifindex: 2, addr: netip.MustParseAddr("10.9.9.9"), port: 5353},
	)
	out := renderResolvedConfig(entries, links)

	for _, b := range parseResolverBlocks(out) {
		if b.iface == "rw-dns" {
			t.Errorf("RouteWise's own link is in the configuration: %+v", b)
		}
		for _, s := range b.servers {
			if s.IsLoopback() || s == netip.MustParseAddr("10.9.9.9") {
				t.Errorf("unusable upstream %v offered on %q", s, b.iface)
			}
		}
	}
}

func TestRenderResolvedConfigMarksNonDefaultLinksSupplemental(t *testing.T) {
	entries, links := resolvedFixture()
	blocks := parseResolverBlocks(renderResolvedConfig(entries, links))

	domains := map[string]string{}
	for _, b := range blocks {
		domains[b.iface] = b.domain
	}
	want := map[string]string{"": "", "eth0": "", "tun0": "corp.example"}
	if !reflect.DeepEqual(domains, want) {
		t.Errorf("block domains = %v, want %v", domains, want)
	}
}

func TestRenderResolvedConfigGuessesWgQuickServersFromDefaultLinks(t *testing.T) {
	// wg-quick through resolvconf hands the servers to a link that is a default
	// route and not a tunnel by name: the guess takes them when allowed.
	entries := []resolvedEntry{
		{ifindex: 2, addr: netip.MustParseAddr("192.168.1.1")},
		{ifindex: 3, addr: netip.MustParseAddr("10.2.0.1")},
	}
	links := map[int]resolvedLink{
		2: {name: "eth0", defaultRoute: true},
		3: {name: "vpnlink0", defaultRoute: true},
	}
	out := renderResolvedConfig(entries, links)
	opts := FallbackOptions{
		Enabled: true,
		IsLocal: func(a netip.Addr) bool { return netip.MustParsePrefix("192.168.1.0/24").Contains(a) },
	}
	got, bound := SelectVPNNameservers(out, "wg0", opts)
	if bound || !reflect.DeepEqual(got, addrs("10.2.0.1")) {
		t.Errorf("guess = %v bound=%v, want the off-link private server", got, bound)
	}
}

func TestRenderResolvedConfigSkipsLinksResolvedDoesNotKnow(t *testing.T) {
	out := renderResolvedConfig([]resolvedEntry{{ifindex: 42, addr: netip.MustParseAddr("10.0.0.1")}}, nil)
	if blocks := parseResolverBlocks(out); len(blocks) != 0 {
		t.Errorf("blocks = %+v, want none", blocks)
	}
}

func TestRenderResolvedConfigHandlesIPv6Servers(t *testing.T) {
	out := renderResolvedConfig([]resolvedEntry{{ifindex: 0, addr: netip.MustParseAddr("2001:4860:4860::8888")}, {ifindex: 0, addr: netip.MustParseAddr("8.8.8.8")}}, nil)
	blocks := parseResolverBlocks(out)
	if len(blocks) != 1 || !reflect.DeepEqual(blocks[0].servers, addrs("8.8.8.8")) {
		t.Errorf("blocks = %+v, want only the IPv4 server", blocks)
	}
}
