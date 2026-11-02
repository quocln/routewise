package dns

import (
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"testing"
)

const scutilSample = `DNS configuration

resolver #1
  search domain[0] : corp.example.com
  nameserver[0] : 10.0.0.2
  nameserver[1] : 10.0.0.3
  if_index : 23 (utun4)
  flags    : Request A records
  reach    : 0x00000003 (Reachable,Transient Connection)

resolver #2
  domain   : corp.example.com
  nameserver[0] : 127.0.0.1
  port     : 53053
  flags    : Request A records
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)

resolver #3
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
  if_index : 6 (en0)
  flags    : Request A records

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 6 (en0)
  flags    : Scoped, Request A records

resolver #2
  nameserver[0] : 10.0.0.3
  nameserver[1] : 10.0.0.4
  nameserver[2] : fd00::53
  if_index : 23 (utun4)
  flags    : Scoped, Request A records
`

func TestParseScutilNameserversKeepsOnlyTheVPNInterface(t *testing.T) {
	got := ParseScutilNameservers(scutilSample, "utun4")
	want := []netip.Addr{
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.3"),
		netip.MustParseAddr("10.0.0.4"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("ParseScutilNameservers = %v, want %v (deduplicated, IPv4 only, both sections)", got, want)
	}
}

func TestParseScutilNameserversNeverReturnsLoopback(t *testing.T) {
	// RouteWise's own resolver files show up as 127.0.0.1 resolvers with no
	// interface; they must never become an upstream of the forwarder.
	for _, iface := range []string{"", "utun4", "lo0"} {
		for _, addr := range ParseScutilNameservers(scutilSample, iface) {
			if addr.IsLoopback() {
				t.Errorf("iface %q returned loopback %s", iface, addr)
			}
		}
	}
}

func TestParseScutilNameserversUnknownInterface(t *testing.T) {
	if got := ParseScutilNameservers(scutilSample, "utun9"); len(got) != 0 {
		t.Errorf("expected nothing for an interface with no resolver, got %v", got)
	}
}

func TestResolverPreferredServersComeFirstAndClearTheCache(t *testing.T) {
	r := NewResolver([]string{"8.8.8.8"}, 0)
	defer r.Close()

	r.putInCache("cached.example.com.", nil)
	r.SetPreferredServers([]netip.Addr{netip.MustParseAddr("10.0.0.2")})

	if got := r.Upstreams(); !slices.Equal(got, []string{"10.0.0.2", "8.8.8.8"}) {
		t.Errorf("Upstreams = %v, want the VPN server first and the configured one as fallback", got)
	}
	if total, _ := r.CacheStats(); total != 0 {
		t.Errorf("changing upstreams must clear the cache, %d entries left", total)
	}

	r.SetPreferredServers(nil)
	if got := r.Upstreams(); !slices.Equal(got, []string{"8.8.8.8"}) {
		t.Errorf("Upstreams after reset = %v, want only the configured server", got)
	}
}

func TestSelectVPNNameserversPrefersServersBoundToTheTunnel(t *testing.T) {
	got, bound := SelectVPNNameservers(scutilSample, "utun4", FallbackOptions{Enabled: true})
	if !bound || len(got) == 0 || got[0] != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("got %v bound=%v, want the utun4-bound servers", got, bound)
	}
}

// wg-quick sets its DNS on every network service, so nothing is bound to the
// tunnel; the private server the LAN cannot reach directly is the VPN's.
const scutilWGQuick = `DNS configuration

resolver #1
  nameserver[0] : 10.64.0.1
  nameserver[1] : 192.168.7.1
  nameserver[2] : 1.1.1.1
  if_index : 6 (en0)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
`

func TestSelectVPNNameserversFindsWGQuickServers(t *testing.T) {
	lan := netip.MustParsePrefix("192.168.7.0/24")
	opts := FallbackOptions{Enabled: true, IsLocal: lan.Contains}

	got, bound := SelectVPNNameservers(scutilWGQuick, "utun3", opts)
	if bound || len(got) != 1 || got[0] != netip.MustParseAddr("10.64.0.1") {
		t.Fatalf("got %v bound=%v, want only the guessed 10.64.0.1 (not the LAN router, not a public server)", got, bound)
	}
}

func TestSelectVPNNameserversGuessesNothingUntilAllowed(t *testing.T) {
	if got, _ := SelectVPNNameservers(scutilWGQuick, "utun3", FallbackOptions{}); len(got) != 0 {
		t.Fatalf("got %v, want no guess while the fallback is off", got)
	}
}

// An office network whose DNS sits on another subnet, a second VPN's resolver,
// and a supplemental per-domain resolver must never be taken for this VPN's.
var scutilOfficeAndSecondVPN = fmt.Sprintf(`DNS configuration

resolver #1
  nameserver[0] : 10.1.1.1
  if_index : 6 (en0)
  flags    : Request A records

resolver #2
  domain   : corp.other.example
  nameserver[0] : 10.99.0.53
  flags    : Request A records

resolver #3
  nameserver[0] : 10.50.0.1
  if_index : 31 (%s)
  flags    : Request A records

resolver #4
  nameserver[0] : 100.64.0.7
  if_index : 6 (en0)
  flags    : Request A records
`, secondVPNTunnelIface)

func TestSelectVPNNameserversGuessSkipsOtherNetworksServers(t *testing.T) {
	skipWithoutUnixTunnelNames(t)
	known := func(a netip.Addr) bool { return a == netip.MustParseAddr("10.1.1.1") }
	opts := FallbackOptions{Enabled: true, Known: known}

	got, _ := SelectVPNNameservers(scutilOfficeAndSecondVPN, "utun3", opts)
	if len(got) != 1 || got[0] != netip.MustParseAddr("100.64.0.7") {
		t.Fatalf("got %v, want only the CGNAT server: the office DNS was configured before the VPN, "+
			"10.99.0.53 is supplemental, and 10.50.0.1 belongs to another tunnel", got)
	}
}

// Any tunnel family counts as another VPN's resolver, not only utun: an IPsec
// client's servers must not be guessed as this tunnel's.
func TestSelectVPNNameserversGuessSkipsNonUtunTunnels(t *testing.T) {
	skipWithoutUnixTunnelNames(t)
	const scutilIPsec = `DNS configuration

resolver #1
  nameserver[0] : 10.50.0.1
  if_index : 12 (ipsec0)
  flags    : Request A records
`
	got, _ := SelectVPNNameservers(scutilIPsec, "utun3", FallbackOptions{Enabled: true})
	if len(got) != 0 {
		t.Fatalf("got %v, want nothing: the only resolver belongs to an ipsec tunnel", got)
	}
}

// The forwarder may ask the servers of one group at once, so the VPN's servers
// and the configured ones, which may be public, must stay separate groups.
func TestUpstreamGroupsKeepPreferredAndConfiguredServersApart(t *testing.T) {
	r := NewResolver([]string{"8.8.8.8", "1.1.1.1"}, 0)
	defer r.Close()

	if got := r.UpstreamGroups(); !slices.EqualFunc(got, [][]string{{"8.8.8.8", "1.1.1.1"}}, slices.Equal[[]string]) {
		t.Errorf("without preferred servers, groups = %v", got)
	}
	r.SetPreferredServers([]netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")})
	want := [][]string{{"10.0.0.2", "10.0.0.3"}, {"8.8.8.8", "1.1.1.1"}}
	if got := r.UpstreamGroups(); !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("groups = %v, want %v", got, want)
	}
}

// skipWithoutUnixTunnelNames skips on Windows: these fixtures are scutil output,
// whose utun and ipsec names mean nothing to Windows' alias rules.
func skipWithoutUnixTunnelNames(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("scutil output is macOS only")
	}
}
