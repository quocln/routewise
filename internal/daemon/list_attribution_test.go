package daemon

import (
	"net/netip"
	"testing"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/dnswatch"
)

func TestMatchingEntryFollowsOwnershipOrderAndPrefersDomainsOverNetworks(t *testing.T) {
	cfg := &config.Config{
		Domains: domainRules([]string{"*.corp.example.com", "198.51.100.0/24"}),
		VPNs: []config.VPNRoute{
			{Client: "high", Domains: domainRules([]string{"10.0.0.0/8", "jira.corp.example.com"})},
			{Client: "low", Domains: domainRules([]string{"*.example.com", "10.1.2.3"})},
		},
	}
	ip := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	cases := []struct {
		name     string
		host     string
		addr     netip.Addr
		list     string
		rule     string
		matching bool
	}{
		{"exact name in the high list", "jira.corp.example.com", ip("10.1.2.3"), "high", "jira.corp.example.com", true},
		{"wildcard in a lower list beats a network in a higher one", "wiki.example.com", ip("10.9.9.9"), "low", "*.example.com", true},
		{"an IP entry beats a CIDR", "", ip("10.1.2.3"), "low", "10.1.2.3", true},
		{"a CIDR when nothing narrower matches", "", ip("10.200.0.1"), "high", "10.0.0.0/8", true},
		{"the Any VPN list is the empty id", "", ip("198.51.100.7"), "", "198.51.100.0/24", true},
		{"no list", "example.org", ip("93.184.216.34"), "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, ok := newRoutingPolicy(cfg, 1, nil).matchingEntry(c.host, c.addr)
			if ok != c.matching || m.list != c.list || m.rule != c.rule {
				t.Errorf("matchingEntry = %+v, %v; want list %q rule %q, %v", m, ok, c.list, c.rule, c.matching)
			}
			if o, oOK := oracleMatchingEntry(cfg, c.host, c.addr); o != m || oOK != ok {
				t.Errorf("reference matchingEntry = %+v, %v; compiled %+v, %v", o, oOK, m, ok)
			}
		})
	}
}

func TestRoutesAndHistoryNameTheListEntryAndTheVPN(t *testing.T) {
	env := newHistoryEnv(t)
	env.answers.set("wg.example.com", "10.100.0.1")
	env.connectWG()
	waitForRoutes(t, env.d, wgIface, "10.100.0.1")

	var found bool
	for _, r := range env.d.GetActiveRoutes() {
		if r.IP != "10.100.0.1" {
			continue
		}
		found = true
		if r.List == nil || *r.List != wireGuardPath || r.Rule != "wg.example.com" || r.ClientID != wireGuardPath || r.VPN == "" {
			t.Errorf("route = %+v, want the WireGuard list entry and client", r)
		}
	}
	if !found {
		t.Fatal("no route for 10.100.0.1")
	}

	env.d.onFlow(flowOn(wgIface, "10.100.0.1", 443, dnswatch.ProtoTCP))
	env.d.onFlow(flowOn("en0", "93.184.216.34", 443, dnswatch.ProtoTCP))
	byIP := map[string]bool{}
	for _, e := range accessEntries(t, env.d) {
		byIP[e.IP] = true
		switch e.IP {
		case "10.100.0.1":
			if e.List == nil || *e.List != wireGuardPath || e.Rule != "wg.example.com" {
				t.Errorf("vpn entry = %+v, want the WireGuard list entry", e)
			}
		case "93.184.216.34":
			if e.List != nil || e.Rule != "" {
				t.Errorf("direct entry = %+v, want no list", e)
			}
		}
	}
	if len(byIP) != 2 {
		t.Fatalf("recorded %v", byIP)
	}
}
