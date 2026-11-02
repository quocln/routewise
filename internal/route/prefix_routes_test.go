package route

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

var (
	cidrA = netip.MustParsePrefix("10.20.0.0/16")
	cidrB = netip.MustParsePrefix("172.16.0.0/12")
)

// observe returns the route changes a manager reports, in order.
func observe(m *Manager) *[]RouteChange {
	var changes []RouteChange
	m.SetChangeObserver(func(c RouteChange) { changes = append(changes, c) })
	return &changes
}

func TestSyncPrefixesAddsViaGatewayThenDeletesWhenLeavingTheSet(t *testing.T) {
	m, fake := newTestManager(t)
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun7)
	changes := observe(m)

	if err := m.SyncPrefixes(map[netip.Prefix]string{cidrA: "10.20.0.0/16", cidrB: "172.16.0.0/12"}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	for _, want := range []string{
		"route -n add -net 10.20.0.0/16 10.8.0.1",
		"route -n add -net 172.16.0.0/12 10.8.0.1",
	} {
		if callsWith(fake, want) != 1 {
			t.Errorf("want one %q in %v", want, fake.callLog)
		}
	}
	if got := m.GetRouteCount(); got != 2 {
		t.Errorf("GetRouteCount = %d, want 2 network routes counted", got)
	}
	if len(m.GetActiveRoutes()) != 0 {
		t.Error("network routes must not appear among the host routes")
	}
	info, ok := m.GetNetRoutes()[cidrA]
	if !ok || info.SourceEntry != "10.20.0.0/16" || info.Interface != tun7 || info.Gateway.String() != "10.8.0.1" {
		t.Errorf("net route = %+v ok=%v", info, ok)
	}

	// A second identical sync changes nothing.
	fake.callLog = nil
	if err := m.SyncPrefixes(map[netip.Prefix]string{cidrA: "10.20.0.0/16", cidrB: "172.16.0.0/12"}); err != nil {
		t.Fatal(err)
	}
	if len(fake.callLog) != 0 {
		t.Errorf("an unchanged sync ran %v", fake.callLog)
	}

	// Dropping one deletes only it.
	if err := m.SyncPrefixes(map[netip.Prefix]string{cidrA: "10.20.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	if callsWith(fake, "route -n delete -net 172.16.0.0/12") != 1 || callsWith(fake, "delete -net 10.20.0.0/16") != 0 {
		t.Errorf("calls = %v", fake.callLog)
	}
	if _, held := m.GetNetRoutes()[cidrB]; held {
		t.Error("the dropped network must be forgotten")
	}

	var kinds []string
	for _, c := range *changes {
		if c.Prefix.IsValid() == c.Destination.IsValid() {
			t.Errorf("a network route change must set Prefix and not Destination: %+v", c)
		}
		kinds = append(kinds, c.Type.String()+" "+c.Prefix.String()+" "+c.Domain)
	}
	want := []string{"added 10.20.0.0/16 10.20.0.0/16", "added 172.16.0.0/12 172.16.0.0/12", "removed 172.16.0.0/12 172.16.0.0/12"}
	if len(kinds) != 3 || !(strings.Contains(strings.Join(kinds, "|"), want[0]) && strings.Contains(strings.Join(kinds, "|"), want[1])) || kinds[2] != want[2] {
		t.Errorf("changes = %v, want %v", kinds, want)
	}
}

func TestSyncPrefixesUsesTheInterfaceWhenTheTunnelHasNoGateway(t *testing.T) {
	m, fake := newTestManager(t)
	m.SetVPNState(netip.Addr{}, tun5)

	if err := m.SyncPrefixes(map[netip.Prefix]string{cidrA: "10.20.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	if callsWith(fake, "route -n add -net 10.20.0.0/16 -interface "+tun5) != 1 {
		t.Errorf("calls = %v", fake.callLog)
	}
}

func TestCleanupRemovesNetworkRoutesWithGatewayAndWithInterface(t *testing.T) {
	for _, tc := range []struct {
		name    string
		gateway netip.Addr
	}{
		{"gateway", netip.MustParseAddr("10.8.0.1")},
		{"interface", netip.Addr{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, fake := newTestManager(t)
			m.SetVPNState(tc.gateway, tun7)
			changes := observe(m)
			if err := m.SyncPrefixes(map[netip.Prefix]string{cidrA: "corp"}); err != nil {
				t.Fatal(err)
			}
			if err := m.AddRoute(netip.MustParseAddr("10.9.9.9"), "host", false); err != nil {
				t.Fatal(err)
			}

			if err := m.Cleanup(); err != nil {
				t.Fatalf("cleanup: %v", err)
			}
			if callsWith(fake, "route -n delete -net 10.20.0.0/16") != 1 || callsWith(fake, "route -n delete -host 10.9.9.9") != 1 {
				t.Errorf("calls = %v", fake.callLog)
			}
			if m.GetRouteCount() != 0 || len(m.GetNetRoutes()) != 0 {
				t.Error("Cleanup must forget every network route")
			}
			last := (*changes)[len(*changes)-1]
			if last.Type != RouteRemoved || last.Prefix != cidrA || last.Domain != "corp" {
				t.Errorf("last change = %+v, want the network removal observed", last)
			}
		})
	}
}

func TestACleanupDeleteFailureKeepsTheNetworkRouteAndRetries(t *testing.T) {
	m, fake := newTestManager(t)
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun7)
	if err := m.SyncPrefixes(map[netip.Prefix]string{cidrA: "corp"}); err != nil {
		t.Fatal(err)
	}
	fake.failNextCall("delete_net 10.20.0.0/16", errors.New("operation not permitted"))

	if err := m.Cleanup(); err == nil {
		t.Fatal("cleanup must report the failed delete")
	}
	if _, held := m.GetNetRoutes()[cidrA]; !held {
		t.Error("a route that could not be deleted is still ours")
	}
	if degraded, _ := m.Degraded(); !degraded {
		t.Error("the failed delete must be recorded as outstanding")
	}
	if err := m.RetryPendingCleanup(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if callsWith(fake, "route -n delete -net 10.20.0.0/16") != 2 {
		t.Errorf("calls = %v, want the delete retried with -net", fake.callLog)
	}
}

func TestAnotherTunnelsNetworkRouteIsAConflictNotAdopted(t *testing.T) {
	m, fake := newTestManager(t)
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun7)
	// Something else (another VPN's tunnel) already routes the network.
	fake.routes = []RouteEntry{{Destination: "10.20.0.0/16", Gateway: "10.9.0.1", Flags: "UGSc", Interface: tun9}}

	err := m.SyncPrefixes(map[netip.Prefix]string{cidrA: "10.20.0.0/16"})
	if !errors.Is(err, ErrRouteOwnedElsewhere) {
		t.Fatalf("err = %v, want ErrRouteOwnedElsewhere", err)
	}
	if !strings.Contains(err.Error(), tun9) {
		t.Errorf("err = %v, want it to name the tunnel that holds the network", err)
	}
	if _, held := m.GetNetRoutes()[cidrA]; held {
		t.Error("a conflicting route must not be adopted")
	}
	if degraded, reason := m.Degraded(); degraded {
		t.Errorf("a conflict must not degrade the manager: %s", reason)
	}
	// The manager did not delete a route that is not its own.
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun7)
	if err := m.SyncPrefixes(nil); err != nil {
		t.Fatal(err)
	}
	if callsWith(fake, "delete -net") != 0 {
		t.Errorf("calls = %v, want no delete of another tunnel's route", fake.callLog)
	}
}

func TestALeftoverNetworkRouteThroughThisTunnelIsAdopted(t *testing.T) {
	m, fake := newTestManager(t)
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun7)
	fake.routes = []RouteEntry{{Destination: "10.20.0.0/16", Gateway: "10.8.0.1", Flags: "UGSc", Interface: tun7}}

	if err := m.SyncPrefixes(map[netip.Prefix]string{cidrA: "10.20.0.0/16"}); err != nil {
		t.Fatalf("a route already leading through this tunnel is ours to adopt: %v", err)
	}
	if _, held := m.GetNetRoutes()[cidrA]; !held {
		t.Error("the leftover route must be adopted")
	}
}

func TestTwoManagersNeverHoldTheSameNetworkRoute(t *testing.T) {
	fake := newFakeRunner()
	registry := NewHostRouteRegistry()
	first, _ := newTestManager(t)
	first.table = newCommandTable(fake)
	first.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun7)
	first.SetHostRouteRegistry(registry)
	second := newSecondManager(t, fake)
	second.SetVPNState(netip.MustParseAddr("10.9.0.1"), tun9)
	second.SetHostRouteRegistry(registry)

	if err := first.SyncPrefixes(map[netip.Prefix]string{cidrA: "a"}); err != nil {
		t.Fatal(err)
	}
	err := second.SyncPrefixes(map[netip.Prefix]string{cidrA: "a"})
	if !errors.Is(err, ErrRouteOwnedElsewhere) {
		t.Fatalf("err = %v, want the registry to refuse a second owner", err)
	}
	if callsWith(fake, "add -net 10.20.0.0/16 10.9.0.1") != 0 {
		t.Errorf("the second manager must not even try: %v", fake.callLog)
	}

	// Once the first gives it up, the second may take it.
	if err := first.SyncPrefixes(nil); err != nil {
		t.Fatal(err)
	}
	if err := second.SyncPrefixes(map[netip.Prefix]string{cidrA: "a"}); err != nil {
		t.Fatalf("after release: %v", err)
	}
	if owner, held := registry.PrefixOwner(cidrA); !held || owner != tun9 {
		t.Errorf("owner = %q held=%v, want utun9", owner, held)
	}
}

func TestSyncPrefixesRefusesUnroutableNetworks(t *testing.T) {
	m, fake := newTestManager(t)
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun7)
	for _, bad := range []string{"0.0.0.0/1", "10.0.0.0/7", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/8", "0.0.0.0/8"} {
		p := netip.MustParsePrefix(bad)
		if err := m.SyncPrefixes(map[netip.Prefix]string{p: bad}); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if err := m.SyncPrefixes(map[netip.Prefix]string{netip.MustParsePrefix("2001:db8::/32"): "v6"}); err == nil {
		t.Error("an IPv6 prefix was accepted")
	}
	if callsWith(fake, "add -net") != 0 {
		t.Errorf("calls = %v, want none", fake.callLog)
	}
}

func TestRouteMatchUsesTheLongestPrefixAndHostRoutesWin(t *testing.T) {
	m, _ := newTestManager(t)
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun7)
	wide, narrow := netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.20.30.0/24")
	if err := m.SyncPrefixes(map[netip.Prefix]string{wide: "wide", narrow: "narrow"}); err != nil {
		t.Fatal(err)
	}
	host := netip.MustParseAddr("10.20.30.40")
	if err := m.AddRoute(host, "host-entry", false); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		ip       string
		want     string
		wantBits int
		ok       bool
	}{
		{"10.20.30.40", "host-entry", 32, true},
		{"10.20.30.41", "narrow", 24, true},
		{"10.20.99.1", "wide", 16, true},
		{"10.21.0.1", "", -1, false},
	} {
		got, bits, ok := m.RouteMatch(netip.MustParseAddr(tc.ip))
		if got != tc.want || ok != tc.ok || (ok && bits != tc.wantBits) {
			t.Errorf("RouteMatch(%s) = %q,%d,%v want %q,%d,%v", tc.ip, got, bits, ok, tc.want, tc.wantBits, tc.ok)
		}
		if domain, routed := m.RoutedFor(netip.MustParseAddr(tc.ip)); domain != tc.want || routed != tc.ok {
			t.Errorf("RoutedFor(%s) = %q,%v", tc.ip, domain, routed)
		}
	}
}

func TestParseNetstatDest(t *testing.T) {
	for raw, want := range map[string]string{
		"10.20.0.0/16":  "10.20.0.0/16",
		"10.20/16":      "10.20.0.0/16",
		"10.20.30/24":   "10.20.30.0/24",
		"10/8":          "10.0.0.0/8",
		"172.16/12":     "172.16.0.0/12",
		"10.20.30.0/25": "10.20.30.0/25",
		"10.20.5.1/16":  "10.20.0.0/16",
	} {
		got, ok := parseNetstatDest(raw)
		if !ok || got.String() != want {
			t.Errorf("parseNetstatDest(%q) = %v,%v want %s", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"default", "10.20.30.40", "link#4", "10.20.30.40.5/24", "fe80::/10", ""} {
		if p, ok := parseNetstatDest(raw); ok {
			t.Errorf("parseNetstatDest(%q) = %v, want it rejected", raw, p)
		}
	}
}
