package daemon

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/dnswatch"
)

func waitNet(t *testing.T, k *fakeKernel, cidr, iface string) {
	t.Helper()
	waitFor(t, cidr+" to route through "+iface, func() bool { return k.hasNet(cidr, iface) })
}

func waitNoNet(t *testing.T, k *fakeKernel, cidr string) {
	t.Helper()
	waitFor(t, cidr+" to leave the routing table", func() bool {
		return !slices.ContainsFunc(k.netRoutes(), func(n kernelNetRoute) bool { return n.dest == cidr })
	})
}

func holdsNet(d *Daemon, iface, cidr string) bool {
	s := d.sessions.get(iface)
	if s == nil {
		return false
	}
	_, ok := s.manager.GetNetRoutes()[netip.MustParsePrefix(cidr)]
	return ok
}

func refusals(d *Daemon, name string) []activity.Event {
	var out []activity.Event
	for _, e := range eventsOfKind(d, activity.KindRefused) {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

func syncNow(d *Daemon) { d.syncRoutes(d.currentGeneration()) }

// --- ownership: a client's own CIDR goes through that client's tunnel only ---

func TestACIDRInAClientListRoutesOnlyThroughThatClient(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, []string{"10.20.0.0/16"}, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForSession(t, d, wgIface)
	waitForSession(t, d, awsIface)

	waitNet(t, k, "10.20.0.0/16", awsIface)
	if holdsNet(d, wgIface, "10.20.0.0/16") || k.has("add -net 10.20.0.0/16 "+wgGW) {
		t.Error("AWS's own CIDR must never be routed through WireGuard")
	}
	if !k.has("add -net 10.20.0.0/16 " + awsGW) {
		t.Errorf("the CIDR must be added as a network route through AWS's gateway: %v", k.log())
	}

	// AWS goes down: the CIDR goes direct. It does not fall to WireGuard.
	env.disconnectAWS()
	waitFor(t, "the AWS session to go", func() bool { return d.sessions.get(awsIface) == nil })
	waitNoNet(t, k, "10.20.0.0/16")
	syncNow(d)
	if holdsNet(d, wgIface, "10.20.0.0/16") || k.has("add -net 10.20.0.0/16 "+wgGW) {
		t.Error("a CIDR must go direct while its tunnel is down, not through another VPN")
	}

	// AWS returns and takes it back.
	env.connectAWS()
	waitNet(t, k, "10.20.0.0/16", awsIface)
}

func TestADegradedTunnelsCIDRGoesDirectNotThroughAnotherVPN(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, []string{"wg.example.com", "10.20.0.0/16"}, nil, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	env.answers.set("wg.example.com", "10.100.0.1")
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForRoutes(t, d, wgIface, "10.100.0.1", "10.50.0.1")
	waitNet(t, k, "10.20.0.0/16", wgIface)

	// WireGuard cannot delete an old address, which degrades it.
	k.failNext("delete -host 10.100.0.1", context.DeadlineExceeded)
	env.answers.set("wg.example.com", "10.100.0.9")
	syncNow(d)
	if degraded, _ := d.sessions.get(wgIface).manager.Degraded(); !degraded {
		t.Fatal("test setup: WireGuard should be degraded")
	}
	syncNow(d)
	if holdsNet(d, awsIface, "10.20.0.0/16") || k.has("add -net 10.20.0.0/16 "+awsGW) {
		t.Error("a degraded tunnel's CIDR must not be handed to another VPN")
	}
}

func TestAnAnyVPNCIDRRoutesThroughTheTopHealthyTunnel(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"172.16.0.0/12"}, nil, nil, nil)
	d := env.d

	// Only AWS is up: it takes the Any VPN list.
	env.connectAWS()
	waitNet(t, k, "172.16.0.0/12", awsIface)

	// WireGuard outranks AWS: the network moves, and is never in the table twice.
	env.connectWG()
	waitNet(t, k, "172.16.0.0/12", wgIface)
	waitFor(t, "AWS to give the network up", func() bool { return !holdsNet(d, awsIface, "172.16.0.0/12") })
	if n := len(k.netRoutes()); n != 1 {
		t.Errorf("net routes = %v, want exactly one", k.netRoutes())
	}

	// WireGuard goes away: the list falls to the next healthy tunnel.
	env.disconnectWG()
	waitNet(t, k, "172.16.0.0/12", awsIface)
}

func TestAClientListCIDRIsNotRoutedByTheAnyVPNOwner(t *testing.T) {
	k := newFakeKernel()
	// Both lists hold the same network; AWS's own list owns it.
	env := newKernelEnv(t, k, []string{"10.20.0.0/16"}, nil, []string{"10.20.0.0/16"}, nil)
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitNet(t, k, "10.20.0.0/16", awsIface)
	syncNow(d)
	if holdsNet(d, wgIface, "10.20.0.0/16") {
		t.Error("the Any VPN owner must not take a network a client's own list holds")
	}
	if got := refusals(d, "10.20.0.0/16"); len(got) != 0 {
		t.Errorf("an Any VPN duplicate is not a conflict between tunnels: %+v", got)
	}
	env.disconnectAWS()
	waitNoNet(t, k, "10.20.0.0/16")
}

func TestTheSameCIDRInTwoClientListsGoesToTheHigherPriorityAndRecordsARefusal(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, []string{"10.30.0.0/16"}, []string{"10.30.0.0/16"}, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForSession(t, d, wgIface)
	waitForSession(t, d, awsIface)

	waitNet(t, k, "10.30.0.0/16", wgIface)
	waitFor(t, "the refusal to be recorded", func() bool { return len(refusals(d, "10.30.0.0/16")) > 0 })
	if holdsNet(d, awsIface, "10.30.0.0/16") || k.hasNet("10.30.0.0/16", awsIface) {
		t.Error("the lower-priority tunnel must not hold a network the higher one routes")
	}
	got := refusals(d, "10.30.0.0/16")
	if len(got) != 1 {
		t.Fatalf("refusals = %+v, want exactly one however many syncs ran", got)
	}
	syncNow(d)
	syncNow(d)
	if again := refusals(d, "10.30.0.0/16"); len(again) != 1 {
		t.Errorf("refusals after more syncs = %d, want it recorded once", len(again))
	}
	if got[0].Interface != wgIface || !strings.Contains(got[0].Detail, "lower priority") {
		t.Errorf("refusal = %+v, want it to name the winning tunnel and the priority rule", got[0])
	}

	// The winner goes away: the entry belongs to its client alone, so it goes
	// direct and never falls through to the lower-priority tunnel that lists it.
	env.disconnectWG()
	waitFor(t, "the winner's route to go", func() bool { return !k.hasNet("10.30.0.0/16", wgIface) })
	syncNow(d)
	syncNow(d)
	if len(k.netRoutes()) != 0 || holdsNet(d, awsIface, "10.30.0.0/16") {
		t.Errorf("with the owner down the CIDR must go direct, routes = %v", k.netRoutes())
	}
}

func TestTheSameIPInTwoClientListsGoesToTheHigherPriorityAndRecordsARefusal(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, []string{"10.30.1.1"}, []string{"10.30.1.1"}, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForSession(t, d, wgIface)
	waitForSession(t, d, awsIface)

	waitHost(t, k, "10.30.1.1", wgIface)
	waitFor(t, "the refusal to be recorded", func() bool { return len(refusals(d, "10.30.1.1")) > 0 })
	if holds(d, awsIface, "10.30.1.1") {
		t.Error("the lower-priority tunnel must not hold the address")
	}
}

// --- LAN safety ---

func TestACIDRThatContainsTheLANGatewayIsRefused(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"192.168.0.0/16", "10.20.0.0/16", "192.168.7.1"}, nil, nil, func(d *Daemon) {
		d.routeManager.SetOriginalGateway(netip.MustParseAddr("192.168.7.1"), "en0")
	})
	d := env.d
	env.connectWG()
	waitNet(t, k, "10.20.0.0/16", wgIface)
	syncNow(d)

	if slices.ContainsFunc(k.netRoutes(), func(n kernelNetRoute) bool { return n.dest == "192.168.0.0/16" }) {
		t.Error("a CIDR that contains the LAN gateway must never be routed")
	}
	if _, ok := k.hostRoute("192.168.7.1"); ok {
		t.Error("the LAN gateway itself must never be routed")
	}
	got := refusals(d, "192.168.0.0/16")
	if len(got) != 1 || !strings.Contains(got[0].Detail, "local gateway") || got[0].Interface != wgIface {
		t.Fatalf("refusals = %+v, want one that names the local gateway", got)
	}
	if got := refusals(d, "192.168.7.1"); len(got) != 1 || !strings.Contains(got[0].Detail, "local gateway") {
		t.Errorf("gateway IP refusals = %+v", got)
	}
}

func TestEntriesOverlappingADirectlyConnectedNetworkAreRefused(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"10.50.0.0/16", "10.50.0.77", "10.60.0.0/16", "10.20.0.0/16"}, nil, nil, func(d *Daemon) {
		d.hooks.localPrefixes = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")} }
	})
	d := env.d
	env.connectWG()
	waitNet(t, k, "10.20.0.0/16", wgIface)
	waitNet(t, k, "10.60.0.0/16", wgIface)
	syncNow(d)

	if holdsNet(d, wgIface, "10.50.0.0/16") {
		t.Error("a CIDR that overlaps a directly connected network must be refused")
	}
	if _, ok := k.hostRoute("10.50.0.77"); ok {
		t.Error("an address on a directly connected network must be refused")
	}
	for _, name := range []string{"10.50.0.0/16", "10.50.0.77"} {
		got := refusals(d, name)
		if len(got) != 1 || !strings.Contains(got[0].Detail, "directly connected network 10.50.0.0/24") {
			t.Errorf("refusals for %s = %+v", name, got)
		}
	}
}

// --- IP entries ---

func TestAnIPEntryIsAHostRouteAndIsNeverResolved(t *testing.T) {
	k := newFakeKernel()
	var mu sync.Mutex
	var resolved []string
	env := newKernelEnv(t, k, nil, []string{"wg.example.com", "10.20.30.40", "10.20.5.1/32"}, nil, func(d *Daemon) {
		inner := d.hooks.resolveExact
		d.hooks.resolveExact = func(ctx context.Context, s *tunnelSession, domains []string) (map[string][]net.IP, error) {
			mu.Lock()
			resolved = append(resolved, domains...)
			mu.Unlock()
			return inner(ctx, s, domains)
		}
	})
	env.answers.set("wg.example.com", "10.100.0.1")
	d := env.d
	env.connectWG()

	waitHost(t, k, "10.20.30.40", wgIface)
	waitHost(t, k, "10.20.5.1", wgIface) // a /32 is stored and routed as the plain IP
	waitHost(t, k, "10.100.0.1", wgIface)
	if !k.has("add -host 10.20.30.40 "+wgGW) || k.has("add -net 10.20.30.40") || k.has("add -net 10.20.5.1") {
		t.Errorf("an IP entry is a host route, never a network route: %v", k.log())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(resolved) == 0 {
		t.Fatal("test setup: the domain was never resolved")
	}
	for _, name := range resolved {
		if looksLikeLiteralEntry(name) {
			t.Errorf("%q was looked up as if it were a domain", name)
		}
	}
	added := eventsOfKind(d, activity.KindRouteAdded)
	var found bool
	for _, e := range added {
		if e.Name == "10.20.30.40" && e.Addresses[0].IP == "10.20.30.40" && e.Addresses[0].Verdict == activity.ViaVPN {
			found = true
		}
	}
	if !found {
		t.Errorf("route events = %+v, want one named for the IP entry", added)
	}
}

func looksLikeLiteralEntry(s string) bool { return net.ParseIP(s) != nil || strings.Contains(s, "/") }

// --- removal, editing, and the read paths ---

func TestRemovingAnEntryRemovesItsRouteAndEditsAreNormalized(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, []string{"10.20.0.0/16", "10.20.30.40"}, nil, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectWG()
	waitNet(t, k, "10.20.0.0/16", wgIface)
	waitHost(t, k, "10.20.30.40", wgIface)

	// A non-canonical CIDR is stored, and routed, as its network address.
	if err := d.AddDomain(wireGuardPath, "10.77.9.9/16"); err != nil {
		t.Fatal(err)
	}
	if list, _ := d.store.DomainList(wireGuardPath); !slices.Contains(list, "10.77.0.0/16") || slices.Contains(list, "10.77.9.9/16") {
		t.Fatalf("list = %v, want the CIDR stored canonically", list)
	}
	syncNow(d)
	waitNet(t, k, "10.77.0.0/16", wgIface)
	if err := d.AddDomain(wireGuardPath, "10.77.0.1/16"); err == nil {
		t.Error("the same network written another way must be a duplicate")
	}

	if err := d.RemoveDomain(wireGuardPath, "10.20.5.5/16"); err != nil { // any spelling of the entry
		t.Fatal(err)
	}
	if err := d.RemoveDomain(wireGuardPath, "10.20.30.40"); err != nil {
		t.Fatal(err)
	}
	syncNow(d)
	waitNoNet(t, k, "10.20.0.0/16")
	waitNoHost(t, k, "10.20.30.40")
	if !k.hasNet("10.77.0.0/16", wgIface) {
		t.Error("removing one entry must leave the others routed")
	}
	removed := eventsOfKind(d, activity.KindRouteRemoved)
	var seen bool
	for _, e := range removed {
		if e.Name == "10.20.0.0/16" && e.Addresses[0].IP == "10.20.0.0/16" && e.Addresses[0].Verdict == activity.Direct {
			seen = true
		}
	}
	if !seen {
		t.Errorf("route_removed events = %+v, want the CIDR as the address and the entry as the name", removed)
	}
}

func TestRoutesListCheckHostAndDNSVerdictsConsultNetworkRoutes(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, []string{"10.20.0.0/16"}, nil, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectWG()
	waitNet(t, k, "10.20.0.0/16", wgIface)
	waitHost(t, k, "10.50.0.1", wgIface)

	var cidrRoute bool
	for _, r := range d.GetActiveRoutes() {
		if r.IP == "10.20.0.0/16" {
			cidrRoute = r.Domain == "10.20.0.0/16" && r.Interface == wgIface && r.Gateway == wgGW
		}
	}
	if !cidrRoute {
		t.Errorf("routes.list = %+v, want the CIDR in ip with its entry and tunnel", d.GetActiveRoutes())
	}
	if got := d.GetRouteCount(); got != 2 {
		t.Errorf("GetRouteCount = %d, want the network route counted with the host route", got)
	}

	check, err := d.CheckHost("10.20.5.5")
	if err != nil {
		t.Fatal(err)
	}
	a := check.Addresses[0]
	if a.RoutedFor != "10.20.0.0/16" || a.Verdict != "vpn" || a.Interface != wgIface {
		t.Errorf("check = %+v, want an address inside the CIDR reported as routed for it", a)
	}
	outside, err := d.CheckHost("10.21.5.5")
	if err != nil {
		t.Fatal(err)
	}
	if outside.Addresses[0].RoutedFor != "" || outside.Addresses[0].Verdict != "direct" {
		t.Errorf("check = %+v, want an address outside every route direct", outside.Addresses[0])
	}

	d.recordDNSAnswer(dnswatch.Answer{
		Name:      "inside.example.org",
		Addresses: []netip.Addr{netip.MustParseAddr("10.20.200.1"), netip.MustParseAddr("93.184.216.34")},
		Server:    netip.MustParseAddr("1.1.1.1"),
		Interface: "en0",
	})
	dnsEvents := eventsOfKind(d, activity.KindDNS)
	if len(dnsEvents) != 1 || dnsEvents[0].Addresses[0].Verdict != activity.ViaVPN || dnsEvents[0].Addresses[1].Verdict != activity.Direct {
		t.Errorf("DNS events = %+v, want the address inside the CIDR marked VPN and the other direct", dnsEvents)
	}
}

// --- overlaps are left to the kernel's longest prefix ---

func TestOverlappingEntriesOnDifferentTunnelsAreBothInstalled(t *testing.T) {
	k := newFakeKernel()
	// WireGuard routes the whole /16; AWS has a host inside it, and a nested
	// /24 of its own.
	env := newKernelEnv(t, k, []string{"any.example.com"}, []string{"10.20.0.0/16"}, []string{"aws.example.com", "10.20.30.0/24"}, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	env.answers.set("aws.example.com", "10.20.1.1")
	d := env.d
	env.connectWG()
	env.connectAWS()

	waitNet(t, k, "10.20.0.0/16", wgIface)
	waitNet(t, k, "10.20.30.0/24", awsIface)
	waitHost(t, k, "10.20.1.1", awsIface)

	sessions := d.sessionList()
	for ip, wantIface := range map[string]string{
		"10.20.1.1":  awsIface, // the /32 beats the /16
		"10.20.30.9": awsIface, // the /24 beats the /16
		"10.20.99.9": wgIface,  // only the /16 covers it
	} {
		s, _ := routedBy(sessions, netip.MustParseAddr(ip))
		if s == nil || s.iface != wantIface {
			t.Errorf("routedBy(%s) = %v, want the longest prefix's tunnel %s", ip, s, wantIface)
		}
	}
	if got := refusals(d, "10.20.30.0/24"); len(got) != 0 {
		t.Errorf("nested networks are not conflicts: %+v", got)
	}
}
