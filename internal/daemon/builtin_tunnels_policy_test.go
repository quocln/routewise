package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
)

// --- profile DNS: routed only while dns.use_vpn_dns is on, and never over DNS the Mac already uses ---

func TestProfileDNSIsRoutedOnlyWhileUseVPNDNSIsOn(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	d := e.d
	if d.useVPNDNS.Load() {
		t.Skip("the test environment starts with dns.use_vpn_dns on")
	}
	office := e.importWireGuard(t, "Office", "vpn.example.com:51820") // DNS = 10.8.0.1
	travel := e.importOutline(t, "Travel", "198.51.100.7")            // default DNS 1.0.0.1
	officeIface := e.connect(t, office)
	travelIface := e.connect(t, travel)
	e.waitState(t, office, api.ProfileConnected)
	e.waitState(t, travel, api.ProfileConnected)
	d.syncRoutes(d.currentGeneration())

	for _, ip := range []string{"10.8.0.1", "1.0.0.1"} {
		if _, ok := k.hostRoute(ip); ok {
			t.Errorf("%s is a profile's DNS server and must not be routed while dns.use_vpn_dns is off", ip)
		}
	}

	// Turning the setting on routes them at the next sync.
	if err := d.SetUseVPNDNS(true); err != nil {
		t.Fatal(err)
	}
	d.syncRoutes(d.currentGeneration())
	waitHost(t, k, "10.8.0.1", officeIface)
	waitHost(t, k, "1.0.0.1", travelIface)
	if s := d.sessions.get(officeIface); !d.sessionDNSKnown(s) {
		t.Error("the profile's DNS must count as known once routed")
	}

	// Turning it off removes them at once, without waiting for a sync.
	if err := d.SetUseVPNDNS(false); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.8.0.1", "1.0.0.1"} {
		if _, ok := k.hostRoute(ip); ok {
			t.Errorf("%s must leave the routing table as soon as dns.use_vpn_dns is turned off", ip)
		}
	}
	d.syncRoutes(d.currentGeneration())
	if _, ok := k.hostRoute("1.0.0.1"); ok {
		t.Error("a later sync must not bring the DNS route back while the setting is off")
	}
}

func TestProfileDNSThatTheMacOrRouteWiseAlreadyUsesIsRefused(t *testing.T) {
	cases := []struct {
		name      string
		configure func(d *Daemon)
		reason    string
	}{
		{"a configured system resolver (fresh read)", func(d *Daemon) {
			d.hooks.systemNameservers = func(context.Context) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.168.7.1"), netip.MustParseAddr("1.0.0.1")}, nil
			}
		}, "configured DNS servers"},
		{"a configured system resolver (baseline)", func(d *Daemon) {
			d.dnsMu.Lock()
			d.dnsBaseline = map[netip.Addr]bool{netip.MustParseAddr("1.0.0.1"): true}
			d.dnsMu.Unlock()
		}, "configured DNS servers"},
		{"an entry of dns.servers", func(d *Daemon) { d.dnsServers = []string{"8.8.8.8", "1.0.0.1"} }, "dns.servers"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := newFakeKernel()
			e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
			d := e.d
			c.configure(d)
			if err := d.SetUseVPNDNS(true); err != nil {
				t.Fatal(err)
			}
			id := e.importOutline(t, "Travel", "198.51.100.7")
			iface := e.connect(t, id)
			e.waitState(t, id, api.ProfileConnected)
			d.syncRoutes(d.currentGeneration())

			if _, ok := k.hostRoute("1.0.0.1"); ok {
				t.Fatal("a resolver the Mac already uses must not be routed into the profile's tunnel")
			}
			if !e.hasActivity(activity.KindRefused, vpnDNSRouteLabel, c.reason) {
				t.Errorf("no refusal recorded mentioning %q: %v", c.reason, e.activityDetails(activity.KindRefused, vpnDNSRouteLabel))
			}
			if !strings.Contains(e.logs.String(), "not routing the profile's DNS server") {
				t.Error("the refusal must be logged")
			}
			s := d.sessions.get(iface)
			if !d.sessionDNSKnown(s) {
				t.Error("a refused DNS server settles the decision; wildcard resolver files must not wait for it forever")
			}
			if c.name != "an entry of dns.servers" && slicesContain(s.resolver.Upstreams(), "1.0.0.1") {
				t.Errorf("the profile's names must resolve through dns.servers, upstreams = %v", s.resolver.Upstreams())
			}
			// The decision is made once, not at every sync.
			refusals := len(e.activityDetails(activity.KindRefused, vpnDNSRouteLabel))
			d.syncRoutes(d.currentGeneration())
			d.syncRoutes(d.currentGeneration())
			if got := len(e.activityDetails(activity.KindRefused, vpnDNSRouteLabel)); got != refusals {
				t.Errorf("syncs recorded %d more refusals", got-refusals)
			}
		})
	}
}

func slicesContain(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestTwoOutlineProfilesSharingTheDefaultDNSRouteItOnlyForOne(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	d := e.d
	if err := d.SetUseVPNDNS(true); err != nil {
		t.Fatal(err)
	}
	a := e.importOutline(t, "Alpha", "198.51.100.7")
	b := e.importOutline(t, "Beta", "198.51.100.8")
	ifaceA := e.connect(t, a)
	ifaceB := e.connect(t, b)
	e.waitState(t, a, api.ProfileConnected)
	e.waitState(t, b, api.ProfileConnected)
	d.syncRoutes(d.currentGeneration())

	holder, ok := k.hostRoute("1.0.0.1")
	if !ok {
		t.Fatal("one of the profiles must route the shared DNS server")
	}
	holderID, other, otherID := a, ifaceB, b
	if holder == ifaceB {
		holderID, other, otherID = b, ifaceA, a
	}
	loser := d.sessions.get(other)
	d.dnsMu.Lock()
	loserDNS := len(loser.vpnDNS)
	d.dnsMu.Unlock()
	if loserDNS != 0 {
		t.Errorf("the second profile must not claim the shared DNS server, vpnDNS = %v", loser.vpnDNS)
	}
	if slicesContain(loser.resolver.Upstreams(), "1.0.0.1") && !slicesContain(d.dnsServers, "1.0.0.1") {
		t.Errorf("the second profile's names must resolve through dns.servers, upstreams = %v", loser.resolver.Upstreams())
	}
	if !e.hasActivity(activity.KindRefused, vpnDNSRouteLabel, "connected profile") {
		t.Errorf("the refusal must name the other profile: %v", e.activityDetails(activity.KindRefused, vpnDNSRouteLabel))
	}
	if !d.sessionDNSKnown(loser) {
		t.Error("the refused profile's DNS decision must be settled")
	}

	// When the holder leaves, the other profile may have the server.
	if err := d.ProfileDisconnect(holderID); err != nil {
		t.Fatal(err)
	}
	d.syncRoutes(d.currentGeneration())
	waitHost(t, k, "1.0.0.1", other)
	_ = otherID
}

func TestADetectedTunnelsBoundDNSIsStillAlwaysRoutedEvenWithUseVPNDNSOff(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	d := e.d
	d.hooks.vpnNameservers = func(_ context.Context, iface string, _ bool) ([]netip.Addr, bool, error) {
		if iface == awsIface {
			return []netip.Addr{netip.MustParseAddr("10.200.0.2")}, true, nil
		}
		return nil, false, nil
	}
	if d.useVPNDNS.Load() {
		t.Skip("the test environment starts with dns.use_vpn_dns on")
	}
	e.connectAWS()
	waitForSession(t, d, awsIface)
	waitHost(t, k, "10.200.0.2", awsIface)
}

// --- Outline address pool ---

func TestOutlineAddressSkipsTheLANAndWireGuardAddresses(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	d := e.d
	// The LAN uses 10.233.0.0/24, and a WireGuard profile's interface address is
	// 10.233.1.0.
	d.hooks.localPrefixes = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("10.233.0.0/24")} }
	otherKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32))
	if _, err := d.ProfileImport(api.ProfileImportParams{Kind: "wireguard", Name: "Home",
		WireguardConfig: wireGuardConfWith(otherKey, "10.233.1.0/24")}); err != nil {
		t.Fatalf("import WireGuard: %v", err)
	}

	id := e.importOutline(t, "Travel", "198.51.100.7")
	e.connect(t, id)
	e.waitState(t, id, api.ProfileConnected)
	got := e.starter.request(0).Address
	if want := netip.MustParseAddr("10.233.1.1"); got != want {
		t.Errorf("Outline address = %v, want %v: the LAN's /24 and the WireGuard address 10.233.1.0 are skipped", got, want)
	}
}

func TestOutlineAddressFailsClearlyWhenThePoolIsTaken(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.d.hooks.localPrefixes = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("10.233.0.0/16")} }
	id := e.importOutline(t, "Travel", "198.51.100.7")
	if err := e.d.ProfileConnect(id); err != nil {
		t.Fatal(err)
	}
	e.waitState(t, id, api.ProfileError)
	if st := e.profileState(id); !strings.Contains(st.Error, "no free tunnel address") {
		t.Errorf("error = %q, want a clear message that no address is free", st.Error)
	}
	if e.starter.startCount() != 0 {
		t.Error("no tunnel may be started without an address")
	}
}

func TestAllocationAvoidsAndStillReusesPerProfile(t *testing.T) {
	m := newTunnelManager()
	avoid := func(a netip.Addr) bool { return a == netip.MustParseAddr("10.233.0.2") }
	a, err := m.allocOutlineAddrAvoiding("a", avoid)
	if err != nil || a != netip.MustParseAddr("10.233.0.3") {
		t.Fatalf("first address = %v, %v; want 10.233.0.3", a, err)
	}
	if again, _ := m.allocOutlineAddrAvoiding("a", avoid); again != a {
		t.Errorf("a profile keeps its address while it holds one, got %v", again)
	}
}

// --- WireGuard AllowedIPs ---

func TestEntriesOutsideThePeersAllowedIPsAreRefusedWithAReason(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.starter.onStart = func(_ tunnelStartRequest, tn *fakeTunnel) {
		tn.allowed = []netip.Prefix{
			netip.MustParsePrefix("10.8.0.0/24"),
			netip.MustParsePrefix("10.9.0.0/25"), netip.MustParsePrefix("10.9.0.128/25"), // together a /24
		}
	}
	e.answers.set("inside.example.com", "10.8.0.7")
	e.answers.set("outside.example.com", "203.0.113.5")
	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	e.setList(t, id, "10.8.0.5", "192.0.2.9", "10.8.0.0/25", "10.8.0.0/16", "10.9.0.0/24",
		"inside.example.com", "outside.example.com")
	iface := e.connect(t, id)
	e.waitState(t, id, api.ProfileConnected)

	waitHost(t, k, "10.8.0.5", iface)
	waitHost(t, k, "10.8.0.7", iface)
	waitFor(t, "the covered CIDRs to route", func() bool { return k.hasNet("10.8.0.0/25", iface) && k.hasNet("10.9.0.0/24", iface) })
	for _, ip := range []string{"192.0.2.9", "203.0.113.5"} {
		if _, ok := k.hostRoute(ip); ok {
			t.Errorf("%s is outside the peer's AllowedIPs and must not be routed", ip)
		}
	}
	if k.hasNet("10.8.0.0/16", iface) {
		t.Error("a /16 that the peer's /24 does not cover must not be routed")
	}
	for _, entry := range []string{"192.0.2.9", "10.8.0.0/16", "outside.example.com"} {
		if !e.hasActivity(activity.KindRefused, entry, "outside the peer's AllowedIPs") {
			t.Errorf("no refusal for %s with the reason: %v", entry, e.activityDetails(activity.KindRefused, entry))
		}
	}
	for _, entry := range []string{"10.8.0.5", "10.8.0.0/25", "10.9.0.0/24", "inside.example.com"} {
		if len(e.activityDetails(activity.KindRefused, entry)) != 0 {
			t.Errorf("%s is covered and must not be refused: %v", entry, e.activityDetails(activity.KindRefused, entry))
		}
	}
}

func TestAllowedIPsCoverage(t *testing.T) {
	pfx := func(texts ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range texts {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	addr := netip.MustParseAddr
	if !addrCovered(pfx("0.0.0.0/0"), addr("203.0.113.5")) {
		t.Error("0.0.0.0/0 covers everything")
	}
	if addrCovered(pfx(), addr("10.0.0.1")) {
		t.Error("no allowed prefix covers nothing")
	}
	if addrCovered(pfx("::/0"), addr("10.0.0.1")) {
		t.Error("an IPv6 prefix does not cover an IPv4 address")
	}
	if !addrCovered(pfx("10.0.0.0/8"), addr("10.255.255.255")) || addrCovered(pfx("10.0.0.0/8"), addr("11.0.0.0")) {
		t.Error("prefix edges")
	}
	if !addrCovered(pfx("1.2.3.4/32"), addr("1.2.3.4")) || addrCovered(pfx("1.2.3.4/32"), addr("1.2.3.5")) {
		t.Error("a /32 covers exactly one address")
	}
	if !prefixCovered(pfx("10.0.0.0/9", "10.128.0.0/9"), netip.MustParsePrefix("10.0.0.0/8")) {
		t.Error("two adjacent halves cover the whole")
	}
	if prefixCovered(pfx("10.0.0.0/10", "10.128.0.0/9"), netip.MustParsePrefix("10.0.0.0/8")) {
		t.Error("a gap must not count as covered")
	}
	if prefixCovered(pfx("10.0.0.0/24"), netip.MustParsePrefix("10.0.0.0/16")) {
		t.Error("a narrower allowed prefix must not cover a wider entry")
	}
	if !prefixCovered(pfx("10.0.0.0/16"), netip.MustParsePrefix("10.0.5.0/24")) {
		t.Error("a wider allowed prefix covers a narrower entry")
	}
	if !prefixCovered(pfx("0.0.0.0/1", "128.0.0.0/1"), netip.MustParsePrefix("8.8.8.0/24")) {
		t.Error("the two-halves default route covers any entry")
	}
}

// --- connect, remove, import ---

func TestAConnectAfterARemovalNeverLeavesASupervisorRetrying(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	d := e.d
	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")

	// A supervisor whose profile is gone ends and forgets itself; it does not
	// retry every minute for ever.
	if _, err := d.store.RemoveProfile(id); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &profileRun{id: id, cancel: cancel, finished: make(chan struct{}), state: api.ProfileConnecting}
	d.tunnels.mu.Lock()
	d.tunnels.runs[id] = run
	d.tunnels.mu.Unlock()
	go d.superviseProfile(ctx, run)
	select {
	case <-run.finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor of a removed profile kept running")
	}
	if d.tunnels.snapshot(id).exists {
		t.Error("the run of a removed profile must leave the table")
	}
	if got := e.clock.waited(); len(got) != 0 {
		t.Errorf("a removed profile must not enter the retry backoff, waits = %v", got)
	}

	// A connect that comes after the removal is refused outright.
	if err := d.ProfileConnect(id); err == nil {
		t.Error("connecting a removed profile must fail")
	}
	if err := d.startRun(id); err == nil {
		t.Error("startRun must re-check that the profile still exists under the control lock")
	}
}

func TestConnectsRacingARemovalNeverLeaveARun(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	d := e.d
	for round := 0; round < 15; round++ {
		id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _ = d.ProfileConnect(id) }()
		}
		if err := d.ProfileRemove(id); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		waitFor(t, "no run left for the removed profile", func() bool { return !d.tunnels.snapshot(id).exists })
		if _, ok := d.store.Profile(id); ok {
			t.Fatal("the profile must be gone")
		}
	}
	if got := e.clock.waited(); len(got) != 0 {
		t.Errorf("no supervisor may be left retrying, backoff waits = %v", got)
	}
}

func TestImportWithAutoConnectConnectsAtOnce(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	id, err := e.d.ProfileImport(api.ProfileImportParams{Kind: "outline", Name: "Travel", AccessKey: outlineAccessKey("198.51.100.7"), AutoConnect: true})
	if err != nil {
		t.Fatal(err)
	}
	e.waitState(t, id, api.ProfileConnected)
	if e.starter.startCount() != 1 {
		t.Errorf("start count = %d, want one connection from the import", e.starter.startCount())
	}

	manual := e.importOutline(t, "Manual", "198.51.100.8")
	if st := e.profileState(manual); st.State != api.ProfileDisconnected {
		t.Errorf("an import without auto-connect must stay disconnected, got %q", st.State)
	}
}

func TestAnImportWhoseAutoConnectFailsStillSucceeds(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.starter.plan = func(int, tunnelStartRequest) ([]netip.Addr, error) { return nil, errors.New("utun unavailable") }
	id, err := e.d.ProfileImport(api.ProfileImportParams{Kind: "outline", Name: "Travel", AccessKey: outlineAccessKey("198.51.100.7"), AutoConnect: true})
	if err != nil || id == "" {
		t.Fatalf("the import must succeed even if the connection then fails: %v", err)
	}
	e.waitState(t, id, api.ProfileError)
}

func TestTwoWireGuardProfilesMayNotShareAListenPort(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	withPort := func(key, addr string) string {
		return strings.Replace(wireGuardConfWith(key, addr), "DNS = 10.8.0.1", "DNS = 10.8.0.1\nListenPort = 51999", 1)
	}
	k1 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32))
	k2 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x62}, 32))
	if _, err := e.d.ProfileImport(api.ProfileImportParams{Kind: "wireguard", Name: "One", WireguardConfig: withPort(k1, "10.20.0.2/32")}); err != nil {
		t.Fatal(err)
	}
	_, err := e.d.ProfileImport(api.ProfileImportParams{Kind: "wireguard", Name: "Two", WireguardConfig: withPort(k2, "10.21.0.2/32")})
	if err == nil || !strings.Contains(err.Error(), "listen port 51999") || !strings.Contains(err.Error(), "One") {
		t.Errorf("a shared ListenPort must be rejected naming the other profile, got %v", err)
	}
	if strings.Contains(err.Error(), k2) {
		t.Error("the error must not carry the key")
	}
}

func TestConcurrentImportsOfOneKeyCannotBothSucceed(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	succeeded := 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.d.ProfileImport(api.ProfileImportParams{Kind: "wireguard", WireguardConfig: wireGuardConf("vpn.example.com:51820")})
			if err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if succeeded != 1 {
		t.Errorf("%d concurrent imports of the same key succeeded, want exactly 1", succeeded)
	}
}

// --- gateway refresh ---

func TestOnlyDetectedTunnelsPauseTheGatewayRefresh(t *testing.T) {
	k := newFakeKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	d := e.d
	gen := d.currentGeneration()
	if d.gatewayRefreshPaused(gen) {
		t.Fatal("with no tunnel the gateway refresh runs")
	}

	id := e.importWireGuard(t, "Office", "vpn.example.com:51820")
	e.connect(t, id)
	e.waitState(t, id, api.ProfileConnected)
	if d.gatewayRefreshPaused(gen) {
		t.Error("a built-in tunnel never changes the default route, so it must not pause the gateway refresh")
	}

	e.connectAWS()
	waitForSession(t, d, awsIface)
	if !d.gatewayRefreshPaused(gen) {
		t.Error("a detected tunnel pauses the gateway refresh")
	}
}

func TestProbeTargetIsTheProfilesFirstIPv4DNSOnPort53(t *testing.T) {
	cases := map[string]struct {
		dns  []string
		want string
	}{
		"profile DNS":      {[]string{"9.9.9.9", "1.1.1.1"}, "9.9.9.9:53"},
		"skips junk":       {[]string{"not-an-ip", "::1", "0.0.0.0", "8.8.4.4"}, "8.8.4.4:53"},
		"empty -> default": {nil, defaultOutlineDNS + ":53"},
	}
	for name, c := range cases {
		if got := probeTarget(c.dns).String(); got != c.want {
			t.Errorf("%s: probe target %s, want %s", name, got, c.want)
		}
	}
}
