package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/route"
	"github.com/quocln/routewise/internal/testenv"
	"github.com/quocln/routewise/internal/vpnclient"
)

var awsClientPath = testenv.Exe("/Applications/AWS VPN Client/AWS VPN Client.app/Contents/Resources/openvpn/acvc-openvpn")

// Two managed tunnels. WireGuard is first on the allowlist, so it outranks
// AWS even though its interface name sorts after AWS's.
const (
	wgGW  = "10.0.0.1"
	awsGW = "10.7.0.1"
)

// tunnelEnv is a started additive-mode daemon with two allowed VPN clients,
// whose exact domains resolve from a table instead of the network.
type tunnelEnv struct {
	d       *Daemon
	w       *fakeVPNWatcher
	runner  *fakeRouteRunner
	dir     string // the resolver-file directory
	answers *answerTable
}

// answerTable maps exact domains to addresses and records which tunnel's
// resolver was asked for each.
type answerTable struct {
	mu      sync.Mutex
	ips     map[string][]string
	askedBy map[string][]string
}

func (a *answerTable) set(domain string, ips ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ips[domain] = ips
}

func (a *answerTable) resolve(s *tunnelSession, domains []string) (map[string][]net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string][]net.IP)
	for _, domain := range domains {
		a.askedBy[domain] = append(a.askedBy[domain], s.iface)
		for _, ip := range a.ips[domain] {
			out[domain] = append(out[domain], net.ParseIP(ip))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no answers")
	}
	return out, nil
}

func (a *answerTable) askedFor(domain string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.askedBy[domain])
}

// newTunnelEnv starts the daemon. configure runs before Start, after the
// allowlist and the lists below are in place.
func newTunnelEnv(t *testing.T, anyList, wgList, awsList []string, configure func(*Daemon)) *tunnelEnv {
	t.Helper()
	env := &tunnelEnv{answers: &answerTable{ips: map[string][]string{}, askedBy: map[string][]string{}}}
	d, w, dir, runner := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.hooks.identifyClient = func(_ context.Context, iface string) (vpnclient.Client, error) {
			switch iface {
			case wgIface:
				return vpnclient.FromPath(wireGuardPath), nil
			case awsIface:
				return vpnclient.FromPath(awsClientPath), nil
			}
			return vpnclient.Client{}, fmt.Errorf("no client owns %s", iface)
		}
		d.hooks.resolveExact = func(_ context.Context, s *tunnelSession, domains []string) (map[string][]net.IP, error) {
			return env.answers.resolve(s, domains)
		}
		// One replace, because a config with no patterns at all is invalid and
		// the lists only exist once their clients are allowed.
		cfg, _ := d.store.Snapshot()
		cfg.VPNs = []config.VPNRoute{
			{Client: wireGuardPath, Domains: domainRules(wgList)},
			{Client: awsClientPath, Domains: domainRules(awsList)},
		}
		if _, err := d.store.Replace(cfg); err != nil {
			t.Fatalf("seed config: %v", err)
		}
		if configure != nil {
			configure(d)
		}
	}, anyList...)
	env.d, env.w, env.dir, env.runner = d, w, dir, runner
	return env
}

func domainRules(patterns []string) []config.DomainRule {
	rules := make([]config.DomainRule, 0, len(patterns))
	for _, p := range patterns {
		rules = append(rules, config.DomainRule{Pattern: p})
	}
	return rules
}

func (e *tunnelEnv) connectWG()    { connectTunnel(e.w, wgIface, wgGW) }
func (e *tunnelEnv) connectAWS()   { connectTunnel(e.w, awsIface, awsGW) }
func (e *tunnelEnv) disconnectWG() { disconnectTunnel(e.w, wgIface) }
func (e *tunnelEnv) disconnectAWS() {
	disconnectTunnel(e.w, awsIface)
}

// routedTo lists the addresses the tunnel's manager routes, sorted.
func routedTo(d *Daemon, iface string) []string {
	s := d.sessions.get(iface)
	if s == nil {
		return nil
	}
	var out []string
	for ip := range s.manager.GetActiveRoutes() {
		out = append(out, ip.String())
	}
	slices.Sort(out)
	return out
}

func waitForRoutes(t *testing.T, d *Daemon, iface string, want ...string) {
	t.Helper()
	slices.Sort(want)
	waitFor(t, fmt.Sprintf("%s to route %v", iface, want), func() bool {
		return slices.Equal(routedTo(d, iface), want)
	})
}

func TestTwoSessionsRouteOnlyTheirOwnLists(t *testing.T) {
	env := newTunnelEnv(t, []string{"any.example.com"}, []string{"wg.example.com"}, []string{"aws.example.com"}, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	env.answers.set("wg.example.com", "10.100.0.1")
	env.answers.set("aws.example.com", "10.200.0.1")
	d := env.d

	env.connectWG()
	env.connectAWS()

	// The Any VPN list goes to the higher-priority tunnel; each client's own
	// list goes through that client's tunnel alone.
	waitForRoutes(t, d, wgIface, "10.100.0.1", "10.50.0.1")
	waitForRoutes(t, d, awsIface, "10.200.0.1")
	if !env.runner.has("add -host 10.100.0.1 "+wgGW) || !env.runner.has("add -host 10.200.0.1 "+awsGW) {
		t.Error("each list's address must be added through its own tunnel's gateway")
	}
	for _, crossed := range []string{"add -host 10.100.0.1 " + awsGW, "add -host 10.200.0.1 " + wgGW, "add -host 10.50.0.1 " + awsGW} {
		if env.runner.has(crossed) {
			t.Errorf("%q: a domain must never route through another VPN", crossed)
		}
	}
	if asked := env.answers.askedFor("aws.example.com"); !slices.Equal(slices.Compact(asked), []string{awsIface}) {
		t.Errorf("aws.example.com was resolved through %v, want only through its own tunnel's resolver", asked)
	}

	tunnels := d.Tunnels()
	if len(tunnels) != 2 || tunnels[0].Interface != wgIface || tunnels[1].Interface != awsIface {
		t.Fatalf("tunnels = %+v, want WireGuard (utun9) then AWS (utun7) in priority order", tunnels)
	}
	if tunnels[0].Client.Name != "WireGuard" || tunnels[0].RouteCount != 2 || tunnels[1].RouteCount != 1 {
		t.Errorf("tunnels = %+v, want WireGuard with 2 routes and AWS with 1", tunnels)
	}
	if got := d.GetRouteCount(); got != 3 {
		t.Errorf("GetRouteCount = %d, want the total of 3", got)
	}
	if iface := d.GetVPNInterface(); iface != wgIface {
		t.Errorf("GetVPNInterface = %q, want the highest-priority tunnel %s", iface, wgIface)
	}
	if managed, _ := d.VPNClients(); managed == nil || managed.Name != "WireGuard" {
		t.Errorf("managed client = %+v, want WireGuard", managed)
	}
	if st := d.GetStatus(); !st.VPNConnected || st.VPNInterface != wgIface || st.RouteCount != 3 {
		t.Errorf("status = %+v, want connected through %s with 3 routes", st, wgIface)
	}

	byIP := map[string]string{}
	for _, r := range d.GetActiveRoutes() {
		byIP[r.IP] = r.Interface
	}
	if len(byIP) != 3 || byIP["10.100.0.1"] != wgIface || byIP["10.50.0.1"] != wgIface || byIP["10.200.0.1"] != awsIface {
		t.Errorf("routes.list = %v, want every route attributed to its own tunnel", byIP)
	}

	for _, e := range eventsOfKind(d, activity.KindRouteAdded) {
		want := map[string]string{"wg.example.com": wgIface, "any.example.com": wgIface, "aws.example.com": awsIface}[e.Name]
		if e.Interface != want {
			t.Errorf("route event %q is on %q, want its own session's interface %q", e.Name, e.Interface, want)
		}
	}
}

func TestAnyVPNListMovesToTheRemainingSessionAndBack(t *testing.T) {
	env := newTunnelEnv(t, []string{"any.example.com"}, []string{"wg.example.com"}, []string{"aws.example.com"}, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	env.answers.set("wg.example.com", "10.100.0.1")
	env.answers.set("aws.example.com", "10.200.0.1")
	d := env.d

	env.connectWG()
	env.connectAWS()
	waitForRoutes(t, d, wgIface, "10.100.0.1", "10.50.0.1")
	waitForRoutes(t, d, awsIface, "10.200.0.1")

	// The higher-priority tunnel leaves: the Any VPN list moves to AWS, and
	// WireGuard's own domains go direct rather than through AWS.
	env.disconnectWG()
	waitForRoutes(t, d, awsIface, "10.200.0.1", "10.50.0.1")
	if env.runner.has("add -host 10.100.0.1 " + awsGW) {
		t.Error("a domain whose VPN is down must go direct, not through another VPN")
	}
	if !env.runner.has("add -host 10.50.0.1 " + awsGW) {
		t.Error("the Any VPN list must now route through the remaining tunnel")
	}

	// It comes back: the Any VPN list returns to it, and the address must
	// leave AWS before WireGuard adds it, since the kernel has one route per
	// destination.
	before := len(env.runner.snapshot())
	env.connectWG()
	waitForRoutes(t, d, wgIface, "10.100.0.1", "10.50.0.1")
	waitForRoutes(t, d, awsIface, "10.200.0.1")
	calls := env.runner.snapshot()[before:]
	del := indexOfCall(calls, "delete -host 10.50.0.1")
	add := indexOfCall(calls, "add -host 10.50.0.1 "+wgGW)
	if del < 0 || add < 0 || del > add {
		t.Errorf("calls = %v, want the route removed from the lower-priority tunnel before the higher one adds it", calls)
	}
}

func indexOfCall(calls []string, substr string) int {
	return slices.IndexFunc(calls, func(c string) bool { return strings.Contains(c, substr) })
}

func TestADomainWhoseVPNIsDownIsNotRouted(t *testing.T) {
	env := newTunnelEnv(t, []string{"any.example.com"}, []string{"wg.example.com"}, []string{"aws.example.com"}, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	env.answers.set("wg.example.com", "10.100.0.1")
	env.answers.set("aws.example.com", "10.200.0.1")

	env.connectAWS()
	waitForRoutes(t, env.d, awsIface, "10.200.0.1", "10.50.0.1")

	if env.runner.has("10.100.0.1") {
		t.Error("WireGuard's domain must go direct while WireGuard is down")
	}
	if asked := env.answers.askedFor("wg.example.com"); len(asked) != 0 {
		t.Errorf("wg.example.com was resolved through %v while its VPN is down", asked)
	}
}

func TestCDNConflictHigherPriorityWinsAndTheLoserIsRefused(t *testing.T) {
	env := newTunnelEnv(t, nil, []string{"wg.example.com"}, []string{"aws.example.com"}, nil)
	env.answers.set("wg.example.com", "10.9.9.9", "10.100.0.1")
	env.answers.set("aws.example.com", "10.9.9.9", "10.200.0.1")
	d := env.d

	// The lower-priority tunnel connects first and holds the shared address.
	env.connectAWS()
	waitForRoutes(t, d, awsIface, "10.200.0.1", "10.9.9.9")

	env.connectWG()
	waitForRoutes(t, d, wgIface, "10.100.0.1", "10.9.9.9")
	waitForRoutes(t, d, awsIface, "10.200.0.1")

	refused := eventsOfKind(d, activity.KindRefused)
	if len(refused) != 1 {
		t.Fatalf("refused events = %+v, want exactly one", refused)
	}
	e := refused[0]
	if e.Name != "aws.example.com" || e.Addresses[0].IP != "10.9.9.9" || e.Interface != wgIface ||
		!strings.Contains(e.Detail, wgIface) || !strings.Contains(e.Detail, "WireGuard") {
		t.Errorf("refused event = %+v, want aws.example.com's 10.9.9.9 refused because %s (WireGuard) routes it", e, wgIface)
	}

	// The same conflict at the next sync is not recorded again.
	d.syncRoutes(d.currentGeneration())
	d.syncRoutes(d.currentGeneration())
	if got := len(eventsOfKind(d, activity.KindRefused)); got != 1 {
		t.Errorf("refused events after more syncs = %d, want the conflict recorded once", got)
	}
	if got := routedTo(d, awsIface); slices.Contains(got, "10.9.9.9") {
		t.Errorf("AWS routes %v, want it never to take back an address a higher priority holds", got)
	}
}

func TestADomainsAnswerForAnAddressAnotherTunnelHoldsFollowsPriority(t *testing.T) {
	env := newTunnelEnv(t, nil, []string{"*.wg.example.com"}, []string{"*.aws.example.com"}, nil)
	d := env.d
	env.connectWG()
	env.connectAWS()
	sWG, sAWS := waitForSession(t, d, wgIface), waitForSession(t, d, awsIface)
	shared := netip.MustParseAddr("10.77.0.1")

	// The lower-priority tunnel's lookup lands first, then the higher one's:
	// the higher-priority tunnel takes the address over.
	d.onWildcardAnswer("git.aws.example.com", []netip.Addr{shared}, time.Minute)
	if _, ok := sAWS.manager.GetRoute(shared); !ok {
		t.Fatal("test setup: AWS should hold the address first")
	}
	d.onWildcardAnswer("git.wg.example.com", []netip.Addr{shared}, time.Minute)
	if _, ok := sWG.manager.GetRoute(shared); !ok {
		t.Error("the higher-priority tunnel must take the address over")
	}
	if _, ok := sAWS.manager.GetRoute(shared); ok {
		t.Error("the lower-priority tunnel must give the address up")
	}
	if _, ok := d.learnedSnapshot(sAWS)[shared]; ok {
		t.Error("the lower-priority tunnel must forget the address it gave up")
	}

	// And the other way round: the lower-priority tunnel is refused.
	d.onWildcardAnswer("git.aws.example.com", []netip.Addr{shared}, time.Minute)
	if _, ok := sAWS.manager.GetRoute(shared); ok {
		t.Error("a lower-priority tunnel must not take an address from a higher one")
	}
	if got := len(eventsOfKind(d, activity.KindRefused)); got != 1 {
		t.Errorf("refused events = %d, want the refusal recorded once", got)
	}
}

func TestDisconnectingOneSessionLeavesTheOthersRoutesIntact(t *testing.T) {
	env := newTunnelEnv(t, nil, []string{"wg.example.com"}, []string{"aws.example.com"}, nil)
	env.answers.set("wg.example.com", "10.100.0.1")
	env.answers.set("aws.example.com", "10.200.0.1")
	d := env.d

	env.connectWG()
	env.connectAWS()
	waitForRoutes(t, d, wgIface, "10.100.0.1")
	waitForRoutes(t, d, awsIface, "10.200.0.1")

	env.disconnectAWS()
	waitFor(t, "the AWS session to go", func() bool { return d.sessions.get(awsIface) == nil })

	waitFor(t, "AWS's route to be removed", func() bool { return env.runner.has("delete -host 10.200.0.1") })
	if env.runner.has("delete -host 10.100.0.1") {
		t.Error("disconnecting AWS must not touch WireGuard's routes")
	}
	if got := routedTo(d, wgIface); !slices.Equal(got, []string{"10.100.0.1"}) {
		t.Errorf("WireGuard routes = %v, want them intact", got)
	}
	if tunnels := d.Tunnels(); len(tunnels) != 1 || tunnels[0].Interface != wgIface {
		t.Errorf("tunnels = %+v, want only WireGuard", tunnels)
	}
	if degraded, reason := d.Degraded(); degraded {
		t.Errorf("a clean disconnect must leave the daemon healthy: %s", reason)
	}
	if !d.GetVPNConnected() {
		t.Error("the daemon must still report a connected VPN")
	}
}

func TestStopTearsDownEverySession(t *testing.T) {
	env := newTunnelEnv(t, nil, []string{"wg.example.com"}, []string{"aws.example.com"}, nil)
	env.answers.set("wg.example.com", "10.100.0.1")
	env.answers.set("aws.example.com", "10.200.0.1")

	env.connectWG()
	env.connectAWS()
	waitForRoutes(t, env.d, wgIface, "10.100.0.1")
	waitForRoutes(t, env.d, awsIface, "10.200.0.1")

	env.d.Stop()

	if !env.runner.has("delete -host 10.100.0.1") || !env.runner.has("delete -host 10.200.0.1") {
		t.Error("Stop must remove the routes of every tunnel")
	}
	if env.d.sessions.has() {
		t.Error("no session may outlive Stop")
	}
}

func TestWildcardSuffixIsResolvedThroughItsOwningSessionsUpstreams(t *testing.T) {
	var published sync.Map
	published.Store(wgIface, true)
	published.Store(awsIface, true)
	env := newTunnelEnv(t, nil, []string{"*.wg.example.com"}, []string{"*.aws.example.com"}, func(d *Daemon) {
		d.useVPNDNS.Store(true)
		d.hooks.vpnNameservers = func(_ context.Context, iface string, _ bool) ([]netip.Addr, bool, error) {
			if _, ok := published.Load(iface); !ok {
				return nil, false, nil
			}
			return []netip.Addr{map[string]netip.Addr{
				wgIface:  netip.MustParseAddr("10.0.0.2"),
				awsIface: netip.MustParseAddr("10.7.0.2"),
			}[iface]}, true, nil
		}
	})
	d := env.d

	env.connectWG()
	env.connectAWS()
	waitFor(t, "both tunnels' DNS servers", func() bool { return len(d.DNSStatus().VPNDNSServers) == 2 })
	waitFor(t, "both suffixes' resolver files", func() bool { return len(d.DNSStatus().WildcardDomains) == 2 })

	if got := slices.Concat(d.upstreamsFor("git.wg.example.com")...); len(got) == 0 || got[0] != "10.0.0.2" || slices.Contains(got, "10.7.0.2") {
		t.Errorf("upstreams for a WireGuard name = %v, want WireGuard's DNS first and not AWS's", got)
	}
	if got := slices.Concat(d.upstreamsFor("git.aws.example.com")...); len(got) == 0 || got[0] != "10.7.0.2" || slices.Contains(got, "10.0.0.2") {
		t.Errorf("upstreams for an AWS name = %v, want AWS's DNS first and not WireGuard's", got)
	}
	if got := slices.Concat(d.upstreamsFor("elsewhere.example.org")...); slices.Contains(got, "10.0.0.2") || slices.Contains(got, "10.7.0.2") {
		t.Errorf("upstreams for an unowned name = %v, want only the configured servers", got)
	}

	// A lookup's answer is routed into the tunnel that owns the name.
	d.onWildcardAnswer("git.wg.example.com", []netip.Addr{netip.MustParseAddr("10.31.0.1")}, time.Minute)
	d.onWildcardAnswer("git.aws.example.com", []netip.Addr{netip.MustParseAddr("10.32.0.1")}, time.Minute)
	if !env.runner.has("add -host 10.31.0.1 "+wgGW) || env.runner.has("add -host 10.31.0.1 "+awsGW) {
		t.Error("a WireGuard name's answer must route through WireGuard only")
	}
	if !env.runner.has("add -host 10.32.0.1 "+awsGW) || env.runner.has("add -host 10.32.0.1 "+wgGW) {
		t.Error("an AWS name's answer must route through AWS only")
	}
	if got := routedTo(d, wgIface); !slices.Contains(got, "10.31.0.1") || slices.Contains(got, "10.32.0.1") {
		t.Errorf("WireGuard routes = %v", got)
	}
	if got := slices.Concat(d.upstreamsFor("git.wg.example.com")...); got[0] != "10.0.0.2" {
		t.Errorf("a name outside every list must not change: %v", got)
	}
}

func TestWildcardFilesWaitForEachOwningSessionsDNS(t *testing.T) {
	var awsPublished atomicFlag
	env := newTunnelEnv(t, nil, []string{"*.wg.example.com"}, []string{"*.aws.example.com"}, func(d *Daemon) {
		d.useVPNDNS.Store(true)
		d.hooks.vpnNameservers = func(_ context.Context, iface string, _ bool) ([]netip.Addr, bool, error) {
			switch {
			case iface == wgIface:
				return []netip.Addr{netip.MustParseAddr("10.0.0.2")}, true, nil
			case iface == awsIface && awsPublished.get():
				return []netip.Addr{netip.MustParseAddr("10.7.0.2")}, true, nil
			}
			return nil, false, nil
		}
	})
	d := env.d
	wgFile := filepath.Join(env.dir, "wg.example.com")
	awsFile := filepath.Join(env.dir, "aws.example.com")

	env.connectWG()
	env.connectAWS()
	waitFor(t, "WireGuard's resolver file", func() bool { _, err := os.Stat(wgFile); return err == nil })
	waitFor(t, "the pending reason", func() bool { return strings.Contains(d.DNSStatus().WildcardError, "waiting for the VPN") })
	if _, err := os.Stat(awsFile); !os.IsNotExist(err) {
		t.Fatal("a suffix must wait for its own tunnel's DNS servers even though another tunnel's are known")
	}

	awsPublished.set(true)
	d.syncRoutes(d.currentGeneration())
	if _, err := os.Stat(awsFile); err != nil {
		t.Fatalf("expected AWS's resolver file once its DNS servers are known: %v", err)
	}
	if got := d.DNSStatus().WildcardError; got != "" {
		t.Errorf("WildcardError = %q, want cleared", got)
	}

	// A tunnel that leaves takes its suffixes with it; the other keeps its own.
	env.disconnectAWS()
	waitFor(t, "AWS's resolver file to go", func() bool { _, err := os.Stat(awsFile); return os.IsNotExist(err) })
	if _, err := os.Stat(wgFile); err != nil {
		t.Errorf("WireGuard's resolver file must stay while WireGuard is connected: %v", err)
	}
}

type atomicFlag struct {
	mu sync.Mutex
	v  bool
}

func (f *atomicFlag) get() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.v }
func (f *atomicFlag) set(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.v = v
}

func TestCheckHostReportsWhichTunnelAnAddressLeavesThrough(t *testing.T) {
	env := newTunnelEnv(t, nil, []string{"wg.example.com"}, []string{"aws.example.com"}, nil)
	env.runner.getOutput = func(host string) string {
		switch host {
		case "10.100.0.1":
			return "   route to: 10.100.0.1\n  interface: " + wgIface + "\n"
		case "10.200.0.1":
			return "   route to: 10.200.0.1\n  interface: " + awsIface + "\n"
		}
		return "   route to: " + host + "\n    gateway: 192.168.7.1\n  interface: en0\n"
	}
	env.connectWG()
	env.connectAWS()
	waitForSession(t, env.d, wgIface)
	waitForSession(t, env.d, awsIface)

	for ip, want := range map[string]struct{ iface, vpn string }{
		"10.100.0.1": {wgIface, "WireGuard"},
		"10.200.0.1": {awsIface, "AWS VPN Client"},
	} {
		check, err := env.d.CheckHost(ip)
		if err != nil {
			t.Fatal(err)
		}
		a := check.Addresses[0]
		if a.Verdict != "vpn" || a.Interface != want.iface || a.VPN != want.vpn {
			t.Errorf("%s: %+v, want a vpn verdict through %s (%s)", ip, a, want.iface, want.vpn)
		}
		if check.VPNInterface != wgIface {
			t.Errorf("VPNInterface = %q, want the highest-priority tunnel", check.VPNInterface)
		}
	}
	direct, err := env.d.CheckHost("93.184.216.34")
	if err != nil {
		t.Fatal(err)
	}
	if a := direct.Addresses[0]; a.Verdict != "direct" || a.VPN != "" {
		t.Errorf("direct address = %+v, want no VPN", a)
	}
}

func TestPerSessionJournalsAreRecoveredAtStart(t *testing.T) {
	journal := func(steps string) string {
		now := time.Now().UTC().Format(time.RFC3339)
		return fmt.Sprintf(`{"schema_version":1,"generation_id":"left-behind","phase":"active","pre_state":[],"steps":%s,"created_at":%q,"updated_at":%q}`,
			steps, now, now)
	}
	var emptyPath, stepsPath string
	d, _, _, runner := newDNSTestDaemonWith(t, func(d *Daemon) {
		dir := filepath.Dir(d.routeManager.JournalPath())
		emptyPath = filepath.Join(dir, "transition-utun7.json")
		stepsPath = filepath.Join(dir, "transition-utun8.json")
		if err := os.WriteFile(emptyPath, []byte(journal(`[]`)), 0o600); err != nil {
			t.Fatal(err)
		}
		// A crashed tunnel that had moved the default route: recovery must give
		// the default back to the LAN gateway it replaced.
		steps := `[{"kind":"change_default","gateway":"10.0.0.1","prior_gateway":"192.168.7.1","existed":false}]`
		if err := os.WriteFile(stepsPath, []byte(journal(steps)), 0o600); err != nil {
			t.Fatal(err)
		}
		// An unrelated file with a similar name is left alone.
		if err := os.WriteFile(filepath.Join(dir, "transition-notes.txt"), []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}, "api.rw-test.invalid")

	for _, path := range []string{emptyPath, stepsPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s must be removed once recovered, stat err=%v", filepath.Base(path), err)
		}
	}
	if !runner.has("-n change default 192.168.7.1") {
		t.Error("recovery of a tunnel journal must replay its compensation through the shared runner")
	}
	if degraded, reason := d.Degraded(); degraded {
		t.Errorf("recovered journals must leave the daemon healthy: %s", reason)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(d.routeManager.JournalPath()), "transition-notes.txt")); err != nil {
		t.Errorf("a file that is not a tunnel journal must be left alone: %v", err)
	}
}

func TestAnUnrecoverableTunnelJournalDegradesTheDaemonAtStart(t *testing.T) {
	var path string
	d, _, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) {
		path = filepath.Join(filepath.Dir(d.routeManager.JournalPath()), "transition-utun7.json")
		now := time.Now().UTC().Format(time.RFC3339)
		body := fmt.Sprintf(`{"schema_version":1,"generation_id":"x","phase":"unrecoverable","failure_reason":"left unverified","pre_state":[],"steps":[],"created_at":%q,"updated_at":%q}`, now, now)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}, "api.rw-test.invalid")

	degraded, reason := d.Degraded()
	if !degraded || !strings.Contains(reason, "left unverified") {
		t.Fatalf("Degraded = %v %q, want the tunnel journal's reason reported", degraded, reason)
	}
	if d.currentGeneration() != nil {
		t.Error("a degraded start must not run any route mutator")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("an unrecoverable journal must stay on disk for the operator: %v", err)
	}
}

func TestSessionJournalLivesNextToTheBaseJournal(t *testing.T) {
	d, watcher, _, _ := newDNSTestDaemonWith(t, nil, "api.rw-test.invalid")
	connectTunnel(watcher, "utun7", "10.7.0.1")
	s := waitForSession(t, d, "utun7")

	want := filepath.Join(filepath.Dir(d.routeManager.JournalPath()), "transition-utun7.json")
	if got := s.manager.JournalPath(); got != want {
		t.Errorf("session journal = %q, want %q", got, want)
	}
	if s.manager.GetOriginalGateway() != d.routeManager.GetOriginalGateway() {
		t.Error("a session must start from the gateway the base manager captured")
	}
}

// In inverted mode each tunnel activates its own split tunnel and journals it
// to its own file, so one tunnel's disconnect can never compensate, or erase,
// another's transition.
func TestEachSessionActivatesAndJournalsItsOwnSplitTunnel(t *testing.T) {
	env := newTunnelEnv(t, nil, []string{"wg.example.com"}, []string{"aws.example.com"}, func(d *Daemon) {
		d.routeManager.SetAdditiveMode(false)
		d.routeManager.SetOriginalGateway(netip.MustParseAddr("192.168.7.1"), "en0")
		d.routeManager.SetCommandRunner(lanDefaultRunner{d.routeManager.CommandRunner()})
	})
	env.answers.set("wg.example.com", "10.100.0.1")
	env.answers.set("aws.example.com", "10.200.0.1")
	d := env.d
	journalDir := filepath.Dir(d.routeManager.JournalPath())
	wgJournal := filepath.Join(journalDir, "transition-"+wgIface+".json")
	awsJournal := filepath.Join(journalDir, "transition-"+awsIface+".json")
	exists := func(path string) bool { _, err := os.Stat(path); return err == nil }

	env.connectWG()
	env.connectAWS()
	waitForRoutes(t, d, wgIface, "10.100.0.1")
	waitForRoutes(t, d, awsIface, "10.200.0.1")
	if !exists(wgJournal) || !exists(awsJournal) {
		t.Fatalf("each active tunnel must journal to its own file: %s %v, %s %v", wgIface, exists(wgJournal), awsIface, exists(awsJournal))
	}
	if exists(d.routeManager.JournalPath()) {
		t.Error("the base journal belongs to no tunnel and must stay unused")
	}

	env.disconnectAWS()
	waitFor(t, "AWS's journal to be removed once it is clean", func() bool { return !exists(awsJournal) })
	if !exists(wgJournal) {
		t.Error("disconnecting AWS must leave WireGuard's journal in place")
	}
	if degraded, reason := d.Degraded(); degraded {
		t.Errorf("a clean disconnect must leave the daemon healthy: %s", reason)
	}

	env.disconnectWG()
	waitFor(t, "WireGuard's journal to be removed", func() bool { return !exists(wgJournal) })
}

// lanDefaultRunner answers `route -n get default` with the LAN default, as the
// kernel does once a tunnel's activation has handed the default back.
type lanDefaultRunner struct{ inner route.CommandRunner }

func (r lanDefaultRunner) Run(ctx context.Context, tool string, args ...string) (string, error) {
	if out, err := r.inner.Run(ctx, tool, args...); err != nil || tool != "route" || !slices.Equal(args, []string{"-n", "get", "default"}) {
		return out, err
	}
	return "    gateway: 192.168.7.1\n  interface: en0\n", nil
}

// A tunnel whose route state cannot be verified stops mutating on its own; the
// other tunnels keep routing.
func TestADegradedSessionStopsAloneAndReportsItsInterface(t *testing.T) {
	env := newTunnelEnv(t, nil, []string{"wg.example.com"}, []string{"aws.example.com"}, nil)
	env.answers.set("wg.example.com", "10.100.0.1")
	env.answers.set("aws.example.com", "10.200.0.1")
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForRoutes(t, d, wgIface, "10.100.0.1")
	waitForRoutes(t, d, awsIface, "10.200.0.1")

	// WireGuard's old address cannot be deleted when its domain moves.
	env.runner.setFailDeleteOf("delete -host 10.100.0.1")
	env.answers.set("wg.example.com", "10.100.0.9")
	env.answers.set("aws.example.com", "10.200.0.9")
	d.syncRoutes(d.currentGeneration())

	degraded, reason := d.Degraded()
	if !degraded || !strings.Contains(reason, wgIface+":") || strings.Contains(reason, awsIface+":") {
		t.Fatalf("Degraded = %v %q, want only %s reported", degraded, reason, wgIface)
	}
	waitForRoutes(t, d, awsIface, "10.200.0.9")

	// AWS still syncs after WireGuard stopped; WireGuard no longer does.
	env.answers.set("aws.example.com", "10.200.0.10")
	env.answers.set("wg.example.com", "10.100.0.10")
	d.syncRoutes(d.currentGeneration())
	waitForRoutes(t, d, awsIface, "10.200.0.10")
	if env.runner.has("add -host 10.100.0.10") {
		t.Error("a degraded tunnel must not add routes")
	}
}
