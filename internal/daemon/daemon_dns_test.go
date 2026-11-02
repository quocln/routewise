package daemon

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/monitor"
	"github.com/quocln/routewise/internal/resolverfiles"
	"github.com/quocln/routewise/internal/vpnclient"
)

// fakeRouteRunner records route commands instead of running them. Deletes fail
// while failDeletes is set, which is how a test drives route state degraded.
type fakeRouteRunner struct {
	mu          sync.Mutex
	calls       []string
	failDeletes bool
	// failDeleteOf, when set, makes deletes fail only for calls containing it.
	failDeleteOf string
	// getOutput, when set, answers `route -n get <host>` lookups.
	getOutput func(host string) string
}

func (f *fakeRouteRunner) Run(_ context.Context, tool string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := tool + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.failDeletes && slices.Contains(args, "delete") {
		return "", errors.New("route: delete: operation not permitted")
	}
	if f.failDeleteOf != "" && slices.Contains(args, "delete") && strings.Contains(call, f.failDeleteOf) {
		return "", errors.New("route: delete: operation not permitted")
	}
	if f.getOutput != nil && len(args) == 3 && args[1] == "get" && args[2] != "default" {
		return f.getOutput(args[2]), nil
	}
	return "", nil
}

func (f *fakeRouteRunner) has(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.ContainsFunc(f.calls, func(c string) bool { return strings.Contains(c, substr) })
}

// snapshot returns the commands run so far, in order.
func (f *fakeRouteRunner) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeRouteRunner) setFailDeleteOf(substr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failDeleteOf = substr
}

func (f *fakeRouteRunner) setFailDeletes(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failDeletes = v
}

// newDNSTestDaemon builds a started, additive-mode daemon with a fake monitor,
// a fake route runner, and DNS side effects confined to a temporary directory. Additive mode keeps
// the connect path hermetic: it never runs the route command to flip the
// default route, and a wildcard-only domain list resolves nothing up front.
func newDNSTestDaemon(t *testing.T, patterns ...string) (*Daemon, *fakeVPNWatcher, string) {
	d, w, dir, _ := newDNSTestDaemonWith(t, nil, patterns...)
	return d, w, dir
}

// newDNSTestDaemonWith also returns the fake route runner, and lets the test
// adjust the daemon before it starts.
func newDNSTestDaemonWith(t *testing.T, configure func(*Daemon), patterns ...string) (*Daemon, *fakeVPNWatcher, string, *fakeRouteRunner) {
	t.Helper()
	tmpDir := t.TempDir()
	cfg := newTestDaemonConfig(tmpDir)
	cfg.Routing.Mode = config.RoutingModeAdditive
	cfg.Domains = nil
	for _, p := range patterns {
		cfg.Domains = append(cfg.Domains, config.DomainRule{Pattern: p})
	}

	d, err := New(cfg, config.YAMLFile(filepath.Join(tmpDir, "config.yaml")))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)
	resolverDir := filepath.Join(tmpDir, "resolver")
	d.resolverFiles = resolverfiles.New(resolverDir, "127.0.0.1", 53053)
	d.routeManager.SetJournalPath(filepath.Join(tmpDir, "transition.json"))
	runner := &fakeRouteRunner{}
	d.routeManager.SetCommandRunner(runner)
	d.hooks.localPrefixes = func() []netip.Prefix { return nil }
	if configure != nil {
		configure(d)
	}

	watcher := newFakeVPNWatcher()
	d.hooks.newMonitor = func(time.Duration) vpnWatcher { return watcher }
	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(d.Stop)
	return d, watcher, resolverDir, runner
}

// connectTunnel mirrors the monitor admitting a tunnel: it records the tunnel
// and delivers the connect event.
func connectTunnel(w *fakeVPNWatcher, iface, gateway string) {
	gw := netip.MustParseAddr(gateway)
	w.setConnected(iface, gw)
	w.events <- monitor.VPNEvent{State: monitor.VPNConnected, Interface: iface, Gateway: gw}
}

func disconnectTunnel(w *fakeVPNWatcher, iface string) {
	w.setDisconnected(iface)
	w.events <- monitor.VPNEvent{State: monitor.VPNDisconnected, Interface: iface}
}

func connect(w *fakeVPNWatcher) { connectTunnel(w, "utun9", "10.0.0.1") }

func disconnect(w *fakeVPNWatcher) { disconnectTunnel(w, "utun9") }

// waitForSession waits until the daemon manages iface and returns its session.
func waitForSession(t *testing.T, d *Daemon, iface string) *tunnelSession {
	t.Helper()
	waitFor(t, "the session for "+iface, func() bool { return d.sessions.get(iface) != nil })
	return d.sessions.get(iface)
}

// learnedCount totals the learned wildcard addresses of every session.
func learnedCount(d *Daemon) int {
	n := 0
	for _, s := range d.sessionList() {
		n += len(d.learnedSnapshot(s))
	}
	return n
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWildcardResolverFilesFollowTheVPNConnection(t *testing.T) {
	d, watcher, resolverDir := newDNSTestDaemon(t, "*.corp.example.com", "qa*.corp.example.com", "*.rw-test.example.net")
	resolverFile := filepath.Join(resolverDir, "corp.example.com")

	watcher.setConnected("utun9", netip.MustParseAddr("10.0.0.1"))
	watcher.events <- monitor.VPNEvent{State: monitor.VPNConnected, Interface: "utun9", Gateway: netip.MustParseAddr("10.0.0.1")}

	waitFor(t, "resolver files to be written", func() bool {
		_, err := os.Stat(resolverFile)
		return err == nil
	})
	got := d.DNSStatus().WildcardDomains
	if !slices.Equal(got, []string{"corp.example.com", "rw-test.example.net"}) {
		t.Errorf("WildcardDomains = %v, want one entry per distinct suffix", got)
	}

	disconnect(watcher)

	waitFor(t, "resolver files to be removed on disconnect", func() bool {
		_, err := os.Stat(resolverFile)
		return os.IsNotExist(err)
	})
	if got := d.DNSStatus().WildcardDomains; len(got) != 0 {
		t.Errorf("WildcardDomains after disconnect = %v, want none", got)
	}
}

func TestStopRemovesResolverFiles(t *testing.T) {
	d, watcher, resolverDir := newDNSTestDaemon(t, "*.corp.example.com")

	watcher.setConnected("utun9", netip.MustParseAddr("10.0.0.1"))
	watcher.events <- monitor.VPNEvent{State: monitor.VPNConnected, Interface: "utun9", Gateway: netip.MustParseAddr("10.0.0.1")}
	resolverFile := filepath.Join(resolverDir, "corp.example.com")
	waitFor(t, "resolver files to be written", func() bool {
		_, err := os.Stat(resolverFile)
		return err == nil
	})

	d.Stop()

	if _, err := os.Stat(resolverFile); !os.IsNotExist(err) {
		t.Errorf("expected Stop to remove the resolver file, stat err=%v", err)
	}
}

func TestStartSweepsResolverFilesLeftByACrashedProcess(t *testing.T) {
	tmpDir := t.TempDir()
	resolverDir := filepath.Join(tmpDir, "resolver")
	if _, err := resolverfiles.New(resolverDir, "127.0.0.1", 53053).Apply([]string{"corp.example.com"}); err != nil {
		t.Fatal(err)
	}

	cfg := newTestDaemonConfig(tmpDir)
	d, err := New(cfg, config.YAMLFile(filepath.Join(tmpDir, "config.yaml")))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)
	d.resolverFiles = resolverfiles.New(resolverDir, "127.0.0.1", 53053)
	d.routeManager.SetJournalPath(filepath.Join(tmpDir, "transition.json"))
	d.hooks.newMonitor = func(time.Duration) vpnWatcher { return newFakeVPNWatcher() }

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(d.Stop)

	if _, err := os.Stat(filepath.Join(resolverDir, "corp.example.com")); !os.IsNotExist(err) {
		t.Errorf("a stale resolver file would send lookups to a dead forwarder; stat err=%v", err)
	}
}

func TestMatchesWildcardUsesTheLiveDomainList(t *testing.T) {
	d, watcher, _ := newDNSTestDaemon(t, "*.corp.example.com", "api.example.com")
	connect(watcher)
	waitForSession(t, d, "utun9")

	if !d.matchesWildcard("git.corp.example.com") {
		t.Error("a name under a wildcard must match")
	}
	if d.matchesWildcard("corp.example.com") || d.matchesWildcard("a.b.corp.example.com") {
		t.Error("a wildcard covers exactly one label")
	}
	if d.matchesWildcard("api.example.com") {
		t.Error("an exact pattern is resolved up front, not through the forwarder")
	}

	if err := d.AddDomain("", "qa*.example.com"); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	if !d.matchesWildcard("qa7.example.com") {
		t.Error("a wildcard added at runtime must match without a restart")
	}
}

func TestWildcardAnswerIsIgnoredWhileTheVPNIsDown(t *testing.T) {
	d, _, _ := newDNSTestDaemon(t, "*.corp.example.com")

	d.onWildcardAnswer("git.corp.example.com", []netip.Addr{netip.MustParseAddr("10.1.2.3")}, time.Minute)

	if learnedCount(d) != 0 {
		t.Error("an answer while the VPN is down must not be remembered")
	}
	if d.GetRouteCount() != 0 {
		t.Error("an answer while the VPN is down must not install a route")
	}
}

func TestLearnedRoutesHonorMinimumLifetimeExpiryAndCap(t *testing.T) {
	d, watcher, _ := newDNSTestDaemon(t, "*.corp.example.com")
	connect(watcher)
	s := waitForSession(t, d, "utun9")

	ip := netip.MustParseAddr("10.1.2.3")
	d.rememberLearned(s, "git.corp.example.com", []netip.Addr{ip}, time.Second)

	d.learnedMu.Lock()
	lifetime := time.Until(s.learned[ip].expires)
	d.learnedMu.Unlock()
	if lifetime < learnedRouteMinLifetime-time.Minute {
		t.Errorf("a short DNS TTL must not shorten the route below the minimum lifetime, got %v", lifetime)
	}
	if got := d.learnedSnapshot(s)[ip]; got != "git.corp.example.com" {
		t.Errorf("snapshot label = %q, want the looked-up name", got)
	}

	d.learnedMu.Lock()
	s.learned[ip] = learnedRoute{domain: "git.corp.example.com", expires: time.Now().Add(-time.Second)}
	d.learnedMu.Unlock()
	if _, ok := d.learnedSnapshot(s)[ip]; ok {
		t.Error("an expired learned address must be dropped")
	}

	var ips []netip.Addr
	for i := 0; i < maxLearnedRoutes+10; i++ {
		ips = append(ips, netip.AddrFrom4([4]byte{10, 9, byte(i >> 8), byte(i)}))
	}
	d.rememberLearned(s, "bulk.corp.example.com", ips, time.Hour)
	if got := len(d.learnedSnapshot(s)); got != maxLearnedRoutes {
		t.Errorf("learned addresses = %d, want capped at %d", got, maxLearnedRoutes)
	}
}

// addTestSession registers a session for a tunnel without a connect event, so
// a test can drive per-session code on its own. The daemon closes it at Stop.
func addTestSession(t *testing.T, d *Daemon, iface, gateway string) *tunnelSession {
	t.Helper()
	s, err := d.newTunnelSession(d.currentGeneration(), iface, netip.MustParseAddr(gateway), vpnclient.Client{})
	if err != nil {
		t.Fatalf("newTunnelSession: %v", err)
	}
	d.mutationMu.Lock()
	d.sessions.add(s)
	d.mutationMu.Unlock()
	return s
}

func TestEnsureVPNDNSOnlyRunsWhileConnected(t *testing.T) {
	d, watcher, _ := newDNSTestDaemon(t, "api.example.com")
	var calls atomic.Int32
	d.hooks.vpnNameservers = func(context.Context, string, bool) ([]netip.Addr, bool, error) {
		calls.Add(1)
		return nil, false, nil
	}
	gen := d.currentGeneration()
	s := addTestSession(t, d, "utun9", "10.0.0.1")

	d.ensureVPNDNS(gen, s, false)
	if calls.Load() != 0 {
		t.Fatal("VPN DNS discovery must not run while the VPN is down")
	}

	watcher.setConnected("utun9", netip.MustParseAddr("10.0.0.1"))
	d.ensureVPNDNS(gen, s, false)
	if calls.Load() != 1 {
		t.Fatalf("expected one discovery once connected, even with dns.use_vpn_dns off, got %d", calls.Load())
	}
	if got := d.DNSStatus().VPNDNSServers; len(got) != 0 {
		t.Errorf("no servers were published, so none may be reported, got %v", got)
	}
}

// Moving the default route off the tunnel would cut a VPN that serves DNS for
// every name off from its own servers, so they are routed through the tunnel
// even when RouteWise itself does not resolve through them.
func TestVPNDNSIsRoutedButNotPreferredWhenDisabled(t *testing.T) {
	vpnServer := netip.MustParseAddr("10.0.0.2")
	d, watcher, _, runner := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.hooks.vpnNameservers = func(context.Context, string, bool) ([]netip.Addr, bool, error) {
			return []netip.Addr{vpnServer}, true, nil
		}
	}, "api.rw-test.invalid")

	connect(watcher)
	waitFor(t, "VPN DNS to be routed", func() bool { return len(d.DNSStatus().VPNDNSServers) == 1 })
	if !runner.has("add -host 10.0.0.2 10.0.0.1") {
		t.Error("the VPN DNS server must be routed through the tunnel")
	}
	if up := d.sessions.get("utun9").resolver.Upstreams(); slices.Contains(up, "10.0.0.2") {
		t.Errorf("Upstreams = %v, the VPN server must not be asked while dns.use_vpn_dns is off", up)
	}
}

func TestSetUseVPNDNSAppliesToTheLiveConnectionAndPersists(t *testing.T) {
	vpnServer := netip.MustParseAddr("10.0.0.2")
	d, watcher, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.hooks.vpnNameservers = func(context.Context, string, bool) ([]netip.Addr, bool, error) {
			return []netip.Addr{vpnServer}, true, nil
		}
	}, "api.rw-test.invalid")
	connect(watcher)
	waitFor(t, "VPN DNS to be routed", func() bool { return len(d.DNSStatus().VPNDNSServers) == 1 })

	if err := d.SetUseVPNDNS(true); err != nil {
		t.Fatalf("SetUseVPNDNS(true): %v", err)
	}
	if up := d.sessions.get("utun9").resolver.Upstreams(); len(up) == 0 || up[0] != "10.0.0.2" {
		t.Errorf("Upstreams = %v, want the VPN server first at once", up)
	}
	if !d.Settings().UseVPNDNS {
		t.Error("Settings must report the new value")
	}
	if cfg, _ := d.store.Snapshot(); !cfg.DNS.UseVPNDNS {
		t.Error("the new value must be saved to the config")
	}

	if err := d.SetUseVPNDNS(false); err != nil {
		t.Fatalf("SetUseVPNDNS(false): %v", err)
	}
	if up := d.sessions.get("utun9").resolver.Upstreams(); slices.Contains(up, "10.0.0.2") {
		t.Errorf("Upstreams = %v, want the VPN server dropped at once", up)
	}
}

func TestDNSStatusReportsAForwarderThatCouldNotStart(t *testing.T) {
	d, _, _ := newDNSTestDaemon(t, "api.example.com")
	d.dnsMu.Lock()
	d.forwarderErr = "DNS forwarder could not listen on 127.0.0.1:53053: address already in use"
	d.dnsMu.Unlock()

	if got := d.DNSStatus().WildcardError; got != "" {
		t.Errorf("without wildcard patterns the forwarder failure is irrelevant, got %q", got)
	}

	if err := d.AddDomain("", "*.corp.example.com"); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	if got := d.DNSStatus().WildcardError; got == "" {
		t.Error("with a wildcard configured, the forwarder failure must be reported")
	}
}

func TestVPNDNSIsRoutedPreferredAndForgottenPerConnection(t *testing.T) {
	var discoveries atomic.Int32
	vpnServer := netip.MustParseAddr("10.0.0.2")
	d, watcher, _, runner := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.useVPNDNS.Store(true)
		d.hooks.vpnNameservers = func(context.Context, string, bool) ([]netip.Addr, bool, error) {
			discoveries.Add(1)
			return []netip.Addr{vpnServer}, true, nil
		}
	}, "api.rw-test.invalid", "*.rw-test.invalid")

	connect(watcher)
	waitFor(t, "VPN DNS to be adopted", func() bool { return len(d.DNSStatus().VPNDNSServers) == 1 })
	if !runner.has("add -host 10.0.0.2 10.0.0.1") {
		t.Error("the VPN DNS server must be routed through the tunnel")
	}
	s := d.sessions.get("utun9")
	if up := s.resolver.Upstreams(); up[0] != "10.0.0.2" {
		t.Errorf("Upstreams = %v, want the VPN DNS server first", up)
	}
	if up := slices.Concat(d.upstreamsFor("git.rw-test.invalid")...); up[0] != "10.0.0.2" {
		t.Errorf("forwarder upstreams = %v, want the owning tunnel's VPN DNS first", up)
	}

	disconnect(watcher)
	waitFor(t, "VPN DNS to be forgotten", func() bool { return len(d.DNSStatus().VPNDNSServers) == 0 })
	if d.sessions.get("utun9") != nil {
		t.Error("the session must be gone after the disconnect")
	}
	if up := slices.Concat(d.upstreamsFor("git.rw-test.invalid")...); slices.Contains(up, "10.0.0.2") {
		t.Errorf("Upstreams after disconnect = %v, a dead tunnel's server must not be asked", up)
	}

	connect(watcher)
	waitFor(t, "VPN DNS to be rediscovered", func() bool { return discoveries.Load() >= 2 })
}

// A disconnect that lands while discovery is in flight must win: the servers
// of a tunnel that is already gone are never published.
func TestVPNDNSDiscoveryRacingADisconnectPublishesNothing(t *testing.T) {
	var watcher *fakeVPNWatcher
	d, w, _, runner := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.useVPNDNS.Store(true)
		d.hooks.vpnNameservers = func(context.Context, string, bool) ([]netip.Addr, bool, error) {
			watcher.setDisconnected("utun9")
			return []netip.Addr{netip.MustParseAddr("10.0.0.2")}, true, nil
		}
	}, "api.rw-test.invalid")
	watcher = w
	w.setConnected("utun9", netip.MustParseAddr("10.0.0.1"))
	s := addTestSession(t, d, "utun9", "10.0.0.1")

	d.ensureVPNDNS(d.currentGeneration(), s, false)

	if got := d.DNSStatus().VPNDNSServers; len(got) != 0 {
		t.Errorf("VPNDNSServers = %v, want none after the tunnel went away", got)
	}
	if runner.has("10.0.0.2") {
		t.Error("no route may be added for a dead tunnel's DNS server")
	}
	if up := s.resolver.Upstreams(); slices.Contains(up, "10.0.0.2") {
		t.Errorf("Upstreams = %v, want the dead tunnel's server absent", up)
	}
}

func TestWildcardFilesWaitForVPNDNSWhenEnabled(t *testing.T) {
	var published atomic.Bool
	d, watcher, resolverDir, _ := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.useVPNDNS.Store(true)
		d.hooks.vpnNameservers = func(context.Context, string, bool) ([]netip.Addr, bool, error) {
			if published.Load() {
				return []netip.Addr{netip.MustParseAddr("10.0.0.2")}, true, nil
			}
			return nil, false, nil
		}
	}, "*.corp.example.com")
	resolverFile := filepath.Join(resolverDir, "corp.example.com")

	connect(watcher)
	waitFor(t, "the pending reason to be reported", func() bool {
		return strings.Contains(d.DNSStatus().WildcardError, "waiting for the VPN")
	})
	if _, err := os.Stat(resolverFile); !os.IsNotExist(err) {
		t.Fatal("resolver files must wait until the VPN's DNS servers are known")
	}

	published.Store(true)
	d.syncRoutes(d.currentGeneration())
	if _, err := os.Stat(resolverFile); err != nil {
		t.Fatalf("expected resolver files once VPN DNS is known: %v", err)
	}
	if got := d.DNSStatus().WildcardError; got != "" {
		t.Errorf("WildcardError = %q, want cleared", got)
	}
}

func TestDisconnectWhileDegradedStillClearsDNSState(t *testing.T) {
	d, watcher, resolverDir, runner := newDNSTestDaemonWith(t, nil, "*.corp.example.com")
	resolverFile := filepath.Join(resolverDir, "corp.example.com")

	connect(watcher)
	waitFor(t, "resolver files to be written", func() bool {
		_, err := os.Stat(resolverFile)
		return err == nil
	})

	// A learned route whose deletion fails leaves route state unverified.
	ip := netip.MustParseAddr("10.7.7.7")
	s := waitForSession(t, d, "utun9")
	d.onWildcardAnswer("git.corp.example.com", []netip.Addr{ip}, time.Minute)
	d.learnedMu.Lock()
	s.learned[ip] = learnedRoute{domain: "git.corp.example.com", expires: time.Now().Add(-time.Second)}
	d.learnedMu.Unlock()
	runner.setFailDeletes(true)
	d.syncRoutes(d.currentGeneration())
	if degraded, _ := d.Degraded(); !degraded {
		t.Fatal("test setup: expected a failed route delete to degrade route state")
	}

	disconnect(watcher)
	waitFor(t, "resolver files to be removed while degraded", func() bool {
		_, err := os.Stat(resolverFile)
		return os.IsNotExist(err)
	})
}

func TestWildcardAnswersNeverRouteLocalOrUpstreamAddresses(t *testing.T) {
	d, watcher, _, runner := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.hooks.localPrefixes = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")} }
	}, "*.corp.example.com")
	connect(watcher)
	s := waitForSession(t, d, "utun9")

	d.onWildcardAnswer("evil.corp.example.com", []netip.Addr{
		netip.MustParseAddr("192.168.1.20"), // directly connected
		netip.MustParseAddr("8.8.8.8"),      // configured DNS upstream
	}, time.Minute)
	d.onWildcardAnswer("git.corp.example.com", []netip.Addr{netip.MustParseAddr("10.5.5.5")}, time.Minute)

	if runner.has("192.168.1.20") || runner.has("add -host 8.8.8.8") {
		t.Error("a wildcard answer must never route a local or upstream address into the tunnel")
	}
	if !runner.has("add -host 10.5.5.5 10.0.0.1") {
		t.Error("a normal wildcard answer must be routed")
	}
	if _, ok := d.learnedSnapshot(s)[netip.MustParseAddr("192.168.1.20")]; ok {
		t.Error("a rejected address must not be remembered")
	}
}

func TestEvictedLearnedAddressLosesItsRoute(t *testing.T) {
	d, watcher, _, runner := newDNSTestDaemonWith(t, nil, "*.corp.example.com")
	connect(watcher)
	s := waitForSession(t, d, "utun9")

	oldest := netip.MustParseAddr("10.6.0.1")
	d.onWildcardAnswer("old.corp.example.com", []netip.Addr{oldest}, time.Second)

	var filler []netip.Addr
	for i := 0; i < maxLearnedRoutes-1; i++ {
		filler = append(filler, netip.AddrFrom4([4]byte{10, 8, byte(i >> 8), byte(i)}))
	}
	d.learnedMu.Lock()
	for _, ip := range filler {
		s.learned[ip] = learnedRoute{domain: "filler", expires: time.Now().Add(time.Hour)}
	}
	d.learnedMu.Unlock()

	d.onWildcardAnswer("new.corp.example.com", []netip.Addr{netip.MustParseAddr("10.6.0.2")}, time.Hour)

	if !runner.has("delete -host 10.6.0.1") {
		t.Error("the evicted address's route must be removed, not left until the next sync")
	}
	if _, ok := s.manager.GetActiveRoutes()[oldest]; ok {
		t.Error("the evicted address must no longer be a managed route")
	}
}

// A VPN profile that names the LAN router as its DNS server must not get a
// /32 into the tunnel: that would cut the Mac off from its own network.
func TestVPNDNSOnTheLANIsNotRoutedIntoTheTunnel(t *testing.T) {
	lanRouter := netip.MustParseAddr("192.168.7.1")
	d, watcher, _, runner := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.hooks.vpnNameservers = func(context.Context, string, bool) ([]netip.Addr, bool, error) {
			return []netip.Addr{lanRouter}, true, nil
		}
	}, "api.rw-test.invalid")
	d.hooks.localPrefixes = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")} }

	connect(watcher)
	s := waitForSession(t, d, "utun9")
	d.ensureVPNDNS(d.currentGeneration(), s, false)

	if runner.has("192.168.7.1") {
		t.Fatal("a LAN DNS server must never be routed through the tunnel")
	}
	if got := d.DNSStatus().VPNDNSServers; len(got) != 0 {
		t.Fatalf("VPNDNSServers = %v, want none", got)
	}
}

// A guessed server is provisional: once the VPN binds its real servers to the
// tunnel, they replace the guess and the guess loses its route.
func TestGuessedVPNDNSIsReplacedByBoundServers(t *testing.T) {
	var bound atomic.Bool
	d, watcher, _, runner := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.hooks.vpnNameservers = func(_ context.Context, _ string, allowGuess bool) ([]netip.Addr, bool, error) {
			if bound.Load() {
				return []netip.Addr{netip.MustParseAddr("10.0.0.2")}, true, nil
			}
			if allowGuess {
				return []netip.Addr{netip.MustParseAddr("10.64.0.1")}, false, nil
			}
			return nil, false, nil
		}
	}, "api.rw-test.invalid")
	connect(watcher)
	s := waitForSession(t, d, "utun9")
	gen := d.currentGeneration()

	d.ensureVPNDNS(gen, s, false)
	if len(d.DNSStatus().VPNDNSServers) != 0 {
		t.Fatal("nothing may be guessed before the guess is allowed")
	}

	d.ensureVPNDNS(gen, s, true)
	if got := d.DNSStatus().VPNDNSServers; len(got) != 1 || got[0] != "10.64.0.1" {
		t.Fatalf("VPNDNSServers = %v, want the guess 10.64.0.1", got)
	}

	bound.Store(true)
	d.ensureVPNDNS(gen, s, true)
	if got := d.DNSStatus().VPNDNSServers; len(got) != 1 || got[0] != "10.0.0.2" {
		t.Fatalf("VPNDNSServers = %v, want the bound server 10.0.0.2 to replace the guess", got)
	}
	if !runner.has("delete -host 10.64.0.1") {
		t.Error("the replaced guess must lose its route")
	}
}

// Domains routed for one VPN live in that VPN's list, so a count of the Any VPN
// list alone reads 0 on a machine that uses only per-VPN lists.
func TestDNSStatusCountsEveryDomainList(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := newTestDaemonConfig(tmpDir)
	cfg.Domains = []config.DomainRule{{Pattern: "any.example.com"}}
	cfg.VPNs = []config.VPNRoute{{
		Client:  "routewise-wireguard:ab12",
		Domains: []config.DomainRule{{Pattern: "a.example.com"}, {Pattern: "*.a.example.com"}},
	}}
	d, err := New(cfg, config.YAMLFile(filepath.Join(tmpDir, "config.yaml")))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)
	if got := d.DNSStatus().DomainCount; got != 3 {
		t.Errorf("DomainCount = %d, want 3", got)
	}
}
