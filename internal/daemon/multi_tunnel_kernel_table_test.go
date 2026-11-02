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
	"sync/atomic"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/testenv"
	"github.com/quocln/routewise/internal/vpnclient"
)

// newKernelEnv is newTunnelEnv with route commands run against a fake kernel
// that models the one-route-per-address rule, and every tunnel interface up.
func newKernelEnv(t *testing.T, k *fakeKernel, anyList, wgList, awsList []string, configure func(*Daemon)) *tunnelEnv {
	t.Helper()
	return newTunnelEnv(t, anyList, wgList, awsList, func(d *Daemon) {
		d.routeManager.SetCommandRunner(k)
		d.hooks.interfaceUp = func(string) bool { return true }
		if configure != nil {
			configure(d)
		}
	})
}

func waitHost(t *testing.T, k *fakeKernel, ip, iface string) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%s to route through %s", ip, iface), func() bool {
		got, ok := k.hostRoute(ip)
		return ok && got == iface
	})
}

func waitNoHost(t *testing.T, k *fakeKernel, ip string) {
	t.Helper()
	waitFor(t, ip+" to leave the routing table", func() bool {
		_, ok := k.hostRoute(ip)
		return !ok
	})
}

func mustSnapshot(d *Daemon) *config.Config {
	cfg, _ := d.store.Snapshot()
	return cfg
}

func holds(d *Daemon, iface, ip string) bool {
	s := d.sessions.get(iface)
	if s == nil {
		return false
	}
	_, ok := s.manager.GetRoute(netip.MustParseAddr(ip))
	return ok
}

func answer(d *Daemon, name string, ips ...string) {
	var addrs []netip.Addr
	for _, ip := range ips {
		addrs = append(addrs, netip.MustParseAddr(ip))
	}
	d.onWildcardAnswer(name, addrs, time.Minute)
}

// --- ownership: a client's own names never reach the Any VPN owner ---

func TestAClientsOwnNamesNeverFallThroughToTheAnyVPNOwner(t *testing.T) {
	k := newFakeKernel()
	// WireGuard outranks AWS and holds the Any VPN list. AWS's own list holds
	// api.example.com and qa*.example.com, which the Any list also covers.
	env := newKernelEnv(t, k,
		[]string{"*.example.com", "api.example.com"}, nil, []string{"api.example.com", "qa*.example.com"}, nil)
	env.answers.set("api.example.com", "10.60.0.1")
	d := env.d
	env.connectWG()
	env.connectAWS()
	sWG, sAWS := waitForSession(t, d, wgIface), waitForSession(t, d, awsIface)

	if got := d.ownerFor("qa1.example.com"); got != sAWS {
		t.Fatalf("qa1.example.com is in AWS's own list; owner = %v, want the AWS session", got)
	}
	if got := d.ownerFor("other.example.com"); got != sWG {
		t.Fatalf("other.example.com is in no client's list; owner = %v, want the Any VPN owner (WireGuard)", got)
	}
	waitHost(t, k, "10.60.0.1", awsIface)
	if holds(d, wgIface, "10.60.0.1") {
		t.Error("an exact name in AWS's own list must never be routed by the Any VPN owner")
	}

	answer(d, "qa1.example.com", "10.61.0.1")
	answer(d, "other.example.com", "10.62.0.1")
	waitHost(t, k, "10.61.0.1", awsIface)
	waitHost(t, k, "10.62.0.1", wgIface)

	// AWS goes down: its names go direct. They do not fall to WireGuard.
	env.disconnectAWS()
	waitFor(t, "the AWS session to go", func() bool { return d.sessions.get(awsIface) == nil })
	if got := d.ownerFor("qa1.example.com"); got != nil {
		t.Errorf("owner of an AWS name while AWS is down = %v, want nil (direct)", got)
	}
	answer(d, "qa2.example.com", "10.63.0.1")
	if _, ok := k.hostRoute("10.63.0.1"); ok {
		t.Error("an AWS name's answer must not be routed through another VPN while AWS is down")
	}
	d.syncRoutes(d.currentGeneration())
	waitNoHost(t, k, "10.60.0.1")
	if holds(d, wgIface, "10.60.0.1") {
		t.Error("api.example.com must go direct while AWS is down, not through WireGuard")
	}
	if asked := env.answers.askedFor("api.example.com"); slices.Contains(asked, wgIface) {
		t.Errorf("api.example.com was resolved through %v; WireGuard must never look it up", asked)
	}
	if _, ok := k.hostRoute("10.62.0.1"); !ok {
		t.Error("the Any VPN list's own answer must stay routed")
	}

	// AWS returns and takes its names back.
	env.connectAWS()
	waitHost(t, k, "10.60.0.1", awsIface)
}

func TestWhenSeveralClientListsMatchTheHighestPriorityClientWins(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, []string{"*.shared.example.com"}, []string{"git.shared.example.com"}, nil)
	env.answers.set("git.shared.example.com", "10.64.0.1")
	d := env.d
	env.connectWG()
	env.connectAWS()
	sWG := waitForSession(t, d, wgIface)
	waitForSession(t, d, awsIface)

	if _, got := d.store.Policy().owningList(d.sessionList(), "git.shared.example.com"); got != sWG {
		t.Errorf("owner = %v, want WireGuard, the higher-priority client whose list matches", got)
	}
	d.syncRoutes(d.currentGeneration())
	if holds(d, awsIface, "10.64.0.1") {
		t.Error("AWS's exact entry is shadowed by WireGuard's wildcard and must not be routed through AWS")
	}
	if asked := env.answers.askedFor("git.shared.example.com"); len(asked) != 0 {
		t.Errorf("a shadowed exact name was resolved through %v", asked)
	}
}

func TestADegradedTunnelIsSkippedForTheAnyVPNListAndItsOwnNamesGoDirect(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, []string{"wg.example.com"}, []string{"aws.example.com"}, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	env.answers.set("wg.example.com", "10.100.0.1")
	env.answers.set("aws.example.com", "10.200.0.1")
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForRoutes(t, d, wgIface, "10.100.0.1", "10.50.0.1")
	waitForRoutes(t, d, awsIface, "10.200.0.1")

	// WireGuard cannot delete an old address, which degrades it.
	k.failNext("delete -host 10.100.0.1", errors.New("route: delete: operation not permitted"))
	env.answers.set("wg.example.com", "10.100.0.9")
	d.syncRoutes(d.currentGeneration())
	if degraded, _ := d.sessions.get(wgIface).manager.Degraded(); !degraded {
		t.Fatal("test setup: WireGuard should be degraded")
	}

	// The Any VPN list now goes through the healthy tunnel; WireGuard's own
	// name goes direct rather than through AWS.
	env.answers.set("any.example.com", "10.50.0.3")
	env.answers.set("wg.example.com", "10.100.0.10")
	d.syncRoutes(d.currentGeneration())
	waitHost(t, k, "10.50.0.3", awsIface)
	if _, ok := k.hostRoute("10.100.0.10"); ok {
		t.Error("a degraded tunnel's own names must go direct, not through another VPN or the degraded tunnel")
	}
}

// --- default route: compensation across two tunnels ---

func lanDefaultKernel() *fakeKernel {
	k := newFakeKernel()
	k.reachable = map[string]bool{"192.168.7.1": true}
	return k
}

// inverted turns the daemon's tunnels into inverted split tunnels on k.
func inverted(k *fakeKernel) func(*Daemon) {
	return func(d *Daemon) {
		d.routeManager.SetAdditiveMode(false)
		d.routeManager.SetOriginalGateway(netip.MustParseAddr("192.168.7.1"), "en0")
		d.routeManager.SetCommandRunner(k)
	}
}

// A NetworkExtension VPN (WireGuard, default route on its tunnel) and a /1-pair
// VPN (AWS) are managed together. Stop must give WireGuard its default back and
// never leave the machine without one.
func TestStopRestoresEachTunnelsOwnDefaultInReverseActivationOrder(t *testing.T) {
	k := lanDefaultKernel()
	k.setDefault("", wgIface) // the WireGuard app owns the global default
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d

	env.connectWG()
	waitForSession(t, d, wgIface)
	waitFor(t, "WireGuard's activation to hand the default to the LAN", func() bool {
		_, iface := k.defaultRoute()
		return iface == "en0"
	})
	k.putNet("0/1", awsGW, awsIface)
	k.putNet("128.0/1", awsGW, awsIface)
	env.connectAWS()
	waitForSession(t, d, awsIface)
	waitFor(t, "AWS's activation to remove its catch-all halves", func() bool { return len(k.netRoutes()) == 0 })

	mark := len(k.log())
	d.Stop()

	if _, iface := k.defaultRoute(); iface != wgIface {
		gw, _ := k.defaultRoute()
		t.Fatalf("default after Stop = %q on %q, want WireGuard's own default back on %s", gw, iface, wgIface)
	}
	calls := k.log()[mark:]
	if indexOf(calls, "delete default", 0) >= 0 {
		t.Errorf("compensation must never delete the default route: %v", calls)
	}
	// AWS activated last, so it is undone first.
	awsBack, wgBack := indexOf(calls, "add -net", 0), indexOf(calls, "change default -interface "+wgIface, 0)
	if awsBack < 0 || wgBack < 0 || awsBack > wgBack {
		t.Errorf("calls = %v, want AWS's compensation before WireGuard's (reverse of activation)", calls)
	}
	if len(k.netRoutes()) != 2 {
		t.Errorf("AWS's catch-all halves = %v, want them restored", k.netRoutes())
	}
}

// Journals an older release left behind recorded a default change even when the
// default was already the LAN. Recovery must undo the newest first, whatever
// order the directory lists them in, or the older journal's restore is undone
// by the newer one's.
func TestStartupRecoveryUndoesTunnelJournalsNewestFirst(t *testing.T) {
	k := lanDefaultKernel() // the crash left the default on the LAN
	journal := func(created time.Time, steps string) string {
		return fmt.Sprintf(`{"schema_version":1,"generation_id":"left-behind","phase":"active","pre_state":[],"steps":%s,"created_at":%q,"updated_at":%q}`,
			steps, created.UTC().Format(time.RFC3339), created.UTC().Format(time.RFC3339))
	}
	now := time.Now()
	var olderPath, newerPath string
	d, _, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.routeManager.SetCommandRunner(k)
		d.hooks.interfaceUp = func(string) bool { return true }
		dir := filepath.Dir(d.routeManager.JournalPath())
		// The directory lists utun7 before utun9, which is the wrong order.
		olderPath = filepath.Join(dir, "transition-utun7.json")
		newerPath = filepath.Join(dir, "transition-utun9.json")
		older := `[{"kind":"change_default","gateway":"192.168.7.1","prior_interface":"` + olderTunIface + `"}]`
		newer := `[{"kind":"change_default","gateway":"192.168.7.1","prior_gateway":"192.168.7.1","prior_interface":"en0"}]`
		for path, body := range map[string]string{
			olderPath: journal(now.Add(-2*time.Minute), older),
			newerPath: journal(now.Add(-time.Minute), newer),
		} {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}, "api.rw-test.invalid")

	if _, iface := k.defaultRoute(); iface != olderTunIface {
		gw, _ := k.defaultRoute()
		t.Fatalf("default after recovery = %q on %q, want the older tunnel's default (%s) kept; the newer journal must not undo it", gw, iface, olderTunIface)
	}
	for _, path := range []string{olderPath, newerPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s must be removed once recovered", filepath.Base(path))
		}
	}
	if degraded, reason := d.Degraded(); degraded {
		t.Errorf("recovery must leave the daemon healthy: %s", reason)
	}
}

// --- sync: a stale plan never applies over a newer one ---

type resolveGate struct {
	armed    atomic.Bool
	entered  chan struct{}
	release  chan struct{}
	enterOne sync.Once
}

func newResolveGate() *resolveGate {
	return &resolveGate{entered: make(chan struct{}), release: make(chan struct{})}
}

// wait blocks the first resolution after arm until release is closed.
func (g *resolveGate) wait() {
	if g.armed.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.release
	}
}

func TestAStaleSyncNeverAppliesOverANewerOne(t *testing.T) {
	k := newFakeKernel()
	gate := newResolveGate()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, []string{"aws.example.com"}, func(d *Daemon) {
		inner := d.hooks.resolveExact
		d.hooks.resolveExact = func(ctx context.Context, s *tunnelSession, domains []string) (map[string][]net.IP, error) {
			gate.wait()
			return inner(ctx, s, domains)
		}
	})
	env.answers.set("any.example.com", "10.50.0.1")
	env.answers.set("aws.example.com", "10.200.0.1")
	d := env.d

	// AWS, the lower-priority tunnel, is alone and holds the Any VPN list.
	env.connectAWS()
	waitForRoutes(t, d, awsIface, "10.200.0.1", "10.50.0.1")
	waitHost(t, k, "10.50.0.1", awsIface)

	// A refresh sync snapshots [AWS] and stalls resolving names.
	gate.armed.Store(true)
	d.TriggerSync()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the refresh sync never started")
	}

	// WireGuard, which outranks AWS, connects while that sync is in flight, and
	// the Any VPN name's address changes meanwhile. The stalled sync resolves
	// it once released, from the sessions it snapshotted.
	env.connectWG()
	waitForSession(t, d, wgIface)
	env.answers.set("any.example.com", "10.50.0.2")
	close(gate.release)

	waitForRoutes(t, d, wgIface, "10.50.0.2")
	waitForRoutes(t, d, awsIface, "10.200.0.1")
	waitHost(t, k, "10.50.0.2", wgIface)
	waitNoHost(t, k, "10.50.0.1")
	if holds(d, awsIface, "10.50.0.2") {
		t.Error("AWS records an address WireGuard owns")
	}
	if k.has("add -host 10.50.0.2 " + awsGW) {
		t.Errorf("a plan built before WireGuard connected was applied: AWS added the Any VPN address WireGuard owns: %v", k.log())
	}
	if degraded, reason := d.Degraded(); degraded {
		t.Errorf("daemon degraded: %s", reason)
	}
}

// --- ownership between RouteWise's own managers and the kernel ---

func TestAHostRouteSomethingElseHoldsIsNeverAdopted(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, []string{"*.wg.example.com"}, nil, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectWG()
	s := waitForSession(t, d, wgIface)
	waitHost(t, k, "10.50.0.1", wgIface)

	// A route to this address already leaves through the LAN, put there by
	// something other than RouteWise.
	k.putHost("10.60.0.1", "192.168.7.1", "en0")
	answer(d, "git.wg.example.com", "10.60.0.1")

	if _, ok := s.manager.GetRoute(netip.MustParseAddr("10.60.0.1")); ok {
		t.Error("a route RouteWise did not add must not be recorded as its own because `File exists`")
	}
	if got := d.learnedSnapshot(s); len(got) != 0 {
		t.Errorf("learned = %v, want an address that could not be routed to be forgotten", got)
	}
	if iface, _ := k.hostRoute("10.60.0.1"); iface != "en0" {
		t.Errorf("the foreign route now leaves through %q, want it left alone", iface)
	}
	d.syncRoutes(d.currentGeneration())
	if holds(d, wgIface, "10.60.0.1") {
		t.Error("a sync must not adopt it either")
	}
	if degraded, reason := d.Degraded(); degraded {
		t.Errorf("a conflict is reported, not a reason to degrade: %s", reason)
	}
}

func TestAnAddressWhoseDeleteFailedStaysWithItsHolderAndIsNotAdopted(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, nil, []string{"wg.example.com"}, []string{"aws.example.com"}, nil)
	env.answers.set("wg.example.com", "10.9.9.9", "10.100.0.1")
	env.answers.set("aws.example.com", "10.9.9.9", "10.200.0.1")
	d := env.d

	// AWS, lower priority, connects first and holds the shared address.
	env.connectAWS()
	waitHost(t, k, "10.9.9.9", awsIface)

	// Taking it away fails, so the higher-priority WireGuard cannot have it.
	k.failAlways("delete -host 10.9.9.9", errors.New("route: delete: operation not permitted"))
	env.connectWG()
	waitForSession(t, d, wgIface)
	waitHost(t, k, "10.100.0.1", wgIface)

	if iface, _ := k.hostRoute("10.9.9.9"); iface != awsIface {
		t.Errorf("shared address leaves through %q, want it still with AWS, whose route could not be removed", iface)
	}
	if holds(d, wgIface, "10.9.9.9") {
		t.Error("WireGuard must not record an address AWS still holds in the kernel")
	}
	if !holds(d, awsIface, "10.9.9.9") {
		t.Error("AWS must keep owning the address while its delete is pending, or nothing would ever remove it")
	}
	if degraded, reason := d.sessions.get(wgIface).manager.Degraded(); degraded {
		t.Errorf("WireGuard did nothing wrong and must stay healthy: %s", reason)
	}

	// Once the delete works, the address moves to its higher-priority owner.
	k.clearFailures()
	if err := d.sessions.get(awsIface).manager.RetryPendingCleanup(); err != nil {
		t.Fatalf("retry AWS cleanup: %v", err)
	}
	d.syncRoutes(d.currentGeneration())
	waitHost(t, k, "10.9.9.9", wgIface)
	if holds(d, awsIface, "10.9.9.9") || !holds(d, wgIface, "10.9.9.9") {
		t.Error("the address must end up with WireGuard alone")
	}
}

func sharedDNS(addr string) func(*Daemon) {
	server := netip.MustParseAddr(addr)
	return func(d *Daemon) {
		d.hooks.vpnNameservers = func(context.Context, string, bool) ([]netip.Addr, bool, error) {
			return []netip.Addr{server}, true, nil
		}
	}
}

func TestAVPNDNSServerTwoTunnelsShareBelongsToTheHigherPriorityAndFollowsIt(t *testing.T) {
	const server = "9.9.9.9"

	t.Run("lower priority connects first and is taken over", func(t *testing.T) {
		k := newFakeKernel()
		env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, sharedDNS(server))
		env.answers.set("any.example.com", "10.50.0.1")
		d := env.d

		env.connectAWS()
		waitHost(t, k, server, awsIface)
		env.connectWG()
		waitHost(t, k, server, wgIface)
		if holds(d, awsIface, server) {
			t.Error("the lower-priority tunnel must give the shared DNS route up")
		}

		env.disconnectWG()
		waitFor(t, "the remaining tunnel to route the DNS server", func() bool {
			iface, ok := k.hostRoute(server)
			return ok && iface == awsIface
		})
		if !holds(d, awsIface, server) {
			t.Error("the next tunnel must re-add the DNS route when the owner leaves; it must not go out the LAN")
		}
	})

	t.Run("higher priority connects first and keeps it", func(t *testing.T) {
		k := newFakeKernel()
		env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, sharedDNS(server))
		env.answers.set("any.example.com", "10.50.0.1")
		d := env.d

		env.connectWG()
		waitHost(t, k, server, wgIface)
		env.connectAWS()
		waitForSession(t, d, awsIface)
		waitFor(t, "AWS to record the DNS server as its own", func() bool {
			return len(d.vpnDNSServersOf(d.sessions.get(awsIface))) == 1
		})
		if iface, _ := k.hostRoute(server); iface != wgIface {
			t.Errorf("DNS server leaves through %q, want it to stay with the higher-priority %s", iface, wgIface)
		}
		if holds(d, awsIface, server) {
			t.Error("the lower-priority tunnel must not claim a route another tunnel holds")
		}

		env.disconnectWG()
		waitFor(t, "AWS to take the DNS route over", func() bool {
			iface, ok := k.hostRoute(server)
			return ok && iface == awsIface
		})
	})
}

// --- the disconnect window ---

func TestAnAnswerDuringADisconnectNeverAdoptsARouteThatIsBeingDeleted(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"*.any.example.com"}, nil, []string{"aws.example.com"}, nil)
	env.answers.set("aws.example.com", "10.200.0.1")
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForSession(t, d, wgIface)
	waitForSession(t, d, awsIface)

	// WireGuard owns the Any VPN list and holds a learned address.
	answer(d, "a.any.example.com", "10.70.0.1")
	waitHost(t, k, "10.70.0.1", wgIface)

	// Pause WireGuard's cleanup at the delete of that address.
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	k.mu.Lock()
	k.beforeRun = func(call string) {
		if strings.Contains(call, "delete -host 10.70.0.1") {
			once.Do(func() {
				close(entered)
				<-release
			})
		}
	}
	k.mu.Unlock()
	env.disconnectWG()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the disconnect never reached the delete")
	}

	// A lookup answers for the same address while the route is being deleted.
	done := make(chan struct{})
	go func() {
		defer close(done)
		answer(d, "b.any.example.com", "10.70.0.1")
	}()
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-done

	// The delete finished first, then the answer routed the address through
	// AWS, which is now the Any VPN owner. Adopting the route mid-delete would
	// leave AWS recording a route the kernel no longer has.
	waitFor(t, "WireGuard to be gone", func() bool { return d.sessions.get(wgIface) == nil })
	waitHost(t, k, "10.70.0.1", awsIface)
	if !holds(d, awsIface, "10.70.0.1") {
		t.Error("AWS must hold the address it now routes")
	}
}

// --- learned routes follow a list change at the next sync ---

func TestMovingAPatternToAnotherClientMovesItsLearnedRoutes(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"*.any.example.com"}, []string{"*.corp.example.com"}, []string{"*.aws.example.com"}, nil)
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForSession(t, d, wgIface)
	waitForSession(t, d, awsIface)

	answer(d, "git.corp.example.com", "10.80.0.1")
	waitHost(t, k, "10.80.0.1", wgIface)

	// *.corp.example.com moves from WireGuard's list to AWS's.
	if err := d.SetDomains(wireGuardPath, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.SetDomains(awsClientPath, []string{"*.aws.example.com", "*.corp.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	mark := len(k.log())
	d.syncRoutes(d.currentGeneration())

	waitHost(t, k, "10.80.0.1", awsIface)
	if holds(d, wgIface, "10.80.0.1") || !holds(d, awsIface, "10.80.0.1") {
		t.Error("the learned route must move to the new owner, not stay with the old one until expiry")
	}
	calls := k.log()[mark:]
	del, add := indexOf(calls, "delete -host 10.80.0.1", 0), indexOf(calls, "add -host 10.80.0.1 "+awsGW, 0)
	if del < 0 || add < 0 || del > add {
		t.Errorf("calls = %v, want the old owner's route deleted before the new owner adds it", calls)
	}
}

func TestMovingAPatternToAClientWhoseTunnelIsDownDropsItsLearnedRoutes(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"*.any.example.com"}, []string{"*.corp.example.com"}, []string{"*.aws.example.com"}, nil)
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForSession(t, d, wgIface)
	waitForSession(t, d, awsIface)
	answer(d, "git.corp.example.com", "10.80.0.1")
	waitHost(t, k, "10.80.0.1", wgIface)

	env.disconnectAWS()
	waitFor(t, "the AWS session to go", func() bool { return d.sessions.get(awsIface) == nil })
	if err := d.SetDomains(wireGuardPath, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := d.SetDomains(awsClientPath, []string{"*.aws.example.com", "*.corp.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	d.syncRoutes(d.currentGeneration())

	waitNoHost(t, k, "10.80.0.1")
	if holds(d, wgIface, "10.80.0.1") {
		t.Error("a name that now belongs to a client whose tunnel is down must go direct")
	}
	if got := learnedCount(d); got != 0 {
		t.Errorf("learned = %d, want it dropped", got)
	}
}

func TestRemovingAPatternDropsItsLearnedRoutesWithoutWaitingForExpiry(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"*.any.example.com"}, []string{"*.corp.example.com"}, nil, nil)
	d := env.d
	env.connectWG()
	waitForSession(t, d, wgIface)
	answer(d, "git.corp.example.com", "10.80.0.1")
	waitHost(t, k, "10.80.0.1", wgIface)

	if err := d.RemoveDomain(wireGuardPath, "*.corp.example.com"); err != nil {
		t.Fatal(err)
	}
	d.syncRoutes(d.currentGeneration())
	waitNoHost(t, k, "10.80.0.1")
}

func TestRevokingAClientDropsItsLearnedRoutesAtTheNextSync(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"*.any.example.com"}, nil, []string{"*.aws.example.com"}, nil)
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForSession(t, d, wgIface)
	waitForSession(t, d, awsIface)
	answer(d, "git.aws.example.com", "10.81.0.1")
	waitHost(t, k, "10.81.0.1", awsIface)

	if err := d.SetVPNClientAllowed(awsClientPath, false); err != nil {
		t.Fatal(err)
	}
	d.syncRoutes(d.currentGeneration())
	waitNoHost(t, k, "10.81.0.1")
}

func TestAHigherPriorityTunnelTakesTheAnyVPNLearnedRoutes(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"*.any.example.com"}, nil, nil, nil)
	d := env.d
	env.connectAWS()
	waitForSession(t, d, awsIface)
	answer(d, "a.any.example.com", "10.82.0.1")
	waitHost(t, k, "10.82.0.1", awsIface)

	env.connectWG()
	waitHost(t, k, "10.82.0.1", wgIface)
	if holds(d, awsIface, "10.82.0.1") {
		t.Error("the lower-priority tunnel must not keep Any VPN addresses the higher one now owns")
	}
}

// --- identifying who owns a tunnel ---

// identity is a switchable answer for which client owns every interface.
type identity struct {
	mu     sync.Mutex
	client vpnclient.Client
	err    error
	calls  int
}

func (i *identity) set(c vpnclient.Client, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.client, i.err = c, err
}

func (i *identity) lookup(context.Context, string) (vpnclient.Client, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.calls++
	return i.client, i.err
}

func TestAReusedTunnelNameIsIdentifiedAgainAfterADisconnect(t *testing.T) {
	id := &identity{client: vpnclient.FromPath(wireGuardPath)}
	d, w, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) { d.hooks.identifyClient = id.lookup }, "api.rw-test.invalid")
	if err := d.SetVPNClientAllowed(wireGuardPath, true); err != nil {
		t.Fatal(err)
	}
	if !d.admitTunnel("utun6") {
		t.Fatal("the allowed WireGuard tunnel must be admitted")
	}
	connectTunnel(w, "utun6", "10.6.0.1")
	waitForSession(t, d, "utun6")

	// WireGuard disconnects and, within the cache's lifetime, a VPN that is
	// not allowed takes the same utun name.
	disconnectTunnel(w, "utun6")
	waitFor(t, "the session to go", func() bool { return d.sessions.get("utun6") == nil })
	id.set(vpnclient.FromPath(testenv.Exe("/opt/other-vpn/bin/other-vpn")), nil)

	if d.admitTunnel("utun6") {
		t.Fatal("a cached identity survived the disconnect: the new VPN was admitted as WireGuard")
	}
	if _, pending := d.VPNClients(); len(pending) != 1 || pending[0].Client.Name != "other-vpn" {
		t.Errorf("pending = %+v, want the new VPN reported", pending)
	}
}

func TestAConnectEventIdentifiesTheTunnelAgainAndRefusesAClientThatIsNotAllowed(t *testing.T) {
	id := &identity{client: vpnclient.FromPath(wireGuardPath)}
	d, w, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) { d.hooks.identifyClient = id.lookup }, "api.rw-test.invalid")
	if err := d.SetVPNClientAllowed(wireGuardPath, true); err != nil {
		t.Fatal(err)
	}
	if !d.admitTunnel("utun6") {
		t.Fatal("setup: WireGuard must be admitted first")
	}

	// By the time the connect event is handled, the interface belongs to a VPN
	// that is not allowed; the admission above used a stale answer.
	id.set(vpnclient.FromPath(testenv.Exe("/opt/other-vpn/bin/other-vpn")), nil)
	connectTunnel(w, "utun6", "10.6.0.1")
	waitFor(t, "the connect to be refused", func() bool {
		_, pending := d.VPNClients()
		return len(pending) == 1
	})
	if d.sessions.get("utun6") != nil {
		t.Error("a tunnel whose fresh owner is not allowed must not be managed")
	}
}

// A failed identification is remembered and retried with a backoff, so an
// ownerless tunnel does not cost a process scan at every monitor check; once
// the wait has passed, or the interface is forgotten, the owner is asked again.
func TestAnIdentifyFailureIsRetriedOnlyAfterItsBackoff(t *testing.T) {
	id := &identity{err: errors.New("lsof found nothing")}
	d, _, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) { d.hooks.identifyClient = id.lookup }, "api.rw-test.invalid")
	if err := d.SetVPNClientAllowed(wireGuardPath, true); err != nil {
		t.Fatal(err)
	}
	if d.admitTunnel("utun6") {
		t.Fatal("an unidentified tunnel must not be admitted")
	}
	id.set(vpnclient.FromPath(wireGuardPath), nil)
	if d.admitTunnel("utun6") || id.calls != 1 {
		t.Fatalf("the failure must be cached during its backoff; admitted/calls = %d lookups", id.calls)
	}

	d.clientMu.Lock()
	c := d.clientCache["utun6"]
	c.retryAt = time.Now().Add(-time.Millisecond)
	d.clientCache["utun6"] = c
	d.clientMu.Unlock()
	if !d.admitTunnel("utun6") {
		t.Fatal("after the backoff the next check must ask again")
	}
}

// --- several pending tunnels ---

func TestSeveralPendingTunnelsAreEachReportedAndLoggedOnce(t *testing.T) {
	id := &identity{}
	byIface := map[string]vpnclient.Client{
		"utun6": vpnclient.FromPath(testenv.Exe("/opt/one/bin/one-vpn")),
		"utun8": vpnclient.FromPath(testenv.Exe("/opt/two/bin/two-vpn")),
	}
	d, _, _, _ := newDNSTestDaemonWith(t, func(d *Daemon) {
		d.hooks.identifyClient = func(ctx context.Context, iface string) (vpnclient.Client, error) {
			id.lookup(ctx, iface)
			return byIface[iface], nil
		}
	}, "api.rw-test.invalid")

	// The monitor checks both on every poll.
	for range 10 {
		d.admitTunnel("utun6")
		d.admitTunnel("utun8")
	}

	_, pending := d.VPNClients()
	if len(pending) != 2 || pending[0].Interface != "utun6" || pending[1].Interface != "utun8" {
		t.Fatalf("pending = %+v, want both tunnels, ordered by interface", pending)
	}
	events := 0
	for _, e := range eventsOfKind(d, activity.KindVPN) {
		if strings.Contains(e.Detail, "not managed") {
			events++
		}
	}
	if events != 2 {
		t.Errorf("activity events = %d, want one per tunnel and not one per check", events)
	}

	// A tunnel that becomes allowed leaves the list; the other stays.
	if err := d.SetVPNClientAllowed(testenv.Exe("/opt/one/bin/one-vpn"), true); err != nil {
		t.Fatal(err)
	}
	d.admitTunnel("utun6")
	if _, pending := d.VPNClients(); len(pending) != 1 || pending[0].Interface != "utun8" {
		t.Errorf("pending = %+v, want only utun8 once utun6 is allowed", pending)
	}
}

// --- smaller fixes ---

func TestRoutesAManagerCouldNotRemoveStayVisibleInStatus(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, []string{"wg.example.com"}, nil, nil)
	env.answers.set("any.example.com", "10.50.0.1")
	env.answers.set("wg.example.com", "10.100.0.1")
	d := env.d
	env.connectWG()
	waitForRoutes(t, d, wgIface, "10.100.0.1", "10.50.0.1")

	k.failAlways("delete -host 10.100.0.1", errors.New("route: delete: operation not permitted"))
	env.disconnectWG()
	waitFor(t, "the WireGuard session to go", func() bool { return d.sessions.get(wgIface) == nil })

	// The kernel still holds the route, so status must still show it.
	if _, ok := k.hostRoute("10.100.0.1"); !ok {
		t.Fatal("test setup: the route should still be in the table")
	}
	if got := d.GetRouteCount(); got != 1 {
		t.Errorf("GetRouteCount = %d, want the one route the retired manager still holds", got)
	}
	var seen bool
	for _, r := range d.GetActiveRoutes() {
		if r.IP == "10.100.0.1" && r.Interface == wgIface {
			seen = true
		}
	}
	if !seen {
		t.Errorf("routes = %+v, want 10.100.0.1 through %s listed", d.GetActiveRoutes(), wgIface)
	}
	k.clearFailures()
}

func TestATunnelConnectedAfterAnImportStillUsesTheServersTheDaemonStartedWith(t *testing.T) {
	k := newFakeKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, nil)
	d := env.d
	before := d.resolver.Upstreams()

	cfg := mustSnapshot(d)
	cfg.DNS.Servers = []string{"203.0.113.9"}
	if _, err := d.store.Replace(cfg); err != nil {
		t.Fatal(err)
	}
	env.connectWG()
	s := waitForSession(t, d, wgIface)

	if got := s.resolver.Upstreams(); !slices.Equal(got, before) {
		t.Errorf("new tunnel's upstreams = %v, want the start-time servers %v like every other resolver, until a restart", got, before)
	}
}
