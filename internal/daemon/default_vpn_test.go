package daemon

import (
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/route"
)

const allGlobalIPv6 = "2000::/3"

func ptr(s string) *string { return &s }

// useInvertedConfig sets the mode the default VPN needs. The test daemon's
// config is additive whatever its managers do.
func useInvertedConfig(t *testing.T, d *Daemon) {
	t.Helper()
	cfg, _ := d.store.Snapshot()
	if cfg.Routing.Mode == config.RoutingModeInverted {
		return
	}
	cfg.Routing.Mode = config.RoutingModeInverted
	if _, err := d.store.Replace(cfg); err != nil {
		t.Fatalf("seed routing mode: %v", err)
	}
}

func setDefaultVPN(t *testing.T, d *Daemon, client, fallback string) {
	t.Helper()
	useInvertedConfig(t, d)
	if err := d.SetDefaultVPN(ptr(client), ptr(fallback)); err != nil {
		t.Fatalf("SetDefaultVPN(%q, %q): %v", client, fallback, err)
	}
}

// hasPair reports whether the role's routes all lead through iface.
func hasPair(k *fakeKernel, iface string) bool {
	for _, p := range route.CatchAllPrefixes() {
		if !k.hasNet(p.String(), iface) {
			return false
		}
	}
	return true
}

// roleRoutes lists the role's routes in the table, leaving out a client's own /1 pair.
func roleRoutes(k *fakeKernel) []kernelNetRoute {
	var out []kernelNetRoute
	for _, n := range k.netRoutes() {
		if strings.HasSuffix(n.dest, "/2") {
			out = append(out, n)
		}
	}
	return out
}

func waitPair(t *testing.T, k *fakeKernel, iface string) {
	t.Helper()
	waitFor(t, "the default VPN routes to lead through "+iface, func() bool { return hasPair(k, iface) })
}

func waitNoPair(t *testing.T, k *fakeKernel) {
	t.Helper()
	waitFor(t, "the default VPN routes to go", func() bool { return len(roleRoutes(k)) == 0 })
}

func waitDefaultVPNState(t *testing.T, d *Daemon, want api.DefaultVPNState, active string) {
	t.Helper()
	waitFor(t, "the default VPN state to be "+string(want), func() bool {
		s := d.DefaultVPNStatus()
		return s != nil && s.State == want && s.ActiveInterface == active
	})
}

// A VPN app as the default VPN: everything unlisted goes through it, and a name
// in another VPN's list keeps its own tunnel, however often the sweeps run.
func TestDefaultVPNCarriesWhatNoListClaimsAndListsKeepTheirTunnel(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, nil, []string{"10.60.0.5"}, nil, inverted(k))
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForSession(t, d, wgIface)
	s := waitForSession(t, d, awsIface)
	waitHost(t, k, "10.60.0.5", wgIface)

	setDefaultVPN(t, d, awsClientPath, "")
	waitPair(t, k, awsIface)
	waitDefaultVPNState(t, d, api.DefaultVPNPrimary, awsIface)

	d.syncRoutes(d.currentGeneration())
	if err := s.manager.EnforceSplitTunnel(); err != nil {
		t.Fatalf("EnforceSplitTunnel: %v", err)
	}
	if !hasPair(k, awsIface) {
		t.Errorf("the sweeps removed the default VPN's routes: %v", k.netRoutes())
	}
	if iface, ok := k.hostRoute("10.60.0.5"); !ok || iface != wgIface {
		t.Errorf("10.60.0.5 leaves through %q, want its own VPN %s", iface, wgIface)
	}
	if gw, iface := k.defaultRoute(); iface != "en0" {
		t.Errorf("default = %q on %q, want it left on the LAN", gw, iface)
	}
	if !k.hasReject(allGlobalIPv6) {
		t.Error("IPv6 must be blocked while the default VPN carries the traffic")
	}
}

// A route that goes missing comes back at the next pass of the timer.
func TestAPassRestoresARouteThatWentMissing(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectAWS()
	waitForSession(t, d, awsIface)
	setDefaultVPN(t, d, awsClientPath, "")
	waitPair(t, k, awsIface)

	if err := k.del([]string{"-net", "128.0.0.0/2"}); err != nil {
		t.Fatalf("drop a route: %v", err)
	}
	d.reconcileDefaultVPN(d.currentGeneration())
	if !hasPair(k, awsIface) {
		t.Errorf("routes after a pass = %v, want all of them back", k.netRoutes())
	}
}

// The role must leave the /1 pair free: it is how a VPN client that connects later
// gets detected, and a client whose route add fails may give up altogether.
func TestAVPNThatConnectsWhileTheRoleIsHeldIsStillDetectedAndSwept(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectWG()
	waitForSession(t, d, wgIface)
	setDefaultVPN(t, d, wireGuardPath, "")
	waitPair(t, k, wgIface)

	for _, half := range []string{"0/1", "128.0/1"} {
		if err := k.add([]string{"-net", half, awsGW}); err != nil {
			t.Fatalf("the client could not add %s while the role is held: %v", half, err)
		}
	}
	env.connectAWS()
	waitForSession(t, d, awsIface)
	waitFor(t, "the client's own pair to be swept", func() bool { return len(k.netRoutes()) == len(route.CatchAllPrefixes()) })
	if !hasPair(k, wgIface) {
		t.Errorf("routes = %v, want the role left where it is", k.netRoutes())
	}
}

func TestDefaultVPNDownGoesDirectWithoutAFallback(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectAWS()
	waitForSession(t, d, awsIface)
	setDefaultVPN(t, d, awsClientPath, "")
	waitPair(t, k, awsIface)

	env.disconnectAWS()
	waitNoPair(t, k)
	waitDefaultVPNState(t, d, api.DefaultVPNDirect, "")
	waitFor(t, "the IPv6 block to go", func() bool { return !k.hasReject(allGlobalIPv6) })
	// The journal goes last, so that a crash cannot lose track of a route.
	waitFor(t, "the journal to go", func() bool {
		_, err := os.Stat(d.defaultVPNJournalPath())
		return errors.Is(err, os.ErrNotExist)
	})
}

func TestDefaultVPNSwitchesToItsFallbackAndBack(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForSession(t, d, wgIface)
	waitForSession(t, d, awsIface)

	setDefaultVPN(t, d, awsClientPath, wireGuardPath)
	waitPair(t, k, awsIface)

	env.disconnectAWS()
	waitPair(t, k, wgIface)
	waitDefaultVPNState(t, d, api.DefaultVPNFallback, wgIface)

	env.connectAWS()
	waitForSession(t, d, awsIface)
	waitPair(t, k, awsIface)
	waitDefaultVPNState(t, d, api.DefaultVPNPrimary, awsIface)
	if k.hasNet("0.0.0.0/2", wgIface) {
		t.Errorf("the fallback kept the routes: %v", k.netRoutes())
	}

	setDefaultVPN(t, d, "", "")
	waitNoPair(t, k)
	if got := d.DefaultVPNStatus(); got != nil {
		t.Errorf("status with no default VPN = %+v, want nil", got)
	}
	if d.Settings().DefaultVPNFallback != "" {
		t.Error("clearing the default VPN must clear its fallback")
	}
}

// A listed name whose VPN is down has no route of its own, so it falls into the
// pair; when its VPN returns its /32 outranks the pair again.
func TestAListedNameFollowsTheDefaultVPNWhileItsOwnVPNIsDown(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, nil, []string{"10.60.0.5"}, nil, inverted(k))
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForSession(t, d, wgIface)
	waitForSession(t, d, awsIface)
	waitHost(t, k, "10.60.0.5", wgIface)
	setDefaultVPN(t, d, awsClientPath, "")
	waitPair(t, k, awsIface)

	env.disconnectWG()
	waitNoHost(t, k, "10.60.0.5")
	if !hasPair(k, awsIface) {
		t.Fatalf("routes = %v, want the pair to take the name", k.netRoutes())
	}

	env.connectWG()
	waitHost(t, k, "10.60.0.5", wgIface)
}

// Stopping the helper hands a VPN app back the routes it installed itself.
func TestStopRemovesTheRoleAndRestoresTheClientsOwnPair(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	k.putNet("0/1", awsGW, awsIface)
	k.putNet("128.0/1", awsGW, awsIface)
	env.connectAWS()
	waitForSession(t, d, awsIface)
	waitFor(t, "activation to remove the client's pair", func() bool { return len(k.netRoutes()) == 0 })

	setDefaultVPN(t, d, awsClientPath, "")
	waitPair(t, k, awsIface)
	d.Stop()

	routes := k.netRoutes()
	if len(routes) != 2 {
		t.Fatalf("routes after Stop = %v, want the client's two halves", routes)
	}
	for _, r := range routes {
		if r.gateway != awsGW {
			t.Errorf("route %+v after Stop, want the client's own, through %s", r, awsGW)
		}
	}
	if k.hasReject(allGlobalIPv6) {
		t.Error("Stop must remove the IPv6 block")
	}
}

func TestAHalfAnotherTunnelHoldsLeavesTrafficDirectAndSaysWhy(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectAWS()
	waitForSession(t, d, awsIface)

	k.putNet("0.0.0.0/2", "", "utun77")
	setDefaultVPN(t, d, awsClientPath, "")
	waitFor(t, "the conflict to be reported", func() bool {
		s := d.DefaultVPNStatus()
		return s != nil && strings.Contains(s.Problem, "utun77")
	})
	if k.hasNet("128.0.0.0/2", awsIface) {
		t.Errorf("part of the role's routes were installed: %v", k.netRoutes())
	}
	if s := d.DefaultVPNStatus(); s.State != api.DefaultVPNDirect {
		t.Errorf("state = %s, want direct", s.State)
	}
}

// A built-in tunnel holds the role only once proven, its server stays outside
// the tunnel, and the role goes at its first failed health check.
func TestBuiltInDefaultVPNIsGatedByHealthAndKeepsItsServerOutOfTheTunnel(t *testing.T) {
	k := lanDefaultKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	e.d.routeManager.SetOriginalGateway(netip.MustParseAddr("192.168.7.1"), "en0")
	k.scopedGW, k.scopedIface = "192.168.7.1", "en0"
	k.setDefault("192.168.7.1", "en0")
	d := e.d
	server := netip.MustParseAddr("198.51.100.7")
	e.starter.plan = func(int, tunnelStartRequest) ([]netip.Addr, error) { return []netip.Addr{server}, nil }
	e.starter.onStart = func(_ tunnelStartRequest, tn *fakeTunnel) { tn.setProbe(errors.New("not up yet")) }

	id := e.importOutline(t, "Travel", "198.51.100.7")
	profile, _ := d.store.Profile(id)
	setDefaultVPN(t, d, profile.ClientID(), "")
	iface := e.connect(t, id)
	e.armed(t, 1)
	if len(roleRoutes(k)) != 0 {
		t.Fatalf("routes before the tunnel is proven = %v, want none", k.netRoutes())
	}

	e.starter.tunnel(id).setProbe(nil)
	e.tick(t, 1)
	waitPair(t, k, iface)
	calls := k.log()
	serverAt, pairAt := indexOf(calls, "add -host "+server.String(), 0), indexOf(calls, "add -net 0.0.0.0/2", 0)
	if serverAt < 0 || serverAt > pairAt {
		t.Errorf("calls = %v, want the server's route before the pair", calls)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "add -host "+server.String()+" 192.168.7.1") {
		t.Errorf("calls = %v, want the server routed through the LAN gateway", calls)
	}

	e.armed(t, 1)
	e.starter.tunnel(id).setProbe(errors.New("probe failed"))
	for range 3 {
		e.tick(t, 1)
	}
	waitNoPair(t, k)
	waitNoHost(t, k, server.String())
	waitDefaultVPNState(t, d, api.DefaultVPNDirect, "")
}

func TestAPeerThatCannotCarryEverythingIsPassedOverForTheFallback(t *testing.T) {
	k := lanDefaultKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	d := e.d
	e.starter.plan = func(int, tunnelStartRequest) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.8")}, nil
	}
	e.starter.onStart = func(_ tunnelStartRequest, tn *fakeTunnel) {
		tn.allowed = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	}
	id := e.importWireGuard(t, "Office", "198.51.100.8:51820")
	profile, _ := d.store.Profile(id)
	setDefaultVPN(t, d, profile.ClientID(), "")
	e.connect(t, id)
	e.tick(t, 1)
	e.waitState(t, id, api.ProfileConnected)

	waitFor(t, "the refusal to be reported", func() bool {
		s := d.DefaultVPNStatus()
		return s != nil && strings.Contains(s.Problem, "AllowedIPs")
	})
	if len(roleRoutes(k)) != 0 {
		t.Errorf("routes = %v, want none through a peer that would drop the traffic", k.netRoutes())
	}
	if !e.hasActivity(activity.KindRefused, "Default VPN", "AllowedIPs") {
		t.Error("the refusal must be recorded in the activity log")
	}
}

func TestAllowingIPv6LiftsTheDefaultVPNsBlock(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectAWS()
	waitForSession(t, d, awsIface)
	setDefaultVPN(t, d, awsClientPath, "")
	waitFor(t, "IPv6 to be blocked", func() bool { return k.hasReject(allGlobalIPv6) })

	if err := d.SetAllowIPv6(true); err != nil {
		t.Fatalf("SetAllowIPv6: %v", err)
	}
	waitFor(t, "the block to lift", func() bool { return !k.hasReject(allGlobalIPv6) })
	if !hasPair(k, awsIface) {
		t.Errorf("routes = %v, want the pair kept", k.netRoutes())
	}
}

func TestSetDefaultVPNRefusesWhatCannotWork(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	d := env.d
	useInvertedConfig(t, d)
	for name, args := range map[string][2]string{
		"unknown client":   {"/Applications/Nobody.app", ""},
		"unknown fallback": {awsClientPath, "/Applications/Nobody.app"},
		"its own fallback": {awsClientPath, awsClientPath},
	} {
		if err := d.SetDefaultVPN(ptr(args[0]), ptr(args[1])); !errors.Is(err, api.ErrRejected) {
			t.Errorf("%s: err = %v, want ErrRejected", name, err)
		}
	}
	if d.Settings().DefaultVPN != "" {
		t.Error("a refused change must not be saved")
	}
}

func TestRevokingTheDefaultVPNClearsTheSetting(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	d := env.d
	setDefaultVPN(t, d, awsClientPath, wireGuardPath)

	cfg, _ := d.store.Snapshot()
	cfg.VPNs = cfg.VPNs[:1] // keeps WireGuard, drops AWS
	if _, err := d.store.Replace(cfg); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got := d.Settings()
	if got.DefaultVPN != "" || got.DefaultVPNFallback != "" {
		t.Errorf("settings = %q, %q, want both cleared with the default gone", got.DefaultVPN, got.DefaultVPNFallback)
	}
}

func TestACrashedHelpersLeftoversAreRemovedAtTheNextStart(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	d := env.d
	k.putHost("198.51.100.9", "192.168.7.1", "en0")
	k.putReject(allGlobalIPv6)
	servers := map[netip.Addr]struct{}{netip.MustParseAddr("198.51.100.9"): {}}
	k.putNet("0.0.0.0/2", "", "utun77")
	if err := d.defaultVPN.saveJournal(true, servers, true); err != nil {
		t.Fatalf("save journal: %v", err)
	}

	d.defaultVPN.recoverLeftovers()

	if _, ok := k.hostRoute("198.51.100.9"); ok {
		t.Error("the leftover server route must go")
	}
	if k.hasReject(allGlobalIPv6) {
		t.Error("the leftover IPv6 block must go")
	}
	if len(roleRoutes(k)) != 0 {
		t.Errorf("routes = %v, a leftover role route must go", k.netRoutes())
	}
	if _, err := os.Stat(d.defaultVPNJournalPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("journal after recovery: %v, want it gone", err)
	}
}

func TestStartRemovesACrashedHelpersLeftovers(t *testing.T) {
	k := lanDefaultKernel()
	k.putReject(allGlobalIPv6)
	newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, func(d *Daemon) {
		inverted(k)(d)
		if err := d.defaultVPN.saveJournal(false, nil, true); err != nil {
			t.Fatalf("save journal: %v", err)
		}
	})
	if k.hasReject(allGlobalIPv6) {
		t.Error("Start must remove the leftover IPv6 block")
	}
}

func TestAnUnreadableJournalStillLiftsTheIPv6Block(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	k.putReject(allGlobalIPv6)
	if err := os.WriteFile(env.d.defaultVPNJournalPath(), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	env.d.defaultVPN.recoverLeftovers()
	if k.hasReject(allGlobalIPv6) {
		t.Error("a reject route only RouteWise adds must not outlive an unreadable journal")
	}
}

func TestAdditiveModeRefusesADefaultVPNAndIgnoresAStoredOne(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, nil)
	d := env.d
	if err := d.SetDefaultVPN(ptr(awsClientPath), nil); !errors.Is(err, api.ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected in additive mode", err)
	}

	cfg, _ := d.store.Snapshot()
	cfg.Routing.DefaultVPN = awsClientPath
	if _, err := d.store.Replace(cfg); err != nil {
		t.Fatal(err)
	}
	env.connectAWS()
	waitForSession(t, d, awsIface)
	d.reconcileDefaultVPN(d.currentGeneration())
	if len(roleRoutes(k)) != 0 {
		t.Errorf("routes = %v, want none in additive mode", k.netRoutes())
	}
	if s := d.DefaultVPNStatus(); s == nil || !strings.Contains(s.Problem, "inverted") {
		t.Errorf("status = %+v, want it to say why", s)
	}
}

func TestSetDefaultVPNRefusesAFallbackWithoutADefault(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	useInvertedConfig(t, env.d)
	if err := env.d.SetDefaultVPN(nil, ptr(wireGuardPath)); !errors.Is(err, api.ErrRejected) {
		t.Errorf("err = %v, want ErrRejected", err)
	}
}

// A removal that fails must not be forgotten: part of IPv4 would stay in a tunnel
// nothing knows about, while the status says direct.
func TestAFailedRemovalIsRetriedAndReportedUntilItWorks(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, inverted(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectAWS()
	waitForSession(t, d, awsIface)
	setDefaultVPN(t, d, awsClientPath, "")
	waitPair(t, k, awsIface)
	gen := d.currentGeneration()

	k.failAlways("delete -net 64.0.0.0/2", errors.New("route: writing to routing socket: operation failed"))
	setDefaultVPN(t, d, "", "")
	d.reconcileDefaultVPN(gen)
	if !k.hasNet("64.0.0.0/2", awsIface) {
		t.Fatalf("routes = %v, the failed delete should have left a route", k.netRoutes())
	}
	if !k.hasReject(allGlobalIPv6) {
		t.Error("the IPv6 block must stay while a role route remains")
	}
	if got := d.defaultVPN.active.Load(); got == nil || got.iface != awsIface {
		t.Errorf("holder = %v, want the tunnel that still holds a route", got)
	}

	k.clearFailures()
	d.reconcileDefaultVPN(gen)
	if len(roleRoutes(k)) != 0 {
		t.Errorf("routes = %v, want the retry to finish", k.netRoutes())
	}
	if k.hasReject(allGlobalIPv6) {
		t.Error("the IPv6 block must go with the last route")
	}
	if degraded, why := d.sessions.get(awsIface).manager.Degraded(); degraded {
		t.Errorf("a failed removal must not degrade the session for good: %s", why)
	}
}

// A holder that cannot be synced may be broken, so it must lose the role.
func TestADegradedHolderLosesTheRoleToItsFallback(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, []string{"10.60.0.5"}, inverted(k))
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectWG()
	env.connectAWS()
	waitForSession(t, d, wgIface)
	waitForSession(t, d, awsIface)
	waitHost(t, k, "10.60.0.5", awsIface)
	setDefaultVPN(t, d, awsClientPath, wireGuardPath)
	waitPair(t, k, awsIface)

	k.failAlways("delete -host 10.60.0.5", errors.New("route: writing to routing socket: operation failed"))
	if err := d.SetDomains(awsClientPath, nil, 0); err != nil {
		t.Fatalf("SetDomains: %v", err)
	}
	d.TriggerSync()
	waitFor(t, "the session to degrade", func() bool {
		degraded, _ := d.sessions.get(awsIface).manager.Degraded()
		return degraded
	})
	k.clearFailures()
	d.reconcileDefaultVPN(d.currentGeneration())

	if !hasPair(k, wgIface) || k.hasNet("0.0.0.0/2", awsIface) {
		t.Errorf("routes = %v, want the role moved to the fallback", k.netRoutes())
	}
	waitDefaultVPNState(t, d, api.DefaultVPNFallback, wgIface)
}

// A route to a built-in VPN's server that the kernel dropped comes back, and one
// through the wrong network moves.
func TestAServerRouteTheKernelDroppedOrMovedIsPutBack(t *testing.T) {
	k := lanDefaultKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	k.scopedGW, k.scopedIface = "192.168.7.1", "en0"
	k.setDefault("192.168.7.1", "en0")
	d := e.d
	e.starter.plan = func(int, tunnelStartRequest) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.7")}, nil
	}
	id := e.importOutline(t, "Travel", "198.51.100.7")
	profile, _ := d.store.Profile(id)
	setDefaultVPN(t, d, profile.ClientID(), "")
	iface := e.connect(t, id)
	e.tick(t, 1)
	waitPair(t, k, iface)
	waitHost(t, k, "198.51.100.7", "en0")

	if err := k.del([]string{"-host", "198.51.100.7"}); err != nil {
		t.Fatal(err)
	}
	d.reconcileDefaultVPN(d.currentGeneration())
	if got, ok := k.hostRoute("198.51.100.7"); !ok || got != "en0" {
		t.Errorf("server route after a pass leaves through %q, want en0", got)
	}

	// A new network: the same server now goes through a new gateway.
	k.reachable = map[string]bool{"10.1.1.1": true}
	k.scopedGW, k.scopedIface = "10.1.1.1", "en0"
	k.setDefault("10.1.1.1", "en0")
	d.reconcileDefaultVPN(d.currentGeneration())
	if !strings.Contains(strings.Join(k.log(), "\n"), "add -host 198.51.100.7 10.1.1.1") {
		t.Errorf("calls = %v, want the server routed through the new gateway", k.log())
	}
}

func TestATunnelOverIPv6KeepsIPv6OpenAndSaysSo(t *testing.T) {
	k := lanDefaultKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	d := e.d
	e.starter.onStart = func(_ tunnelStartRequest, tn *fakeTunnel) { tn.ipv6Transport = true }
	id := e.importOutline(t, "Travel", "198.51.100.7")
	profile, _ := d.store.Profile(id)
	setDefaultVPN(t, d, profile.ClientID(), "")
	iface := e.connect(t, id)
	e.tick(t, 1)
	waitPair(t, k, iface)
	if k.hasReject(allGlobalIPv6) {
		t.Error("blocking IPv6 would cut this tunnel's own transport")
	}
	if s := d.DefaultVPNStatus(); !strings.Contains(s.Problem, "connects over IPv6") {
		t.Errorf("problem = %q, want it to say IPv6 is open and why", s.Problem)
	}
}

func TestATunnelWhoseServerIsUnknownIsPassedOver(t *testing.T) {
	k := lanDefaultKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	d := e.d
	id := e.importOutline(t, "Travel", "198.51.100.7")
	profile, _ := d.store.Profile(id)
	setDefaultVPN(t, d, profile.ClientID(), "")
	e.connect(t, id)
	e.tick(t, 1)
	e.waitState(t, id, api.ProfileConnected)
	waitFor(t, "the refusal to be reported", func() bool {
		s := d.DefaultVPNStatus()
		return s != nil && strings.Contains(s.Problem, "server address")
	})
	if len(roleRoutes(k)) != 0 {
		t.Errorf("routes = %v, the routes would swallow the tunnel's own transport", k.netRoutes())
	}
}

func TestAnAnswerOnTheLANIsNotCalledVPNTraffic(t *testing.T) {
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, []string{"any.example.com"}, nil, nil, func(d *Daemon) {
		inverted(k)(d)
		d.hooks.localPrefixes = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")} }
	})
	env.answers.set("any.example.com", "10.50.0.1")
	d := env.d
	env.connectAWS()
	s := waitForSession(t, d, awsIface)
	setDefaultVPN(t, d, awsClientPath, "")
	waitPair(t, k, awsIface)

	for _, tt := range []struct {
		ip   string
		want *tunnelSession
	}{
		{"93.184.216.34", s},
		{"192.168.7.20", nil},
		{"127.0.0.1", nil},
		{"169.254.1.1", nil},
		{"2606:2800:220:1::1", nil},
	} {
		if got := d.defaultVPN.carries(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("%s carried by %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// The timer rereads each running tunnel while a default VPN is set. A real tunnel
// handle cannot be compared, and doing so once took the helper and every tunnel down.
func TestRereadingARunningTunnelFollowsItsServer(t *testing.T) {
	k := lanDefaultKernel()
	e := newBuiltinEnv(t, k, []string{"any.example.com"}, nil, nil)
	e.answers.set("any.example.com", "10.50.0.1")
	k.scopedGW, k.scopedIface = "192.168.7.1", "en0"
	k.setDefault("192.168.7.1", "en0")
	d := e.d
	e.starter.plan = func(int, tunnelStartRequest) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.7")}, nil
	}
	id := e.importOutline(t, "Travel", "198.51.100.7")
	profile, _ := d.store.Profile(id)
	setDefaultVPN(t, d, profile.ClientID(), "")
	iface := e.connect(t, id)
	e.tick(t, 1)
	waitPair(t, k, iface)
	waitHost(t, k, "198.51.100.7", "en0")

	tunnel := e.starter.tunnel(id)
	tunnel.mu.Lock()
	tunnel.endpoints = []netip.Addr{netip.MustParseAddr("198.51.100.8")}
	tunnel.mu.Unlock()
	d.tunnels.refreshTransports()
	d.reconcileDefaultVPN(d.currentGeneration())

	waitHost(t, k, "198.51.100.8", "en0")
	waitNoHost(t, k, "198.51.100.7")

	// A read that finds nothing keeps what is known.
	tunnel.mu.Lock()
	tunnel.endpoints = nil
	tunnel.mu.Unlock()
	d.tunnels.refreshTransports()
	d.reconcileDefaultVPN(d.currentGeneration())
	if _, ok := k.hostRoute("198.51.100.8"); !ok {
		t.Error("a failed read must not take the route to a server still in use away")
	}
}

// stubDefaultVPNHost shows how little the role needs from the daemon. Its route table
// is nil, so a controller that touched the table when it had nothing to do would panic.
type stubDefaultVPNHost struct {
	pol      *routingPolicy
	sessions []*tunnelSession
	journal  string
	events   []activity.Event
}

func (h *stubDefaultVPNHost) policy() *routingPolicy           { return h.pol }
func (h *stubDefaultVPNHost) sessionList() []*tunnelSession    { return h.sessions }
func (h *stubDefaultVPNHost) isRegistered(*tunnelSession) bool { return true }
func (h *stubDefaultVPNHost) ownsGeneration(*generation) bool  { return true }
func (h *stubDefaultVPNHost) mayMutate(*generation) bool       { return true }
func (h *stubDefaultVPNHost) mayMutateSession(*generation, *tunnelSession) bool {
	return true
}
func (h *stubDefaultVPNHost) routeTable() route.Table               { return nil }
func (h *stubDefaultVPNHost) localInterface() string                { return "en0" }
func (h *stubDefaultVPNHost) localPrefixes() []netip.Prefix         { return nil }
func (h *stubDefaultVPNHost) endpointOwners() map[netip.Addr]string { return nil }
func (h *stubDefaultVPNHost) serverKnown(string) bool               { return true }
func (h *stubDefaultVPNHost) ipv6TransportNames() []string          { return nil }
func (h *stubDefaultVPNHost) ipv6Allowed() bool                     { return false }
func (h *stubDefaultVPNHost) recordActivity(e activity.Event)       { h.events = append(h.events, e) }
func (h *stubDefaultVPNHost) defaultVPNJournalPath() string         { return h.journal }

func TestWithNoDefaultVPNAndNothingHeldTheRoleDoesNothing(t *testing.T) {
	host := &stubDefaultVPNHost{
		pol:     newRoutingPolicy(config.DefaultConfig(), 1, nil),
		journal: t.TempDir() + "/journal.json",
	}
	c := newDefaultVPNController(host, slog.Default())
	c.reconcileLocked(nil)
	if len(host.events) != 0 {
		t.Errorf("events = %v", host.events)
	}
	if c.status() != nil {
		t.Errorf("status = %+v, want none with no default VPN", c.status())
	}
	if c.active.Load() != nil {
		t.Error("nothing should hold the role")
	}
}
