package daemon

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
)

func setExceptions(t *testing.T, d *Daemon, patterns ...string) {
	t.Helper()
	if err := d.SetDefaultVPNExcept(patterns); err != nil {
		t.Fatalf("SetDefaultVPNExcept(%v): %v", patterns, err)
	}
}

// exceptionEnv connects AWS as the default VPN and WireGuard with wgList. configure
// runs before the daemon starts, which is the only time its hooks may be set.
func exceptionEnv(t *testing.T, wgList []string, configure ...func(*Daemon)) (*tunnelEnv, *fakeKernel) {
	t.Helper()
	k := lanDefaultKernel()
	env := newKernelEnv(t, k, nil, wgList, nil, func(d *Daemon) {
		inverted(k)(d)
		d.hooks.resolveExcepted = func(context.Context, []string) (map[string][]net.IP, error) { return nil, nil }
		for _, c := range configure {
			c(d)
		}
	})
	env.connectAWS()
	waitForSession(t, env.d, awsIface)
	setDefaultVPN(t, env.d, awsClientPath, "")
	waitPair(t, k, awsIface)
	return env, k
}

// An IP and a network each get a route through the LAN while the role is held, and
// lose it the moment nothing holds the role, since everything is direct then.
func TestExceptedAddressesGoThroughTheLANOnlyWhileTheRoleIsHeld(t *testing.T) {
	env, k := exceptionEnv(t, nil)
	d := env.d

	setExceptions(t, d, "203.0.113.9", "198.51.100.0/24")
	waitHost(t, k, "203.0.113.9", "en0")
	waitFor(t, "the network to lead through the LAN", func() bool { return k.hasNet("198.51.100.0/24", "en0") })
	if !hasPair(k, awsIface) {
		t.Errorf("the role's routes went away: %v", k.netRoutes())
	}

	env.disconnectAWS()
	waitNoPair(t, k)
	waitNoHost(t, k, "203.0.113.9")
	waitFor(t, "the network route to go", func() bool { return !k.hasNet("198.51.100.0/24", "en0") })
}

// Removing an exception removes its route, and the address returns to the role.
func TestRemovingAnExceptionRemovesItsRoute(t *testing.T) {
	env, k := exceptionEnv(t, nil)
	setExceptions(t, env.d, "203.0.113.9", "203.0.113.10")
	waitHost(t, k, "203.0.113.9", "en0")
	waitHost(t, k, "203.0.113.10", "en0")

	setExceptions(t, env.d, "203.0.113.10")
	waitNoHost(t, k, "203.0.113.9")
	if _, ok := k.hostRoute("203.0.113.10"); !ok {
		t.Error("the exception that stayed lost its route")
	}
}

// An exact name resolves in the sync, and an app's answer through the forwarder adds
// whatever else it was told, which is what keeps a CDN direct.
func TestExceptedNamesRouteWhatTheyResolveToAndWhatAppsAreTold(t *testing.T) {
	env, k := exceptionEnv(t, nil, func(d *Daemon) {
		d.hooks.resolveExcepted = func(_ context.Context, names []string) (map[string][]net.IP, error) {
			out := make(map[string][]net.IP)
			for _, name := range names {
				if name == "bank.example.com" {
					out[name] = []net.IP{net.ParseIP("203.0.113.20")}
				}
			}
			return out, nil
		}
	})
	d := env.d

	setExceptions(t, d, "bank.example.com", "*.cdn.example.com")
	waitHost(t, k, "203.0.113.20", "en0")

	for _, name := range []string{"bank.example.com", "a.cdn.example.com"} {
		if !d.matchesWildcard(name) {
			t.Errorf("the forwarder would not route answers for %s", name)
		}
	}
	if d.matchesWildcard("other.example.com") {
		t.Error("the forwarder would route answers for a name nothing covers")
	}

	d.onWildcardAnswer("bank.example.com", []netip.Addr{netip.MustParseAddr("203.0.113.21")}, time.Minute)
	waitHost(t, k, "203.0.113.21", "en0")
	d.onWildcardAnswer("a.cdn.example.com", []netip.Addr{netip.MustParseAddr("203.0.113.22")}, time.Minute)
	waitHost(t, k, "203.0.113.22", "en0")
	d.onWildcardAnswer("other.example.com", []netip.Addr{netip.MustParseAddr("203.0.113.23")}, time.Minute)
	if _, ok := k.hostRoute("203.0.113.23"); ok {
		t.Error("an answer for a name nothing covers got a direct route")
	}
}

// With a list and an exception on one name, the list wins while its VPN is up, and the
// exception decides once it is down, instead of the name falling into the default VPN.
func TestAListKeepsItsNameWhileItsVPNIsUpAndTheExceptionTakesOverAfter(t *testing.T) {
	env, k := exceptionEnv(t, []string{"10.60.0.5"})
	d := env.d
	setExceptions(t, d, "10.60.0.5")
	waitHost(t, k, "10.60.0.5", "en0")

	env.connectWG()
	waitForSession(t, d, wgIface)
	waitHost(t, k, "10.60.0.5", wgIface)

	d.reconcileDefaultVPN(d.currentGeneration())
	if iface, _ := k.hostRoute("10.60.0.5"); iface != wgIface {
		t.Errorf("a pass of the role moved 10.60.0.5 to %q, want its list's VPN %s", iface, wgIface)
	}

	env.disconnectWG()
	waitHost(t, k, "10.60.0.5", "en0")
}

// A wildcard list wins over an exception on a name under it in the same way.
func TestAnExceptedNameAVPNListClaimsIsNotRoutedDirect(t *testing.T) {
	env, k := exceptionEnv(t, []string{"*.corp.example.com"})
	d := env.d
	setExceptions(t, d, "app.corp.example.com")
	env.connectWG()
	waitForSession(t, d, wgIface)

	sessions := d.sessionList()
	if d.store.Policy().exceptedName(sessions, "app.corp.example.com") {
		t.Fatal("an exception outranked the list of a connected VPN")
	}
	d.onWildcardAnswer("app.corp.example.com", []netip.Addr{netip.MustParseAddr("10.70.0.1")}, time.Minute)
	waitHost(t, k, "10.70.0.1", wgIface)
}

// An exception inside a network a list routes would outrank it in the kernel, by being
// longer, so it is not added at all. One around a list's route may stay, since the
// list's is the longer there.
func TestAnExceptionInsideAListedNetworkIsNotRouted(t *testing.T) {
	env, k := exceptionEnv(t, []string{"10.60.0.0/16"})
	d := env.d
	env.connectWG()
	waitForSession(t, d, wgIface)
	waitFor(t, "the list's network", func() bool { return k.hasNet("10.60.0.0/16", wgIface) })

	setExceptions(t, d, "10.60.0.5", "10.60.1.0/24", "10.0.0.0/8")
	waitFor(t, "the network around the list's", func() bool { return k.hasNet("10.0.0.0/8", "en0") })
	if _, ok := k.hostRoute("10.60.0.5"); ok {
		t.Error("an IP inside a listed network got a route of its own")
	}
	if k.hasNet("10.60.1.0/24", "en0") {
		t.Error("a network inside a listed network got a route of its own")
	}
	if !k.hasNet("10.60.0.0/16", wgIface) {
		t.Error("the list lost its network")
	}
}

// A list that later asks for an address the exception holds gets it, and a network a
// list adds around an exception replaces it.
func TestAnExceptionGivesWayToAListAddedLater(t *testing.T) {
	env, k := exceptionEnv(t, nil)
	d := env.d
	env.connectWG()
	waitForSession(t, d, wgIface)
	setExceptions(t, d, "10.60.0.5", "10.70.0.5")
	waitHost(t, k, "10.60.0.5", "en0")
	waitHost(t, k, "10.70.0.5", "en0")

	if err := d.SetDomains(wireGuardPath, []string{"10.60.0.5", "10.70.0.0/16"}, 0); err != nil {
		t.Fatalf("SetDomains: %v", err)
	}
	d.TriggerSync()
	waitHost(t, k, "10.60.0.5", wgIface)
	waitFor(t, "the list's network", func() bool { return k.hasNet("10.70.0.0/16", wgIface) })
	waitNoHost(t, k, "10.70.0.5")
}

// What is on the LAN needs no route, and a route that was already there is left to
// whoever made it: a VPN app's route to its own server can lead through the LAN, and
// adopting it would delete it when the role ends.
func TestAnExceptionLeavesLANAddressesAndOtherRoutesAlone(t *testing.T) {
	env, k := exceptionEnv(t, nil, func(d *Daemon) {
		d.hooks.localPrefixes = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")} }
	})
	d := env.d
	k.putHost("198.51.100.77", "192.168.7.1", "en0")

	setExceptions(t, d, "192.168.7.50", "198.51.100.77", "203.0.113.9")
	waitHost(t, k, "203.0.113.9", "en0")
	if _, ok := k.hostRoute("192.168.7.50"); ok {
		t.Error("an address on the LAN got a route")
	}

	env.disconnectAWS()
	waitNoPair(t, k)
	waitNoHost(t, k, "203.0.113.9")
	if _, ok := k.hostRoute("198.51.100.77"); !ok {
		t.Error("the role's end deleted a route it never made")
	}
}

// A route the kernel dropped comes back at the next pass.
func TestAnExceptionsRouteTheKernelDroppedIsRestored(t *testing.T) {
	env, k := exceptionEnv(t, nil)
	d := env.d
	setExceptions(t, d, "203.0.113.9")
	waitHost(t, k, "203.0.113.9", "en0")

	if _, err := k.Run(context.Background(), "route", "-n", "delete", "-host", "203.0.113.9"); err != nil {
		t.Fatalf("drop the route: %v", err)
	}
	waitNoHost(t, k, "203.0.113.9")
	d.reconcileDefaultVPN(d.currentGeneration())
	waitHost(t, k, "203.0.113.9", "en0")
}

// Traffic to an exception is not reported as going through the default VPN.
func TestAnExceptionIsNotCarriedByTheDefaultVPN(t *testing.T) {
	env, k := exceptionEnv(t, nil)
	d := env.d
	waitFor(t, "the role to be held", func() bool { return d.defaultVPN.carries(netip.MustParseAddr("203.0.113.9")) != nil })

	setExceptions(t, d, "203.0.113.9")
	waitHost(t, k, "203.0.113.9", "en0")
	waitFor(t, "the exception to leave the role", func() bool { return d.defaultVPN.carries(netip.MustParseAddr("203.0.113.9")) == nil })
	if d.defaultVPN.carries(netip.MustParseAddr("203.0.113.10")) == nil {
		t.Error("an address no exception covers left the role")
	}
}

// The user sees a route an exception added, as direct.
func TestAnExceptionsRouteIsRecordedAsDirect(t *testing.T) {
	env, k := exceptionEnv(t, nil)
	setExceptions(t, env.d, "203.0.113.9")
	waitHost(t, k, "203.0.113.9", "en0")

	events := env.d.activity.List(0, 0)
	found := slices.ContainsFunc(events, func(e activity.Event) bool {
		return e.Kind == activity.KindRouteAdded && e.Detail == exceptionRouteDetail && len(e.Addresses) == 1 &&
			e.Addresses[0].IP == "203.0.113.9" && e.Addresses[0].Verdict == activity.Direct
	})
	if !found {
		t.Errorf("no event for the exception's route in %+v", events)
	}
}

// A crash leaves static routes through the LAN that nothing would ever remove, so the
// journal names them and the next start takes them away.
func TestACrashedHelpersExceptionRoutesAreRemovedAtTheNextStart(t *testing.T) {
	env, k := exceptionEnv(t, nil)
	d := env.d
	setExceptions(t, d, "203.0.113.9", "198.51.100.0/24")
	waitHost(t, k, "203.0.113.9", "en0")
	waitFor(t, "the network route", func() bool { return k.hasNet("198.51.100.0/24", "en0") })

	raw, err := os.ReadFile(d.defaultVPNJournalPath())
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	for _, want := range []string{"203.0.113.9", "198.51.100.0/24"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("journal %s does not name %s", raw, want)
		}
	}

	d.mutationMu.Lock()
	d.defaultVPN.exceptions = exceptionRoutes{}
	d.defaultVPN.recoverLeftovers()
	d.mutationMu.Unlock()
	if _, ok := k.hostRoute("203.0.113.9"); ok {
		t.Error("the leftover host route stayed")
	}
	if k.hasNet("198.51.100.0/24", "en0") {
		t.Error("the leftover network route stayed")
	}
}

func TestAnExceptionThatIsNotAnEntryIsRefused(t *testing.T) {
	env, _ := exceptionEnv(t, nil)
	for _, bad := range []string{"*.com", "127.0.0.1", "10.0.0.0/4"} {
		if err := env.d.SetDefaultVPNExcept([]string{bad}); err == nil {
			t.Errorf("SetDefaultVPNExcept(%q) was accepted", bad)
		}
	}
	cfg, _ := env.d.store.Snapshot()
	if len(cfg.Routing.DefaultVPNExcept) != 0 {
		t.Errorf("a refused list was kept: %v", cfg.Routing.DefaultVPNExcept)
	}
}

func TestExceptionsAreSavedNormalized(t *testing.T) {
	env, _ := exceptionEnv(t, nil)
	setExceptions(t, env.d, " Bank.Example.COM ", "bank.example.com", "10.20.5.1/16")
	cfg, _ := env.d.store.Snapshot()
	if want := []string{"bank.example.com", "10.20.0.0/16"}; !slices.Equal(cfg.Routing.DefaultVPNExcept, want) {
		t.Errorf("saved %v, want %v", cfg.Routing.DefaultVPNExcept, want)
	}
}

// A suffix no resolver file can hold must not cost the others theirs, and nothing is
// asked of the resolver while no tunnel holds the role.
func TestExceptionSuffixes(t *testing.T) {
	env, k := exceptionEnv(t, nil)
	d := env.d
	setExceptions(t, d, "intranet", "bank.example.com", "*.cdn.example.com", "203.0.113.9")
	waitHost(t, k, "203.0.113.9", "en0")

	owners := []wildcardOwner{{suffix: "cdn.example.com"}}
	var got []string
	for _, o := range d.defaultVPN.exceptionSuffixes(owners) {
		got = append(got, o.suffix)
	}
	if want := []string{"bank.example.com"}; !slices.Equal(got, want) {
		t.Errorf("suffixes = %v, want %v", got, want)
	}

	env.disconnectAWS()
	waitNoPair(t, k)
	waitFor(t, "the role to end", func() bool { return d.defaultVPN.active.Load() == nil })
	if got := d.defaultVPN.exceptionSuffixes(nil); got != nil {
		t.Errorf("suffixes with no role = %v", got)
	}
}
