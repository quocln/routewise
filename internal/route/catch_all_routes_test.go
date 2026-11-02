package route

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

const catchAllTunnel = "utun9"

func newCatchAllManager(t *testing.T) (*Manager, *fakeRunner) {
	t.Helper()
	m, fake := newTestManager(t)
	m.SetVPNState(netip.Addr{}, catchAllTunnel)
	return m, fake
}

func TestIsCatchAllRouteReadsEveryNotationTheTablePrints(t *testing.T) {
	for _, dest := range []string{"0.0.0.0/2", "0/2", "64/2", "64.0/2", "128/2", "192.0.0.0/2"} {
		if _, ok := isCatchAllRoute(RouteEntry{Destination: dest}); !ok {
			t.Errorf("%s not recognized", dest)
		}
	}
	for _, dest := range []string{"0/1", "128.0/1", "default", "10.0.0.0/8", "32/3", "64.0.0.1"} {
		if _, ok := isCatchAllRoute(RouteEntry{Destination: dest}); ok {
			t.Errorf("%s must not count as one of the role's routes", dest)
		}
	}
}

func tableHolds(fake *fakeRunner, iface string) int {
	n := 0
	for _, r := range fake.routes {
		if _, ok := isCatchAllRoute(r); ok && r.Interface == iface {
			n++
		}
	}
	return n
}

func TestSetCatchAllAddsEachRouteThroughTheTunnelAndRemovesThem(t *testing.T) {
	m, fake := newCatchAllManager(t)
	if err := m.SetCatchAll(true); err != nil {
		t.Fatal(err)
	}
	for _, p := range CatchAllPrefixes() {
		if want := "route -n add -net " + p.String() + " -interface " + catchAllTunnel; callsWith(fake, want) != 1 {
			t.Errorf("want one %q in %v", want, fake.callLog)
		}
	}
	if !m.CatchAll() || tableHolds(fake, catchAllTunnel) != len(CatchAllPrefixes()) {
		t.Fatalf("CatchAll = %v, routes = %v", m.CatchAll(), fake.routes)
	}

	// Already in place: nothing to do.
	fake.callLog = nil
	if err := m.SetCatchAll(true); err != nil {
		t.Fatal(err)
	}
	if callsWith(fake, "route -n add") != 0 {
		t.Errorf("an unchanged pass added %v", fake.callLog)
	}

	if err := m.SetCatchAll(false); err != nil {
		t.Fatal(err)
	}
	if m.CatchAll() || tableHolds(fake, catchAllTunnel) != 0 {
		t.Errorf("CatchAll = %v, routes = %v, want all gone", m.CatchAll(), fake.routes)
	}
}

// The route tool reports `File exists` as success, so an add can succeed with
// another tunnel's route in the table. Only reading back tells them apart.
func TestSetCatchAllNoticesARouteThatDidNotAppear(t *testing.T) {
	m, fake := newCatchAllManager(t)
	fake.failNextCall("add_net 64.0.0.0/2", errors.New("route: writing to routing socket: File exists"))
	err := m.SetCatchAll(true)
	if err == nil || !strings.Contains(err.Error(), "did not appear") {
		t.Fatalf("err = %v, want the read-back to notice", err)
	}
	if !m.CatchAll() {
		t.Error("routes exist after a failure, so CatchAll must stay true")
	}
}

func TestSetCatchAllIsRefusedWhenAnotherInterfaceHoldsARoute(t *testing.T) {
	m, fake := newCatchAllManager(t)
	fake.routes = []RouteEntry{{Destination: "64/2", Gateway: "utun3", Flags: "UGSc", Interface: "utun3"}}
	err := m.SetCatchAll(true)
	if err == nil || !strings.Contains(err.Error(), "utun3") {
		t.Fatalf("err = %v, want it to name the interface in the way", err)
	}
	if callsWith(fake, "route -n add") != 0 {
		t.Errorf("nothing may be added before the conflict is known: %v", fake.callLog)
	}
}

func TestSetCatchAllIgnoresAnInterfaceScopedRoute(t *testing.T) {
	m, fake := newCatchAllManager(t)
	fake.routes = []RouteEntry{{Destination: "64/2", Gateway: "utun3", Flags: "UGScI", Interface: "utun3"}}
	if err := m.SetCatchAll(true); err != nil {
		t.Fatalf("a scoped route is in no one's way: %v", err)
	}
}

func TestSetCatchAllOffStaysOnUntilEveryRouteIsGone(t *testing.T) {
	m, fake := newCatchAllManager(t)
	if err := m.SetCatchAll(true); err != nil {
		t.Fatal(err)
	}
	fake.failNextCall("delete_net 64.0.0.0/2", errors.New("route: operation failed"))

	if err := m.SetCatchAll(false); err == nil {
		t.Fatal("a failed delete must be reported")
	}
	if !m.CatchAll() {
		t.Fatal("a route is left, so CatchAll must stay true for the retry")
	}
	if degraded, why := m.Degraded(); degraded {
		t.Errorf("the caller retries a failed removal, which must not degrade the manager: %s", why)
	}

	if err := m.SetCatchAll(false); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if m.CatchAll() || tableHolds(fake, catchAllTunnel) != 0 {
		t.Errorf("CatchAll = %v, routes = %v, want all gone", m.CatchAll(), fake.routes)
	}
}

func TestSetCatchAllOffOnANonHolderTouchesNothing(t *testing.T) {
	m, fake := newCatchAllManager(t)
	if err := m.SetCatchAll(false); err != nil {
		t.Fatal(err)
	}
	if len(fake.callLog) != 0 {
		t.Errorf("a manager that never held the role ran %v", fake.callLog)
	}
}

func TestSetCatchAllOffLeavesAClientsOwnPairAndOtherTunnelsAlone(t *testing.T) {
	m, fake := newCatchAllManager(t)
	if err := m.SetCatchAll(true); err != nil {
		t.Fatal(err)
	}
	fake.routes = append(fake.routes,
		RouteEntry{Destination: "0/1", Gateway: catchAllTunnel, Flags: "UGSc", Interface: catchAllTunnel},
		RouteEntry{Destination: "128.0/1", Gateway: catchAllTunnel, Flags: "UGSc", Interface: catchAllTunnel},
		RouteEntry{Destination: "32/3", Gateway: "utun3", Flags: "UGSc", Interface: "utun3"},
	)
	if err := m.SetCatchAll(false); err != nil {
		t.Fatal(err)
	}
	if len(fake.routes) != 3 {
		t.Errorf("routes = %v, want only the role's routes removed", fake.routes)
	}
}
