package route

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// newSecondManager builds another manager on the same fake kernel as m, with
// its own journal, as the daemon does for a second tunnel.
func newSecondManager(t *testing.T, fake *fakeRunner) *Manager {
	t.Helper()
	m := NewManager()
	m.table = newCommandTable(fake)
	m.journal = &transactionStore{path: filepath.Join(t.TempDir(), "transition.json")}
	m.interfaceUp = func(string) bool { return true }
	m.generation = func() string { return "second-gen" }
	return m
}

func callsWith(fake *fakeRunner, substr string) int {
	n := 0
	for _, c := range fake.callLog {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

func TestActivationJournalsNoDefaultChangeWhenTheDefaultAlreadyLeadsToTheLAN(t *testing.T) {
	m, fake := newTestManager(t)
	fake.defaultGW = "192.168.7.1"
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun7)
	fake.routes = []RouteEntry{
		{Destination: "0/1", Gateway: "10.8.0.1", Flags: "UGSc", Interface: tun7},
		{Destination: "128.0/1", Gateway: "10.8.0.1", Flags: "UGSc", Interface: tun7},
	}
	fake.callLog = nil

	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if callsWith(fake, "change default") != 0 || callsWith(fake, "delete default") != 0 {
		t.Errorf("the default already leads to the LAN, nothing may change it: %v", fake.callLog)
	}
	tx, ok, err := m.journal.load()
	if err != nil || !ok {
		t.Fatalf("journal: ok=%v err=%v", ok, err)
	}
	for _, step := range tx.Steps {
		if step.Kind == stepChangeDefault {
			t.Errorf("journaled a default change that moved nothing: %+v", step)
		}
	}
	if m.state.DefaultRouteModified {
		t.Error("DefaultRouteModified must stay false when the default was not touched")
	}
}

// A NetworkExtension VPN and a /1-pair VPN are managed together. Whatever order
// they are torn down in, the NetworkExtension VPN gets its own default route
// back and nothing takes it away again.
func TestTeardownOrderNeverStripsAnotherTunnelsDefaultRoute(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order []int // indexes into []*Manager{ne, pair}
	}{
		{"priority order", []int{0, 1}},
		{"reverse of activation", []int{1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ne, fake := newTestManager(t)
			networkExtensionVPN(fake, tun5)
			if err := ne.CaptureOriginalGateway(); err != nil {
				t.Fatal(err)
			}
			ne.SetVPNState(netip.Addr{}, tun5)
			if err := ne.ActivateInvertedSplitTunnel(); err != nil {
				t.Fatalf("activate the NetworkExtension tunnel: %v", err)
			}

			pair := newSecondManager(t, fake)
			pair.SetOriginalGateway(ne.GetOriginalGateway(), ne.GetLocalInterface())
			pair.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun7)
			fake.routes = append(fake.routes,
				RouteEntry{Destination: "0/1", Gateway: "10.8.0.1", Flags: "UGSc", Interface: tun7},
				RouteEntry{Destination: "128.0/1", Gateway: "10.8.0.1", Flags: "UGSc", Interface: tun7})
			if err := pair.ActivateInvertedSplitTunnel(); err != nil {
				t.Fatalf("activate the /1-pair tunnel: %v", err)
			}
			if tx, ok, _ := pair.journal.load(); ok {
				for _, step := range tx.Steps {
					if step.Kind == stepChangeDefault {
						t.Fatalf("the /1-pair tunnel journaled a default change although the default was the LAN: %+v", step)
					}
				}
			}

			managers := []*Manager{ne, pair}
			for _, i := range tc.order {
				if err := managers[i].DeactivateInvertedSplitTunnel(); err != nil {
					t.Fatalf("deactivate: %v", err)
				}
			}
			if fake.defaultIface != tun5 {
				t.Fatalf("default = %q on %q, want the NetworkExtension VPN's own default back on utun5",
					fake.defaultGW, fake.defaultInterface())
			}
		})
	}
}

func TestRestoreNeverDeletesTheDefaultRoute(t *testing.T) {
	seed := func(t *testing.T) (*Manager, *fakeRunner) {
		m, fake := newTestManager(t)
		// A tunnel holds the default; the journal says the LAN had it on a
		// network this machine has since left.
		fake.defaultGW, fake.defaultIface = "10.8.0.1", tun5
		tx := &transaction{
			SchemaVersion: transactionSchemaVersion,
			GenerationID:  "old",
			Phase:         phaseActive,
			Steps:         []journalStep{{Kind: stepChangeDefault, Gateway: "10.8.0.1", PriorGateway: "192.168.1.1", PriorInterface: "en0"}},
			CreatedAt:     time.Now().UTC(),
		}
		if err := m.journal.save(tx); err != nil {
			t.Fatal(err)
		}
		return m, fake
	}

	t.Run("a gateway on a network that is gone leaves the current default", func(t *testing.T) {
		m, fake := seed(t)
		fake.failNextCall("change_default", fmt.Errorf("route: writing to routing socket: Network is unreachable"))
		fake.callLog = nil

		if err := m.RecoverTransition(); err != nil {
			t.Fatalf("an unreachable stale gateway is not a failure: %v", err)
		}
		if callsWith(fake, "delete default") != 0 || callsWith(fake, "add default") != 0 {
			t.Errorf("restore must never delete and re-add the default: %v", fake.callLog)
		}
		if fake.defaultGW != "10.8.0.1" || fake.defaultIface != tun5 {
			t.Errorf("default = %q on %q, want the existing default left in place", fake.defaultGW, fake.defaultIface)
		}
	})

	t.Run("another failure is reported and still keeps the default", func(t *testing.T) {
		m, fake := seed(t)
		fake.failNextCall("change_default", fmt.Errorf("route: change: operation not permitted"))
		fake.callLog = nil

		if err := m.RecoverTransition(); err == nil {
			t.Fatal("a real failure to restore must be reported")
		}
		if callsWith(fake, "delete default") != 0 {
			t.Errorf("restore must never delete the default: %v", fake.callLog)
		}
		if fake.defaultIface != tun5 {
			t.Errorf("default on %q, want it left alone", fake.defaultIface)
		}
	})

	t.Run("a LAN default already in place is not touched", func(t *testing.T) {
		m, fake := seed(t)
		fake.defaultGW, fake.defaultIface = "172.16.0.1", "en0"
		fake.callLog = nil

		if err := m.RecoverTransition(); err != nil {
			t.Fatal(err)
		}
		if callsWith(fake, "change default") != 0 {
			t.Errorf("the default already leads to a LAN: %v", fake.callLog)
		}
		if fake.defaultGW != "172.16.0.1" {
			t.Errorf("default = %q, want the current LAN default kept", fake.defaultGW)
		}
	})
}

func TestRestoreDoesNotTakeTheDefaultFromAnotherTunnel(t *testing.T) {
	m, fake := newTestManager(t)
	// This tunnel's journal gives the default back to utun5, but utun6 holds it
	// now: that is another VPN's.
	fake.defaultGW, fake.defaultIface = "", tun6
	tx := &transaction{
		SchemaVersion: transactionSchemaVersion,
		GenerationID:  "old",
		Phase:         phaseActive,
		Steps:         []journalStep{{Kind: stepChangeDefault, Gateway: "192.168.7.1", PriorInterface: tun5}},
		CreatedAt:     time.Now().UTC(),
	}
	if err := m.journal.save(tx); err != nil {
		t.Fatal(err)
	}
	if err := m.RecoverTransition(); err != nil {
		t.Fatal(err)
	}
	if fake.defaultIface != tun6 {
		t.Errorf("default on %q, want the other tunnel's default untouched", fake.defaultIface)
	}
}

func TestSessionJournalPathsAreOrderedNewestFirst(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "transition.json")
	now := time.Now().UTC()
	write := func(name string, created time.Time) {
		body := fmt.Sprintf(`{"schema_version":1,"phase":"active","steps":[],"created_at":%q}`, created.Format(time.RFC3339))
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Names sort the other way round from their ages, so glob order is wrong.
	write("transition-utun3.json", now.Add(-time.Minute))
	write("transition-utun9.json", now.Add(-3*time.Minute))
	write("transition-utun6.json", now)
	if err := os.WriteFile(filepath.Join(dir, "transition-utun4.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := SessionJournalPaths(base)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range got {
		names = append(names, filepath.Base(p))
	}
	want := []string{"transition-utun6.json", "transition-utun3.json", "transition-utun9.json", "transition-utun4.json"}
	if !slices.Equal(names, want) {
		t.Errorf("order = %v, want newest first with the unreadable one last: %v", names, want)
	}
}

func TestManagersSharingARegistryNeverAdoptEachOthersHostRoutes(t *testing.T) {
	a, fake := newTestManager(t)
	reg := NewHostRouteRegistry()
	a.SetHostRouteRegistry(reg)
	a.SetVPNState(netip.Addr{}, tun5)
	b := newSecondManager(t, fake)
	b.SetHostRouteRegistry(reg)
	b.SetVPNState(netip.Addr{}, tun6)
	dns := netip.MustParseAddr("1.1.1.1")

	if err := a.AddRoute(dns, "VPN DNS", true); err != nil {
		t.Fatal(err)
	}
	err := b.AddRoute(dns, "VPN DNS", true)
	if !errors.Is(err, ErrRouteOwnedElsewhere) {
		t.Fatalf("second manager's add = %v, want a conflict", err)
	}
	if _, ok := b.GetRoute(dns); ok {
		t.Error("the second manager must not record a route it does not own")
	}
	if holder, _ := reg.Owner(dns); holder != tun5 {
		t.Errorf("owner = %q, want utun5", holder)
	}

	// Once the owner gives it up, the other can take it.
	if err := a.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := b.AddRoute(dns, "VPN DNS", true); err != nil {
		t.Fatalf("after the owner left, the add must succeed: %v", err)
	}
	if holder, _ := reg.Owner(dns); holder != tun6 {
		t.Errorf("owner = %q, want utun6", holder)
	}
}

func TestFileExistsIsAcceptedOnlyForARouteThroughTheSameTunnel(t *testing.T) {
	m, fake := newTestManager(t)
	m.SetVPNState(netip.Addr{}, tun5)
	other := netip.MustParseAddr("10.1.1.1")
	mine := netip.MustParseAddr("10.1.1.2")
	fake.routes = []RouteEntry{
		{Destination: "10.1.1.1", Gateway: tun6, Flags: "UHS", Interface: tun6},
		{Destination: "10.1.1.2", Gateway: tun5, Flags: "UHS", Interface: tun5},
	}

	if err := m.AddRoute(other, "x", false); !errors.Is(err, ErrRouteOwnedElsewhere) {
		t.Fatalf("a route through another tunnel: err = %v, want a conflict", err)
	}
	if _, ok := m.GetRoute(other); ok {
		t.Error("a conflicting route must not be recorded as ours")
	}
	if degraded, _ := m.Degraded(); degraded {
		t.Error("a conflict is reported, it does not degrade the manager")
	}
	if err := m.AddRoute(mine, "x", false); err != nil {
		t.Fatalf("a leftover route through this tunnel is adopted: %v", err)
	}
	if _, ok := m.GetRoute(mine); !ok {
		t.Error("the adopted route must be recorded")
	}

	// A verification that cannot run is a conflict too, never silent success.
	unknown := netip.MustParseAddr("10.1.1.4")
	fake.routes = append(fake.routes, RouteEntry{Destination: "10.1.1.4", Gateway: "", Flags: "UHS", Interface: ""})
	if err := m.AddRoute(unknown, "x", false); !errors.Is(err, ErrRouteOwnedElsewhere) {
		t.Errorf("a route with no interface: err = %v, want a conflict", err)
	}
}

func TestSyncRoutesKeepsAnAddressWhoseDeleteFailed(t *testing.T) {
	m, fake := newTestManager(t)
	reg := NewHostRouteRegistry()
	m.SetHostRouteRegistry(reg)
	m.SetVPNState(netip.Addr{}, tun5)
	ip := netip.MustParseAddr("10.2.2.2")
	if err := m.SyncRoutes(map[netip.Addr]string{ip: "a.example.com"}); err != nil {
		t.Fatal(err)
	}

	fake.failNextCall("delete_host 10.2.2.2", errors.New("route: delete: operation not permitted"))
	if err := m.SyncRoutes(map[netip.Addr]string{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.GetRoute(ip); !ok {
		t.Error("the kernel route is still there, so the manager must still own it")
	}
	if holder, _ := reg.Owner(ip); holder != tun5 {
		t.Errorf("registry owner = %q, want the claim kept while the delete is pending", holder)
	}
	if degraded, _ := m.Degraded(); !degraded {
		t.Error("a failed delete must be reported")
	}

	// A retry that fails again does not pile up another pending item, and one
	// that works lets go of the address.
	fake.failNextCall("delete_host 10.2.2.2", errors.New("route: delete: operation not permitted"))
	_ = m.SyncRoutes(map[netip.Addr]string{})
	if n := len(m.PendingCleanup()); n != 1 {
		t.Errorf("pending items = %d, want one", n)
	}
	if err := m.SyncRoutes(map[netip.Addr]string{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.GetRoute(ip); ok {
		t.Error("the route must be forgotten once its delete succeeds")
	}
	if _, held := reg.Owner(ip); held {
		t.Error("the claim must be released once its delete succeeds")
	}
}

func TestSyncRoutesReportsAConflictWithoutDegrading(t *testing.T) {
	a, fake := newTestManager(t)
	reg := NewHostRouteRegistry()
	a.SetHostRouteRegistry(reg)
	a.SetVPNState(netip.Addr{}, tun5)
	b := newSecondManager(t, fake)
	b.SetHostRouteRegistry(reg)
	b.SetVPNState(netip.Addr{}, tun6)
	ip := netip.MustParseAddr("10.3.3.3")
	if err := a.SyncRoutes(map[netip.Addr]string{ip: "a"}); err != nil {
		t.Fatal(err)
	}

	err := b.SyncRoutes(map[netip.Addr]string{ip: "b", netip.MustParseAddr("10.3.3.4"): "b"})
	if !errors.Is(err, ErrRouteOwnedElsewhere) {
		t.Fatalf("SyncRoutes = %v, want the conflict reported", err)
	}
	if _, ok := b.GetRoute(ip); ok {
		t.Error("b must not record a's address")
	}
	if _, ok := b.GetRoute(netip.MustParseAddr("10.3.3.4")); !ok {
		t.Error("the rest of the sync must still apply")
	}
	if degraded, reason := b.Degraded(); degraded {
		t.Errorf("a conflict must not degrade the manager: %s", reason)
	}
	if callsWith(fake, "add -host 10.3.3.3") != 1 {
		t.Error("the conflicting address must not be added a second time")
	}
}
