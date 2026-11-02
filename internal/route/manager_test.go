package route

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner is a commandRunner that models just enough of macOS's route/
// netstat behavior for Manager tests: an in-memory table of routes and a
// default gateway, mutated the same way the real "route" tool would mutate
// the kernel table. No test in this file ever invokes /sbin/route or
// /usr/sbin/netstat.
type fakeRunner struct {
	mu        sync.Mutex
	routes    []RouteEntry
	defaultGW string
	// defaultIface is the interface of the global default route; empty means
	// en0. A NetworkExtension VPN's default points at its utun with no
	// gateway IP, modeled as defaultIface set and defaultGW empty.
	defaultIface string
	// scopedLANGW, when set, renders the interface-scoped LAN default macOS
	// keeps while a VPN owns the global default.
	scopedLANGW string
	// failOps maps a one-shot failure key (e.g. "delete_net 0.0.0.0/1") to
	// the error it should return. The entry is consumed (deleted) on use, so
	// a retried operation succeeds unless the test re-arms it.
	failOps map[string]error
	callLog []string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{failOps: make(map[string]error)}
}

func (f *fakeRunner) failNextCall(key string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failOps[key] = err
}

func (f *fakeRunner) consumeFail(key string) error {
	if err, ok := f.failOps[key]; ok {
		delete(f.failOps, key)
		return err
	}
	return nil
}

func (f *fakeRunner) Run(_ context.Context, tool string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callLog = append(f.callLog, tool+" "+strings.Join(args, " "))

	switch tool {
	case toolNetstat:
		return f.renderTable(), nil
	case toolRoute:
		if len(args) < 2 || args[0] != "-n" {
			return "", fmt.Errorf("fakeRunner: unexpected route args %v", args)
		}
		switch args[1] {
		case "get":
			return f.handleGet(args[2:])
		case "add":
			return f.handleAdd(args[2:])
		case "delete":
			return f.handleDelete(args[2:])
		case "change":
			return f.handleChange(args[2:])
		default:
			return "", fmt.Errorf("fakeRunner: unknown route action %q", args[1])
		}
	default:
		return "", fmt.Errorf("fakeRunner: unknown tool %q", tool)
	}
}

func (f *fakeRunner) handleGet(rest []string) (string, error) {
	if len(rest) == 1 && rest[0] != "default" {
		// A host lookup: a /32 RouteWise added wins, otherwise the default.
		for _, e := range f.routes {
			if e.Destination == rest[0] {
				return fmt.Sprintf("   route to: %s\n     interface: %s\n", rest[0], e.Interface), nil
			}
		}
		return fmt.Sprintf("   route to: %s\n       gateway: %s\n     interface: %s\n", rest[0], f.defaultGW, f.defaultInterface()), nil
	}
	if len(rest) != 1 || rest[0] != "default" {
		return "", fmt.Errorf("fakeRunner: unsupported get args %v", rest)
	}
	if err := f.consumeFail("get_default"); err != nil {
		return "", err
	}
	if f.defaultGW == "" && f.defaultIface == "" {
		return "", fmt.Errorf("route: not in table")
	}
	out := "   route to: default\ndestination: default\n"
	if f.defaultGW != "" {
		out += fmt.Sprintf("       gateway: %s\n", f.defaultGW)
	}
	return out + fmt.Sprintf("     interface: %s\n", f.defaultInterface()), nil
}

func (f *fakeRunner) handleAdd(rest []string) (string, error) {
	if len(rest) == 2 && rest[0] == "default" {
		if err := f.consumeFail("add_default"); err != nil {
			return "", err
		}
		f.defaultGW, f.defaultIface = rest[1], ""
		return "", nil
	}
	if len(rest) == 3 && rest[0] == "default" && rest[1] == "-interface" {
		if err := f.consumeFail("add_default"); err != nil {
			return "", err
		}
		f.defaultGW, f.defaultIface = "", rest[2]
		return "", nil
	}
	if len(rest) < 3 {
		return "", fmt.Errorf("fakeRunner: bad add args %v", rest)
	}
	kind := strings.TrimPrefix(rest[0], "-") // "host" or "net"
	dest := rest[1]

	var gateway, iface string
	if len(rest) >= 4 && rest[2] == "-interface" {
		iface = rest[3]
	} else {
		gateway = rest[2]
	}

	key := fmt.Sprintf("add_%s %s", kind, dest)
	if err := f.consumeFail(key); err != nil {
		return "", err
	}

	for _, e := range f.routes {
		if e.Destination == dest {
			return "", fmt.Errorf("route: writev: File exists")
		}
	}
	display := gateway
	outIface := iface
	if display == "" {
		// Point-to-point interface routes print the interface name in both
		// the gateway and interface columns, matching real netstat output.
		display = iface
	} else if outIface == "" {
		// Real netstat always names the egress interface, even for
		// gateway-based routes; a fixed placeholder is enough since no test
		// depends on which physical interface a gateway route egresses via.
		outIface = "en0"
	}
	f.routes = append(f.routes, RouteEntry{Destination: dest, Gateway: display, Flags: "UGHS", Interface: outIface})
	return "", nil
}

func (f *fakeRunner) handleDelete(rest []string) (string, error) {
	if len(rest) == 1 && rest[0] == "default" {
		if err := f.consumeFail("delete_default"); err != nil {
			return "", err
		}
		f.defaultGW, f.defaultIface = "", ""
		return "", nil
	}
	if len(rest) < 2 {
		return "", fmt.Errorf("fakeRunner: bad delete args %v", rest)
	}
	kind := strings.TrimPrefix(rest[0], "-")
	dest := rest[1]

	key := fmt.Sprintf("delete_%s %s", kind, dest)
	if err := f.consumeFail(key); err != nil {
		return "", err
	}

	for i, e := range f.routes {
		if e.Destination == dest {
			f.routes = append(f.routes[:i], f.routes[i+1:]...)
			return "", nil
		}
	}
	return "", fmt.Errorf("route: delete: not in table")
}

func (f *fakeRunner) handleChange(rest []string) (string, error) {
	if len(rest) == 3 && rest[0] == "default" && rest[1] == "-interface" {
		if err := f.consumeFail("change_default"); err != nil {
			return "", err
		}
		f.defaultGW, f.defaultIface = "", rest[2]
		return "", nil
	}
	if len(rest) != 2 || rest[0] != "default" {
		return "", fmt.Errorf("fakeRunner: unsupported change args %v", rest)
	}
	if err := f.consumeFail("change_default"); err != nil {
		return "", err
	}
	f.defaultGW, f.defaultIface = rest[1], ""
	return "", nil
}

func (f *fakeRunner) defaultInterface() string {
	if f.defaultIface != "" {
		return f.defaultIface
	}
	return "en0"
}

func (f *fakeRunner) renderTable() string {
	var b strings.Builder
	b.WriteString("Routing tables\n\nInternet:\n")
	b.WriteString("Destination        Gateway            Flags       Netif Expire\n")
	for _, e := range f.routes {
		fmt.Fprintf(&b, "%s %s %s %s\n", e.Destination, e.Gateway, e.Flags, e.Interface)
	}
	switch {
	case f.defaultGW != "":
		fmt.Fprintf(&b, "default %s UGSc %s\n", f.defaultGW, f.defaultInterface())
	case f.defaultIface != "":
		fmt.Fprintf(&b, "default link#22 UCSg %s\n", f.defaultIface)
	}
	if f.scopedLANGW != "" {
		fmt.Fprintf(&b, "default %s UGScIg en0\n", f.scopedLANGW)
	}
	return b.String()
}

// newTestManager returns a Manager wired to an isolated fake runner and a
// journal file under t.TempDir(), so no test touches /var/run or invokes a
// real subprocess.
func newTestManager(t *testing.T) (*Manager, *fakeRunner) {
	t.Helper()
	m := NewManager()
	fake := newFakeRunner()
	m.table = newCommandTable(fake)
	m.journal = &transactionStore{path: filepath.Join(t.TempDir(), "transition.json")}
	// Every tunnel counts as up unless a test says otherwise, so results do
	// not depend on which utun interfaces the machine running tests has.
	m.interfaceUp = func(string) bool { return true }
	gen := 0
	m.generation = func() string {
		gen++
		return fmt.Sprintf("test-gen-%d", gen)
	}
	return m, fake
}

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.activeRoutes == nil {
		t.Error("activeRoutes should be initialized")
	}
	if m.changes == nil {
		t.Error("changes should be initialized")
	}
	if m.table == nil {
		t.Error("table should be initialized")
	}
	if m.journal == nil {
		t.Error("journal should be initialized")
	}
}

func TestRouteState(t *testing.T) {
	m := NewManager()

	vpnGW := netip.MustParseAddr("10.0.0.1")
	m.SetVPNState(vpnGW, tun0)

	if m.GetVPNGateway() != vpnGW {
		t.Errorf("expected VPN gateway %s, got %s", vpnGW, m.GetVPNGateway())
	}
	if m.GetVPNInterface() != tun0 {
		t.Errorf("expected VPN interface utun0, got %s", m.GetVPNInterface())
	}
}

func TestGetActiveRoutes(t *testing.T) {
	m := NewManager()

	m.mu.Lock()
	m.activeRoutes[netip.MustParseAddr("1.1.1.1")] = RouteInfo{
		Destination: netip.MustParseAddr("1.1.1.1"),
		Gateway:     netip.MustParseAddr("10.0.0.1"),
		IsProtected: false,
	}
	m.activeRoutes[netip.MustParseAddr("2.2.2.2")] = RouteInfo{
		Destination: netip.MustParseAddr("2.2.2.2"),
		Gateway:     netip.MustParseAddr("10.0.0.1"),
		IsProtected: true,
	}
	m.mu.Unlock()

	routes := m.GetActiveRoutes()

	if len(routes) != 2 {
		t.Errorf("expected 2 routes, got %d", len(routes))
	}
	if m.GetRouteCount() != 2 {
		t.Errorf("expected count 2, got %d", m.GetRouteCount())
	}

	delete(routes, netip.MustParseAddr("1.1.1.1"))
	if m.GetRouteCount() != 2 {
		t.Error("modifying returned map affected original")
	}
}

func TestRecordChange(t *testing.T) {
	m := NewManager()

	dest := netip.MustParseAddr("1.1.1.1")
	gw := netip.MustParseAddr("10.0.0.1")

	m.mu.Lock()
	m.recordChange(RouteAdded, dest, gw, "")
	m.recordChange(RouteRemoved, dest, netip.Addr{}, "")
	m.mu.Unlock()

	changes := m.GetRecentChanges(10)
	if len(changes) != 2 {
		t.Errorf("expected 2 changes, got %d", len(changes))
	}
	if changes[0].Type != RouteAdded {
		t.Errorf("expected RouteAdded, got %v", changes[0].Type)
	}
	if changes[1].Type != RouteRemoved {
		t.Errorf("expected RouteRemoved, got %v", changes[1].Type)
	}
}

func TestChangeLimit(t *testing.T) {
	m := NewManager()

	dest := netip.MustParseAddr("1.1.1.1")
	gw := netip.MustParseAddr("10.0.0.1")

	m.mu.Lock()
	for i := 0; i < 150; i++ {
		m.recordChange(RouteAdded, dest, gw, "")
	}
	m.mu.Unlock()

	m.mu.RLock()
	if len(m.changes) != 100 {
		t.Errorf("expected 100 changes, got %d", len(m.changes))
	}
	m.mu.RUnlock()

	changes := m.GetRecentChanges(5)
	if len(changes) != 5 {
		t.Errorf("expected 5 changes, got %d", len(changes))
	}
}

func TestRouteChangeTypeString(t *testing.T) {
	tests := []struct {
		typ  RouteChangeType
		want string
	}{
		{RouteAdded, "added"},
		{RouteRemoved, "removed"},
		{RouteUpdated, "updated"},
		{RouteChangeType(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.typ.String()
		if got != tt.want {
			t.Errorf("RouteChangeType(%d).String() = %q, want %q", tt.typ, got, tt.want)
		}
	}
}

func TestAddRouteWithoutVPNGateway(t *testing.T) {
	m := NewManager()

	err := m.AddRoute(netip.MustParseAddr("1.1.1.1"), "test.com", false)
	if err == nil {
		t.Error("expected error when VPN gateway not set")
	}
}

func TestSyncRoutesWithoutVPNGateway(t *testing.T) {
	m := NewManager()

	err := m.SyncRoutes(map[netip.Addr]string{
		netip.MustParseAddr("1.1.1.1"): "test.com",
	})
	if err == nil {
		t.Error("expected error when VPN gateway not set")
	}
}

func TestActivateWithoutOriginalGateway(t *testing.T) {
	m := NewManager()

	err := m.ActivateInvertedSplitTunnel()
	if err == nil {
		t.Error("expected error when original gateway not captured")
	}
}

// --- Ownership-scoped /1 removal ---

func TestEnforceSplitTunnelRemovesOwnedRoutes(t *testing.T) {
	m, fake := newTestManager(t)
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun5)

	fake.routes = []RouteEntry{
		{Destination: "0.0.0.0/1", Gateway: tun5, Flags: "UGSc", Interface: tun5},
		{Destination: "128.0.0.0/1", Gateway: tun5, Flags: "UGSc", Interface: tun5},
	}

	if err := m.EnforceSplitTunnel(); err != nil {
		t.Fatalf("EnforceSplitTunnel: %v", err)
	}
	if len(fake.routes) != 0 {
		t.Errorf("expected owned split tunnel routes removed, got %+v", fake.routes)
	}
}

func TestEnforceSplitTunnelSkipsForeignRoutes(t *testing.T) {
	m, fake := newTestManager(t)
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun5)

	// A different VPN client's own catch-all routes: different interface and
	// gateway from ours. These must never be touched.
	foreign := []RouteEntry{
		{Destination: "0.0.0.0/1", Gateway: tun9, Flags: "UGSc", Interface: tun9},
		{Destination: "128.0.0.0/1", Gateway: tun9, Flags: "UGSc", Interface: tun9},
	}
	fake.routes = append([]RouteEntry(nil), foreign...)

	if err := m.EnforceSplitTunnel(); err != nil {
		t.Fatalf("EnforceSplitTunnel: %v", err)
	}
	if len(fake.routes) != 2 {
		t.Fatalf("expected foreign split tunnel routes to survive, got %+v", fake.routes)
	}
	for i, e := range fake.routes {
		if e != foreign[i] {
			t.Errorf("foreign route %d mutated: got %+v, want %+v", i, e, foreign[i])
		}
	}
}

// --- Activation: journaling and verification ---

func setupActivatedManager(t *testing.T) (*Manager, *fakeRunner) {
	t.Helper()
	m, fake := newTestManager(t)

	fake.defaultGW = "192.168.1.1"
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatalf("CaptureOriginalGateway: %v", err)
	}

	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun5)

	fake.routes = []RouteEntry{
		{Destination: "0.0.0.0/1", Gateway: tun5, Flags: "UGSc", Interface: tun5},
		{Destination: "128.0.0.0/1", Gateway: tun5, Flags: "UGSc", Interface: tun5},
	}

	// By the time activation runs, the AWS VPN client has already taken over
	// the default route (pointing it at its own gateway). Activation's job
	// is to flip that back to the original local gateway. A default through
	// the VPN's gateway egresses on the tunnel interface, as the kernel
	// reports it.
	fake.defaultGW = "10.8.0.1"
	fake.defaultIface = tun5
	return m, fake
}

func TestActivateInvertedSplitTunnelSucceedsAndJournals(t *testing.T) {
	m, fake := setupActivatedManager(t)

	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("ActivateInvertedSplitTunnel: %v", err)
	}

	if fake.defaultGW != "192.168.1.1" {
		t.Errorf("expected default gateway 192.168.1.1, got %s", fake.defaultGW)
	}
	for _, e := range fake.routes {
		if e.Destination == "0.0.0.0/1" || e.Destination == "128.0.0.0/1" {
			t.Errorf("expected owned split tunnel route %s removed", e.Destination)
		}
	}

	tx, ok, err := m.journal.load()
	if err != nil || !ok {
		t.Fatalf("expected journal present after activation, ok=%v err=%v", ok, err)
	}
	if tx.Phase != phaseActive {
		t.Errorf("expected phase %q, got %q", phaseActive, tx.Phase)
	}
	if len(tx.Steps) != 3 {
		t.Fatalf("expected 3 journaled steps (2 deletes + default change), got %d: %+v", len(tx.Steps), tx.Steps)
	}

	if degraded, reason := m.Degraded(); degraded {
		t.Errorf("expected healthy manager after clean activation, got degraded: %s", reason)
	}
}

func TestActivateInvertedSplitTunnelPartialFailureIsJournaledAndDegraded(t *testing.T) {
	m, fake := setupActivatedManager(t)

	// The second /1 deletion fails; the first must still be journaled and
	// applied before activation aborts.
	fake.failNextCall("delete_net 128.0.0.0/1", fmt.Errorf("route: delete: operation not permitted"))

	err := m.ActivateInvertedSplitTunnel()
	if err == nil {
		t.Fatal("expected activation to fail")
	}

	tx, ok, loadErr := m.journal.load()
	if loadErr != nil || !ok {
		t.Fatalf("expected journal present after partial failure, ok=%v err=%v", ok, loadErr)
	}
	if tx.Phase != phaseActivating {
		t.Errorf("expected phase still %q, got %q", phaseActivating, tx.Phase)
	}

	var sawDelete001 bool
	for _, s := range tx.Steps {
		if s.Kind == stepDeleteRoute && s.Destination == "0.0.0.0/1" {
			sawDelete001 = true
		}
	}
	if !sawDelete001 {
		t.Error("expected the succeeding 0.0.0.0/1 delete to be journaled")
	}

	found128 := false
	for _, e := range fake.routes {
		if e.Destination == "128.0.0.0/1" {
			found128 = true
		}
	}
	if !found128 {
		t.Error("expected 128.0.0.0/1 to remain since its deletion failed")
	}

	degraded, reason := m.Degraded()
	if !degraded {
		t.Fatal("expected manager to report degraded after partial activation failure")
	}
	if !strings.Contains(reason, "delete_route") {
		t.Errorf("expected degraded reason to mention delete_route, got %q", reason)
	}
}

// --- Deactivation / compensation ---

func TestDeactivateCompensatesReverseOrderAndRemovesJournal(t *testing.T) {
	m, fake := setupActivatedManager(t)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("ActivateInvertedSplitTunnel: %v", err)
	}

	if err := m.DeactivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("DeactivateInvertedSplitTunnel: %v", err)
	}

	// Compensation restores the default gateway exactly to what it was
	// immediately before RouteWise's own change (the VPN client's own
	// gateway), not to the pre-VPN local gateway captured at connect time.
	if fake.defaultGW != "10.8.0.1" {
		t.Errorf("expected default gateway restored to 10.8.0.1 (pre-RouteWise-change value), got %s", fake.defaultGW)
	}

	var has001, has128 bool
	for _, e := range fake.routes {
		if e.Destination == "0.0.0.0/1" {
			has001 = true
		}
		if e.Destination == "128.0.0.0/1" {
			has128 = true
		}
		if e.Destination == "52.1.2.3" {
			t.Error("expected endpoint route removed on compensation since it did not preexist")
		}
	}
	if !has001 || !has128 {
		t.Errorf("expected split tunnel routes restored, got %+v", fake.routes)
	}

	if _, ok, err := m.journal.load(); err != nil || ok {
		t.Errorf("expected journal removed after full compensation, ok=%v err=%v", ok, err)
	}
	if degraded, reason := m.Degraded(); degraded {
		t.Errorf("expected healthy manager after full compensation, got degraded: %s", reason)
	}
}

func TestDeactivateIsIdempotent(t *testing.T) {
	m, _ := setupActivatedManager(t)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("ActivateInvertedSplitTunnel: %v", err)
	}

	if err := m.DeactivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("first DeactivateInvertedSplitTunnel: %v", err)
	}
	// Second call: DefaultRouteModified is now false, so this must be a
	// pure no-op regardless of journal state.
	if err := m.DeactivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("second DeactivateInvertedSplitTunnel should be a no-op: %v", err)
	}
}

func TestDeactivateFailsClosedWhenActiveJournalIsMissing(t *testing.T) {
	m, fake := setupActivatedManager(t)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("ActivateInvertedSplitTunnel: %v", err)
	}
	if err := os.Remove(m.journal.path); err != nil {
		t.Fatalf("remove transition journal: %v", err)
	}

	err := m.DeactivateInvertedSplitTunnel()
	if err == nil {
		t.Fatal("expected deactivation without its active journal to fail closed")
	}
	if !strings.Contains(err.Error(), "no transition journal") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.state.DefaultRouteModified {
		t.Fatal("manager discarded active route ownership after losing its journal")
	}
	if fake.defaultGW != "192.168.1.1" {
		t.Fatalf("default gateway changed without restoration authority: %s", fake.defaultGW)
	}
	if degraded, reason := m.Degraded(); !degraded || !strings.Contains(reason, "journal") {
		t.Fatalf("missing journal was not surfaced as degraded: degraded=%v reason=%q", degraded, reason)
	}

	restarted := NewManager()
	restarted.SetJournalPath(m.journal.path)
	if err := restarted.RecoverTransition(); err == nil {
		t.Fatal("fresh manager accepted a durable unrecoverable sentinel")
	}
	if degraded, reason := restarted.Degraded(); !degraded || !strings.Contains(reason, "journal") {
		t.Fatalf("restart lost fail-closed state: degraded=%v reason=%q", degraded, reason)
	}
}

func TestDeactivateFailsClosedWhenActiveJournalIsMalformed(t *testing.T) {
	m, fake := setupActivatedManager(t)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("ActivateInvertedSplitTunnel: %v", err)
	}
	if err := os.WriteFile(m.journal.path, []byte("{malformed"), journalFileMode); err != nil {
		t.Fatalf("write malformed transition journal: %v", err)
	}

	err := m.DeactivateInvertedSplitTunnel()
	if err == nil || !errors.Is(err, ErrJournalMalformed) && !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("expected malformed journal failure, got %v", err)
	}
	if !m.state.DefaultRouteModified {
		t.Fatal("manager discarded active ownership after rejecting malformed journal")
	}
	if fake.defaultGW != "192.168.1.1" {
		t.Fatalf("default gateway changed without trusted compensation data: %s", fake.defaultGW)
	}
	if degraded, reason := m.Degraded(); !degraded || !strings.Contains(reason, "journal") {
		t.Fatalf("malformed journal was not surfaced as degraded: degraded=%v reason=%q", degraded, reason)
	}
}

func TestDeactivateJournalPersistenceFailureMarksOwnershipDegraded(t *testing.T) {
	m, fake := setupActivatedManager(t)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("ActivateInvertedSplitTunnel: %v", err)
	}
	m.journal.beforeWrite = func() error {
		return errors.New("injected journal write failure")
	}

	err := m.DeactivateInvertedSplitTunnel()
	if err == nil || !strings.Contains(err.Error(), "persist transition journal") {
		t.Fatalf("expected journal persistence failure, got %v", err)
	}
	if !m.state.DefaultRouteModified {
		t.Fatal("manager discarded active ownership after journal persistence failure")
	}
	if fake.defaultGW != "192.168.1.1" {
		t.Fatalf("default gateway changed after journal persistence failure: %s", fake.defaultGW)
	}
	if degraded, reason := m.Degraded(); !degraded || !strings.Contains(reason, "journal") {
		t.Fatalf("journal persistence failure was not degraded: degraded=%v reason=%q", degraded, reason)
	}
}

func TestCompensationFailureLeavesDegradedAndRetryResolves(t *testing.T) {
	m, fake := setupActivatedManager(t)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("ActivateInvertedSplitTunnel: %v", err)
	}

	fake.failNextCall("add_net 128.0.0.0/1", fmt.Errorf("route: add: operation not permitted"))

	err := m.DeactivateInvertedSplitTunnel()
	if err == nil {
		t.Fatal("expected deactivation to report compensation failure")
	}

	degraded, reason := m.Degraded()
	if !degraded {
		t.Fatal("expected degraded state after compensation failure")
	}
	if !strings.Contains(reason, "restore_route") {
		t.Errorf("expected degraded reason to mention restore_route, got %q", reason)
	}

	// The journal must still exist with the unresolved step, so a later
	// process restart would retry the same compensation.
	tx, ok, loadErr := m.journal.load()
	if loadErr != nil || !ok {
		t.Fatalf("expected journal to remain after failed compensation, ok=%v err=%v", ok, loadErr)
	}
	if len(tx.Steps) != 1 || tx.Steps[0].Destination != "128.0.0.0/1" {
		t.Errorf("expected exactly the failed restore step to remain, got %+v", tx.Steps)
	}

	// Retrying (e.g. the underlying transient failure cleared) must resolve
	// the degraded state without needing another full deactivation.
	if err := m.RetryPendingCleanup(); err != nil {
		t.Fatalf("RetryPendingCleanup: %v", err)
	}
	if degraded, reason := m.Degraded(); degraded {
		t.Errorf("expected healthy manager after successful retry, got degraded: %s", reason)
	}
	found := false
	for _, e := range fake.routes {
		if e.Destination == "128.0.0.0/1" {
			found = true
		}
	}
	if !found {
		t.Error("expected 128.0.0.0/1 restored after retry")
	}
}

// --- Startup recovery ---

func TestRecoverTransitionCompensatesIncompleteJournal(t *testing.T) {
	m, fake := newTestManager(t)

	// Simulate a previous process that completed activation and then crashed
	// before deactivating, leaving phaseActive on disk. The journal was
	// written by an older release that also added a VPN endpoint route, so
	// recovery must still compensate add_route steps.
	tx := &transaction{
		SchemaVersion: transactionSchemaVersion,
		GenerationID:  "crashed-gen",
		Phase:         phaseActive,
		Steps: []journalStep{
			{Kind: stepAddRoute, Destination: "52.1.2.3", Gateway: "192.168.1.1", Existed: false},
			{Kind: stepDeleteRoute, Destination: "0.0.0.0/1", Gateway: tun5, Interface: tun5, Existed: true},
			{Kind: stepDeleteRoute, Destination: "128.0.0.0/1", Gateway: tun5, Interface: tun5, Existed: true},
			{Kind: stepChangeDefault, Gateway: "10.8.0.1", PriorGateway: "192.168.1.1"},
		},
		CreatedAt: time.Now().UTC(),
	}
	if err := m.journal.save(tx); err != nil {
		t.Fatalf("seed journal: %v", err)
	}

	// Kernel state as the crashed process left it: endpoint route present,
	// /1 routes absent, default gateway flipped to the VPN gateway.
	fake.routes = []RouteEntry{{Destination: "52.1.2.3", Gateway: "192.168.1.1", Flags: "UGHS"}}
	fake.defaultGW = "10.8.0.1"
	fake.defaultIface = tun5

	if err := m.RecoverTransition(); err != nil {
		t.Fatalf("RecoverTransition: %v", err)
	}

	if fake.defaultGW != "192.168.1.1" {
		t.Errorf("expected default gateway restored to 192.168.1.1, got %s", fake.defaultGW)
	}
	var has001, has128, hasEndpoint bool
	for _, e := range fake.routes {
		switch e.Destination {
		case "0.0.0.0/1":
			has001 = true
		case "128.0.0.0/1":
			has128 = true
		case "52.1.2.3":
			hasEndpoint = true
		}
	}
	if !has001 || !has128 {
		t.Errorf("expected split tunnel routes restored, got %+v", fake.routes)
	}
	if hasEndpoint {
		t.Error("expected endpoint route removed on recovery since it did not preexist")
	}

	if _, ok, err := m.journal.load(); err != nil || ok {
		t.Errorf("expected journal removed after recovery, ok=%v err=%v", ok, err)
	}
	if degraded, reason := m.Degraded(); degraded {
		t.Errorf("expected healthy manager after full recovery, got degraded: %s", reason)
	}
}

func TestRecoverTransitionNoJournalIsNoop(t *testing.T) {
	m, _ := newTestManager(t)

	if err := m.RecoverTransition(); err != nil {
		t.Fatalf("expected no-op recovery to succeed, got %v", err)
	}
	if degraded, reason := m.Degraded(); degraded {
		t.Errorf("expected healthy manager with no journal present, got degraded: %s", reason)
	}
}

func TestDegradedReportsEmptyWhenHealthy(t *testing.T) {
	m := NewManager()
	if degraded, reason := m.Degraded(); degraded || reason != "" {
		t.Errorf("expected fresh manager to be healthy, got degraded=%v reason=%q", degraded, reason)
	}
}

// --- Integration tests (require root and actual network) ---

func TestIntegrationCaptureGateway(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	m := NewManager()
	err := m.CaptureOriginalGateway()
	if err != nil {
		t.Fatalf("CaptureOriginalGateway failed: %v", err)
	}

	gw := m.GetOriginalGateway()
	if !gw.IsValid() {
		t.Error("expected valid gateway")
	}
	t.Logf("Captured gateway: %s", gw)
}

func TestIntegrationGetDefaultGateway(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// The LAN gateway, which is what RouteWise needs. The global default may
	// legitimately belong to a VPN on the machine running the test.
	gw, _, err := systemTable().LocalGateway(context.Background(), "")
	if err != nil {
		t.Fatalf("getLocalGateway failed: %v", err)
	}
	if !gw.IsValid() {
		t.Error("expected valid gateway")
	}
	t.Logf("Default gateway: %s", gw)
}

func TestIntegrationListRoutes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	routes, err := ListRoutes()
	if err != nil {
		t.Fatalf("listRoutes failed: %v", err)
	}
	if len(routes) == 0 {
		t.Error("expected at least one route")
	}
	t.Logf("Found %d routes", len(routes))
}
