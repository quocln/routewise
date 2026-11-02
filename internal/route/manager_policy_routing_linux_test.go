//go:build linux

package route

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// newNetlinkManager returns a Manager driving table, with its journal in a
// temp dir.
func newNetlinkManager(t *testing.T, table *testTable, journal string) *Manager {
	t.Helper()
	m := NewManager()
	m.table = table.netlinkTable
	m.journal = &transactionStore{path: journal}
	m.interfaceUp = func(string) bool { return true }
	return m
}

// addWGQuickRules sets the namespace up the way wg-quick does for a full
// tunnel on testTunIface: the default route in table 51820, the rule sending
// unmarked traffic there, and the rule that lets the main table's routes with
// a prefix win first.
func addWGQuickRules(t *testing.T, table *testTable) {
	t.Helper()
	for _, args := range [][]string{
		{"route", "add", "default", "dev", testTunIface, "table", "51820"},
		{"rule", "add", "not", "fwmark", "51820", "table", "51820", "priority", "32765"},
		{"rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", "32764"},
	} {
		runIP(t, append([]string{"-n", table.ns}, args...)...)
	}
}

// execIP runs ip in the table's namespace and returns its error.
func execIP(table *testTable, args ...string) (string, error) {
	out, err := exec.Command("ip", append([]string{"-n", table.ns}, args...)...).CombinedOutput()
	return string(out), err
}

func routeGet(t *testing.T, table *testTable, dest string) string {
	t.Helper()
	return runIP(t, "-n", table.ns, "route", "get", dest)
}

func ownedRules(t *testing.T, table *testTable) []netlink.Rule {
	t.Helper()
	h, err := table.handle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ruleList(h)
	if err != nil {
		t.Fatal(err)
	}
	var owned []netlink.Rule
	for _, r := range rules {
		if r.Protocol == ownedRuleProtocol {
			owned = append(owned, r)
		}
	}
	return owned
}

func TestInvertedModeSteersUnlistedTrafficPastAPolicyRoutedTunnel(t *testing.T) {
	table := newTestTable(t)
	addWGQuickRules(t, table)
	runIP(t, "-n", table.ns, "route", "add", "203.0.113.9/32", "dev", testTunIface)
	if out := routeGet(t, table, "198.51.100.7"); !strings.Contains(out, "dev "+testTunIface) {
		t.Fatalf("before activation all traffic enters the tunnel:\n%s", out)
	}

	m := newNetlinkManager(t, table, filepath.Join(t.TempDir(), "transition.json"))
	m.SetVPNState(mustAddr(testTunGateway), testTunIface)
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatalf("CaptureOriginalGateway: %v", err)
	}
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("ActivateInvertedSplitTunnel: %v", err)
	}

	rules := ownedRules(t, table)
	if len(rules) != 1 || rules[0].Priority != 32764 || rules[0].Table != 254 {
		t.Fatalf("want one owned main lookup just ahead of the tunnel rule (32765), got %+v", rules)
	}
	if out := routeGet(t, table, "198.51.100.7"); !strings.Contains(out, "dev "+testLANIface) {
		t.Fatalf("unlisted traffic must leave through the LAN:\n%s", out)
	}
	if out := routeGet(t, table, "203.0.113.9"); !strings.Contains(out, "dev "+testTunIface) {
		t.Fatalf("a listed address must still use the tunnel:\n%s", out)
	}

	if err := m.DeactivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("DeactivateInvertedSplitTunnel: %v", err)
	}
	if rules := ownedRules(t, table); len(rules) != 0 {
		t.Fatalf("deactivation must remove the rule, left %+v", rules)
	}
	if out := routeGet(t, table, "198.51.100.7"); !strings.Contains(out, "dev "+testTunIface) {
		t.Fatalf("after deactivation all traffic enters the tunnel again:\n%s", out)
	}
}

func TestRecoveryRemovesTheMainLookupRuleOfACrashedProcess(t *testing.T) {
	table := newTestTable(t)
	addWGQuickRules(t, table)
	journal := filepath.Join(t.TempDir(), "transition.json")

	m := newNetlinkManager(t, table, journal)
	m.SetVPNState(mustAddr(testTunGateway), testTunIface)
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatal(err)
	}
	if len(ownedRules(t, table)) != 1 {
		t.Fatal("activation should have added the rule")
	}

	// A fresh manager over the same journal is the next process.
	next := newNetlinkManager(t, table, journal)
	if err := next.RecoverTransition(); err != nil {
		t.Fatalf("RecoverTransition: %v", err)
	}
	if rules := ownedRules(t, table); len(rules) != 0 {
		t.Fatalf("recovery must remove the rule, left %+v", rules)
	}
}

func TestMainLookupRuleLeavesOtherRulesAlone(t *testing.T) {
	table := newTestTable(t)
	ctx := context.Background()

	// No policy rule: a tunnel whose routes sit in the main table needs nothing.
	if _, found, err := table.MainLookupPriority(ctx, testTunIface); err != nil || found {
		t.Fatalf("MainLookupPriority without rules = found %v, %v", found, err)
	}

	addWGQuickRules(t, table)

	// A marked main lookup (Tailscale's) is not where unmarked traffic
	// reaches the main table, so it does not hide the tunnel's rule.
	runIP(t, "-n", table.ns, "rule", "add", "fwmark", "0x80000/0xff0000", "table", "main", "priority", "100")
	priority, found, err := table.MainLookupPriority(ctx, testTunIface)
	if err != nil || !found || priority != 32764 {
		t.Fatalf("MainLookupPriority = %d, %v, %v; want 32764", priority, found, err)
	}

	// An administrator's own rule of the same priority is never deleted.
	runIP(t, "-n", table.ns, "rule", "add", "table", "main", "priority", "32000")
	if err := table.AddMainLookupRule(ctx, 32000); err != nil {
		t.Fatal(err)
	}
	if err := table.DeleteMainLookupRule(ctx, 32000); err != nil {
		t.Fatal(err)
	}
	if out := runIP(t, "-n", table.ns, "rule", "show"); !strings.Contains(out, "32000:") {
		t.Fatalf("the administrator's rule was removed:\n%s", out)
	}
	if err := table.DeleteMainLookupRule(ctx, 32000); err != nil {
		t.Fatalf("deleting a rule that is gone must succeed: %v", err)
	}
}

// TestRestoreGivesTheDefaultBackToATunnelWithoutATunnelName covers a VPN whose
// device name is no tunnel family (OpenVPN `dev corp0`): the default it held
// before activation goes back to it.
func TestRestoreGivesTheDefaultBackToATunnelWithoutATunnelName(t *testing.T) {
	table := newTestTable(t)
	runIP(t, "-n", table.ns, "link", "add", "corp0", "type", "dummy")
	runIP(t, "-n", table.ns, "addr", "add", "10.99.0.1/24", "dev", "corp0")
	runIP(t, "-n", table.ns, "link", "set", "corp0", "up")
	runIP(t, "-n", table.ns, "route", "add", "default", "via", "10.99.0.254", "dev", "corp0", "metric", "5")

	m := newNetlinkManager(t, table, filepath.Join(t.TempDir(), "transition.json"))
	m.SetVPNState(mustAddr("10.99.0.254"), "corp0")
	m.state.OriginalLocalGateway = mustAddr(testLANGateway)
	m.state.LocalInterface = testLANIface
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("ActivateInvertedSplitTunnel: %v", err)
	}
	if _, iface, _ := table.Default(context.Background()); iface != testLANIface {
		t.Fatalf("activation should move the default to the LAN, got %q", iface)
	}
	if err := m.DeactivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("DeactivateInvertedSplitTunnel: %v", err)
	}
	if gw, iface, err := table.Default(context.Background()); err != nil || iface != "corp0" || gw != mustAddr("10.99.0.254") {
		t.Fatalf("default after deactivation = %v, %q, %v; want it back on corp0", gw, iface, err)
	}
}

func TestLocalGatewaySkipsATunnelByLinkType(t *testing.T) {
	table := newTestTable(t)
	// A tun device with a name no tunnel family claims, holding the best default.
	if out, err := execIP(table, "tuntap", "add", "dev", "corp0", "mode", "tun"); err != nil {
		t.Skipf("cannot create a tun device: %v: %s", err, out)
	}
	runIP(t, "-n", table.ns, "addr", "add", "10.99.0.1/24", "dev", "corp0")
	runIP(t, "-n", table.ns, "link", "set", "corp0", "up")
	runIP(t, "-n", table.ns, "route", "add", "default", "via", "10.99.0.254", "dev", "corp0", "metric", "5")

	gw, iface, err := table.LocalGateway(context.Background(), "")
	if err != nil || gw != mustAddr(testLANGateway) || iface != testLANIface {
		t.Fatalf("LocalGateway = %v, %q, %v; want the LAN gateway, not the tunnel's", gw, iface, err)
	}
}

// TestNetlinkTableReadsRoutesThatUseNexthopObjects: the kernel reports a route
// through a nexthop object with its interface (or, for a group, its hops), and
// a read of the table must not fail on one.
func TestNetlinkTableReadsRoutesThatUseNexthopObjects(t *testing.T) {
	table := newTestTable(t)
	for _, args := range [][]string{
		{"nexthop", "add", "id", "7", "via", testLANGateway, "dev", testLANIface},
		{"nexthop", "add", "id", "8", "via", "10.77.0.253", "dev", testLANIface},
		{"nexthop", "add", "id", "9", "group", "7/8"},
	} {
		if out, err := execIP(table, args...); err != nil {
			t.Skipf("the kernel has no nexthop objects: %v: %s", err, out)
		}
	}
	runIP(t, "-n", table.ns, "route", "add", "198.18.0.0/24", "nhid", "7")
	runIP(t, "-n", table.ns, "route", "add", "198.19.0.0/24", "nhid", "9")

	ctx := context.Background()
	entries, err := table.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Destination] = true
	}
	if !seen["198.18.0.0/24"] || !seen["198.19.0.0/24"] {
		t.Fatalf("routes through nexthop objects missing from the snapshot: %+v", entries)
	}
	if gw, iface, err := table.Default(ctx); err != nil || gw != mustAddr(testLANGateway) || iface != testLANIface {
		t.Fatalf("Default = %v, %q, %v", gw, iface, err)
	}
}

func TestRoutesWithoutAnOutputInterfaceAreSkipped(t *testing.T) {
	if !hasNoOutputInterface(netlink.Route{}) {
		t.Error("a route with no link and no hops names no interface")
	}
	if hasNoOutputInterface(netlink.Route{LinkIndex: 3}) {
		t.Error("a route with a link is usable")
	}
	if hasNoOutputInterface(netlink.Route{MultiPath: []*netlink.NexthopInfo{{LinkIndex: 3}}}) {
		t.Error("a multipath route is usable")
	}
}
