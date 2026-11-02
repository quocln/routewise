//go:build linux

package route

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Interfaces and addresses of the throwaway namespace every test runs in: a
// LAN link with a gateway, and a tunnel-named link with a peer gateway.
const (
	testLANIface    = "lan0"
	testLANGateway  = "10.77.0.254"
	testTunIface    = "tun7"
	testTunGateway  = "10.88.0.254"
	testUnconnected = "192.0.2.1"
)

// newTestTable returns a netlinkTable bound to a fresh network namespace that
// holds lan0 (10.77.0.1/24, default via 10.77.0.254 at metric 100) and tun7
// (10.88.0.1/24), so no test ever touches the host's routing table. It skips
// when the test cannot create a namespace.
func newTestTable(t *testing.T) *testTable {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("netlink route tests need root to create a network namespace")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("netlink route tests need the ip tool to create a network namespace")
	}

	ns := fmt.Sprintf("rw-route-test-%d-%d", os.Getpid(), time.Now().UnixNano()%100000)
	runIP(t, "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", testLANIface, "type", "dummy"},
		{"addr", "add", "10.77.0.1/24", "dev", testLANIface},
		{"link", "set", testLANIface, "up"},
		{"link", "add", testTunIface, "type", "dummy"},
		{"addr", "add", "10.88.0.1/24", "dev", testTunIface},
		{"link", "set", testTunIface, "up"},
		{"route", "add", "default", "via", testLANGateway, "metric", "100"},
	} {
		runIP(t, append([]string{"-n", ns}, args...)...)
	}

	handle, err := netns.GetFromName(ns)
	if err != nil {
		t.Fatalf("open namespace %s: %v", ns, err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	table := newNetlinkTable(func() (*netlink.Handle, error) {
		return netlink.NewHandleAt(handle, unix.NETLINK_ROUTE)
	})
	t.Cleanup(table.close)
	return &testTable{netlinkTable: table, ns: ns}
}

// testTable is a netlinkTable together with the name of the namespace it
// drives, for the ip commands that set up and inspect that namespace.
type testTable struct {
	*netlinkTable
	ns string
}

// runIP runs the ip tool and fails the test on error.
func runIP(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// showRoutes lists the namespace's routes as `ip route show` prints them.
func showRoutes(t *testing.T, table *testTable, extra ...string) string {
	t.Helper()
	return runIP(t, append([]string{"-n", table.ns}, append(extra, "route", "show")...)...)
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestNetlinkTableReadsDefaultAndLocalGateway(t *testing.T) {
	table := newTestTable(t)
	ctx := context.Background()

	gw, iface, err := table.Default(ctx)
	if err != nil || gw != mustAddr(testLANGateway) || iface != testLANIface {
		t.Fatalf("Default = %v, %q, %v", gw, iface, err)
	}
	if got, err := table.DefaultGateway(ctx); err != nil || got != gw {
		t.Fatalf("DefaultGateway = %v, %v", got, err)
	}

	// A VPN default on a tunnel link, with a lower metric, takes the global
	// default and has no gateway; the LAN gateway must still be found.
	runIP(t, "-n", table.ns, "route", "add", "default", "dev", testTunIface, "metric", "10")
	gw, iface, err = table.Default(ctx)
	if err != nil || gw.IsValid() || iface != testTunIface {
		t.Fatalf("Default under a VPN = %v, %q, %v", gw, iface, err)
	}
	if _, err := table.DefaultGateway(ctx); err == nil {
		t.Error("DefaultGateway must fail when the default has no gateway")
	}
	gw, iface, err = table.LocalGateway(ctx, "")
	if err != nil || gw != mustAddr(testLANGateway) || iface != testLANIface {
		t.Fatalf("LocalGateway under a VPN = %v, %q, %v", gw, iface, err)
	}
}

func TestNetlinkTableSnapshotUsesTheBSDNotation(t *testing.T) {
	table := newTestTable(t)
	ctx := context.Background()
	runIP(t, "-n", table.ns, "route", "add", "10.99.0.5/32", "via", testTunGateway)
	runIP(t, "-n", table.ns, "route", "add", "10.99.1.0/24", "dev", testTunIface)
	runIP(t, "-n", table.ns, "route", "add", "0.0.0.0/1", "dev", testTunIface)

	entries, err := table.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for dest, want := range map[string]RouteEntry{
		"default":      {Destination: "default", Gateway: testLANGateway, Flags: "UG", Interface: testLANIface},
		"10.99.0.5":    {Destination: "10.99.0.5", Gateway: testTunGateway, Flags: "UGH", Interface: testTunIface},
		"10.99.1.0/24": {Destination: "10.99.1.0/24", Gateway: "link#" + ifIndex(t, table, testTunIface), Flags: "U", Interface: testTunIface},
		"0.0.0.0/1":    {Destination: "0.0.0.0/1", Gateway: "link#" + ifIndex(t, table, testTunIface), Flags: "U", Interface: testTunIface},
	} {
		got, ok := findRoute(entries, dest)
		if !ok || got != want {
			t.Errorf("entry %q = %+v (found %v), want %+v", dest, got, ok, want)
		}
	}
	if _, ok := canonicalSplitTunnelDest("0.0.0.0/1"); !ok {
		t.Fatal("test premise: the /1 destination must be recognised")
	}
	if len(findSplitTunnelRoutes(entries)) != 1 {
		t.Errorf("split tunnel routes = %v, want the one /1", findSplitTunnelRoutes(entries))
	}
}

func ifIndex(t *testing.T, table *testTable, name string) string {
	t.Helper()
	h, err := table.handle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	link, err := h.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(link.Attrs().Index)
}

func TestNetlinkTableHostRouteLifecycle(t *testing.T) {
	table := newTestTable(t)
	ctx := context.Background()
	dest := mustAddr("10.99.0.5")
	gw := mustAddr(testTunGateway)

	if err := table.AddHost(ctx, dest, gw, ""); err != nil {
		t.Fatalf("AddHost via gateway: %v", err)
	}
	iface, gotGW, err := table.Lookup(ctx, dest)
	if err != nil || iface != testTunIface || gotGW != gw {
		t.Fatalf("Lookup = %q, %v, %v", iface, gotGW, err)
	}
	if out := showRoutes(t, table, "-d"); !strings.Contains(out, "10.99.0.5 via "+testTunGateway+" dev "+testTunIface+" proto 245") {
		t.Errorf("route is not stamped with the owned protocol:\n%s", out)
	}

	// The same route again is a leftover of this tunnel and is adopted; one
	// through another interface is a conflict, never success.
	if err := table.AddHost(ctx, dest, gw, ""); err != nil {
		t.Errorf("re-adding the same route: %v", err)
	}
	if err := table.AddHost(ctx, dest, netip.Addr{}, testTunIface); err != nil {
		t.Errorf("adopting by interface: %v", err)
	}
	err = table.AddHost(ctx, dest, netip.Addr{}, testLANIface)
	if !errors.Is(err, ErrRouteOwnedElsewhere) {
		t.Errorf("a route through another interface = %v, want ErrRouteOwnedElsewhere", err)
	}

	if err := table.DeleteHost(ctx, dest); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	if err := table.DeleteHost(ctx, dest); err != nil {
		t.Errorf("deleting a route that is gone: %v", err)
	}
	if iface, _, err := table.Lookup(ctx, dest); err != nil || iface != testLANIface {
		t.Errorf("after delete Lookup = %q, %v, want the LAN default", iface, err)
	}
}

func TestNetlinkTableHostRouteThroughInterface(t *testing.T) {
	table := newTestTable(t)
	ctx := context.Background()
	dest := mustAddr("10.99.0.6")
	if err := table.AddHost(ctx, dest, netip.Addr{}, testTunIface); err != nil {
		t.Fatalf("AddHost via interface: %v", err)
	}
	iface, gw, err := table.Lookup(ctx, dest)
	if err != nil || iface != testTunIface || gw.IsValid() {
		t.Fatalf("Lookup = %q, %v, %v, want the tunnel and no gateway", iface, gw, err)
	}
	if err := table.AddHost(ctx, dest, netip.Addr{}, ""); err == nil {
		t.Error("a route with neither gateway nor interface must be refused")
	}
	if err := table.AddHost(ctx, dest, netip.Addr{}, "nope0"); err == nil {
		t.Error("an unknown interface must be refused")
	}
}

func TestNetlinkTablePrefixAndNetRoutes(t *testing.T) {
	table := newTestTable(t)
	ctx := context.Background()
	prefix := netip.MustParsePrefix("10.99.8.0/24")

	if err := table.AddPrefix(ctx, prefix, netip.Addr{}, testTunIface); err != nil {
		t.Fatalf("AddPrefix: %v", err)
	}
	if err := table.AddPrefix(ctx, prefix, netip.Addr{}, testTunIface); err != nil {
		t.Errorf("adopting the same prefix: %v", err)
	}
	if err := table.AddPrefix(ctx, prefix, netip.Addr{}, testLANIface); !errors.Is(err, ErrRouteOwnedElsewhere) {
		t.Errorf("a prefix through another interface = %v, want ErrRouteOwnedElsewhere", err)
	}
	if err := table.AddPrefix(ctx, netip.MustParsePrefix("2001:db8::/32"), netip.Addr{}, testTunIface); err == nil {
		t.Error("an IPv6 prefix must be refused")
	}
	if err := table.DeleteNet(ctx, prefix.String(), "", ""); err != nil {
		t.Fatalf("DeleteNet: %v", err)
	}
	if err := table.DeleteNet(ctx, prefix.String(), "", ""); err != nil {
		t.Errorf("deleting a prefix that is gone: %v", err)
	}

	// The catch-all halves round-trip through the notation the table prints.
	for _, raw := range []string{"0/1", "128.0/1"} {
		if err := table.AddNet(ctx, raw, testTunGateway, ""); err != nil {
			t.Fatalf("AddNet %s: %v", raw, err)
		}
		if err := table.AddNet(ctx, raw, testTunGateway, ""); err != nil {
			t.Errorf("AddNet %s again must be accepted: %v", raw, err)
		}
	}
	entries, err := table.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := findSplitTunnelRoutes(entries); len(got) != 2 {
		t.Fatalf("split tunnel routes = %v, want both halves", got)
	}
	for _, e := range findSplitTunnelRoutes(entries) {
		if err := table.DeleteNet(ctx, e.Destination, "", ""); err != nil {
			t.Errorf("DeleteNet %s: %v", e.Destination, err)
		}
	}
	entries, _ = table.Snapshot(ctx)
	if got := findSplitTunnelRoutes(entries); len(got) != 0 {
		t.Errorf("split tunnel routes left behind: %v", got)
	}
	if err := table.AddNet(ctx, "not-a-route", testTunGateway, ""); err == nil {
		t.Error("an unparsable destination must be refused")
	}
}

// A VPN client that adds its catch-all halves through the interface alone, as
// `ip route add 0.0.0.0/1 dev wg0` does, gets link-scope routes; deleting them
// must not depend on the scope the table would have used itself.
func TestNetlinkTableDeletesAVPNClientsLinkScopeRoutes(t *testing.T) {
	table := newTestTable(t)
	ctx := context.Background()
	for _, dest := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		runIP(t, "-n", table.ns, "route", "add", dest, "dev", testTunIface)
	}
	entries, err := table.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range findSplitTunnelRoutes(entries) {
		if err := table.DeleteNet(ctx, e.Destination, "", ""); err != nil {
			t.Errorf("DeleteNet %s: %v", e.Destination, err)
		}
	}
	if routes := showRoutes(t, table); strings.Contains(routes, "/1 dev") {
		t.Errorf("link-scope catch-all routes left behind:\n%s", routes)
	}
}

func TestNetlinkTableChangesDefaultInPlace(t *testing.T) {
	table := newTestTable(t)
	ctx := context.Background()
	newGW := mustAddr(testTunGateway)

	if err := table.ChangeDefault(ctx, newGW); err != nil {
		t.Fatalf("ChangeDefault: %v", err)
	}
	if gw, iface, err := table.Default(ctx); err != nil || gw != newGW || iface != testTunIface {
		t.Fatalf("Default = %v, %q, %v", gw, iface, err)
	}
	// The metric of the route is kept, so the LAN default was replaced rather
	// than a second default added beside it.
	if out := showRoutes(t, table); strings.Count(out, "default") != 1 || !strings.Contains(out, "metric 100") {
		t.Errorf("default was not replaced in place:\n%s", out)
	}

	if err := table.ReplaceDefault(ctx, mustAddr(testLANGateway)); err != nil {
		t.Fatalf("ReplaceDefault: %v", err)
	}
	if err := table.ChangeDefaultStrict(ctx, newGW); err != nil {
		t.Fatalf("ChangeDefaultStrict: %v", err)
	}
	if err := table.ChangeDefaultToInterface(ctx, testTunIface); err != nil {
		t.Fatalf("ChangeDefaultToInterface: %v", err)
	}
	if gw, iface, err := table.Default(ctx); err != nil || gw.IsValid() || iface != testTunIface {
		t.Fatalf("Default after restoring the interface route = %v, %q, %v", gw, iface, err)
	}
	if err := table.ChangeDefaultToInterface(ctx, "nope0"); err == nil {
		t.Error("an unknown interface must be refused")
	}
}

func TestNetlinkTableStrictChangeNeverAddsADefault(t *testing.T) {
	table := newTestTable(t)
	ctx := context.Background()
	runIP(t, "-n", table.ns, "route", "del", "default")

	if err := table.ChangeDefaultStrict(ctx, mustAddr(testLANGateway)); err == nil {
		t.Error("ChangeDefaultStrict without a default must fail")
	}
	if err := table.ReplaceDefault(ctx, mustAddr(testLANGateway)); err == nil {
		t.Error("ReplaceDefault without a default must fail")
	}
	if err := table.ChangeDefaultToInterface(ctx, testTunIface); err == nil {
		t.Error("ChangeDefaultToInterface without a default must fail")
	}
	if out := showRoutes(t, table); strings.Contains(out, "default") {
		t.Fatalf("a strict change added a default:\n%s", out)
	}

	// The lenient change adds one when there is none.
	if err := table.ChangeDefault(ctx, mustAddr(testLANGateway)); err != nil {
		t.Fatalf("ChangeDefault without a default: %v", err)
	}
	if gw, _, err := table.Default(ctx); err != nil || gw != mustAddr(testLANGateway) {
		t.Errorf("Default = %v, %v", gw, err)
	}
}

func TestNetlinkTableReportsUnreachableGateway(t *testing.T) {
	table := newTestTable(t)
	err := table.AddHost(context.Background(), mustAddr("10.99.0.7"), mustAddr(testUnconnected), "")
	if err == nil || !table.IsUnreachable(err) {
		t.Fatalf("AddHost via a gateway on no connected network = %v, want an unreachable error", err)
	}
	if table.IsUnreachable(errors.New("operation not permitted")) || table.IsUnreachable(nil) {
		t.Error("other errors are not unreachable")
	}
}

func TestNetlinkTableIPv6RejectAll(t *testing.T) {
	ctx := context.Background()
	table := newTestTable(t)
	for range 2 {
		if err := table.AddIPv6RejectAll(ctx); err != nil {
			t.Fatalf("AddIPv6RejectAll: %v", err)
		}
	}
	for range 2 {
		if err := table.DeleteIPv6RejectAll(ctx); err != nil {
			t.Fatalf("DeleteIPv6RejectAll: %v", err)
		}
	}
}

func TestNetlinkTableIPv6Reject(t *testing.T) {
	table := newTestTable(t)
	ctx := context.Background()
	addr := mustAddr("2001:db8::10")

	if err := table.AddIPv6Reject(ctx, addr); err != nil {
		t.Fatalf("AddIPv6Reject: %v", err)
	}
	if err := table.AddIPv6Reject(ctx, addr); err != nil {
		t.Errorf("an existing reject route must be adopted: %v", err)
	}
	if out := runIP(t, "-n", table.ns, "-6", "route", "show", "type", "unreachable"); !strings.Contains(out, "2001:db8::10 dev lo") || !strings.Contains(out, "proto 245") {
		t.Errorf("reject route not installed as ours:\n%s", out)
	}
	if _, _, err := table.Lookup(ctx, addr); !errors.Is(err, unix.EHOSTUNREACH) {
		t.Errorf("Lookup of a rejected address = %v, want EHOSTUNREACH", err)
	}
	if err := table.DeleteIPv6Reject(ctx, addr); err != nil {
		t.Fatalf("DeleteIPv6Reject: %v", err)
	}
	if err := table.DeleteIPv6Reject(ctx, addr); err != nil {
		t.Errorf("deleting a reject route that is gone: %v", err)
	}
	if out := runIP(t, "-n", table.ns, "-6", "route", "show", "type", "unreachable"); strings.Contains(out, "2001:db8::10") {
		t.Errorf("reject route not removed:\n%s", out)
	}

	// A real route to the address is not ours to delete.
	runIP(t, "-n", table.ns, "-6", "route", "add", "2001:db8::10/128", "dev", testLANIface)
	if err := table.DeleteIPv6Reject(ctx, addr); err != nil {
		t.Errorf("DeleteIPv6Reject beside a real route: %v", err)
	}
	if out := runIP(t, "-n", table.ns, "-6", "route", "show"); !strings.Contains(out, "2001:db8::10 dev "+testLANIface) {
		t.Errorf("the real route was deleted:\n%s", out)
	}

	for _, bad := range []string{"::1", "fe80::1", "10.0.0.1"} {
		a := mustAddr(bad)
		if table.AddIPv6Reject(ctx, a) == nil || table.DeleteIPv6Reject(ctx, a) == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
}

func TestNetlinkTableHonoursACancelledContext(t *testing.T) {
	table := newTestTable(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := table.Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Snapshot = %v, want context.Canceled", err)
	}
	if err := table.AddHost(ctx, mustAddr("10.99.0.8"), mustAddr(testTunGateway), ""); !errors.Is(err, context.Canceled) {
		t.Errorf("AddHost = %v, want context.Canceled", err)
	}
}

func TestParseRouteDest(t *testing.T) {
	for raw, want := range map[string]string{
		"default":      "0.0.0.0/0",
		"0/1":          "0.0.0.0/1",
		"128.0/1":      "128.0.0.0/1",
		"10.20.0.0/16": "10.20.0.0/16",
		"10.20.30.40":  "10.20.30.40/32",
		"2001:db8::1":  "2001:db8::1/128",
	} {
		got, err := parseRouteDest(raw)
		if err != nil || got.String() != want {
			t.Errorf("parseRouteDest(%q) = %v, %v, want %s", raw, got, err, want)
		}
	}
	for _, bad := range []string{"", "link#4", "10.0.0.0/33", "x"} {
		if _, err := parseRouteDest(bad); err == nil {
			t.Errorf("parseRouteDest(%q) must fail", bad)
		}
	}
}

// Two tunnels that both carry a 0/1 route, at different metrics: deleting one
// tunnel's route must not take the other's, whichever the kernel lists first.
func TestNetlinkTableDeleteNetOnlyRemovesTheOwnersRoute(t *testing.T) {
	table := newTestTable(t)
	ctx := context.Background()
	runIP(t, "-n", table.ns, "route", "add", "0.0.0.0/1", "dev", testLANIface, "metric", "5")
	runIP(t, "-n", table.ns, "route", "add", "0.0.0.0/1", "via", testTunGateway, "dev", testTunIface, "metric", "50")

	if err := table.DeleteNet(ctx, "0.0.0.0/1", testTunGateway, testTunIface); err != nil {
		t.Fatalf("DeleteNet: %v", err)
	}
	routes := showRoutes(t, table)
	if !strings.Contains(routes, "0.0.0.0/1 dev "+testLANIface) || strings.Contains(routes, testTunGateway) {
		t.Fatalf("only the %s route may go:\n%s", testTunIface, routes)
	}

	// With no interface the gateway names the owner.
	runIP(t, "-n", table.ns, "route", "add", "0.0.0.0/1", "via", testTunGateway, "dev", testTunIface, "metric", "50")
	if err := table.DeleteNet(ctx, "0.0.0.0/1", testTunGateway, ""); err != nil {
		t.Fatalf("DeleteNet by gateway: %v", err)
	}
	routes = showRoutes(t, table)
	if !strings.Contains(routes, "0.0.0.0/1 dev "+testLANIface) || strings.Contains(routes, testTunGateway) {
		t.Fatalf("only the gateway's route may go:\n%s", routes)
	}

	// An interface that no longer exists has no routes left to delete.
	if err := table.DeleteNet(ctx, "0.0.0.0/1", "", "gone0"); err != nil {
		t.Fatalf("DeleteNet on a missing interface: %v", err)
	}
}
