package route

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/quocln/routewise/internal/winnet"
)

// fakeWinOps is an in-memory Windows route table.
type fakeWinOps struct {
	adapterList []winnet.Adapter
	table       []winnet.Route
	table6      []winnet.Route
	calls       []string
	createErr   error
}

func (f *fakeWinOps) adapters() ([]winnet.Adapter, error) { return f.adapterList, nil }

func (f *fakeWinOps) routes(family int) ([]winnet.Route, error) {
	if family == 6 {
		return slices.Clone(f.table6), nil
	}
	return slices.Clone(f.table), nil
}

func (f *fakeWinOps) store(r winnet.Route) *[]winnet.Route {
	if r.Dest.Addr().Is6() {
		return &f.table6
	}
	return &f.table
}

func (f *fakeWinOps) create(n newWinRoute) error {
	f.calls = append(f.calls, "create "+n.Dest.String()+" "+n.Adapter.Alias)
	if f.createErr != nil {
		return f.createErr
	}
	r := winnet.Route{Adapter: n.Adapter, Dest: n.Dest, NextHop: n.NextHop, Metric: n.Metric, Protocol: winnet.ProtocolNetMgmt}
	st := f.store(r)
	for _, e := range *st {
		if keyOf(e) == keyOf(r) {
			return errWinRouteExists
		}
	}
	*st = append(*st, r)
	return nil
}

func (f *fakeWinOps) setMetric(r winnet.Route, metric uint32) error {
	f.calls = append(f.calls, "metric "+r.Dest.String()+" "+r.Adapter.Alias)
	st := f.store(r)
	for i := range *st {
		if keyOf((*st)[i]) == keyOf(r) {
			(*st)[i].Metric = metric
			return nil
		}
	}
	return errWinRouteGone
}

func (f *fakeWinOps) remove(r winnet.Route) error {
	f.calls = append(f.calls, "remove "+r.Dest.String()+" "+r.Adapter.Alias)
	st := f.store(r)
	for i := range *st {
		if keyOf((*st)[i]) == keyOf(r) {
			*st = slices.Delete(*st, i, i+1)
			return nil
		}
	}
	return errWinRouteGone
}

var (
	ethernet = winnet.Adapter{Index: 5, LUID: 5, Alias: "Ethernet", Description: "Intel(R) Ethernet", IfType: 6, Up: true, Metric: 25}
	wifi     = winnet.Adapter{Index: 7, LUID: 7, Alias: "Wi-Fi", Description: "Intel(R) Wi-Fi 6", IfType: 71, Up: true, Metric: 50}
	tap      = winnet.Adapter{Index: 12, LUID: 12, Alias: "Local Area Connection 3", Description: "TAP-Windows Adapter V9", IfType: 6, Up: true, Metric: 1}
	wintun   = winnet.Adapter{Index: 14, LUID: 14, Alias: "wg-office", Description: "Wintun Userspace Tunnel", IfType: 53, Up: true, Metric: 0}
	loopback = winnet.Adapter{Index: 1, LUID: 1, Alias: "Loopback Pseudo-Interface 1", Description: "Software Loopback Interface 1", IfType: 24, Up: true, Metric: 75}
)

func rt(a winnet.Adapter, dest, hop string, metric, proto uint32) winnet.Route {
	r := winnet.Route{Adapter: a, Dest: netip.MustParsePrefix(dest), Metric: metric, Protocol: proto}
	if hop != "" {
		r.NextHop = netip.MustParseAddr(hop)
	} else if r.Dest.Addr().Is6() {
		r.NextHop = netip.IPv6Unspecified()
	} else {
		r.NextHop = netip.IPv4Unspecified()
	}
	return r
}

// lanTable is a laptop on Ethernet (192.168.1.0/24) and Wi-Fi (10.1.0.0/24).
func lanTable() *fakeWinOps {
	return &fakeWinOps{
		adapterList: []winnet.Adapter{ethernet, wifi, tap, wintun, loopback},
		table: []winnet.Route{
			rt(ethernet, "0.0.0.0/0", "192.168.1.1", 0, 16),
			rt(wifi, "0.0.0.0/0", "10.1.0.1", 0, 16),
			rt(ethernet, "192.168.1.0/24", "", 256, winnet.ProtocolLocal),
			rt(ethernet, "192.168.1.20/32", "", 256, winnet.ProtocolLocal),
			rt(wifi, "10.1.0.0/24", "", 256, winnet.ProtocolLocal),
			rt(loopback, "127.0.0.0/8", "", 331, winnet.ProtocolLocal),
			rt(ethernet, "224.0.0.0/4", "", 256, winnet.ProtocolLocal),
			rt(ethernet, "255.255.255.255/32", "", 256, winnet.ProtocolLocal),
		},
	}
}

// withOpenVPN adds an OpenVPN connection: a TAP adapter on 10.8.0.0/24 with the
// def1 pair through 10.8.0.1.
func withOpenVPN(f *fakeWinOps) *fakeWinOps {
	f.table = append(f.table,
		rt(tap, "10.8.0.0/24", "", 256, winnet.ProtocolLocal),
		rt(tap, "0.0.0.0/1", "10.8.0.1", 1, winnet.ProtocolNetMgmt),
		rt(tap, "128.0.0.0/1", "10.8.0.1", 1, winnet.ProtocolNetMgmt),
	)
	return f
}

func ctx() context.Context { return context.Background() }

func TestWindowsSnapshotUsesTheBSDNotation(t *testing.T) {
	tab := newWindowsTable(withOpenVPN(lanTable()))
	got, err := tab.Snapshot(ctx())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]RouteEntry{
		"default":        {Destination: "default", Gateway: "192.168.1.1", Flags: "UG", Interface: "Ethernet"},
		"192.168.1.20":   {Destination: "192.168.1.20", Gateway: "link#5", Flags: "UH", Interface: "Ethernet"},
		"192.168.1.0/24": {Destination: "192.168.1.0/24", Gateway: "link#5", Flags: "U", Interface: "Ethernet"},
		"0.0.0.0/1":      {Destination: "0.0.0.0/1", Gateway: "10.8.0.1", Flags: "UG", Interface: "Local Area Connection 3"},
		"128.0.0.0/1":    {Destination: "128.0.0.0/1", Gateway: "10.8.0.1", Flags: "UG", Interface: "Local Area Connection 3"},
	}
	byDest := map[string]RouteEntry{}
	for _, e := range got {
		if e.Destination == "default" && e.Interface == "Wi-Fi" {
			continue
		}
		byDest[e.Destination] = e
	}
	for d, w := range want {
		if byDest[d] != w {
			t.Errorf("%s: got %+v, want %+v", d, byDest[d], w)
		}
	}
	for _, skipped := range []string{"127.0.0.0/8", "224.0.0.0/4", "255.255.255.255"} {
		if _, ok := byDest[skipped]; ok {
			t.Errorf("%s must not be listed", skipped)
		}
	}
	if len(findSplitTunnelRoutes(got)) != 2 {
		t.Error("the manager must find the 0/1 and 128/1 pair in the snapshot")
	}
}

func TestWindowsDefaultPrefersTheLowestEffectiveMetric(t *testing.T) {
	f := lanTable()
	tab := newWindowsTable(f)
	gw, iface, err := tab.Default(ctx())
	if err != nil || gw != netip.MustParseAddr("192.168.1.1") || iface != "Ethernet" {
		t.Fatalf("Default = %v %q %v, want Ethernet's gateway (25 beats 50)", gw, iface, err)
	}

	// A VPN default route with its metric of 1 wins over both LANs.
	f.table = append(f.table, rt(tap, "0.0.0.0/0", "10.8.0.1", 1, winnet.ProtocolNetMgmt))
	gw, iface, _ = tab.Default(ctx())
	if gw != netip.MustParseAddr("10.8.0.1") || iface != tap.Alias {
		t.Fatalf("Default = %v %q, want the tunnel's", gw, iface)
	}
	lan, lanIface, err := tab.LocalGateway(ctx(), "")
	if err != nil || lan != netip.MustParseAddr("192.168.1.1") || lanIface != "Ethernet" {
		t.Fatalf("LocalGateway = %v %q %v, want Ethernet skipping the tunnel", lan, lanIface, err)
	}
	lan, lanIface, _ = tab.LocalGateway(ctx(), "wi-fi")
	if lan != netip.MustParseAddr("10.1.0.1") || lanIface != "Wi-Fi" {
		t.Fatalf("LocalGateway(prefer Wi-Fi) = %v %q", lan, lanIface)
	}
}

func TestWindowsDefaultGatewayFailsForAnInterfaceRoute(t *testing.T) {
	f := &fakeWinOps{adapterList: []winnet.Adapter{wintun}, table: []winnet.Route{rt(wintun, "0.0.0.0/0", "", 0, winnet.ProtocolNetMgmt)}}
	tab := newWindowsTable(f)
	gw, iface, err := tab.Default(ctx())
	if err != nil || gw.IsValid() || iface != wintun.Alias {
		t.Fatalf("Default = %v %q %v, want an invalid gateway on the interface", gw, iface, err)
	}
	if _, err := tab.DefaultGateway(ctx()); err == nil {
		t.Fatal("DefaultGateway must fail when the default has no gateway")
	}
	if _, _, err := tab.LocalGateway(ctx(), ""); err == nil {
		t.Fatal("LocalGateway must fail when only a tunnel has a default")
	}
	if _, _, err := newWindowsTable(&fakeWinOps{}).Default(ctx()); err == nil {
		t.Fatal("no default route is an error")
	}
}

func TestWindowsLookupLongestPrefixThenMetric(t *testing.T) {
	tab := newWindowsTable(withOpenVPN(lanTable()))
	iface, gw, err := tab.Lookup(ctx(), netip.MustParseAddr("192.168.1.77"))
	if err != nil || iface != "Ethernet" || gw.IsValid() {
		t.Fatalf("Lookup LAN = %q %v %v, want on-link Ethernet", iface, gw, err)
	}
	iface, gw, _ = tab.Lookup(ctx(), netip.MustParseAddr("93.184.216.34"))
	if iface != tap.Alias || gw != netip.MustParseAddr("10.8.0.1") {
		t.Fatalf("Lookup internet = %q %v, want the /1 pair on the TAP adapter (longer than the default)", iface, gw)
	}
	if _, _, err := tab.Lookup(ctx(), netip.Addr{}); err == nil {
		t.Fatal("invalid address must fail")
	}
}

func TestWindowsAddHostViaGatewayFindsTheInterface(t *testing.T) {
	f := withOpenVPN(lanTable())
	tab := newWindowsTable(f)
	if err := tab.AddHost(ctx(), netip.MustParseAddr("52.1.2.3"), netip.MustParseAddr("10.8.0.1"), ""); err != nil {
		t.Fatal(err)
	}
	last := f.table[len(f.table)-1]
	if last.Dest != netip.MustParsePrefix("52.1.2.3/32") || last.Adapter.Alias != tap.Alias || last.NextHop != netip.MustParseAddr("10.8.0.1") {
		t.Fatalf("created %+v", last)
	}
	// Adding it again adopts it.
	before := len(f.table)
	if err := tab.AddHost(ctx(), netip.MustParseAddr("52.1.2.3"), netip.MustParseAddr("10.8.0.1"), tap.Alias); err != nil {
		t.Fatal(err)
	}
	if len(f.table) != before {
		t.Fatal("an existing route through the tunnel is adopted, not duplicated")
	}
}

func TestWindowsAddHostThroughAnInterfaceIsOnLink(t *testing.T) {
	f := lanTable()
	tab := newWindowsTable(f)
	if err := tab.AddHost(ctx(), netip.MustParseAddr("52.1.2.3"), netip.Addr{}, "WG-OFFICE"); err != nil {
		t.Fatal(err)
	}
	last := f.table[len(f.table)-1]
	if last.Adapter.Alias != "wg-office" || !last.OnLink() {
		t.Fatalf("created %+v, want an on-link route on wg-office (alias matched ignoring case)", last)
	}
	if err := tab.AddHost(ctx(), netip.MustParseAddr("52.1.2.4"), netip.Addr{}, "nope"); err == nil {
		t.Fatal("unknown interface must fail")
	}
	if err := tab.AddHost(ctx(), netip.MustParseAddr("52.1.2.4"), netip.Addr{}, ""); err == nil {
		t.Fatal("neither gateway nor interface must fail")
	}
}

func TestWindowsAddHostRefusesAForeignRoute(t *testing.T) {
	f := lanTable()
	f.table = append(f.table, rt(ethernet, "52.1.2.3/32", "192.168.1.1", 5, winnet.ProtocolNetMgmt))
	tab := newWindowsTable(f)
	err := tab.AddHost(ctx(), netip.MustParseAddr("52.1.2.3"), netip.Addr{}, wintun.Alias)
	if !errors.Is(err, ErrRouteOwnedElsewhere) || !strings.Contains(err.Error(), "Ethernet") {
		t.Fatalf("got %v, want ErrRouteOwnedElsewhere naming Ethernet", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("nothing may be created: %v", f.calls)
	}
}

func TestWindowsAddPrefixAndAddNet(t *testing.T) {
	f := withOpenVPN(lanTable())
	tab := newWindowsTable(f)
	if err := tab.AddPrefix(ctx(), netip.MustParsePrefix("172.16.5.9/16"), netip.MustParseAddr("10.8.0.1"), tap.Alias); err != nil {
		t.Fatal(err)
	}
	if got := f.table[len(f.table)-1].Dest; got != netip.MustParsePrefix("172.16.0.0/16") {
		t.Fatalf("prefix stored as %v, want it masked", got)
	}
	if err := tab.AddPrefix(ctx(), netip.MustParsePrefix("2001:db8::/32"), netip.Addr{}, wintun.Alias); err == nil {
		t.Fatal("IPv6 prefix must be refused")
	}

	// AddNet restores a /1 even beside another VPN's identical route.
	f.table = append(f.table, rt(wintun, "0.0.0.0/1", "", 0, winnet.ProtocolNetMgmt))
	n := len(f.table)
	if err := tab.AddNet(ctx(), "0/1", "10.8.0.1", tap.Alias); err != nil {
		t.Fatalf("existing route must be accepted: %v", err)
	}
	if len(f.table) != n {
		t.Fatal("AddNet of an existing route changes nothing")
	}
	if err := tab.AddNet(ctx(), "128.0/1", "", wintun.Alias); err != nil {
		t.Fatal(err)
	}
	if err := tab.AddNet(ctx(), "bogus", "", wintun.Alias); err == nil {
		t.Fatal("bad destination must fail")
	}
}

func TestWindowsAddThroughAGatewayNoAdapterReachesIsUnreachable(t *testing.T) {
	tab := newWindowsTable(lanTable())
	err := tab.AddHost(ctx(), netip.MustParseAddr("52.1.2.3"), netip.MustParseAddr("172.31.0.1"), "")
	if !tab.IsUnreachable(err) {
		t.Fatalf("got %v, want an unreachable-gateway error", err)
	}
	err = tab.ChangeDefaultStrict(ctx(), netip.MustParseAddr("172.31.0.1"))
	if !tab.IsUnreachable(err) {
		t.Fatalf("got %v, want an unreachable-gateway error", err)
	}
	if tab.IsUnreachable(errors.New("access denied")) {
		t.Fatal("other errors are not unreachable")
	}
	if !tab.IsUnreachable(errnoNetworkUnreachable) || !tab.IsUnreachable(errnoHostUnreachable) {
		t.Fatal("the Win32 unreachable codes count")
	}
}

func TestWindowsTunnelOnLinkRoutesDoNotClaimGateways(t *testing.T) {
	// A WireGuard tunnel's on-link 0.0.0.0/1 contains every gateway; only the
	// connected subnets of real addresses decide which adapter reaches one.
	f := lanTable()
	f.table = append(f.table, rt(wintun, "0.0.0.0/1", "", 0, winnet.ProtocolNetMgmt), rt(wintun, "128.0.0.0/1", "", 0, winnet.ProtocolNetMgmt))
	a, ok := adapterForGateway(f.table, netip.MustParseAddr("192.168.1.1"))
	if !ok || a.Alias != "Ethernet" {
		t.Fatalf("got %+v %v, want Ethernet", a, ok)
	}
	if _, ok := adapterForGateway(f.table, netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("a gateway on no connected network has no adapter")
	}
}

func TestWindowsDeleteRemovesRoutesAnyClientAdded(t *testing.T) {
	f := withOpenVPN(lanTable())
	f.table = append(f.table, rt(ethernet, "52.1.2.3/32", "192.168.1.1", 5, winnet.ProtocolNetMgmt))
	tab := newWindowsTable(f)
	if err := tab.DeleteNet(ctx(), "128.0/1", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := tab.DeleteNet(ctx(), "0.0.0.0/1", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := tab.DeleteHost(ctx(), netip.MustParseAddr("52.1.2.3")); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.table {
		if r.Dest.Bits() == 1 || r.Dest.Addr() == netip.MustParseAddr("52.1.2.3") {
			t.Fatalf("%v is still there", r.Dest)
		}
	}
	// Gone is not an error, and the address's own route is never touched.
	if err := tab.DeleteHost(ctx(), netip.MustParseAddr("52.1.2.3")); err != nil {
		t.Fatal(err)
	}
	if err := tab.DeleteHost(ctx(), netip.MustParseAddr("192.168.1.20")); err != nil {
		t.Fatal(err)
	}
	if got := len(routesTo(f.table, netip.MustParsePrefix("192.168.1.20/32"))); got != 1 {
		t.Fatalf("the interface's own address route was deleted (%d left)", got)
	}
}

func TestWindowsReplaceDefaultAddsTheNewRouteBeforeDeletingTheTunnels(t *testing.T) {
	f := lanTable()
	f.table = append(f.table, rt(tap, "10.8.0.0/24", "", 256, winnet.ProtocolLocal), rt(tap, "0.0.0.0/0", "10.8.0.1", 1, winnet.ProtocolNetMgmt))
	tab := newWindowsTable(f)
	f.calls = nil
	// Ethernet's own default exists, so it is re-ranked instead of duplicated.
	if err := tab.ChangeDefault(ctx(), netip.MustParseAddr("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	// Ethernet is re-ranked ahead of the tunnel, the tunnel's default goes, and
	// Ethernet gets its own metric back.
	if want := []string{"metric 0.0.0.0/0 Ethernet", "remove 0.0.0.0/0 Local Area Connection 3", "metric 0.0.0.0/0 Ethernet"}; !slices.Equal(f.calls, want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
	gw, iface, _ := tab.Default(ctx())
	if gw != netip.MustParseAddr("192.168.1.1") || iface != "Ethernet" {
		t.Fatalf("Default = %v %q, want Ethernet's gateway", gw, iface)
	}
	for _, r := range defaultRoutesOf(f.table) {
		if r.Metric != 0 {
			t.Fatalf("%s default left at metric %d, want its own 0 back", r.Adapter.Alias, r.Metric)
		}
	}
	if got := len(defaultRoutesOf(f.table)); got != 2 {
		t.Fatalf("%d default routes, want Ethernet's and Wi-Fi's", got)
	}
}

func TestWindowsDefaultSwapCreatesThenRestoresTheTunnelDefault(t *testing.T) {
	// An interface-only default of a WireGuard-style tunnel is moved to the LAN
	// gateway and given back.
	f := lanTable()
	f.table = append(f.table, rt(wintun, "0.0.0.0/0", "", 0, winnet.ProtocolNetMgmt))
	tab := newWindowsTable(f)
	f.calls = nil
	if err := tab.ReplaceDefault(ctx(), netip.MustParseAddr("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 3 || !strings.HasPrefix(f.calls[0], "metric") || !strings.HasPrefix(f.calls[1], "remove") || !strings.HasPrefix(f.calls[2], "metric") {
		t.Fatalf("calls = %v", f.calls)
	}
	if _, iface, _ := tab.Default(ctx()); iface != "Ethernet" {
		t.Fatalf("default on %q, want Ethernet", iface)
	}

	f.calls = nil
	if err := tab.ChangeDefaultToInterface(ctx(), wintun.Alias); err != nil {
		t.Fatal(err)
	}
	if want := []string{"create 0.0.0.0/0 wg-office"}; !slices.Equal(f.calls, want) {
		t.Fatalf("calls = %v, want %v: Ethernet's default is the user's, not ours", f.calls, want)
	}
	if _, iface, _ := tab.Default(ctx()); iface != wintun.Alias {
		t.Fatalf("default on %q, want the tunnel", iface)
	}
	// Doing it again is a no-op.
	f.calls = nil
	if err := tab.ChangeDefaultToInterface(ctx(), wintun.Alias); err != nil || len(f.calls) != 0 {
		t.Fatalf("got %v %v, want nothing", err, f.calls)
	}
}

func TestWindowsDefaultSwapRemovesTheDefaultItCreated(t *testing.T) {
	f := lanTable()
	f.table = []winnet.Route{
		rt(ethernet, "192.168.1.0/24", "", 256, winnet.ProtocolLocal),
		rt(wintun, "0.0.0.0/0", "", 0, winnet.ProtocolNetMgmt),
	}
	tab := newWindowsTable(f)
	if err := tab.ChangeDefault(ctx(), netip.MustParseAddr("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	if got := f.calls; len(got) != 2 || got[0] != "create 0.0.0.0/0 Ethernet" || got[1] != "remove 0.0.0.0/0 wg-office" {
		t.Fatalf("calls = %v", got)
	}
	f.calls = nil
	if err := tab.ChangeDefaultToInterface(ctx(), wintun.Alias); err != nil {
		t.Fatal(err)
	}
	if got := f.calls; len(got) != 2 || got[0] != "create 0.0.0.0/0 wg-office" || got[1] != "remove 0.0.0.0/0 Ethernet" {
		t.Fatalf("calls = %v, want the default RouteWise created to go away", got)
	}
}

func TestWindowsFailedCreateLeavesTheDefaultAlone(t *testing.T) {
	f := lanTable()
	f.table = append(f.table, rt(tap, "10.8.0.0/24", "", 256, winnet.ProtocolLocal), rt(tap, "0.0.0.0/0", "10.8.0.1", 1, winnet.ProtocolNetMgmt))
	f.table = slices.DeleteFunc(f.table, func(r winnet.Route) bool { return r.Dest == defaultV4 && r.Adapter.Index != tap.Index })
	f.createErr = errors.New("access denied")
	tab := newWindowsTable(f)
	if err := tab.ChangeDefaultStrict(ctx(), netip.MustParseAddr("192.168.1.1")); err == nil {
		t.Fatal("must fail")
	}
	if _, iface, _ := tab.Default(ctx()); iface != tap.Alias {
		t.Fatalf("default moved to %q after a failed change", iface)
	}
}

func TestWindowsStrictChangeNeedsAnExistingDefault(t *testing.T) {
	f := &fakeWinOps{adapterList: []winnet.Adapter{ethernet}, table: []winnet.Route{rt(ethernet, "192.168.1.0/24", "", 256, winnet.ProtocolLocal)}}
	tab := newWindowsTable(f)
	if err := tab.ReplaceDefault(ctx(), netip.MustParseAddr("192.168.1.1")); err == nil {
		t.Fatal("ReplaceDefault must not add a default")
	}
	if err := tab.ChangeDefault(ctx(), netip.MustParseAddr("192.168.1.1")); err != nil {
		t.Fatal(err)
	}
	if gw, _, err := tab.Default(ctx()); err != nil || gw != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("Default = %v %v", gw, err)
	}
}

func TestWindowsIPv6RejectUsesTheLoopbackAndNeverTouchesRealRoutes(t *testing.T) {
	f := lanTable()
	addr := netip.MustParseAddr("2606:4700::6810:84e5")
	f.table6 = []winnet.Route{rt(ethernet, "2606:4700::6810:84e5/128", "fe80::1", 0, winnet.ProtocolNetMgmt)}
	tab := newWindowsTable(f)
	if err := tab.AddIPv6Reject(ctx(), addr); err != nil {
		t.Fatal(err)
	}
	if err := tab.AddIPv6Reject(ctx(), addr); err != nil {
		t.Fatalf("adopting a leftover: %v", err)
	}
	if got := len(f.table6); got != 2 {
		t.Fatalf("%d IPv6 routes, want the real one and one reject", got)
	}
	if err := tab.DeleteIPv6Reject(ctx(), addr); err != nil {
		t.Fatal(err)
	}
	if len(f.table6) != 1 || f.table6[0].Adapter.Alias != "Ethernet" {
		t.Fatalf("left %+v, want only the real route", f.table6)
	}
	if err := tab.DeleteIPv6Reject(ctx(), addr); err != nil {
		t.Fatalf("already gone: %v", err)
	}
	for _, bad := range []string{"fe80::1", "::1", "fd00::1", "192.0.2.1"} {
		if err := tab.AddIPv6Reject(ctx(), netip.MustParseAddr(bad)); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
	noLoop := newWindowsTable(&fakeWinOps{adapterList: []winnet.Adapter{ethernet}})
	if err := noLoop.AddIPv6Reject(ctx(), addr); err == nil {
		t.Fatal("no loopback interface must fail")
	}
}

func TestWindowsCancelledContextFailsBeforeTouchingTheTable(t *testing.T) {
	f := lanTable()
	c, cancel := context.WithCancel(ctx())
	cancel()
	tab := newWindowsTable(f)
	if err := tab.AddHost(c, netip.MustParseAddr("52.1.2.3"), netip.Addr{}, wintun.Alias); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatal("no call may be made")
	}
}

func TestWindowsDeleteNetLeavesAnotherTunnelsRoutes(t *testing.T) {
	f := withOpenVPN(lanTable())
	f.table = append(f.table,
		rt(wintun, "0.0.0.0/1", "10.9.0.1", 0, winnet.ProtocolNetMgmt),
		rt(wintun, "128.0.0.0/1", "10.9.0.1", 0, winnet.ProtocolNetMgmt),
	)
	tab := newWindowsTable(f)
	for _, dest := range []string{"0.0.0.0/1", "128.0/1"} {
		if err := tab.DeleteNet(ctx(), dest, "10.8.0.1", tap.Alias); err != nil {
			t.Fatal(err)
		}
	}
	for _, dest := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		got := routesTo(f.table, netip.MustParsePrefix(dest))
		if len(got) != 1 || got[0].Adapter.Alias != wintun.Alias {
			t.Fatalf("%s: routes left = %+v, want only the other tunnel's", dest, got)
		}
	}
	// With no interface the gateway names the owner.
	if err := tab.DeleteNet(ctx(), "0.0.0.0/1", "10.9.0.1", ""); err != nil {
		t.Fatal(err)
	}
	if got := routesTo(f.table, netip.MustParsePrefix("0.0.0.0/1")); len(got) != 0 {
		t.Fatalf("routes left by gateway = %+v", got)
	}
}

func TestWindowsIPv6RejectAllUsesTheLoopbackAndNeverTouchesRealRoutes(t *testing.T) {
	f := lanTable()
	f.table6 = []winnet.Route{rt(ethernet, "2000::/3", "fe80::1", 0, winnet.ProtocolNetMgmt)}
	tab := newWindowsTable(f)
	for range 2 {
		if err := tab.AddIPv6RejectAll(ctx()); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(f.table6); got != 2 {
		t.Fatalf("%d IPv6 routes, want the real one and one reject", got)
	}
	for range 2 {
		if err := tab.DeleteIPv6RejectAll(ctx()); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(f.table6); got != 1 || f.table6[0].Adapter.IsLoopback() {
		t.Fatalf("routes after delete = %v, want only the real one", f.table6)
	}
}
