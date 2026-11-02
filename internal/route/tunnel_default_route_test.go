package route

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// networkExtensionVPN sets up the table a NetworkExtension VPN (the WireGuard
// app, for example) leaves behind: the global default points at its utun with
// no gateway IP, and the LAN default survives only as an interface-scoped
// route.
func networkExtensionVPN(fake *fakeRunner, iface string) {
	fake.defaultGW = ""
	fake.defaultIface = iface
	fake.scopedLANGW = "192.168.7.1"
}

func TestCaptureOriginalGatewayReadsTheScopedLANDefault(t *testing.T) {
	m, fake := newTestManager(t)
	networkExtensionVPN(fake, tun5)

	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatalf("capture: %v", err)
	}
	if got := m.GetOriginalGateway(); got != netip.MustParseAddr("192.168.7.1") {
		t.Fatalf("original gateway = %s, want the LAN gateway 192.168.7.1", got)
	}
}

func TestCaptureOriginalGatewayIgnoresATunnelGatewayIP(t *testing.T) {
	m, fake := newTestManager(t)
	// OpenVPN without def1 replaces the default with its peer IP.
	fake.defaultGW = "10.8.0.1"
	fake.defaultIface = tun6
	fake.scopedLANGW = "192.168.7.1"

	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatalf("capture: %v", err)
	}
	if got := m.GetOriginalGateway(); got != netip.MustParseAddr("192.168.7.1") {
		t.Fatalf("original gateway = %s, want 192.168.7.1, not the tunnel peer", got)
	}
}

func TestActivateTakesTheDefaultFromANetworkExtensionVPN(t *testing.T) {
	m, fake := newTestManager(t)
	networkExtensionVPN(fake, tun5)
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	m.SetVPNState(netip.Addr{}, tun5)

	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if fake.defaultGW != "192.168.7.1" || fake.defaultInterface() != "en0" {
		t.Fatalf("default = %q on %s, want 192.168.7.1 on en0", fake.defaultGW, fake.defaultInterface())
	}

	tx, ok, err := m.journal.load()
	if err != nil || !ok {
		t.Fatalf("journal: ok=%v err=%v", ok, err)
	}
	last := tx.Steps[len(tx.Steps)-1]
	if last.Kind != stepChangeDefault || last.PriorInterface != tun5 || last.PriorGateway != "" {
		t.Fatalf("journal step = %+v, want change_default from utun5 with no gateway", last)
	}
}

func TestDeactivateGivesTheDefaultBackWhileTheTunnelIsUp(t *testing.T) {
	m, fake := newTestManager(t)
	m.interfaceUp = func(string) bool { return true }
	networkExtensionVPN(fake, tun5)
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	m.SetVPNState(netip.Addr{}, tun5)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatal(err)
	}

	if err := m.DeactivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if fake.defaultIface != tun5 || fake.defaultGW != "" {
		t.Fatalf("default = %q on %q, want it back on utun5", fake.defaultGW, fake.defaultIface)
	}
}

func TestDeactivateLeavesTheLANDefaultOnceTheTunnelIsGone(t *testing.T) {
	m, fake := newTestManager(t)
	m.interfaceUp = func(string) bool { return false }
	networkExtensionVPN(fake, tun5)
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	m.SetVPNState(netip.Addr{}, tun5)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatal(err)
	}

	if err := m.DeactivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if fake.defaultGW != "192.168.7.1" || fake.defaultInterface() != "en0" {
		t.Fatalf("default = %q on %s, want the LAN default kept", fake.defaultGW, fake.defaultInterface())
	}
	if degraded, reason := m.Degraded(); degraded {
		t.Fatalf("a vanished tunnel must not degrade the manager: %s", reason)
	}
}

func TestEnforceReclaimsADefaultTheVPNTookBack(t *testing.T) {
	m, fake := newTestManager(t)
	networkExtensionVPN(fake, tun5)
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	m.SetVPNState(netip.Addr{}, tun5)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatal(err)
	}

	// The client re-asserts its default route.
	fake.defaultGW, fake.defaultIface = "", tun5

	if err := m.EnforceSplitTunnel(); err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if fake.defaultGW != "192.168.7.1" || fake.defaultInterface() != "en0" {
		t.Fatalf("default = %q on %s, want it reclaimed for the LAN", fake.defaultGW, fake.defaultInterface())
	}
}

func TestEnforceLeavesAnUnrelatedDefaultAlone(t *testing.T) {
	m, fake := newTestManager(t)
	fake.defaultGW = "192.168.7.1"
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun4)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatal(err)
	}

	// The user switched networks; the new LAN default is not RouteWise's to move.
	fake.defaultGW = "10.0.0.1"
	if err := m.EnforceSplitTunnel(); err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if fake.defaultGW != "10.0.0.1" {
		t.Fatalf("default = %q, want the new LAN default left alone", fake.defaultGW)
	}
}

func TestHostRoutesUseTheInterfaceWhenTheTunnelHasNoGatewayIP(t *testing.T) {
	m, fake := newTestManager(t)
	m.SetVPNState(netip.Addr{}, tun3)

	if err := m.AddRoute(netip.MustParseAddr("10.20.30.40"), "api.corp.example.com", false); err != nil {
		t.Fatalf("add route: %v", err)
	}
	want := toolRoute + " -n add -host 10.20.30.40 -interface " + tun3
	for _, call := range fake.callLog {
		if call == want {
			return
		}
	}
	t.Fatalf("expected an -interface host route, calls: %v", fake.callLog)
}

func TestGetDefaultRouteParsesAnInterfaceOnlyDefault(t *testing.T) {
	fake := newFakeRunner()
	networkExtensionVPN(fake, tun5)

	gw, iface, err := getDefaultRoute(context.Background(), fake)
	if err != nil {
		t.Fatal(err)
	}
	if gw.IsValid() || iface != tun5 {
		t.Fatalf("getDefaultRoute = (%s, %q), want (invalid, utun5)", gw, iface)
	}
}

func TestChangeObserverSeesAddedAndRemovedRoutesWithTheirDomain(t *testing.T) {
	m, _ := newTestManager(t)
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun4)
	var seen []RouteChange
	m.SetChangeObserver(func(c RouteChange) { seen = append(seen, c) })

	ip := netip.MustParseAddr("10.20.30.40")
	if err := m.AddRoute(ip, "api.corp.example.com", false); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveRoute(ip); err != nil {
		t.Fatal(err)
	}

	if len(seen) != 2 || seen[0].Type != RouteAdded || seen[1].Type != RouteRemoved {
		t.Fatalf("changes = %+v, want an add then a remove", seen)
	}
	for _, c := range seen {
		if c.Domain != "api.corp.example.com" || c.Interface != tun4 || c.Destination != ip {
			t.Fatalf("change = %+v, want domain, interface, and destination filled in", c)
		}
	}
}

func TestLookupRouteReportsTheTunnelForARoutedHost(t *testing.T) {
	m, fake := newTestManager(t)
	fake.defaultGW = "192.168.7.1"
	m.SetVPNState(netip.Addr{}, tun3)
	routed := netip.MustParseAddr("10.20.30.40")
	if err := m.AddRoute(routed, "api.corp.example.com", false); err != nil {
		t.Fatal(err)
	}

	if iface, _, err := m.LookupRoute(routed); err != nil || iface != tun3 {
		t.Fatalf("LookupRoute(routed) = %q, %v; want utun3", iface, err)
	}
	iface, gw, err := m.LookupRoute(netip.MustParseAddr("1.1.1.1"))
	if err != nil || iface != "en0" || gw != netip.MustParseAddr("192.168.7.1") {
		t.Fatalf("LookupRoute(other) = %q %s %v; want en0 via 192.168.7.1", iface, gw, err)
	}
}

// wgQuickVPN sets up the table wg-quick leaves behind: the /1 halves point at
// the interface itself, with no gateway IP.
func wgQuickVPN(fake *fakeRunner, iface string) {
	fake.defaultGW = "192.168.7.1"
	fake.routes = []RouteEntry{
		{Destination: "0/1", Gateway: iface, Flags: "USc", Interface: iface},
		{Destination: "128.0/1", Gateway: iface, Flags: "USc", Interface: iface},
	}
}

func hasCall(fake *fakeRunner, call string) bool {
	for _, c := range fake.callLog {
		if c == call {
			return true
		}
	}
	return false
}

func TestWGQuickHalvesGoBackWithInterfaceRoutes(t *testing.T) {
	m, fake := newTestManager(t)
	wgQuickVPN(fake, tun3)
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	m.SetVPNState(netip.Addr{}, tun3)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("activate: %v", err)
	}

	if err := m.DeactivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	// `route add -net 0/1 utun3` is rejected by the real route tool.
	for _, dest := range []string{"0/1", "128.0/1"} {
		want := toolRoute + " -n add -net " + dest + " -interface " + tun3
		if !hasCall(fake, want) {
			t.Errorf("missing %q; calls: %v", want, fake.callLog)
		}
	}
	if degraded, reason := m.Degraded(); degraded {
		t.Fatalf("deactivation must succeed: %s", reason)
	}
}

func TestHalvesOfAVanishedTunnelAreNotRestored(t *testing.T) {
	m, fake := newTestManager(t)
	wgQuickVPN(fake, tun3)
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	m.SetVPNState(netip.Addr{}, tun3)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatal(err)
	}

	m.interfaceUp = func(string) bool { return false }
	if err := m.DeactivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("deactivate after the tunnel went away: %v", err)
	}
	for _, c := range fake.callLog {
		if strings.HasPrefix(c, toolRoute+" -n add -net") {
			t.Fatalf("no /1 route may be added for a tunnel that is gone, got %q", c)
		}
	}
	if degraded, reason := m.Degraded(); degraded {
		t.Fatalf("a normal disconnect must not degrade: %s", reason)
	}
}

func TestActivationLeavesAnotherVPNsDefaultAlone(t *testing.T) {
	m, fake := newTestManager(t)
	// The WireGuard app owns the default on utun6; an OpenVPN-style client
	// with a /1 pair then connects on utun7 and is the one being activated.
	networkExtensionVPN(fake, tun6)
	fake.routes = []RouteEntry{
		{Destination: "0/1", Gateway: "10.8.0.1", Flags: "UGSc", Interface: tun7},
		{Destination: "128.0/1", Gateway: "10.8.0.1", Flags: "UGSc", Interface: tun7},
	}
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	m.SetVPNState(netip.MustParseAddr("10.8.0.1"), tun7)

	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if fake.defaultIface != tun6 {
		t.Fatalf("default moved to %q on %q; the other VPN's default must stay", fake.defaultGW, fake.defaultInterface())
	}
	if len(fake.routes) != 0 {
		t.Fatalf("the activated tunnel's halves must still be removed, left %v", fake.routes)
	}
}

func TestReclaimFollowsANetworkChangeWithoutDeletingTheDefault(t *testing.T) {
	m, fake := newTestManager(t)
	networkExtensionVPN(fake, tun5)
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	m.SetVPNState(netip.Addr{}, tun5)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatal(err)
	}

	// The user joins another Wi-Fi; the VPN re-asserts its default.
	fake.scopedLANGW = "10.0.0.1"
	fake.defaultGW, fake.defaultIface = "", tun5
	fake.callLog = nil

	if err := m.ReclaimDefaultRoute(); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if fake.defaultGW != "10.0.0.1" {
		t.Fatalf("default = %q, want the new LAN gateway 10.0.0.1", fake.defaultGW)
	}
	if hasCall(fake, toolRoute+" -n delete default") {
		t.Fatal("reclaim must never delete the default route")
	}
	if m.GetOriginalGateway() != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("original gateway = %s, want it refreshed", m.GetOriginalGateway())
	}
}

func TestReclaimFailureKeepsTheVPNDefault(t *testing.T) {
	m, fake := newTestManager(t)
	networkExtensionVPN(fake, tun5)
	if err := m.CaptureOriginalGateway(); err != nil {
		t.Fatal(err)
	}
	m.SetVPNState(netip.Addr{}, tun5)
	if err := m.ActivateInvertedSplitTunnel(); err != nil {
		t.Fatal(err)
	}
	fake.defaultGW, fake.defaultIface = "", tun5
	fake.failNextCall("change_default", fmt.Errorf("route: writev: Network is unreachable"))

	if err := m.ReclaimDefaultRoute(); err == nil {
		t.Fatal("expected the failed change to be reported")
	}
	if fake.defaultIface != tun5 {
		t.Fatal("a failed reclaim must leave the VPN default in place, not delete it")
	}
}

func TestRecoveryTreatsALegacyInvalidIPGatewayAsUnknown(t *testing.T) {
	m, fake := newTestManager(t)
	fake.defaultGW = "192.168.7.1"
	tx := &transaction{
		SchemaVersion: transactionSchemaVersion,
		GenerationID:  "crashed-gen",
		Phase:         phaseActive,
		Steps: []journalStep{
			{Kind: stepChangeDefault, Gateway: "192.168.7.1", PriorGateway: "invalid IP"},
		},
		CreatedAt: time.Now().UTC(),
	}
	if err := m.journal.save(tx); err != nil {
		t.Fatal(err)
	}

	if err := m.RecoverTransition(); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if degraded, reason := m.Degraded(); degraded {
		t.Fatalf("an older journal's unknown gateway must not degrade forever: %s", reason)
	}
}

func TestLocalGatewayPrefersTheInterfaceThatHeldTheDefault(t *testing.T) {
	fake := newFakeRunner()
	fake.defaultIface = tun5
	fake.routes = []RouteEntry{
		{Destination: "default", Gateway: "172.20.10.1", Flags: "UGScIg", Interface: "en7"},
		{Destination: "default", Gateway: "192.168.7.1", Flags: "UGScIg", Interface: "en0"},
	}

	gw, iface, err := getLocalGateway(context.Background(), fake, "en0")
	if err != nil || gw != netip.MustParseAddr("192.168.7.1") || iface != "en0" {
		t.Fatalf("getLocalGateway = %s %q %v, want 192.168.7.1 on en0", gw, iface, err)
	}
}

// Outline answers DNS on 169.254.113.53 inside its tunnel. The kernel had
// already cloned an ARP entry for that address on en0, so queries went to the
// LAN and every lookup on the Mac failed while RouteWise managed Outline.
func TestALinkLocalVPNDNSServerIsRoutedIntoTheTunnel(t *testing.T) {
	m, fake := newTestManager(t)
	fake.defaultGW = "192.168.7.1"
	fake.routes = []RouteEntry{{Destination: "169.254.113.53", Gateway: "link#6", Flags: "UHLSW", Interface: "en0"}}
	m.SetVPNState(netip.Addr{}, tun6)
	dns := netip.MustParseAddr("169.254.113.53")

	if err := m.AddRoute(dns, "VPN DNS", true); err != nil {
		t.Fatalf("route the VPN DNS server: %v", err)
	}
	if !hasCall(fake, toolRoute+" -n delete -host 169.254.113.53") {
		t.Error("the cloned ARP entry on en0 must be dropped first")
	}
	if !hasCall(fake, toolRoute+" -n add -host 169.254.113.53 -interface "+tun6) {
		t.Fatalf("expected a host route into utun6; calls: %v", fake.callLog)
	}
}

func TestOnlyAVPNDNSRouteMayBeLinkLocal(t *testing.T) {
	m, _ := newTestManager(t)
	m.SetVPNState(netip.Addr{}, tun6)

	if err := m.AddRoute(netip.MustParseAddr("169.254.10.10"), "api.example.com", false); err == nil {
		t.Fatal("a domain's link-local answer must still be refused")
	}
}
