package monitor

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestNewVPNMonitor(t *testing.T) {
	t.Run("default interval", func(t *testing.T) {
		m := NewVPNMonitor(0)
		if m.pollInterval != time.Second {
			t.Errorf("expected 1s default, got %v", m.pollInterval)
		}
	})

	t.Run("custom interval", func(t *testing.T) {
		m := NewVPNMonitor(5 * time.Second)
		if m.pollInterval != 5*time.Second {
			t.Errorf("expected 5s, got %v", m.pollInterval)
		}
	})
}

func TestVPNStateString(t *testing.T) {
	tests := []struct {
		state VPNState
		want  string
	}{
		{VPNDisconnected, "disconnected"},
		{VPNConnected, "connected"},
		{VPNState(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("VPNState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestVPNEvent(t *testing.T) {
	t.Run("connect event", func(t *testing.T) {
		e := VPNEvent{State: VPNConnected}
		if !e.IsConnect() {
			t.Error("expected IsConnect() to be true")
		}
		if e.IsDisconnect() {
			t.Error("expected IsDisconnect() to be false")
		}
	})

	t.Run("disconnect event", func(t *testing.T) {
		e := VPNEvent{State: VPNDisconnected}
		if e.IsConnect() {
			t.Error("expected IsConnect() to be false")
		}
		if !e.IsDisconnect() {
			t.Error("expected IsDisconnect() to be true")
		}
	})
}

func TestVPNMonitorInitialState(t *testing.T) {
	m := NewVPNMonitor(time.Second)
	defer m.Stop()

	if m.IsConnected() {
		t.Log("VPN appears to be connected (this may be correct if you have VPN active)")
	} else {
		t.Log("VPN is disconnected")
	}
}

func TestVPNMonitorStop(t *testing.T) {
	m := NewVPNMonitor(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		m.Start(ctx)
		close(done)
	}()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	// Stop should cause Start to return
	m.Stop()

	select {
	case <-done:
		// Good, Start returned
	case <-time.After(time.Second):
		t.Error("Start did not return after Stop")
	}

	// Stop should be idempotent
	m.Stop() // Should not panic
}

func TestVPNMonitorContextCancellation(t *testing.T) {
	m := NewVPNMonitor(100 * time.Millisecond)
	defer m.Stop()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		m.Start(ctx)
		close(done)
	}()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	// Cancel should cause Start to return
	cancel()

	select {
	case <-done:
		// Good
	case <-time.After(time.Second):
		t.Error("Start did not return after context cancel")
	}
}

func TestFindUTunInterface(t *testing.T) {
	m := NewVPNMonitor(time.Second)
	defer m.Stop()

	found := m.findUTunInterfaces(nil)

	if len(found) > 0 {
		t.Logf("Found VPN interfaces: %v", found)
	} else {
		t.Log("No VPN interface found (expected if no full-tunnel VPN is connected)")
	}
}

// loadFixture reads a redacted netstat -rn capture committed under testdata.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	return data
}

type wantTunnel struct {
	iface   string
	gateway string
}

func TestFindVPNFromRoutes(t *testing.T) {
	tests := []struct {
		name    string
		routes  string
		fixture string
		// want lists every expected tunnel as interface -> gateway ("" when
		// the routes point at the interface), in interface-name order.
		want []wantTunnel
	}{
		{
			name: "routed utun without the paired catch-all routes",
			routes: `Destination        Gateway            Flags        Netif
default            link#36            UCSIg        utun10
100.64.0.10/32     link#36            UCS          utun10
100.64.0.11        100.64.0.11        UH           utun10
`,
		},
		{
			name: "aws full tunnel",
			routes: `Destination        Gateway            Flags        Netif
0/1                172.31.20.129      UGSc         utun11
128.0/1            172.31.20.129      UGSc         utun11
`,

			want: []wantTunnel{{"utun11", "172.31.20.129"}},
		},
		{
			name: "openvpn redirect-gateway def1",
			routes: `Destination        Gateway            Flags        Netif
0/1                10.8.0.1           UGSc         utun4
default            192.168.7.1        UGScg        en0
128.0/1            10.8.0.1           UGSc         utun4
`,

			want: []wantTunnel{{"utun4", "10.8.0.1"}},
		},
		{
			name: "wg-quick routes the halves at the interface",
			routes: `Destination        Gateway            Flags        Netif
0/1                utun3              USc          utun3
default            192.168.7.1        UGScg        en0
128.0/1            utun3              USc          utun3
`,

			want: []wantTunnel{{"utun3", ""}},
		},
		{
			name: "interface halves shown as link references",
			routes: `Destination        Gateway            Flags        Netif
0/1                link#22            UCS          utun3
128.0/1            link#22            UCS          utun3
`,

			want: []wantTunnel{{"utun3", ""}},
		},
		{
			name: "networkextension client owns the global default",
			routes: `Destination        Gateway            Flags        Netif
default            link#22            UCSg         utun5
default            192.168.7.1        UGScIg       en0
10.64.0.1          link#22            UHWIi        utun5
`,

			want: []wantTunnel{{"utun5", ""}},
		},
		{
			name: "openvpn redirect-gateway without def1 replaces the default",
			routes: `Destination        Gateway            Flags        Netif
default            10.8.0.1           UGSc         utun6
default            192.168.7.1        UGScIg       en0
`,

			want: []wantTunnel{{"utun6", "10.8.0.1"}},
		},
		{
			name: "a /1 pair and another tunnel's default are both reported",
			routes: `Destination        Gateway            Flags        Netif
default            link#22            UCSg         utun2
0/1                10.8.0.1           UGSc         utun9
128.0/1            10.8.0.1           UGSc         utun9
`,

			want: []wantTunnel{{"utun2", ""}, {"utun9", "10.8.0.1"}},
		},
		{
			name: "a default on a non-tunnel interface is the LAN",
			routes: `Destination        Gateway            Flags        Netif
default            192.168.7.1        UGScg        en0
`,
		},
		{
			name: "aws next to another routed utun",
			routes: `Destination        Gateway            Flags        Netif
default            link#36            UCSIg        utun10
100.64.0.10/32     link#36            UCS          utun10
0.0.0.0/1          172.31.20.129      UGSc         utun11
128.0.0.0/1        172.31.20.129      UGSc         utun11
`,

			want: []wantTunnel{{"utun11", "172.31.20.129"}},
		},
		{
			name: "incomplete aws signature",
			routes: `Destination        Gateway            Flags        Netif
0/1                172.31.20.129      UGSc         utun11
`,
		},
		{
			name: "halves on different interfaces",
			routes: `Destination        Gateway            Flags        Netif
0/1                172.31.20.129      UGSc         utun11
128.0/1            172.31.20.161      UGSc         utun12
`,
		},
		{
			name: "different gateways",
			routes: `Destination        Gateway            Flags        Netif
0/1                172.31.20.129      UGSc         utun11
128.0/1            172.31.20.130      UGSc         utun11
`,
		},
		{
			name: "interface-scoped pair is not AWS",
			routes: `Destination        Gateway            Flags        Netif
0/1                100.101.102.9      UGSIc        utun8
128.0/1            100.101.102.9      UGSIc        utun8
`,
		},
		{
			name: "aws picked over an interface-scoped pair",
			routes: `Destination        Gateway            Flags        Netif
0/1                100.101.102.9      UGSIc        utun2
128.0/1            100.101.102.9      UGSIc        utun2
0/1                172.31.20.129      UGSc         utun11
128.0/1            172.31.20.129      UGSc         utun11
`,

			want: []wantTunnel{{"utun11", "172.31.20.129"}},
		},
		{
			name: "two matching tunnels are both reported in interface-name order",
			routes: `Destination        Gateway            Flags        Netif
0/1                172.31.20.129      UGSc         utun7
128.0/1            172.31.20.129      UGSc         utun7
0/1                10.8.0.1           UGSc         utun5
128.0/1            10.8.0.1           UGSc         utun5
`,

			want: []wantTunnel{{"utun5", "10.8.0.1"}, {"utun7", "172.31.20.129"}},
		},
		{
			name:    "AWS using CGNAT gateway remains discoverable",
			fixture: "aws_cgnat.txt",

			want: []wantTunnel{{"utun9", "100.65.0.5"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := []byte(tt.routes)
			if tt.fixture != "" {
				routes = loadFixture(t, tt.fixture)
			}

			var got []wantTunnel
			for _, match := range findVPNFromRoutes(parseNetstatRoutes(routes)) {
				gw := ""
				if match.gateway.IsValid() {
					gw = match.gateway.String()
				}
				got = append(got, wantTunnel{match.iface, gw})
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("findVPNFromRoutes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUTunInterfaces(t *testing.T) {
	interfaces := GetUTunInterfaces()
	t.Logf("UTun interfaces: %v", interfaces)
	// This is informational, not assertive
}

func TestVPNMonitorEvents(t *testing.T) {
	m := NewVPNMonitor(100 * time.Millisecond)
	defer m.Stop()

	events := m.Events()
	if events == nil {
		t.Fatal("Events channel should not be nil")
	}
}

// newTestMonitor builds a VPNMonitor with every real I/O probe replaced so
// tests never shell out to netstat.
func newTestMonitor(t *testing.T, routes []byte) *VPNMonitor {
	t.Helper()
	m := NewVPNMonitor(time.Second)
	t.Cleanup(m.Stop)

	entries := parseNetstatRoutes(routes)
	m.routeTable = func() ([]routeEntry, error) { return entries, nil }
	m.interfaceUp = func(string) bool { return true }
	return m
}

func TestVPNMonitorAWSCGNATDiscoverable(t *testing.T) {
	routes := loadFixture(t, "aws_cgnat.txt")
	m := newTestMonitor(t, routes)
	m.checkState()

	if !m.IsConnected() {
		t.Fatal("expected the CGNAT-addressed AWS interface to be discoverable")
	}
	if got := m.CurrentInterface(); got != "utun9" {
		t.Fatalf("CurrentInterface() = %q, want utun9", got)
	}
}

func TestVPNMonitorStaleDiagnosticStateAfterRestart(t *testing.T) {
	first := newTestMonitor(t, loadFixture(t, "aws_cgnat.txt"))
	first.checkState()
	if !first.IsConnected() {
		t.Fatal("expected the first generation to detect AWS")
	}

	// A helper restart produces a brand new VPNMonitor with no memory of the
	// prior generation's interface, gateway, or connected state; nothing here
	// is loaded from disk.
	restarted := NewVPNMonitor(time.Second)
	defer restarted.Stop()

	if restarted.IsConnected() {
		t.Fatal("a freshly constructed monitor must not start connected")
	}
	if got := restarted.CurrentInterface(); got != "" {
		t.Fatalf("a freshly constructed monitor must not remember an interface, got %q", got)
	}
	if restarted.CurrentGateway().IsValid() {
		t.Fatal("a freshly constructed monitor must not remember a gateway")
	}
}

func TestVPNMonitorInterfaceNumberReuse(t *testing.T) {
	// Generation 1: AWS owns utun8.
	awsRoutes := []byte(`Destination        Gateway            Flags        Netif
0/1                172.31.40.5        UGSc         utun8
128.0/1            172.31.40.5        UGSc         utun8
`)
	gen1 := newTestMonitor(t, awsRoutes)
	gen1.checkState()
	if got := gen1.CurrentInterface(); got != "utun8" {
		t.Fatalf("generation 1 CurrentInterface() = %q, want utun8", got)
	}

	// Generation 2 (post-restart, fresh instance): utun8 has been reassigned
	// to another tunnel whose catch-all routes are interface-scoped. Fresh
	// discovery must reject it even though the number matches what used to be
	// AWS.
	tsRoutes := []byte(`Destination        Gateway            Flags        Netif
0/1                100.101.102.9      UGSIc        utun8
128.0/1            100.101.102.9      UGSIc        utun8
100.101.102.9      100.101.102.9      UH           utun8
`)
	gen2 := newTestMonitor(t, tsRoutes)
	gen2.checkState()

	if gen2.IsConnected() {
		t.Fatalf("expected the reused utun8 (now another tunnel) to be rejected, got interface %q", gen2.CurrentInterface())
	}
}

func TestVPNMonitorInterfaceUpInjectionOnStickyPath(t *testing.T) {
	// Once connected, checkState must consult the injected interfaceUp probe
	// for the sticky interface rather than shelling out, and must disconnect
	// cleanly (clearing currentIface/currentGW) when it reports down.
	m := newTestMonitor(t, loadFixture(t, "aws_cgnat.txt"))
	m.checkState()
	if !m.IsConnected() {
		t.Fatal("expected AWS to be detected")
	}

	m.interfaceUp = func(string) bool { return false }
	m.checkState()

	if m.IsConnected() {
		t.Fatal("expected disconnect once the sticky interface reports down")
	}
	if got := m.CurrentInterface(); got != "" {
		t.Fatalf("CurrentInterface() after disconnect = %q, want empty", got)
	}
	if m.CurrentGateway().IsValid() {
		t.Fatal("CurrentGateway() after disconnect should be invalid")
	}
}

func TestVPNMonitorRouteTableUnavailable(t *testing.T) {
	m := NewVPNMonitor(time.Second)
	defer m.Stop()

	m.routeTable = func() ([]routeEntry, error) { return nil, errors.New("netstat unavailable") }
	m.interfaceUp = func(string) bool { return true }

	m.checkState()

	if m.IsConnected() {
		t.Fatal("expected no AWS connection when the route table is unavailable")
	}
}

func TestVPNMonitorLeavesATunnelItMayNotManage(t *testing.T) {
	routes := loadFixture(t, "aws_cgnat.txt")
	m := newTestMonitor(t, routes)
	allowed := false
	m.SetAdmission(func(string) bool { return allowed })

	m.checkState()
	if m.IsConnected() {
		t.Fatal("a tunnel from a client that is not allowed must not count as connected")
	}

	allowed = true
	m.checkState()
	if !m.IsConnected() {
		t.Fatal("once allowed, the tunnel must be picked up")
	}

	// Revoking while connected hands the tunnel back.
	allowed = false
	m.checkState()
	if m.IsConnected() {
		t.Fatal("revoking the client must end management of its tunnel")
	}
}

// drainEvents returns the events queued so far without blocking.
func drainEvents(m *VPNMonitor) []VPNEvent {
	var out []VPNEvent
	for {
		select {
		case e := <-m.events:
			out = append(out, e)
		default:
			return out
		}
	}
}

const twoTunnelRoutes = `Destination        Gateway            Flags        Netif
0/1                172.31.20.129      UGSc         utun9
128.0/1            172.31.20.129      UGSc         utun9
default            link#22            UCSg         utun5
`

func TestVPNMonitorTracksTwoTunnelsAndKeepsTheOtherAfterOneLeaves(t *testing.T) {
	m := newTestMonitor(t, []byte(twoTunnelRoutes))
	up := map[string]bool{"utun5": true, "utun9": true}
	m.interfaceUp = func(iface string) bool { return up[iface] }

	m.checkState()

	want := []Tunnel{
		{Interface: "utun5"},
		{Interface: "utun9", Gateway: netip.MustParseAddr("172.31.20.129")},
	}
	if got := m.Tunnels(); !slices.Equal(got, want) {
		t.Fatalf("Tunnels() = %v, want %v", got, want)
	}
	events := drainEvents(m)
	if len(events) != 2 || events[0].Interface != "utun5" || events[1].Interface != "utun9" ||
		!events[0].IsConnect() || !events[1].IsConnect() {
		t.Fatalf("events = %+v, want a connect per tunnel in interface order", events)
	}
	if got := m.CurrentInterface(); got != "utun5" {
		t.Fatalf("CurrentInterface() = %q, want the first tunnel", got)
	}

	// RouteWise removes each managed tunnel's catch-alls, so the route table
	// no longer shows either. Both must stay tracked while their interfaces
	// are up, and a repeated check must not report them again.
	m.routeTable = func() ([]routeEntry, error) { return nil, nil }
	m.checkState()
	if got := m.Tunnels(); !slices.Equal(got, want) {
		t.Fatalf("Tunnels() after the catch-alls were removed = %v, want both still tracked", got)
	}
	if events := drainEvents(m); len(events) != 0 {
		t.Fatalf("events = %+v, want none for an unchanged state", events)
	}

	// One tunnel goes away; the other keeps being tracked.
	up["utun9"] = false
	m.checkState()
	events = drainEvents(m)
	if len(events) != 1 || !events[0].IsDisconnect() || events[0].Interface != "utun9" {
		t.Fatalf("events = %+v, want only utun9 disconnecting", events)
	}
	if !m.IsConnected() || m.CurrentInterface() != "utun5" {
		t.Fatalf("connected=%v interface=%q, want utun5 still connected", m.IsConnected(), m.CurrentInterface())
	}
	if got := m.Tunnels(); len(got) != 1 || got[0].Interface != "utun5" {
		t.Fatalf("Tunnels() = %v, want only utun5", got)
	}
}

func TestVPNMonitorAdmitsTunnelsIndependently(t *testing.T) {
	m := newTestMonitor(t, []byte(twoTunnelRoutes))
	m.SetAdmission(func(iface string) bool { return iface == "utun9" })

	m.checkState()
	if got := m.Tunnels(); len(got) != 1 || got[0].Interface != "utun9" {
		t.Fatalf("Tunnels() = %v, want only the admitted utun9", got)
	}
}

func TestVPNMonitorRetriesAnEventThatDidNotFitTheQueue(t *testing.T) {
	m := newTestMonitor(t, []byte(twoTunnelRoutes))
	for len(m.events) < cap(m.events) {
		m.events <- VPNEvent{}
	}

	m.checkState()
	if m.IsConnected() {
		t.Fatal("a tunnel whose connect event was dropped must not be recorded as connected")
	}

	drainEvents(m)
	m.checkState()
	if got := m.Tunnels(); len(got) != 2 {
		t.Fatalf("Tunnels() = %v, want both tunnels once the queue has room", got)
	}
}
