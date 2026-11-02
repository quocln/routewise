package monitor

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quocln/routewise/internal/ifacename"
)

// VPNMonitor polls routes and interface state to detect VPN tunnels coming and going.
type VPNMonitor struct {
	pollInterval time.Duration
	events       chan VPNEvent
	stopCh       chan struct{}

	// mu guards tunnels, the admitted full-tunnel interfaces being tracked and
	// each one's gateway (invalid when its routes point at the interface).
	mu      sync.RWMutex
	tunnels map[string]netip.Addr

	// routeTable and interfaceUp are injectable so tests exercise the real
	// classification logic without reading the system's routes. NewVPNMonitor
	// wires the production defaults.
	routeTable  func() ([]routeEntry, error)
	interfaceUp func(string) bool

	// admit decides whether a detected tunnel may be managed. A tunnel it
	// turns down is treated as no VPN at all. nil admits every tunnel.
	admit func(iface string) bool
	// recheck asks the loop to re-evaluate at once, for example after the
	// user allowed or revoked a VPN client.
	recheck chan struct{}
}

// NewVPNMonitor creates a new VPN monitor with the specified poll interval.
func NewVPNMonitor(pollInterval time.Duration) *VPNMonitor {
	if pollInterval <= 0 {
		pollInterval = time.Second
	}

	m := &VPNMonitor{
		pollInterval: pollInterval,
		events:       make(chan VPNEvent, 10),
		stopCh:       make(chan struct{}),
		tunnels:      make(map[string]netip.Addr),
		routeTable:   fetchRouteTable,
		interfaceUp:  isInterfaceUp,
		recheck:      make(chan struct{}, 1),
	}

	return m
}

// SetAdmission installs the check that decides whether a detected tunnel may
// be managed. Call it before Start.
func (m *VPNMonitor) SetAdmission(admit func(iface string) bool) {
	m.admit = admit
}

// Recheck re-evaluates the VPN state as soon as possible.
func (m *VPNMonitor) Recheck() {
	select {
	case m.recheck <- struct{}{}:
	default:
	}
}

func (m *VPNMonitor) admitted(iface string) bool {
	return m.admit == nil || m.admit(iface)
}

// Events returns the channel for receiving VPN state change events.
func (m *VPNMonitor) Events() <-chan VPNEvent {
	return m.events
}

// Start begins monitoring VPN interface state.
// Blocks until context is cancelled or Stop() is called.
func (m *VPNMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	// Check initial state
	m.checkState()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-m.recheck:
			m.checkState()
		case <-ticker.C:
			// Periodic check
			m.checkState()
		}
	}
}

// Stop stops the VPN monitor.
func (m *VPNMonitor) Stop() {
	select {
	case <-m.stopCh:
		// Already closed
	default:
		close(m.stopCh)
	}
}

// Tunnel is one admitted full-tunnel interface and its next hop. Gateway is
// invalid when the tunnel's routes point straight at the interface.
type Tunnel struct {
	Interface string
	Gateway   netip.Addr
}

// Tunnels returns every tracked tunnel, sorted by interface name.
func (m *VPNMonitor) Tunnels() []Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return sortedTunnels(m.tunnels)
}

func sortedTunnels(tunnels map[string]netip.Addr) []Tunnel {
	out := make([]Tunnel, 0, len(tunnels))
	for iface, gw := range tunnels {
		out = append(out, Tunnel{Interface: iface, Gateway: gw})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Interface < out[j].Interface })
	return out
}

// IsConnected returns whether any tunnel is currently connected.
func (m *VPNMonitor) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tunnels) > 0
}

// CurrentInterface returns the first tunnel's interface name (the lowest
// name), or "" when none is connected.
func (m *VPNMonitor) CurrentInterface() string {
	if t := m.Tunnels(); len(t) > 0 {
		return t[0].Interface
	}
	return ""
}

// CurrentGateway returns the first tunnel's gateway.
func (m *VPNMonitor) CurrentGateway() netip.Addr {
	if t := m.Tunnels(); len(t) > 0 {
		return t[0].Gateway
	}
	return netip.Addr{}
}

// checkState reconciles the tracked tunnels with the live system and emits
// one event per tunnel that appeared or went away.
//
// A tracked tunnel stays tracked while its interface is up and admitted: in
// inverted mode RouteWise removes the tunnel's catch-all routes used for
// initial discovery, so the route table no longer shows it. This is a
// generation-local check only: it never re-derives trust from a persisted or
// remembered name after a restart, because a restarted process starts with no
// tracked tunnels and always takes the fresh-discovery path below.
//
// A state change is committed only when its event was queued, so a full event
// channel delays the change to the next check instead of losing it.
func (m *VPNMonitor) checkState() {
	m.mu.RLock()
	tracked := make(map[string]netip.Addr, len(m.tunnels))
	for iface, gw := range m.tunnels {
		tracked[iface] = gw
	}
	m.mu.RUnlock()

	alive := make(map[string]netip.Addr, len(tracked))
	for iface, gw := range tracked {
		if m.interfaceUp(iface) && m.admitted(iface) {
			alive[iface] = gw
		}
	}
	found := m.findUTunInterfaces(alive)

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, t := range sortedTunnels(tracked) {
		if _, ok := alive[t.Interface]; ok {
			continue
		}
		slog.Info("VPN disconnected", "interface", t.Interface)
		if m.emit(VPNEvent{State: VPNDisconnected, Interface: t.Interface, Timestamp: time.Now()}) {
			delete(m.tunnels, t.Interface)
		} else {
			slog.Warn("VPN event channel full, dropping disconnect event")
		}
	}
	for _, t := range found {
		slog.Info("VPN detected", "interface", t.Interface, "gateway", t.Gateway)
		if m.emit(VPNEvent{State: VPNConnected, Interface: t.Interface, Gateway: t.Gateway, Timestamp: time.Now()}) {
			m.tunnels[t.Interface] = t.Gateway
		} else {
			slog.Warn("VPN event channel full, dropping connect event")
		}
	}
}

// emit queues an event without blocking and reports whether it was queued.
func (m *VPNMonitor) emit(e VPNEvent) bool {
	select {
	case m.events <- e:
		return true
	default:
		return false
	}
}

// findUTunInterfaces finds every admitted full-tunnel VPN interface that is
// not already tracked, sorted by interface name. A routed tunnel interface
// alone is not enough, because other tunnels and macOS system services also
// use routed utun interfaces; only a tunnel that takes over all IPv4 traffic
// qualifies.
func (m *VPNMonitor) findUTunInterfaces(tracked map[string]netip.Addr) []Tunnel {
	entries, err := m.routeTable()
	if err != nil {
		return nil
	}

	var out []Tunnel
	for _, match := range findVPNFromRoutes(entries) {
		if _, ok := tracked[match.iface]; ok {
			continue
		}
		if !m.interfaceUp(match.iface) || !m.admitted(match.iface) {
			continue
		}
		out = append(out, Tunnel{Interface: match.iface, Gateway: match.gateway})
	}
	return out
}

// vpnMatch is a tunnel interface carrying a full IPv4 tunnel. gateway is the
// tunnel's next hop when the routes name one; it is invalid when the routes
// point straight at the interface (wg-quick, NetworkExtension clients), and
// routes are then added by interface instead.
type vpnMatch struct {
	iface   string
	gateway netip.Addr
}

type splitRouteSignature struct {
	lowerHalf bool
	upperHalf bool
	gateway   netip.Addr
	// scoped records whether either half was interface-scoped (macOS
	// RTF_IFSCOPE). A full tunnel's catch-all routes are global; a scoped pair
	// never overrides the default route and so belongs to some other tunnel
	// that RouteWise must leave alone.
	scoped bool
}

var (
	defaultPrefix = netip.MustParsePrefix("0.0.0.0/0")
	lowerHalf     = netip.MustParsePrefix("0.0.0.0/1")
	upperHalf     = netip.MustParsePrefix("128.0.0.0/1")
)

// findVPNFromRoutes identifies a full-tunnel VPN in a route table. Two route
// shapes qualify, both on a tunnel interface and neither interface-scoped:
//
//   - complementary 0.0.0.0/1 and 128.0.0.0/1 routes sharing one gateway, as
//     AWS Client VPN, OpenVPN (redirect-gateway def1), and wg-quick install;
//   - a global default route, as NetworkExtension clients such as the
//     WireGuard app and OpenVPN without def1 install. On macOS the LAN default
//     then survives only as an interface-scoped route.
//
// The gateway may be an IP (CGNAT included) or absent; absent means the route
// points at the interface. Every matching interface is returned, sorted by
// name so the order is stable. An interface carrying both shapes counts once,
// as a /1 pair.
func findVPNFromRoutes(entries []routeEntry) []vpnMatch {
	pairs := make(map[string]splitRouteSignature)
	defaults := make(map[string]netip.Addr)

	for _, e := range entries {
		// Cheap tests first: most rows are neither a tunnel's nor a catch-all.
		if !e.Tunnel || !detectorDest(e.Dest) || ifacename.Validate(e.Iface) != nil {
			continue
		}

		if e.Dest == defaultPrefix {
			if !e.Scoped {
				defaults[e.Iface] = e.Gateway
			}
			continue
		}

		isLower := e.Dest == lowerHalf
		isUpper := e.Dest == upperHalf
		if !isLower && !isUpper {
			continue
		}

		signature, seen := pairs[e.Iface]
		if seen && signature.gateway != e.Gateway {
			delete(pairs, e.Iface)
			continue
		}
		signature.gateway = e.Gateway
		signature.lowerHalf = signature.lowerHalf || isLower
		signature.upperHalf = signature.upperHalf || isUpper
		signature.scoped = signature.scoped || e.Scoped
		pairs[e.Iface] = signature
	}

	byIface := make(map[string]vpnMatch)
	for iface, gateway := range defaults {
		byIface[iface] = vpnMatch{iface: iface, gateway: gateway}
	}
	for iface, signature := range pairs {
		if !signature.lowerHalf || !signature.upperHalf || signature.scoped {
			continue
		}
		byIface[iface] = vpnMatch{iface: iface, gateway: signature.gateway}
	}
	matches := make([]vpnMatch, 0, len(byIface))
	for _, match := range byIface {
		matches = append(matches, match)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].iface < matches[j].iface })
	return matches
}

// GetUTunInterfaces returns all utun interfaces (for debugging).
func GetUTunInterfaces() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var utuns []string
	for _, iface := range ifaces {
		if ifacename.IsTunnel(iface.Name) {
			status := "down"
			if iface.Flags&net.FlagUp != 0 {
				status = "up"
			}
			addrs, _ := iface.Addrs()
			utuns = append(utuns, iface.Name+" ("+status+", "+strings.Join(addrStrings(addrs), ", ")+")")
		}
	}
	return utuns
}

func addrStrings(addrs []net.Addr) []string {
	var strs []string
	for _, a := range addrs {
		strs = append(strs, a.String())
	}
	if len(strs) == 0 {
		strs = append(strs, "no addrs")
	}
	return strs
}
