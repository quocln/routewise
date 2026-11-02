package daemon

import (
	"fmt"
	"slices"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/resolverfiles"
	"github.com/quocln/routewise/internal/route"
)

// vpnDNSServersOf lists s's VPN DNS servers as strings.
func (d *Daemon) vpnDNSServersOf(s *tunnelSession) []string {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	out := make([]string, 0, len(s.vpnDNS))
	for _, server := range s.vpnDNS {
		out = append(out, server.String())
	}
	return out
}

// DNSStatus reports wildcard routing and VPN DNS state for status.get. The VPN
// DNS servers are those of every connected tunnel, highest priority first.
func (d *Daemon) DNSStatus() api.DNSStatus {
	sessions := d.sessionList()
	var servers []string
	for _, s := range sessions {
		for _, server := range d.vpnDNSServersOf(s) {
			if !slices.Contains(servers, server) {
				servers = append(servers, server)
			}
		}
	}
	wildcards := d.hasWildcardPatterns()
	cfg, _ := d.store.Snapshot()

	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()

	status := api.DNSStatus{
		DomainCount:     cfg.PatternCount(),
		WildcardDomains: d.resolverFiles.Active(),
		UseVPNDNS:       d.useVPNDNS.Load(),
		VPNDNSServers:   servers,
	}
	if d.dnsWatcher != nil {
		status.CaptureDropped = d.dnsWatcher.Dropped()
	}
	switch {
	case d.forwarderErr != "" && wildcards:
		status.WildcardError = d.forwarderErr
	case d.resolverFileErr != "":
		status.WildcardError = d.resolverFileErr
	case len(d.wildcardSkipped) > 0:
		status.WildcardError = fmt.Sprintf(
			"not routing wildcards under %v: a resolver file RouteWise does not own already exists in %s",
			d.wildcardSkipped, resolverfiles.DefaultDir)
	}
	return status
}

// GetStatus returns the current daemon status. VPNInterface and VPNGateway
// describe the highest-priority connected tunnel; RouteCount is the total
// across every tunnel.
func (d *Daemon) GetStatus() Status {
	d.mu.RLock()
	running := d.isRunning
	gen := d.current
	d.mu.RUnlock()

	status := Status{Running: running, RouteCount: d.GetRouteCount()}
	if gen == nil {
		return status
	}
	status.VPNConnected = gen.monitor.IsConnected() || d.sessions.has()
	if sessions := d.sessionList(); len(sessions) > 0 {
		status.VPNInterface, status.VPNGateway = sessions[0].iface, sessions[0].gateway
	} else {
		status.VPNInterface = gen.monitor.CurrentInterface()
		status.VPNGateway = gen.monitor.CurrentGateway()
	}
	return status
}

// GetVPNConnected reports whether any tunnel RouteWise manages is up.
func (d *Daemon) GetVPNConnected() bool {
	gen := d.currentGeneration()
	if gen == nil {
		return false
	}
	return gen.monitor.IsConnected() || d.sessions.has()
}

// GetVPNInterface returns the interface of the highest-priority connected
// tunnel.
func (d *Daemon) GetVPNInterface() string {
	gen := d.currentGeneration()
	if gen == nil {
		return ""
	}
	if sessions := d.sessionList(); len(sessions) > 0 {
		return sessions[0].iface
	}
	return gen.monitor.CurrentInterface()
}

// GetRouteCount returns the number of active routes across every tunnel,
// including routes a retired manager could not remove: they are still in the
// kernel table.
func (d *Daemon) GetRouteCount() int {
	n := 0
	for _, s := range d.sessionList() {
		n += s.manager.GetRouteCount()
	}
	for _, m := range d.sessions.retiredManagers() {
		n += m.GetRouteCount()
	}
	return n
}

// Tunnels lists every connected, managed tunnel, highest priority first.
func (d *Daemon) Tunnels() []api.TunnelStatus {
	sessions := d.sessionList()
	out := make([]api.TunnelStatus, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, api.TunnelStatus{
			Interface:     s.iface,
			Client:        api.VPNClient{ID: s.client.ID, Name: s.client.Name},
			RouteCount:    s.manager.GetRouteCount(),
			VPNDNSServers: d.vpnDNSServersOf(s),
			ProfileID:     s.profileID,
		})
	}
	return out
}

// GetActiveRoutes returns the active routes of every tunnel as API types,
// highest-priority tunnel first, then the routes retired managers could not
// remove.
func (d *Daemon) GetActiveRoutes() []api.RouteEntry {
	pol := d.store.Policy()
	result := make([]api.RouteEntry, 0)
	for _, s := range d.sessionList() {
		via := routeVia{iface: s.iface, vpn: s.client.Name, clientID: s.client.ID}
		result = appendRouteEntries(result, pol, via, s.manager)
	}
	for _, m := range d.sessions.retiredManagers() {
		result = appendRouteEntries(result, pol, routeVia{iface: m.GetVPNInterface()}, m)
	}
	return result
}

// routeVia is the tunnel a manager's routes go through. A retired manager's
// tunnel has no client any more.
type routeVia struct {
	iface    string
	vpn      string
	clientID string
}

// appendRouteEntries lists m's routes as routes through via: the host routes
// sorted by address, then the network routes sorted by prefix, whose ip field
// holds the CIDR. Each names the list entry it was added for.
func appendRouteEntries(result []api.RouteEntry, pol *routingPolicy, via routeVia, m *route.Manager) []api.RouteEntry {
	infos := make([]route.RouteInfo, 0)
	for _, info := range m.GetActiveRoutes() {
		infos = append(infos, info)
	}
	slices.SortFunc(infos, func(a, b route.RouteInfo) int { return a.Destination.Compare(b.Destination) })
	for _, info := range infos {
		gw := ""
		if info.Gateway.IsValid() {
			gw = info.Gateway.String()
		}
		entry := api.RouteEntry{
			IP:        info.Destination.String(),
			Gateway:   gw,
			Interface: via.iface,
			Domain:    info.SourceDomain,
			AddedAt:   info.AddedAt.Format(time.RFC3339),
			Protected: info.IsProtected,
			VPN:       via.vpn,
			ClientID:  via.clientID,
		}
		if !info.IsProtected {
			if match, ok := pol.matchingEntry(info.SourceDomain, info.Destination); ok {
				entry.List, entry.Rule = &match.list, match.rule
			}
		}
		result = append(result, entry)
	}

	nets := make([]route.PrefixRouteInfo, 0)
	for _, info := range m.GetNetRoutes() {
		nets = append(nets, info)
	}
	slices.SortFunc(nets, func(a, b route.PrefixRouteInfo) int {
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c
		}
		return a.Prefix.Bits() - b.Prefix.Bits()
	})
	for _, info := range nets {
		gw := ""
		if info.Gateway.IsValid() {
			gw = info.Gateway.String()
		}
		entry := api.RouteEntry{
			IP:        info.Prefix.String(),
			Gateway:   gw,
			Interface: via.iface,
			Domain:    info.SourceEntry,
			AddedAt:   info.AddedAt.Format(time.RFC3339),
			VPN:       via.vpn,
			ClientID:  via.clientID,
		}
		if list, ok := pol.listHolding(info.SourceEntry); ok {
			entry.List, entry.Rule = &list, info.SourceEntry
		}
		result = append(result, entry)
	}
	return result
}
