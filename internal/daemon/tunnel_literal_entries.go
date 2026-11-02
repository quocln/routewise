package daemon

import (
	"fmt"
	"net/netip"

	"github.com/quocln/routewise/internal/activity"
)

// IP and CIDR list entries are routed exactly as written: an IP as a /32 host
// route, a CIDR as a network route. They are never resolved or looked up. The
// sync treats them like resolved domains for ownership and priority (see
// applyPlansLocked), with one extra check: an entry that would cut this
// machine off from its own LAN is refused.
//
// The kernel uses the longest matching prefix. Entries that overlap are
// therefore not prevented: a domain's /32 inside another tunnel's CIDR leaves
// through the /32's tunnel, and nested CIDRs on different tunnels are both
// installed, the narrower one serving the addresses it covers.

// lanGuard is a snapshot of what an IP or CIDR entry must not capture: the
// original LAN gateways and the directly connected networks. Taking it once per
// sync keeps a list of hundreds of entries from reading the interfaces for each.
type lanGuard struct {
	gateways []netip.Addr
	prefixes []netip.Prefix
	// endpoints are the transport addresses of the running built-in tunnels,
	// by the name of their profile. An address or network that covers one is
	// refused whichever tunnel it was meant for.
	endpoints map[netip.Addr]string
}

// newLANGuard captures the LAN gateways and directly connected prefixes now.
// The caller should hold mutationMu when the answer must agree with the
// sessions it is applied to.
func (d *Daemon) newLANGuard() lanGuard {
	g := lanGuard{
		gateways: []netip.Addr{d.routeManager.GetOriginalGateway()},
		prefixes: d.hooks.localPrefixes(),

		endpoints: d.endpointOwners(),
	}
	for _, s := range d.sessionList() {
		g.gateways = append(g.gateways, s.manager.GetOriginalGateway())
	}
	return g
}

// unsafeAddr explains why a /32 to ip through a tunnel would cut this machine
// off from its own network, or returns "".
func (g lanGuard) unsafeAddr(ip netip.Addr) string {
	if reason := g.endpointReason(ip); reason != "" {
		return reason
	}
	for _, gw := range g.gateways {
		if gw.IsValid() && ip == gw {
			return "local gateway"
		}
	}
	for _, prefix := range g.prefixes {
		if prefix.Contains(ip) {
			return "on a directly connected network " + prefix.String()
		}
	}
	return ""
}

// unsafePrefix explains why a network route to p through a tunnel would cut
// this machine off from its own network, or returns "": it contains the LAN
// gateway or overlaps a directly connected network.
func (g lanGuard) unsafePrefix(p netip.Prefix) string {
	if reason := g.endpointInPrefix(p); reason != "" {
		return reason
	}
	for _, gw := range g.gateways {
		if gw.IsValid() && p.Contains(gw) {
			return "contains the local gateway " + gw.String()
		}
	}
	for _, prefix := range g.prefixes {
		if prefix.Overlaps(p) {
			return "overlaps the directly connected network " + prefix.String()
		}
	}
	return ""
}

// screenEntries returns the IP and CIDR entries of plan that are safe to route
// through the session. An unsafe one is refused: it is logged and recorded as
// a refused activity event, once until its reason changes. resolved holds the
// addresses the session's domains resolved to; any that is a built-in tunnel's
// transport address, or that a WireGuard tunnel's peers do not accept, is
// removed from it and refused the same way, so a domain that re-resolves onto
// such an address is caught too. The caller must hold mutationMu.
func (d *Daemon) screenEntries(s *tunnelSession, p *syncPlan, guard lanGuard, resolved map[netip.Addr]string) (ips []netip.Addr, prefixes []netip.Prefix) {
	refused := make(map[string]string)
	// A resolved address is refused under its own key, so it is recorded even
	// when a list entry with the same address was refused before.
	type resolvedRefusal struct{ name, ip string }
	resolvedRefusals := make(map[string]resolvedRefusal)
	for ip, domain := range resolved {
		reason := guard.endpointReason(ip)
		if reason == "" {
			reason = s.outsideAllowedReason(ip)
		}
		if reason != "" {
			key := domain + " -> " + ip.String()
			refused[key] = reason
			resolvedRefusals[key] = resolvedRefusal{name: domain, ip: ip.String()}
			delete(resolved, ip)
		}
	}
	for _, ip := range p.entryIPs {
		reason := guard.unsafeAddr(ip)
		if reason == "" {
			reason = s.outsideAllowedReason(ip)
		}
		if reason != "" {
			refused[ip.String()] = reason
			continue
		}
		ips = append(ips, ip)
	}
	for _, prefix := range p.entryNets {
		reason := guard.unsafePrefix(prefix)
		if reason == "" {
			reason = s.outsidePrefixReason(prefix)
		}
		if reason != "" {
			refused[prefix.String()] = reason
			continue
		}
		prefixes = append(prefixes, prefix)
	}

	d.dnsMu.Lock()
	previous := s.refusedEntries
	s.refusedEntries = refused
	d.dnsMu.Unlock()

	for entry, reason := range refused {
		if previous[entry] == reason {
			continue
		}
		d.logger.Warn("not routing list entry", "entry", entry, "interface", s.iface, "reason", reason)
		name, ip := entry, entry
		if r, ok := resolvedRefusals[entry]; ok {
			name, ip = r.name, r.ip
		}
		d.recordActivity(activity.Event{
			Kind:      activity.KindRefused,
			Name:      name,
			Addresses: []activity.Address{{IP: ip, Verdict: activity.Direct}},
			Interface: s.iface,
			Detail:    "not routed: " + reason,
		})
	}
	return ips, prefixes
}

// noteNetConflict records, once per prefix and winner, that a lower-priority
// tunnel was refused a network a higher-priority one already routes.
func (d *Daemon) noteNetConflict(loser, winner *tunnelSession, p netip.Prefix, entry string) {
	d.dnsMu.Lock()
	known := loser.netConflicts[p] == winner.iface
	loser.netConflicts[p] = winner.iface
	d.dnsMu.Unlock()
	if known {
		return
	}

	d.logger.Warn("network already routed through another VPN",
		"entry", entry, "prefix", p, "winner", winner.iface, "refused", loser.iface)
	d.recordActivity(activity.Event{
		Kind:      activity.KindRefused,
		Name:      entry,
		Addresses: []activity.Address{{IP: p.String(), Verdict: activity.ViaVPN}},
		Interface: winner.iface,
		Detail: fmt.Sprintf("already routed through %s; not routed through %s, which has lower priority",
			describeTunnel(winner), describeTunnel(loser)),
	})
}

// setNetConflicts replaces the networks s lost in the sync that just ran.
func (d *Daemon) setNetConflicts(s *tunnelSession, conflicts map[netip.Prefix]string) {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	s.netConflicts = conflicts
}
