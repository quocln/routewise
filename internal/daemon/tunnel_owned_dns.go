package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/route"
)

// A built-in profile's DNS server is routed into its utun as a /32 only while
// dns.use_vpn_dns is on and the tunnel is proven to work. macOS never points the
// system resolver at a profile's DNS, so with the setting off the route would
// only capture every other process's traffic to that address (1.1.1.1 in a
// WireGuard .conf, Cloudflare's resolver as the Outline default). Even with the
// setting on, a server is refused when routing it would redirect DNS the machine
// already uses:
//
//   - one of the system's configured resolvers (the scutil baseline captured
//     while no VPN was up, or a fresh read);
//   - one of the dns.servers RouteWise itself resolves through;
//   - the DNS server another connected profile routes, so two profiles that
//     share a default (two Outline keys both use 1.0.0.1) never send each
//     other's queries through the wrong server.
//
// The profile's names then resolve through dns.servers. Detected tunnels keep
// their own rule: their bound DNS servers are always routed.

// refusedByProfile starts the reason given when another connected profile
// already routes the server. Only such a refusal is worth deciding again when a
// profile disconnects: the others (a system resolver, a dns.servers entry) do
// not change with it.
const refusedByProfile = "it is already the DNS server of the connected profile "

// ensureOwnedDNS decides and routes an owned session's DNS servers once per
// (use_vpn_dns, routable) state. The decision is remembered, even when every
// server was refused, so a sync does not repeat it and its refusals are
// recorded once.
func (d *Daemon) ensureOwnedDNS(gen *generation, s *tunnelSession) {
	if !d.useVPNDNS.Load() || !s.routable() {
		return
	}
	d.dnsMu.Lock()
	settled := s.vpnDNSSettled
	d.dnsMu.Unlock()
	if settled {
		return
	}

	// Reading the system's resolvers runs scutil: do it before taking the lock.
	system := d.systemResolverSet(gen.ctx)

	var candidates []netip.Addr
	for _, server := range s.ownedDNS {
		if reason := d.ownedDNSStaticRefusal(server, system); reason != "" {
			d.refuseOwnedDNS(s, server, reason)
			continue
		}
		if reason := d.unsafeTunnelAddr(server); reason != "" {
			d.refuseOwnedDNS(s, server, reason)
			continue
		}
		candidates = append(candidates, server)
	}

	var routed []netip.Addr
	ran, _ := d.withSessionMutation(gen, s, func() error {
		if !d.useVPNDNS.Load() || !s.routable() {
			return nil
		}
		for _, server := range candidates {
			if other := d.otherProfileRouting(s, server); other != nil {
				d.refuseOwnedDNS(s, server, refusedByProfile+other.client.Name)
				continue
			}
			d.defaultVPN.yieldHostLocked(server)
			if err := s.manager.AddRoute(server, vpnDNSRouteLabel, true); err != nil {
				if errors.Is(err, route.ErrRouteOwnedElsewhere) {
					d.refuseOwnedDNS(s, server, "it is already routed through another tunnel")
				} else {
					d.logger.Warn("could not route the profile's DNS server", "server", server, "interface", s.iface, "error", err)
				}
				continue
			}
			routed = append(routed, server)
		}
		if len(routed) > 0 {
			s.resolver.SetPreferredServers(routed)
		}
		d.dnsMu.Lock()
		s.vpnDNS, s.vpnDNSBound, s.vpnDNSDeferred = routed, true, nil
		s.vpnDNSSettled = true
		d.dnsMu.Unlock()
		return nil
	})
	if ran && len(routed) > 0 {
		d.logger.Info("routing the profile's DNS servers through its tunnel",
			"interface", s.iface, "servers", routed, "use_vpn_dns", true)
	}
}

// systemResolverSet is every DNS server this Mac is configured to use: the
// baseline captured while no VPN was up, and a fresh read of the configuration.
func (d *Daemon) systemResolverSet(ctx context.Context) map[netip.Addr]bool {
	out := make(map[netip.Addr]bool)
	d.dnsMu.Lock()
	for a := range d.dnsBaseline {
		out[a] = true
	}
	d.dnsMu.Unlock()
	if d.hooks.systemNameservers != nil {
		if servers, err := d.hooks.systemNameservers(ctx); err == nil {
			for _, a := range servers {
				out[a] = true
			}
		} else {
			d.logger.Debug("could not read the DNS configuration to vet a profile's DNS server", "error", err)
		}
	}
	return out
}

// ownedDNSStaticRefusal explains why a profile DNS server must not be routed
// because RouteWise or the system already uses it, or returns "".
func (d *Daemon) ownedDNSStaticRefusal(server netip.Addr, system map[netip.Addr]bool) string {
	if system[server] {
		return "it is one of this Mac's configured DNS servers, so routing it would send every app's DNS through the VPN"
	}
	if slices.ContainsFunc(d.dnsServers, func(text string) bool {
		a, err := netip.ParseAddr(text)
		return err == nil && a == server
	}) {
		return "it is one of the dns.servers RouteWise resolves through"
	}
	return ""
}

// otherProfileRouting returns another registered owned session that routes
// server as its DNS, or nil. The caller must hold mutationMu.
func (d *Daemon) otherProfileRouting(s *tunnelSession, server netip.Addr) *tunnelSession {
	sessions := d.sessionList()
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	for _, other := range sessions {
		if other != s && other.owned && slices.Contains(other.vpnDNS, server) {
			return other
		}
	}
	return nil
}

// refuseOwnedDNS logs and records that a profile's DNS server was not routed,
// and that the profile's names resolve through dns.servers instead.
func (d *Daemon) refuseOwnedDNS(s *tunnelSession, server netip.Addr, reason string) {
	d.logger.Warn("not routing the profile's DNS server into its tunnel; its names resolve through dns.servers",
		"profile", s.client.Name, "server", server, "interface", s.iface, "reason", reason)
	d.recordActivity(activity.Event{
		Kind:      activity.KindRefused,
		Name:      vpnDNSRouteLabel,
		Addresses: []activity.Address{{IP: server.String(), Verdict: activity.Direct}},
		Interface: s.iface,
		Detail:    fmt.Sprintf("not routed: %s; names of %s resolve through dns.servers", reason, s.client.Name),
	})
	d.dnsMu.Lock()
	if s.refusedDNS == nil {
		s.refusedDNS = make(map[netip.Addr]string)
	}
	s.refusedDNS[server] = reason
	d.dnsMu.Unlock()
}

// clearOwnedDNSLocked removes an owned session's DNS routes and forgets the
// decision, so the next sync decides again under the current setting. The caller
// must hold mutationMu.
func (d *Daemon) clearOwnedDNSLocked(s *tunnelSession) {
	d.dnsMu.Lock()
	old := s.vpnDNS
	s.vpnDNS, s.vpnDNSBound, s.vpnDNSDeferred = nil, false, nil
	s.vpnDNSSettled = false
	s.refusedDNS = nil
	d.dnsMu.Unlock()
	for _, server := range old {
		if err := s.manager.RemoveProtectedRoute(server, vpnDNSRouteLabel); err != nil {
			d.logger.Debug("could not remove a profile's DNS route", "server", server, "interface", s.iface, "error", err)
		}
	}
	s.resolver.SetPreferredServers(nil)
}

// dropOwnedDNS forgets one DNS server of an owned session whose route another
// tunnel took over. The caller must hold mutationMu and has already removed the
// route.
func (d *Daemon) dropOwnedDNS(s *tunnelSession, server netip.Addr, reason string) {
	d.dnsMu.Lock()
	s.vpnDNS = slices.DeleteFunc(slices.Clone(s.vpnDNS), func(a netip.Addr) bool { return a == server })
	remaining := slices.Clone(s.vpnDNS)
	d.dnsMu.Unlock()
	s.resolver.SetPreferredServers(remaining)
	d.refuseOwnedDNS(s, server, reason)
}

// retryRefusedOwnedDNS lets every owned session that was refused a DNS server
// decide again, after a tunnel that may have held it is gone.
func (d *Daemon) retryRefusedOwnedDNS(gen *generation) {
	retry := false
	d.mutationMu.Lock()
	for _, s := range d.sessionList() {
		d.dnsMu.Lock()
		refused := false
		if s.owned {
			for _, reason := range s.refusedDNS {
				refused = refused || strings.HasPrefix(reason, refusedByProfile)
			}
		}
		if refused {
			s.vpnDNSSettled = false
			s.refusedDNS = nil
		}
		d.dnsMu.Unlock()
		retry = retry || refused
	}
	d.mutationMu.Unlock()
	if retry {
		d.TriggerSync()
	}
}
