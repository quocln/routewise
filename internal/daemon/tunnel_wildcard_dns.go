package daemon

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/resolverfiles"
	"github.com/quocln/routewise/internal/route"
)

// refreshResolverFilesLocked makes the resolver files match the wildcard
// suffixes of the tunnels connected right now. The caller must hold
// mutationMu.
func (d *Daemon) refreshResolverFilesLocked() {
	owners := wildcardOwners(assignPatterns(d.store.Policy(), d.sessionList()))
	d.applyResolverFilesLocked(append(owners, d.defaultVPN.exceptionSuffixes(owners)...))
}

// applyResolverFilesLocked makes the resolver files match the wildcard
// suffixes of the connected tunnels while the forwarder is listening, and
// removes them otherwise. With dns.use_vpn_dns on, a suffix waits until the
// DNS servers of the tunnel that owns it are known: a lookup answered by a
// public server before then would return, and macOS would cache, a negative
// answer for internal names. A suffix with no owner (one excepted from the default
// VPN) has no such servers to wait for. The caller must hold mutationMu.
func (d *Daemon) applyResolverFilesLocked(owners []wildcardOwner) {
	pending := ""
	if len(owners) > 0 && d.ensureForwarderLocked() {
		var ready []string
		for _, o := range owners {
			if o.owner != nil && d.useVPNDNS.Load() && !d.sessionDNSKnown(o.owner) {
				pending = "waiting for the VPN to publish its DNS servers (dns.use_vpn_dns is on)"
				continue
			}
			ready = append(ready, o.suffix)
		}
		if len(ready) > 0 {
			skipped, err := d.resolverFiles.Apply(ready)
			errText := pending
			if err != nil {
				d.logger.Warn("could not write resolver files", "error", err)
				errText = err.Error()
			}
			if len(skipped) > 0 {
				d.logger.Warn("not routing wildcards: resolver file already exists and is not RouteWise's",
					"domains", skipped, "dir", resolverfiles.DefaultDir)
			}
			d.setResolverFileState(skipped, errText)
			return
		}
	}

	if err := d.resolverFiles.RemoveAll(); err != nil {
		d.logger.Warn("could not remove resolver files", "error", err)
	}
	d.setResolverFileState(nil, pending)
}

// ensureForwarderLocked restarts the forwarder if it is not serving, for
// example because its port was taken when the daemon started. It reports
// whether the forwarder is serving. The caller must hold mutationMu.
func (d *Daemon) ensureForwarderLocked() bool {
	if d.forwarder.Running() {
		return true
	}
	err := d.forwarder.Start()
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	if err != nil {
		d.forwarderErr = fmt.Sprintf("DNS forwarder could not listen on %s: %v", d.forwarder.Addr(), err)
		return false
	}
	d.forwarderErr = ""
	return true
}

func (d *Daemon) setResolverFileState(skipped []string, errText string) {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	d.wildcardSkipped = skipped
	d.resolverFileErr = errText
}

// onWildcardAnswer routes the addresses a wildcard-matched lookup resolved to
// into the tunnel that owns the name. The forwarder calls it before replying,
// so the client's first connection to any of them already goes through the
// tunnel.
func (d *Daemon) onWildcardAnswer(name string, ips []netip.Addr, ttl time.Duration) {
	// Every answer names its addresses, routed or not.
	d.names.Add(name, ips, ttl)
	gen := d.currentGeneration()
	if gen == nil {
		return
	}
	s := d.ownerFor(name)
	if s == nil {
		d.routeExceptedAnswer(gen, name, ips, ttl)
		return
	}

	// The LAN is read once for the whole answer, not once per address.
	vet := d.newAnswerVetter(s, d.newLANGuard())
	var safe []netip.Addr
	for _, ip := range ips {
		if reason := vet.unsafeAddr(ip); reason != "" {
			d.logger.Warn("not routing wildcard answer", "domain", name, "ip", ip, "reason", reason)
			d.recordActivity(activity.Event{
				Kind:      activity.KindRefused,
				Name:      name,
				Addresses: []activity.Address{{IP: ip.String(), Verdict: activity.Direct}},
				Interface: s.iface,
				Detail:    reason,
			})
			continue
		}
		safe = append(safe, ip)
	}
	if len(safe) == 0 {
		return
	}

	// withSessionMutation checks the session under the lock: a disconnect
	// that ran first has already unregistered it, and nothing may repopulate
	// its state. Ownership is decided again under the lock too, because a list
	// edit, an allow or revoke, or a tunnel coming or going since the lookup
	// may have moved the name to another tunnel or sent it direct.
	_, err := d.withSessionMutation(gen, s, func() error {
		if d.ownerFor(name) != s {
			d.logger.Debug("wildcard answer no longer belongs to this tunnel", "domain", name, "interface", s.iface)
			return nil
		}
		var routable []netip.Addr
		for _, ip := range safe {
			if d.claimAddressLocked(s, ip, name) {
				routable = append(routable, ip)
			}
		}
		// Only addresses that were routed are remembered: an address another
		// tunnel or the kernel already holds is refused, and remembering it
		// would have every sync try, and fail, to add it again.
		var errs []error
		var added []netip.Addr
		// One read of the system's route table serves every address of the
		// answer, where a change otherwise reads it again.
		defer s.manager.BeginRouteBatch()()
		for _, ip := range routable {
			if err := s.manager.AddRoute(ip, name, false); err != nil {
				errs = append(errs, err)
				continue
			}
			added = append(added, ip)
		}
		for ip, domain := range d.rememberLearned(s, name, added, ttl) {
			errs = append(errs, s.manager.RemoveRouteIfSource(ip, domain))
		}
		return errors.Join(errs...)
	})
	if err != nil {
		d.logger.Warn("could not route wildcard answer", "domain", name, "interface", s.iface, "error", err)
		return
	}
	d.logger.Debug("routed wildcard answer", "domain", name, "interface", s.iface, "ips", len(safe))
}

// claimAddressLocked frees ip for session s when another tunnel holds a route
// to it, and reports whether s may add its own. The higher-priority tunnel
// keeps an address; s takes it over only from a lower-priority tunnel's
// ordinary route. A kernel route table has one entry per destination, so the
// holder's route is removed before s adds its own. The caller must hold
// mutationMu.
func (d *Daemon) claimAddressLocked(s *tunnelSession, ip netip.Addr, name string) bool {
	sessions := d.sessionList()
	rank := slices.Index(sessions, s)
	for i, other := range sessions {
		if other == s {
			continue
		}
		info, held := other.manager.GetRoute(ip)
		if !held {
			continue
		}
		if info.IsProtected || i < rank {
			d.noteConflict(s, other, ip, name)
			return false
		}
		if err := other.manager.RemoveRoute(ip); err != nil {
			d.logger.Warn("could not take an address over from a lower-priority tunnel",
				"ip", ip, "from", other.iface, "error", err)
			return false
		}
		d.forgetLearned(other, ip)
	}
	d.defaultVPN.yieldHostLocked(ip)
	return true
}

// answerVetter explains why an address from a wildcard answer must not be
// routed into one tunnel. DNS answers come from the network, and a /32 for the
// local gateway, a directly connected address, or a DNS upstream would cut this
// machine off from its own network. It holds what the checks read, so vetting
// every address of an answer costs no more than vetting one.
type answerVetter struct {
	s     *tunnelSession
	guard lanGuard
	// upstreams are the DNS servers of s's resolver and of the daemon's own.
	upstreams map[netip.Addr]struct{}
}

func (d *Daemon) newAnswerVetter(s *tunnelSession, guard lanGuard) answerVetter {
	v := answerVetter{s: s, guard: guard, upstreams: make(map[netip.Addr]struct{})}
	for _, upstream := range slices.Concat(s.resolver.Upstreams(), d.resolver.Upstreams()) {
		if addr, err := netip.ParseAddr(upstream); err == nil {
			v.upstreams[addr] = struct{}{}
		}
	}
	return v
}

// unsafeAddr returns why ip must not be routed into the tunnel, or "".
func (v answerVetter) unsafeAddr(ip netip.Addr) string {
	if !ip.Is4() {
		return "not an IPv4 address"
	}
	if _, ok := v.upstreams[ip]; ok {
		return "DNS upstream"
	}
	if reason := v.s.outsideAllowedReason(ip); reason != "" {
		return reason
	}
	return v.guard.unsafeAddr(ip)
}

// unsafeTunnelAddr explains why a /32 to ip through a tunnel would cut this
// machine off from its own network, or returns "".
func (d *Daemon) unsafeTunnelAddr(ip netip.Addr) string {
	return d.newLANGuard().unsafeAddr(ip)
}

// ensureVPNDNS discovers a detected tunnel's DNS servers and routes them through
// that tunnel, whatever dns.use_vpn_dns says: once the default route leaves the
// tunnel, a VPN that serves DNS for every name would otherwise lose all
// lookups. With dns.use_vpn_dns on, the tunnel's resolver also asks them
// first. A built-in profile's DNS follows different rules (see ensureOwnedDNS).
//
// Servers bound to the tunnel are final. When allowGuess is set and nothing is
// bound, the servers are guessed (see dns.SelectVPNNameservers); a guess is
// replaced as soon as the VPN binds its real servers. Routing the servers and
// publishing them happen in one critical section that re-checks the session
// and its interface, so a disconnect can never leave a dead tunnel's servers
// in use.
func (d *Daemon) ensureVPNDNS(gen *generation, s *tunnelSession, allowGuess bool) {
	if !d.tunnelUp(gen, s) || !d.sessions.isRegistered(s) {
		return
	}
	if s.owned {
		d.ensureOwnedDNS(gen, s)
		return
	}
	d.dnsMu.Lock()
	known, bound := len(s.vpnDNS) > 0, s.vpnDNSBound
	d.dnsMu.Unlock()
	if known && bound {
		d.retryDeferredVPNDNS(gen, s)
		return
	}

	servers, isBound, err := d.hooks.vpnNameservers(gen.ctx, s.iface, allowGuess && !known)
	if err != nil {
		d.logger.Warn("could not read VPN DNS servers", "interface", s.iface, "error", err)
		return
	}
	if len(servers) == 0 || (known && !isBound) {
		if !known {
			d.logger.Debug("VPN has not published DNS servers yet", "interface", s.iface)
		}
		return
	}

	// A VPN profile can name the LAN router or a LAN address as its DNS
	// server. Routing that into the tunnel would cut this machine off from
	// its own network.
	guard := d.newLANGuard()
	var safe []netip.Addr
	for _, server := range servers {
		if reason := guard.unsafeAddr(server); reason != "" {
			d.logger.Warn("not routing VPN DNS server into the tunnel", "server", server, "interface", s.iface, "reason", reason)
			d.recordActivity(activity.Event{
				Kind:      activity.KindRefused,
				Name:      vpnDNSRouteLabel,
				Addresses: []activity.Address{{IP: server.String(), Verdict: activity.Direct}},
				Interface: s.iface,
				Detail:    reason,
			})
			continue
		}
		safe = append(safe, server)
	}
	if len(safe) == 0 {
		return
	}

	var routed, deferred []netip.Addr
	_, _ = d.withSessionMutation(gen, s, func() error {
		if !d.tunnelUp(gen, s) {
			return nil
		}
		d.dnsMu.Lock()
		previous, previousBound := s.vpnDNS, s.vpnDNSBound
		d.dnsMu.Unlock()
		if len(previous) > 0 && (previousBound || !isBound) {
			return nil
		}
		for _, server := range safe {
			wait, err := d.routeDNSServerLocked(s, server)
			if err != nil {
				d.logger.Warn("could not route VPN DNS server", "server", server, "interface", s.iface, "error", err)
				continue
			}
			routed = append(routed, server)
			if wait {
				deferred = append(deferred, server)
			}
		}
		if len(routed) == 0 {
			return nil
		}
		for _, old := range previous {
			if !slices.Contains(routed, old) {
				_ = s.manager.RemoveProtectedRoute(old, vpnDNSRouteLabel)
			}
		}
		if d.useVPNDNS.Load() {
			s.resolver.SetPreferredServers(routed)
		}
		d.dnsMu.Lock()
		s.vpnDNS = routed
		s.vpnDNSBound = isBound
		s.vpnDNSDeferred = deferred
		d.dnsMu.Unlock()
		return nil
	})
	if len(routed) > 0 {
		d.logger.Info("routing VPN DNS servers through the tunnel",
			"interface", s.iface, "servers", routed, "bound_to_tunnel", isBound, "use_vpn_dns", d.useVPNDNS.Load())
	}
	if len(deferred) > 0 {
		d.logger.Info("VPN DNS servers already routed through another tunnel; this tunnel adds them when that one leaves",
			"interface", s.iface, "servers", deferred)
	}
}

// routeDNSServerLocked routes a VPN DNS server into s's tunnel. Two tunnels
// can publish one resolver address (two WireGuard configs with the same DNS
// line), and the kernel holds one route per address: the higher-priority tunnel
// owns it. It reports wait when another tunnel owns the route now, in which
// case s adds it when that tunnel lets go. A lower-priority tunnel's route is
// taken over, and that tunnel waits instead. The caller must hold mutationMu.
func (d *Daemon) routeDNSServerLocked(s *tunnelSession, server netip.Addr) (wait bool, err error) {
	d.defaultVPN.yieldHostLocked(server)
	err = s.manager.AddRoute(server, vpnDNSRouteLabel, true)
	if !errors.Is(err, route.ErrRouteOwnedElsewhere) {
		return false, err
	}

	sessions := d.sessionList()
	rank := slices.Index(sessions, s)
	for i, other := range sessions {
		if other == s {
			continue
		}
		info, held := other.manager.GetRoute(server)
		if !held {
			continue
		}
		// A built-in profile's DNS never outranks a detected tunnel's own.
		if i < rank && !other.owned {
			d.logger.Debug("VPN DNS server is routed through a higher-priority tunnel; waiting for it",
				"server", server, "interface", s.iface, "owner", other.iface)
			return true, nil
		}
		var removeErr error
		if info.IsProtected {
			removeErr = other.manager.RemoveProtectedRoute(server, info.SourceDomain)
		} else {
			removeErr = other.manager.RemoveRoute(server)
		}
		if removeErr != nil {
			d.logger.Warn("could not take a VPN DNS server over from a lower-priority tunnel",
				"server", server, "from", other.iface, "error", removeErr)
			return true, nil
		}
		d.forgetLearned(other, server)
		if other.owned {
			d.dropOwnedDNS(other, server, "the VPN "+s.client.Name+" uses it as its own DNS server")
		} else {
			d.deferVPNDNS(other, server)
		}
		if err := s.manager.AddRoute(server, vpnDNSRouteLabel, true); err != nil {
			return errors.Is(err, route.ErrRouteOwnedElsewhere), err
		}
		return false, nil
	}
	// Held by something RouteWise cannot move: a route outside its tables, or
	// a retired manager that could not finish cleaning up.
	d.logger.Debug("VPN DNS server already has a route RouteWise does not own; waiting",
		"server", server, "interface", s.iface, "error", err)
	return true, nil
}

// deferVPNDNS marks server as one s must route again once it can.
func (d *Daemon) deferVPNDNS(s *tunnelSession, server netip.Addr) {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	if slices.Contains(s.vpnDNS, server) && !slices.Contains(s.vpnDNSDeferred, server) {
		s.vpnDNSDeferred = append(s.vpnDNSDeferred, server)
	}
}

// retryDeferredVPNDNS adds the DNS server routes s was waiting for, now that
// the tunnel that held them may have gone.
func (d *Daemon) retryDeferredVPNDNS(gen *generation, s *tunnelSession) {
	d.dnsMu.Lock()
	waiting := slices.Clone(s.vpnDNSDeferred)
	d.dnsMu.Unlock()
	if len(waiting) == 0 {
		return
	}
	_, _ = d.withSessionMutation(gen, s, func() error {
		var still []netip.Addr
		for _, server := range waiting {
			wait, err := d.routeDNSServerLocked(s, server)
			if err != nil {
				d.logger.Warn("could not route VPN DNS server", "server", server, "interface", s.iface, "error", err)
				still = append(still, server)
				continue
			}
			if wait {
				still = append(still, server)
				continue
			}
			d.logger.Info("routing a VPN DNS server through the tunnel after the tunnel that held it left",
				"server", server, "interface", s.iface)
		}
		d.dnsMu.Lock()
		s.vpnDNSDeferred = still
		d.dnsMu.Unlock()
		return nil
	})
}

// applyUseVPNDNSLocked switches dns.use_vpn_dns for the running daemon: each
// tunnel's resolver starts or stops asking that tunnel's DNS servers first. A
// built-in profile's DNS route exists only while the setting is on, so turning
// it off removes those routes at once; turning it on adds them at the next sync.
// The caller must hold mutationMu.
func (d *Daemon) applyUseVPNDNSLocked(enabled bool) {
	d.useVPNDNS.Store(enabled)
	for _, s := range d.sessionList() {
		if s.owned {
			d.clearOwnedDNSLocked(s)
			continue
		}
		var preferred []netip.Addr
		if enabled {
			d.dnsMu.Lock()
			preferred = slices.Clone(s.vpnDNS)
			d.dnsMu.Unlock()
		}
		s.resolver.SetPreferredServers(preferred)
	}
}

// resetDNSStateLocked forgets the shared DNS-side state at shutdown. Each
// session's own VPN DNS servers and learned addresses go with the session.
// The caller must hold mutationMu.
func (d *Daemon) resetDNSStateLocked() {
	d.resolver.SetPreferredServers(nil)
	d.dnsMu.Lock()
	d.wildcardSkipped = nil
	d.resolverFileErr = ""
	d.dnsMu.Unlock()
}
