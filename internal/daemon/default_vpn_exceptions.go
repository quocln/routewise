package daemon

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/resolverfiles"
	"github.com/quocln/routewise/internal/route"
)

// An exception is a name, IP or network that goes direct instead of through the
// default VPN. It gets a route of its own through the LAN gateway, which outranks the
// role's /2 routes by being longer. A list still outranks an exception: a host route
// a list wants is given up to it, and an exception a list route already covers is not
// added, whatever the kernel's longest-prefix rule would have made of the two. So an
// exception decides only what would otherwise have entered the default VPN, including
// a listed name whose VPN is down.
//
// Names are learned two ways: each sync resolves the exact ones, and the forwarder
// reports the answer an app actually gets, before the app gets it. The second is what
// makes a CDN work, whose answer differs from one lookup to the next, and it is the
// only way a wildcard is learned at all.

const exceptionRouteDetail = "excepted from the default VPN"

// exceptionRoutes is what the role holds for its exceptions. It is guarded by
// mutationMu, except view.
type exceptionRoutes struct {
	// hosts and nets are the routes in the table, by the entry each one serves.
	hosts map[netip.Addr]string
	nets  map[netip.Prefix]string
	// addingHosts and addingNets are what the current pass is about to add, so the
	// journal names a route before it can exist.
	addingHosts map[netip.Addr]string
	addingNets  map[netip.Prefix]string
	// gateway and iface are where the routes lead.
	gateway netip.Addr
	iface   string
	// names are the addresses the excepted names resolved to.
	names map[netip.Addr]learnedRoute
	// view answers covers without the lock, for the DNS and flow paths.
	view atomic.Pointer[exceptionView]
}

// exceptionView is an immutable copy of the routes held.
type exceptionView struct {
	hosts map[netip.Addr]struct{}
	nets  []netip.Prefix
}

func (e *exceptionRoutes) holdsAny() bool { return len(e.hosts) > 0 || len(e.nets) > 0 }

// gatewayText is the gateway as a table's delete takes it, empty when unknown.
func (e *exceptionRoutes) gatewayText() string {
	if !e.gateway.IsValid() {
		return ""
	}
	return e.gateway.String()
}

// covers reports whether traffic to ip takes an exception's route.
func (e *exceptionRoutes) covers(ip netip.Addr) bool {
	v := e.view.Load()
	if v == nil {
		return false
	}
	if _, ok := v.hosts[ip]; ok {
		return true
	}
	return slices.ContainsFunc(v.nets, func(p netip.Prefix) bool { return p.Contains(ip) })
}

func (e *exceptionRoutes) publishView() {
	v := &exceptionView{hosts: make(map[netip.Addr]struct{}, len(e.hosts))}
	for addr := range e.hosts {
		v.hosts[addr] = struct{}{}
	}
	for p := range e.nets {
		v.nets = append(v.nets, p)
	}
	e.view.Store(v)
}

// journalEntries names every route that exists or is about to.
func (e *exceptionRoutes) journalEntries() (hosts, nets []string) {
	for _, m := range []map[netip.Addr]string{e.hosts, e.addingHosts} {
		for addr := range m {
			hosts = append(hosts, addr.String())
		}
	}
	for _, m := range []map[netip.Prefix]string{e.nets, e.addingNets} {
		for p := range m {
			nets = append(nets, p.String())
		}
	}
	slices.Sort(hosts)
	slices.Sort(nets)
	return slices.Compact(hosts), slices.Compact(nets)
}

// exceptsName reports whether the answer for name should get a direct route now.
func (c *defaultVPNController) exceptsName(name string) bool {
	return c.active.Load() != nil && c.host.policy().exceptedName(c.host.sessionList(), name)
}

// exceptionSuffixes lists the resolver-file suffixes that send the exceptions' lookups
// to the forwarder while the role is held, leaving out those owners already covers. A
// suffix also carries the names under it, which the forwarder answers unrouted unless
// they match.
func (c *defaultVPNController) exceptionSuffixes(owners []wildcardOwner) []wildcardOwner {
	if c.active.Load() == nil {
		return nil
	}
	seen := make(map[string]bool, len(owners))
	for _, o := range owners {
		seen[o.suffix] = true
	}
	var out []wildcardOwner
	for _, pattern := range c.host.policy().except.patterns {
		if config.IsLiteralEntry(pattern) {
			continue
		}
		suffix := foldName(pattern)
		if config.IsWildcardPattern(pattern) {
			suffix = config.WildcardSuffix(pattern)
		}
		// One name no resolver file can hold must not cost the rest theirs. An exact
		// name still gets its route from the sync's own lookup.
		if resolverfiles.ValidDomain(suffix) && !seen[suffix] {
			seen[suffix] = true
			out = append(out, wildcardOwner{suffix: suffix})
		}
	}
	return out
}

// resolveExceptions resolves the exact excepted names, so their routes exist before
// the first lookup that goes through the forwarder. It runs with no lock held, since a
// lookup can take seconds. A name that fails keeps the addresses it had.
func (d *Daemon) resolveExceptions(gen *generation) {
	if d.defaultVPN.active.Load() == nil {
		return
	}
	pol, sessions := d.store.Policy(), d.sessionList()
	exact, _ := sessionPatterns{patterns: pol.except.patterns}.split()
	exact = slices.DeleteFunc(exact, func(name string) bool { return !pol.exceptedName(sessions, name) })
	if len(exact) == 0 {
		return
	}
	results, err := d.hooks.resolveExcepted(gen.ctx, exact)
	if err != nil {
		d.logger.Warn("could not resolve every name excepted from the default VPN", "error", err)
	}
	_, _ = d.withGenerationMutation(gen, func() error {
		for domain, ips := range results {
			var addrs []netip.Addr
			for _, ip := range ips {
				if addr := netIPToNetipAddr(ip); addr.IsValid() {
					addrs = append(addrs, addr)
				}
			}
			d.names.Add(domain, addrs, 0)
			d.defaultVPN.rememberExceptionLocked(domain, addrs, 0)
		}
		return nil
	})
}

// routeExceptedAnswer gives the addresses of an excepted name their direct routes. The
// forwarder calls it before replying, so the app's first connection already goes
// direct.
func (d *Daemon) routeExceptedAnswer(gen *generation, name string, ips []netip.Addr, ttl time.Duration) {
	if !d.defaultVPN.exceptsName(name) {
		return
	}
	_, err := d.withGenerationMutation(gen, func() error {
		// Decided again under the lock: a tunnel may have come up since the lookup.
		if !d.defaultVPN.exceptsName(name) {
			return nil
		}
		d.defaultVPN.rememberExceptionLocked(name, ips, ttl)
		if problem := d.defaultVPN.refreshExceptionsLocked(); problem != "" {
			return errors.New(problem)
		}
		return nil
	})
	if err != nil {
		d.logger.Warn("could not route an answer excepted from the default VPN", "domain", name, "error", err)
	}
}

// rememberExceptionLocked records addresses of an excepted name, dropping the entries
// closest to expiry over the cap. The next refresh routes them. The caller must hold
// mutationMu.
func (c *defaultVPNController) rememberExceptionLocked(name string, ips []netip.Addr, ttl time.Duration) {
	e := &c.exceptions
	if e.names == nil {
		e.names = make(map[netip.Addr]learnedRoute)
	}
	expires := time.Now().Add(max(ttl, learnedRouteMinLifetime))
	for _, ip := range ips {
		if ip = ip.Unmap(); ip.Is4() {
			e.names[ip] = learnedRoute{domain: name, expires: expires}
		}
	}
	for len(e.names) > maxLearnedRoutes {
		var oldest netip.Addr
		var oldestExpiry time.Time
		for ip, lr := range e.names {
			if !oldest.IsValid() || lr.expires.Before(oldestExpiry) {
				oldest, oldestExpiry = ip, lr.expires
			}
		}
		delete(e.names, oldest)
	}
}

// wantedExceptionsLocked decides which direct routes should exist: what the exception
// list and the names learned for it cover, less what a list route already serves, what
// is on the LAN anyway, and a built-in tunnel's server, which has its own route. The
// caller must hold mutationMu.
func (c *defaultVPNController) wantedExceptionsLocked() (hosts map[netip.Addr]string, nets map[netip.Prefix]string) {
	e := &c.exceptions
	hosts, nets = make(map[netip.Addr]string), make(map[netip.Prefix]string)
	pol, sessions := c.host.policy(), c.host.sessionList()
	local := c.host.localPrefixes()

	wantHost := func(ip netip.Addr, label string) {
		if _, server := c.held.servers[ip]; server {
			return
		}
		if slices.ContainsFunc(local, func(p netip.Prefix) bool { return p.Contains(ip) }) {
			return
		}
		if owner, _ := routedBy(sessions, ip); owner != nil {
			return
		}
		hosts[ip] = label
	}

	now := time.Now()
	for ip, lr := range e.names {
		if now.After(lr.expires) || !pol.exceptedName(sessions, lr.domain) {
			delete(e.names, ip)
			continue
		}
		wantHost(ip, lr.domain)
	}
	ips, prefixes := sessionPatterns{patterns: pol.except.patterns}.entries()
	for _, ip := range ips {
		wantHost(ip, ip.String())
	}
	for _, p := range prefixes {
		if slices.ContainsFunc(local, func(l netip.Prefix) bool { return prefixCovers(l, p) }) {
			continue
		}
		if slices.ContainsFunc(sessions, func(s *tunnelSession) bool {
			for held := range s.manager.GetNetRoutes() {
				if prefixCovers(held, p) {
					return true
				}
			}
			return false
		}) {
			continue
		}
		nets[p] = p.String()
	}
	return hosts, nets
}

// prefixCovers reports whether every address of inner is in outer.
func prefixCovers(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// refreshExceptionsLocked brings the direct routes to what is wanted while the role is
// held, and does nothing otherwise, since everything is direct then anyway. It checks
// the kernel each time, like holdRoutesLocked: a change of network can drop a static
// route. It returns what went wrong, for the status. The caller must hold mutationMu.
func (c *defaultVPNController) refreshExceptionsLocked() string {
	if c.active.Load() == nil && !c.preparing {
		return ""
	}
	wantHosts, wantNets := c.wantedExceptionsLocked()
	e := &c.exceptions
	if len(wantHosts) == 0 && len(wantNets) == 0 && !e.holdsAny() {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultVPNCommandTimeout)
	defer cancel()
	table := c.host.routeTable()
	gateway, iface, err := table.LocalGateway(ctx, c.host.localInterface())
	if err != nil {
		return "could not keep exceptions out of the default VPN: " + err.Error()
	}
	entries, err := table.Snapshot(ctx)
	if err != nil {
		return "could not keep exceptions out of the default VPN: " + err.Error()
	}
	kernel := route.StaticDestinations(entries)
	moved := gateway != e.gateway || iface != e.iface

	beforeHosts, beforeNets := len(e.hosts), len(e.nets)
	var errs []error
	for addr, label := range e.hosts {
		dest := netip.PrefixFrom(addr, addr.BitLen())
		if _, keep := wantHosts[addr]; keep && !moved && kernel[dest] == iface {
			continue
		}
		if err := c.dropExceptionHostLocked(ctx, addr, label, wantHosts); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(kernel, dest)
	}
	for p, label := range e.nets {
		if _, keep := wantNets[p]; keep && !moved && kernel[p] == iface {
			continue
		}
		if err := table.DeleteNet(ctx, p.String(), e.gatewayText(), e.iface); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(e.nets, p)
		delete(kernel, p)
		if _, keep := wantNets[p]; !keep {
			c.recordExceptionRoute(activity.KindRouteRemoved, label, p.String(), e.iface)
		}
	}

	// What something else already routes is left to it: a VPN app's own route to its
	// server may lead through the LAN too, and adopting it would have us delete it.
	addHosts := make(map[netip.Addr]string)
	for addr, label := range wantHosts {
		_, held := e.hosts[addr]
		_, taken := kernel[netip.PrefixFrom(addr, addr.BitLen())]
		if !held && !taken {
			addHosts[addr] = label
		}
	}
	addNets := make(map[netip.Prefix]string)
	for p, label := range wantNets {
		_, held := e.nets[p]
		_, taken := kernel[p]
		if !held && !taken {
			addNets[p] = label
		}
	}

	if len(addHosts) > 0 || len(addNets) > 0 {
		e.gateway, e.iface = gateway, iface
		e.addingHosts, e.addingNets = addHosts, addNets
		err := c.saveJournal(true, c.held.servers, c.held.ipv6Rejected)
		if err == nil {
			for addr, label := range addHosts {
				if err := table.AddHost(ctx, addr, gateway, iface); err != nil {
					if !errors.Is(err, route.ErrRouteOwnedElsewhere) {
						errs = append(errs, err)
					}
					c.logger.Debug("exception not routed", "address", addr, "error", err)
					continue
				}
				if e.hosts == nil {
					e.hosts = make(map[netip.Addr]string)
				}
				e.hosts[addr] = label
				c.recordExceptionRoute(activity.KindRouteAdded, label, addr.String(), iface)
			}
			for p, label := range addNets {
				if err := table.AddPrefix(ctx, p, gateway, iface); err != nil {
					if !errors.Is(err, route.ErrRouteOwnedElsewhere) {
						errs = append(errs, err)
					}
					c.logger.Debug("exception not routed", "network", p, "error", err)
					continue
				}
				if e.nets == nil {
					e.nets = make(map[netip.Prefix]string)
				}
				e.nets[p] = label
				c.recordExceptionRoute(activity.KindRouteAdded, label, p.String(), iface)
			}
		} else {
			errs = append(errs, err)
		}
		e.addingHosts, e.addingNets = nil, nil
	}
	if len(addHosts) > 0 || len(addNets) > 0 || len(e.hosts) != beforeHosts || len(e.nets) != beforeNets {
		if err := c.saveJournal(true, c.held.servers, c.held.ipv6Rejected); err != nil {
			errs = append(errs, err)
		}
		e.publishView()
	}
	if err := errors.Join(errs...); err != nil {
		return "could not keep exceptions out of the default VPN: " + err.Error()
	}
	return ""
}

// dropExceptionHostLocked removes one host route. want says whether it is only moving,
// which is no event for the user. The caller must hold mutationMu.
func (c *defaultVPNController) dropExceptionHostLocked(ctx context.Context, addr netip.Addr, label string, want map[netip.Addr]string) error {
	e := &c.exceptions
	if err := c.host.routeTable().DeleteHost(ctx, addr); err != nil {
		return err
	}
	delete(e.hosts, addr)
	if _, keep := want[addr]; !keep {
		c.recordExceptionRoute(activity.KindRouteRemoved, label, addr.String(), e.iface)
	}
	return nil
}

// recordExceptionRoute tells the user what the role just did for an exception.
func (c *defaultVPNController) recordExceptionRoute(kind activity.Kind, name, dest, iface string) {
	c.host.recordActivity(activity.Event{
		Kind:      kind,
		Name:      name,
		Addresses: []activity.Address{{IP: dest, Verdict: activity.Direct}},
		Interface: iface,
		Detail:    exceptionRouteDetail,
	})
	c.logger.Info("default VPN exception route", "kind", kind, "name", name, "destination", dest, "interface", iface)
}

// yieldHostLocked removes an exception's route to ip, because a list is about to take
// the address. The kernel keeps one route per destination, so the list could not add
// its own otherwise. The caller must hold mutationMu.
func (c *defaultVPNController) yieldHostLocked(ip netip.Addr) {
	e := &c.exceptions
	label, held := e.hosts[ip]
	if !held {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultVPNCommandTimeout)
	defer cancel()
	if err := c.dropExceptionHostLocked(ctx, ip, label, nil); err != nil {
		c.logger.Warn("could not give up an exception's route to a VPN list", "address", ip, "error", err)
		return
	}
	c.afterYieldLocked()
}

// yieldPlannedLocked removes every exception route a planned list route replaces: the
// same destination, or one inside a network a list routes. A network that merely
// contains a list's route can stay, since the list's is longer. The caller must hold
// mutationMu.
func (c *defaultVPNController) yieldPlannedLocked(plans []sessionRoutePlan) {
	e := &c.exceptions
	if !e.holdsAny() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultVPNCommandTimeout)
	defer cancel()
	table := c.host.routeTable()
	changed := false
	for addr, label := range e.hosts {
		if !plansCover(plans, addr) {
			continue
		}
		if err := c.dropExceptionHostLocked(ctx, addr, label, nil); err != nil {
			c.logger.Warn("could not give up an exception's route to a VPN list", "address", addr, "error", err)
			continue
		}
		changed = true
	}
	for p, label := range e.nets {
		if !plansCoverPrefix(plans, p) {
			continue
		}
		if err := table.DeleteNet(ctx, p.String(), e.gatewayText(), e.iface); err != nil {
			c.logger.Warn("could not give up an exception's route to a VPN list", "network", p, "error", err)
			continue
		}
		delete(e.nets, p)
		c.recordExceptionRoute(activity.KindRouteRemoved, label, p.String(), e.iface)
		changed = true
	}
	if changed {
		c.afterYieldLocked()
	}
}

func plansCover(plans []sessionRoutePlan, ip netip.Addr) bool {
	for _, plan := range plans {
		if _, ok := plan.hosts[ip]; ok {
			return true
		}
		for p := range plan.nets {
			if p.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func plansCoverPrefix(plans []sessionRoutePlan, inner netip.Prefix) bool {
	for _, plan := range plans {
		for p := range plan.nets {
			if prefixCovers(p, inner) {
				return true
			}
		}
	}
	return false
}

func (c *defaultVPNController) afterYieldLocked() {
	c.exceptions.publishView()
	if err := c.saveJournal(true, c.held.servers, c.held.ipv6Rejected); err != nil {
		c.logger.Error("default VPN journal not saved", "error", err)
	}
}

// releaseExceptionsLocked removes every direct route, since nothing needs one once no
// tunnel holds the role. What cannot be removed stays recorded for the next pass. The
// caller must hold mutationMu.
func (c *defaultVPNController) releaseExceptionsLocked(ctx context.Context) {
	e := &c.exceptions
	table := c.host.routeTable()
	for addr, label := range e.hosts {
		if err := c.dropExceptionHostLocked(ctx, addr, label, nil); err != nil {
			c.logger.Error("could not remove an exception's route", "address", addr, "error", err)
		}
	}
	for p, label := range e.nets {
		if err := table.DeleteNet(ctx, p.String(), e.gatewayText(), e.iface); err != nil {
			c.logger.Error("could not remove an exception's route", "network", p, "error", err)
			continue
		}
		delete(e.nets, p)
		c.recordExceptionRoute(activity.KindRouteRemoved, label, p.String(), e.iface)
	}
	e.names = nil
	e.publishView()
}

// recoverExceptions removes the direct routes a crashed helper left, and keeps what it
// could not, so the next pass retries and the journal keeps naming it.
func (c *defaultVPNController) recoverExceptions(ctx context.Context, j defaultVPNJournal) (failed bool) {
	e := &c.exceptions
	table := c.host.routeTable()
	for _, text := range j.ExceptHosts {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			c.logger.Warn("default VPN journal names something that is not an address; skipped", "entry", text)
			continue
		}
		if err := table.DeleteHost(ctx, addr); err != nil {
			c.logger.Error("leftover exception route not removed", "address", addr, "error", err)
			if e.hosts == nil {
				e.hosts = make(map[netip.Addr]string)
			}
			e.hosts[addr] = text
			failed = true
		}
	}
	for _, text := range j.ExceptNets {
		p, err := netip.ParsePrefix(text)
		if err != nil {
			c.logger.Warn("default VPN journal names something that is not a network; skipped", "entry", text)
			continue
		}
		if err := table.DeleteNet(ctx, p.String(), "", j.ExceptInterface); err != nil {
			c.logger.Error("leftover exception route not removed", "network", p, "error", err)
			if e.nets == nil {
				e.nets = make(map[netip.Prefix]string)
			}
			e.nets[p] = text
			failed = true
		}
	}
	if failed {
		e.iface = j.ExceptInterface
	}
	return failed
}
