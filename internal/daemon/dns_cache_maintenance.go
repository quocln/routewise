package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/quocln/routewise/internal/dns"
)

// resolvers lists every resolver holding a DNS cache: the daemon's own and the
// one of each tunnel.
func (d *Daemon) resolvers() []*dns.Resolver {
	out := []*dns.Resolver{d.resolver}
	for _, s := range d.sessionList() {
		if !slices.Contains(out, s.resolver) {
			out = append(out, s.resolver)
		}
	}
	return out
}

// clearDNSCaches empties RouteWise's DNS caches and the system's. RouteWise's
// are always emptied, whatever happens to the system's.
func (d *Daemon) clearDNSCaches() error {
	for _, r := range d.resolvers() {
		r.ClearCache()
	}
	// Not under mutationMu: this runs external tools, and route changes must
	// not wait on them.
	if err := d.hooks.flushSystemDNS(context.Background()); err != nil {
		return fmt.Errorf("RouteWise's DNS cache was cleared, but the system's was not: %w", err)
	}
	return nil
}

// ClearDNSCache empties the DNS caches and changes no route. It deliberately does
// not trigger a sync: a sync would re-resolve every exact domain now, and an
// address no longer returned would lose its route under a connection still using
// it. Exact domains are re-resolved at the next scheduled sync, as they would be
// when their cache entries expire.
func (d *Daemon) ClearDNSCache() error {
	if err := d.clearDNSCaches(); err != nil {
		return err
	}
	d.logger.Info("DNS caches cleared")
	return nil
}

// CleanDNS removes the routes learned from wildcard lookups and empties the DNS
// caches, then syncs, so every name is routed afresh from its next lookup. A
// connection open over a removed route can drop. Routes come first: a lookup made
// after the system's cache is empty must re-learn its route, not lose it.
func (d *Daemon) CleanDNS() (int, error) {
	removed, routeErr := d.removeLearnedRoutes()
	cacheErr := d.clearDNSCaches()
	d.TriggerSync()
	d.logger.Info("DNS cleaned", "routes_removed", removed)
	if err := errors.Join(routeErr, cacheErr); err != nil {
		return removed, fmt.Errorf("removed %d learned routes, but: %w", removed, err)
	}
	return removed, nil
}

// removeLearnedRoutes removes every learned route of every tunnel and forgets the
// addresses. A route another domain or a VPN DNS server now relies on stays. A
// tunnel that cannot be changed right now (degraded, or going away) keeps its
// routes; a degraded one reports that through status.
func (d *Daemon) removeLearnedRoutes() (int, error) {
	gen := d.currentGeneration()
	removed := 0
	var errs []error
	for _, s := range d.sessionList() {
		ran, err := d.withSessionMutation(gen, s, func() error {
			defer s.manager.BeginRouteBatch()()
			var sessionErrs []error
			for ip, domain := range d.takeLearned(s) {
				info, held := s.manager.GetRoute(ip)
				if !held || info.IsProtected || info.SourceDomain != domain {
					continue
				}
				if err := s.manager.RemoveRouteIfSource(ip, domain); err != nil {
					sessionErrs = append(sessionErrs, fmt.Errorf("remove route to %s: %w", ip, err))
					continue
				}
				removed++
			}
			return errors.Join(sessionErrs...)
		})
		if !ran {
			d.logger.Warn("left learned routes in place: the tunnel cannot be changed now", "interface", s.iface)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return removed, errors.Join(errs...)
}

// takeLearned hands over s's learned addresses, expired ones included since their
// routes may still be installed, and forgets them all.
func (d *Daemon) takeLearned(s *tunnelSession) map[netip.Addr]string {
	d.learnedMu.Lock()
	defer d.learnedMu.Unlock()
	out := make(map[netip.Addr]string, len(s.learned))
	for ip, lr := range s.learned {
		out[ip] = lr.domain
	}
	clear(s.learned)
	return out
}
