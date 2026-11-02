package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/dns"
	"github.com/quocln/routewise/internal/route"
	"github.com/quocln/routewise/internal/vpnclient"
)

// tunnelSession is everything RouteWise keeps for one connected, managed
// tunnel: its own route manager and transition journal, its own resolver, its
// VPN DNS servers, its learned wildcard routes, and its own enforcer. Sessions
// never share route state, so one tunnel's disconnect or failure cannot undo
// another's routes.
type tunnelSession struct {
	iface   string
	gateway netip.Addr
	client  vpnclient.Client
	// seq orders sessions by when they were registered, which is the order
	// their split tunnels were activated. Teardown runs in the reverse order.
	// It is set once, under mutationMu, when the session is registered.
	seq uint64

	manager  *route.Manager
	resolver *dns.Resolver

	// owned marks a tunnel the helper itself runs for a built-in profile (see
	// owned_session.go). profileID and ownedDNS are set once, before the
	// session is registered, and never change.
	owned     bool
	profileID string
	ownedDNS  []netip.Addr
	// allowed is the set of destinations a WireGuard tunnel's peers accept; nil
	// means no restriction. It is set once, before registration.
	allowed []netip.Prefix
	// proven is true while an owned session's tunnel is known to work. An
	// unproven owned session takes no routes: its entries go direct.
	proven atomic.Bool
	// holding is true while a freshly started owned tunnel has not been proven
	// yet but may still take routes, for at most connectHoldLimit. A connection
	// opened in that window waits for the tunnel instead of going direct and
	// staying direct for its whole life. It is never set again once cleared.
	holding atomic.Bool

	// enforcingSince is when enforcement began, nil for a session that has none. The
	// control loop alone uses nextEnforce and enforceErr.
	enforcingSince atomic.Pointer[time.Time]
	nextEnforce    time.Time
	enforceErr     string

	// ctx ends when the session is torn down. It is a child of the generation's
	// context, so shutdown ends it too.
	ctx    context.Context
	cancel context.CancelFunc

	// The fields below are guarded by Daemon.dnsMu.
	//
	// vpnDNS are the tunnel's DNS servers, routed through it. vpnDNSBound is
	// true when they came from servers bound to the tunnel; false means they
	// were guessed and are replaced once real ones appear.
	vpnDNS      []netip.Addr
	vpnDNSBound bool
	// vpnDNSDeferred are the servers in vpnDNS another tunnel routes right now
	// (two VPNs can publish one resolver). The higher-priority tunnel owns
	// the route; this one adds it when that tunnel lets go.
	vpnDNSDeferred []netip.Addr
	// vpnDNSSettled is set on an owned session once its DNS servers were
	// decided for the current dns.use_vpn_dns setting and health, even when every
	// one was refused, so the decision is made once and not at every sync.
	vpnDNSSettled bool
	// refusedDNS maps each profile DNS server an owned session was refused to the
	// reason, until the decision is made again.
	refusedDNS map[netip.Addr]string
	// conflicts maps each address a higher-priority tunnel won from this one
	// in the last sync to that tunnel's interface, so a refusal is recorded
	// once rather than at every sync.
	conflicts map[netip.Addr]string
	// netConflicts is conflicts for CIDR entries: each network route a
	// higher-priority tunnel won from this one, by prefix.
	netConflicts map[netip.Prefix]string
	// refusedEntries maps each IP or CIDR entry this tunnel was refused for
	// LAN safety in the last sync to the reason, so a refusal is recorded once
	// rather than at every sync.
	refusedEntries map[string]string

	// learned is guarded by Daemon.learnedMu.
	learned map[netip.Addr]learnedRoute
}

// newSessionManager builds a route manager for one tunnel. It shares the base
// manager's route table, additive mode, change observer, and captured LAN
// gateway, and journals to journalPath.
func (d *Daemon) newSessionManager(journalPath string) *route.Manager {
	m := route.NewManager()
	m.SetTable(d.routeManager.Table())
	m.SetAdditiveMode(d.routeManager.Additive())
	m.SetJournalPath(journalPath)
	m.SetChangeObserver(d.onRouteChange)
	// One registry for every tunnel: a /32 one tunnel holds is never adopted
	// by another, even though the kernel answers `File exists` to both.
	m.SetHostRouteRegistry(d.hostRoutes)
	if d.hooks.interfaceUp != nil {
		m.SetInterfaceProbe(d.hooks.interfaceUp)
	}
	// The base manager's gateway is not refreshed while any tunnel is up, so
	// read it again: the user may have changed networks since another VPN
	// connected. The scoped LAN default is readable even while a VPN owns the
	// global one; on failure the last known gateway is kept.
	if err := d.routeManager.CaptureOriginalGateway(); err != nil {
		d.logger.Debug("could not re-read the LAN gateway for a new tunnel", "error", err)
	}
	m.SetOriginalGateway(d.routeManager.GetOriginalGateway(), d.routeManager.GetLocalInterface())
	return m
}

// newTunnelSession builds the session for a tunnel that just connected. It is
// not registered until the caller adds it under mutationMu.
func (d *Daemon) newTunnelSession(gen *generation, iface string, gateway netip.Addr, client vpnclient.Client) (*tunnelSession, error) {
	journalPath, err := route.SessionJournalPath(d.routeManager.JournalPath(), iface)
	if err != nil {
		return nil, err
	}
	s := &tunnelSession{
		iface:          iface,
		gateway:        gateway,
		client:         client,
		manager:        d.newSessionManager(journalPath),
		resolver:       dns.NewResolver(d.dnsServers, d.dnsCacheTTL),
		conflicts:      make(map[netip.Addr]string),
		netConflicts:   make(map[netip.Prefix]string),
		refusedEntries: make(map[string]string),
		learned:        make(map[netip.Addr]learnedRoute),
	}
	s.ctx, s.cancel = context.WithCancel(gen.ctx)
	s.manager.SetVPNState(gateway, iface)
	return s, nil
}

// recoverSessionJournals compensates the per-tunnel journals a previous
// process left behind, each through a manager bound to its own path. A journal
// that cannot be recovered leaves its manager degraded, which keeps the daemon
// from mutating routes until an operator resolves it.
func (d *Daemon) recoverSessionJournals() {
	paths, err := route.SessionJournalPaths(d.routeManager.JournalPath())
	if err != nil {
		d.logger.Error("could not list leftover tunnel journals", "error", err)
		return
	}
	for _, path := range paths {
		m := d.newSessionManager(path)
		if err := m.RecoverTransition(); err != nil {
			d.logger.Error("tunnel transition recovery failed", "journal", path, "error", err)
		}
		if degraded, _ := m.Degraded(); degraded {
			d.sessions.retire(m)
		}
	}
}

// globalDegraded reports whether the base manager or a retired one is
// degraded. That halts every mutation, because route ownership is unverified.
func (d *Daemon) globalDegraded() bool {
	if degraded, _ := d.routeManager.Degraded(); degraded {
		return true
	}
	for _, m := range d.sessions.retiredManagers() {
		if degraded, _ := m.Degraded(); degraded {
			return true
		}
	}
	return false
}

// Degraded reports whether route ownership could not be verified, with the
// reason. A degraded base or retired manager stops every mutation; a degraded
// tunnel manager stops that tunnel alone.
func (d *Daemon) Degraded() (bool, string) {
	var reasons []string
	if degraded, reason := d.routeManager.Degraded(); degraded {
		reasons = append(reasons, reason)
	}
	for _, m := range d.sessions.retiredManagers() {
		if degraded, reason := m.Degraded(); degraded {
			reasons = append(reasons, fmt.Sprintf("%s: %s", m.JournalPath(), reason))
		}
	}
	for _, s := range d.sessionList() {
		if degraded, reason := s.manager.Degraded(); degraded {
			reasons = append(reasons, fmt.Sprintf("%s: %s", s.iface, reason))
		}
	}
	if len(reasons) == 0 {
		return false, ""
	}
	return true, joinReasons(reasons)
}

func joinReasons(reasons []string) string {
	out := reasons[0]
	for _, r := range reasons[1:] {
		out += "; " + r
	}
	return out
}

// sessionList returns the connected sessions, highest priority first (see
// sessionRegistry.ordered). The slice is shared: callers must not modify it.
func (d *Daemon) sessionList() []*tunnelSession {
	return d.sessions.ordered(d.store.Policy())
}

// sessionPatterns is the list of patterns that route through one session.
type sessionPatterns struct {
	session  *tunnelSession
	patterns []string
}

// healthy reports whether the session may take routes: a tunnel whose route
// manager is degraded stops mutating, so nothing new is assigned to it, and an
// owned tunnel that is neither proven to work nor holding its first connect
// takes nothing either.
func (s *tunnelSession) healthy() bool {
	if s.owned && !s.routable() {
		return false
	}
	degraded, _ := s.manager.Degraded()
	return !degraded
}

// routable reports whether an owned session may carry its list and its DNS
// servers: proven to work, or still holding its first connect.
func (s *tunnelSession) routable() bool {
	return s.proven.Load() || s.holding.Load()
}

// clientSession returns the session that serves a VPN client's own list: the
// first healthy tunnel of that client. Two tunnels of one client share a list,
// so only the first takes it. sessions must be in priority order.
func clientSession(sessions []*tunnelSession, clientID string) *tunnelSession {
	if clientID == "" {
		return nil
	}
	for _, s := range sessions {
		if s.client.ID == clientID && s.healthy() {
			return s
		}
	}
	return nil
}

// anyVPNSession returns the session the Any VPN list routes through: the
// highest-priority connected detected tunnel that is healthy. A built-in profile
// never takes it: it carries only its own list, so with no healthy detected
// tunnel the Any VPN entries go direct. sessions must be in priority order.
func anyVPNSession(sessions []*tunnelSession) *tunnelSession {
	for _, s := range sessions {
		if !s.owned && s.healthy() {
			return s
		}
	}
	return nil
}

// assignPatterns decides which patterns route through which session, by the
// same ownership rules as owningList. A session gets its client's own list, and
// the Any VPN list goes to the highest-priority healthy detected session. An exact name
// goes only to its owner, so a name in a client's list never reaches the Any
// VPN owner. A wildcard goes with its list, and wildcardOwnerOf settles each name it
// matches when a lookup answers. sessions must be in priority order.
func assignPatterns(pol *routingPolicy, sessions []*tunnelSession) []sessionPatterns {
	anyOwner := anyVPNSession(sessions)
	out := make([]sessionPatterns, 0, len(sessions))
	for _, s := range sessions {
		var list []string
		if s == anyOwner {
			for _, pattern := range pol.any.patterns {
				if !config.IsWildcardPattern(pattern) {
					// A name or an IP or CIDR entry a client's own list holds
					// belongs to that client alone, never to the Any VPN owner.
					if _, owned := pol.entryOwner(pattern); owned {
						continue
					}
				}
				list = append(list, pattern)
			}
		}
		if id := s.client.ID; clientSession(sessions, id) == s {
			if own, ok := pol.list(id); ok {
				for _, pattern := range own.patterns {
					// An entry is owned by the highest-priority client whose list
					// holds it, domain, IP, or CIDR alike. A domain goes to its
					// owner alone. A literal entry also goes to a lower-priority
					// client while the owner's tunnel is up, so that the two meet
					// in the sync, where the owner wins and the other records a
					// refusal; while the owner is down or degraded nobody routes
					// it and it goes direct, never through the lower tunnel.
					if !config.IsWildcardPattern(pattern) {
						owner, _ := pol.entryOwner(pattern)
						if owner != id && (!config.IsLiteralEntry(pattern) || clientSession(sessions, owner) == nil) {
							continue
						}
					}
					list = append(list, pattern)
				}
			}
		}
		out = append(out, sessionPatterns{session: s, patterns: dedupe(list)})
	}
	return out
}

// dedupe drops repeated patterns, keeping the first of each in order.
func dedupe(list []string) []string {
	seen := make(map[string]struct{}, len(list))
	out := make([]string, 0, len(list))
	for _, v := range list {
		if _, dup := seen[v]; !dup {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

// split separates a session's patterns into exact hosts, resolved up front,
// and the suffixes of wildcards, resolved as lookups happen. IP and CIDR
// entries are neither: they are routed as written (see entries) and never
// looked up.
func (sp sessionPatterns) split() (exact, suffixes []string) {
	for _, pattern := range sp.patterns {
		if config.IsLiteralEntry(pattern) {
			continue
		}
		if suffix := config.WildcardSuffix(pattern); suffix != "" {
			if !slices.Contains(suffixes, suffix) {
				suffixes = append(suffixes, suffix)
			}
			continue
		}
		if !config.IsWildcardPattern(pattern) {
			exact = append(exact, pattern)
		}
	}
	return exact, suffixes
}

// entries returns a session's IP entries and CIDR entries, each in canonical
// form. A /32 is an IP entry, never a CIDR.
func (sp sessionPatterns) entries() (ips []netip.Addr, prefixes []netip.Prefix) {
	for _, pattern := range sp.patterns {
		e, err := config.ParseEntry(pattern)
		if err != nil {
			continue
		}
		switch e.Kind {
		case config.EntryIP:
			ips = append(ips, e.Addr)
		case config.EntryCIDR:
			prefixes = append(prefixes, e.Prefix)
		}
	}
	return ips, prefixes
}

// wildcardOwner is a resolver-file suffix and the session whose lookups it
// serves.
type wildcardOwner struct {
	suffix string
	owner  *tunnelSession
}

// wildcardOwners lists every wildcard suffix in play with its owner: the
// highest-priority session that wants it.
func wildcardOwners(assign []sessionPatterns) []wildcardOwner {
	var out []wildcardOwner
	seen := make(map[string]bool)
	for _, sp := range assign {
		_, suffixes := sp.split()
		for _, suffix := range suffixes {
			if !seen[suffix] {
				seen[suffix] = true
				out = append(out, wildcardOwner{suffix: suffix, owner: sp.session})
			}
		}
	}
	return out
}

// ownerFor returns the session a wildcard-matched name routes through right
// now, or nil when it goes direct or no wildcard of its owning list matches.
func (d *Daemon) ownerFor(name string) *tunnelSession {
	return d.store.Policy().wildcardOwnerOf(d.sessionList(), name)
}

// hasWildcardPatterns reports whether any configured pattern is a wildcard.
func (d *Daemon) hasWildcardPatterns() bool {
	return d.store.Policy().hasWildcards
}

// matchesWildcard reports whether name falls under a wildcard pattern that a
// connected tunnel routes. The forwarder calls it for every query.
func (d *Daemon) matchesWildcard(name string) bool {
	return d.ownerFor(name) != nil
}

// upstreamsFor lists the server groups to resolve name through: the owning
// tunnel's, whose VPN DNS is a group of its own ahead of the configured servers
// when dns.use_vpn_dns is on, and the configured servers otherwise.
func (d *Daemon) upstreamsFor(name string) [][]string {
	if name != "" {
		if s := d.ownerFor(name); s != nil {
			return s.resolver.UpstreamGroups()
		}
	}
	return d.resolver.UpstreamGroups()
}

// tearDownSessionRoutes gives a session's routes back: it deactivates the
// split tunnel (which removes the session's journal once everything is
// undone) and removes every route the session added. The caller must hold
// mutationMu.
func (d *Daemon) tearDownSessionRoutes(s *tunnelSession) error {
	s.cancel()
	return deactivateAndCleanup(s.manager)
}

func deactivateAndCleanup(m *route.Manager) error {
	// The default VPN's routes go with the tunnel they lead through.
	catchAllErr := m.SetCatchAll(false)
	deactivateErr := m.DeactivateInvertedSplitTunnel()
	cleanupErr := m.Cleanup()
	return errors.Join(catchAllErr, deactivateErr, cleanupErr)
}

// sessionDNSKnown reports whether s's VPN DNS servers are settled: a detected
// tunnel has published some, or an owned session has decided which of its
// profile's servers it routes (possibly none, when each was refused).
func (d *Daemon) sessionDNSKnown(s *tunnelSession) bool {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	return len(s.vpnDNS) > 0 || (s.owned && s.vpnDNSSettled)
}

// rememberLearned records addresses a wildcard lookup returned for s, so the
// next sync keeps their routes until they expire. Over the cap it drops the
// entries closest to expiry and returns them, so the caller can remove their
// routes.
func (d *Daemon) rememberLearned(s *tunnelSession, name string, ips []netip.Addr, ttl time.Duration) map[netip.Addr]string {
	lifetime := max(ttl, learnedRouteMinLifetime)
	expires := time.Now().Add(lifetime)

	d.learnedMu.Lock()
	defer d.learnedMu.Unlock()
	for _, ip := range ips {
		s.learned[ip] = learnedRoute{domain: name, expires: expires}
	}
	var evicted map[netip.Addr]string
	for len(s.learned) > maxLearnedRoutes {
		var oldest netip.Addr
		var oldestExpiry time.Time
		for ip, lr := range s.learned {
			if !oldest.IsValid() || lr.expires.Before(oldestExpiry) {
				oldest, oldestExpiry = ip, lr.expires
			}
		}
		if evicted == nil {
			evicted = make(map[netip.Addr]string)
		}
		evicted[oldest] = s.learned[oldest].domain
		delete(s.learned, oldest)
	}
	return evicted
}

// learnedSnapshot returns s's unexpired learned addresses and drops the rest.
func (d *Daemon) learnedSnapshot(s *tunnelSession) map[netip.Addr]string {
	now := time.Now()
	d.learnedMu.Lock()
	defer d.learnedMu.Unlock()
	out := make(map[netip.Addr]string, len(s.learned))
	for ip, lr := range s.learned {
		if now.After(lr.expires) {
			delete(s.learned, ip)
			continue
		}
		out[ip] = lr.domain
	}
	return out
}

// forgetLearned drops one learned address of s.
func (d *Daemon) forgetLearned(s *tunnelSession, ip netip.Addr) {
	d.learnedMu.Lock()
	defer d.learnedMu.Unlock()
	delete(s.learned, ip)
}
