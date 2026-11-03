package daemon

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/quocln/routewise/internal/activity"
)

// syncPlan is what one session should route after a sync.
type syncPlan struct {
	session *tunnelSession
	// desired maps each address the session's exact domains resolved to the
	// domain it serves.
	desired map[netip.Addr]string
	// entryIPs and entryNets are the IP and CIDR entries of the session's
	// lists. They need no resolution, and are checked against the LAN when the
	// plan is applied.
	entryIPs  []netip.Addr
	entryNets []netip.Prefix
	// resolved is false when the session's exact domains could not be
	// resolved, in which case its routes are left as they are.
	resolved bool
}

// maxSyncAttempts bounds how often one sync recomputes its plan because the
// sessions or the config changed while it resolved names. After that the sync
// asks for another pass instead of spinning.
const maxSyncAttempts = 3

const (
	// syncSliceBudget bounds how long one pass of a sync keeps mutationMu while
	// it changes routes. Where a change costs a process start, a sync of
	// hundreds of routes would otherwise hold it for seconds.
	syncSliceBudget = 100 * time.Millisecond
	// syncYield is the pause between passes, long enough for a goroutine woken
	// by the release to take the lock before the sync asks for it again.
	syncYield = 2 * time.Millisecond
)

// syncRoutes resolves each tunnel's exact domains through that tunnel's
// resolver, merges in the addresses wildcard lookups have learned, hands each
// address to one tunnel, updates every tunnel's routes, and points resolver
// files for wildcard domains at the forwarder.
//
// A domain routes through the tunnel of the VPN client whose list holds it;
// the Any VPN list routes through the highest-priority healthy detected tunnel,
// never through a built-in profile. A tunnel that is not connected, or a
// built-in one not proven to work, contributes nothing, so its domains go
// direct.
//
// Syncs are serialized: only one plan is computed and applied at a time. A plan
// is applied only if the sessions and config revision it was built from are
// still current once mutationMu is held; otherwise it is discarded and
// recomputed, so a slow sync can never overwrite a newer one.
func (d *Daemon) syncRoutes(gen *generation) {
	d.syncMu.Lock()
	defer d.syncMu.Unlock()

	for attempt := 0; attempt < maxSyncAttempts; attempt++ {
		if !d.mayMutate(gen) {
			return
		}

		// The default VPN moves first: resolving a name can go through its routes,
		// and would wait on a tunnel that just died.
		d.reconcileDefaultVPN(gen)
		d.resolveExceptions(gen)

		// Read before the sessions: a health change after this point makes the
		// plan stale, and topologyUnchangedLocked discards it.
		epoch := d.healthEpoch.Load()
		sessions := d.sessionList()
		pol := d.store.Policy()
		revision := pol.revision
		assign := assignPatterns(pol, sessions)

		plans := make([]*syncPlan, 0, len(assign))
		for _, sp := range assign {
			// VPN DNS servers may be published a moment after the tunnel's
			// routes, so keep trying until they are found.
			d.ensureVPNDNS(gen, sp.session, false)
			plans = append(plans, d.resolvePlan(gen, sp))
		}

		var total int
		stale := false
		firstPass := true
		for {
			// A pass applies changes for at most syncSliceBudget and reports
			// that more are left; the lock is released between passes so a
			// DNS answer waiting to route its addresses is not held up for
			// the whole of a large sync. Each pass recomputes from the live
			// state, so the sessions and config are checked again every time.
			var more bool
			ran, _ := d.withGenerationMutation(gen, func() error {
				if !d.topologyUnchangedLocked(sessions, revision, epoch) {
					stale = true
					return nil
				}
				if firstPass {
					d.refreshResolverFilesLocked()
					firstPass = false
				}
				total, more = d.applyPlansLocked(gen, sessions, pol, plans)
				return nil
			})
			if !ran {
				return
			}
			if stale || !more {
				break
			}
			// Let a waiter that was woken by the release take the lock.
			time.Sleep(syncYield)
		}
		if !stale {
			d.logger.Info("routes synced", "tunnels", len(plans), "count", total)
			return
		}
		d.logger.Debug("sessions or config changed during a sync; recomputing", "attempt", attempt+1)
	}
	d.logger.Warn("sessions or config kept changing during route sync; will sync again")
	d.TriggerSync()
}

// topologyUnchangedLocked reports whether the registered sessions, in priority
// order, the config revision, and the built-in tunnels' health are still what a
// plan was built from. The caller must hold mutationMu, which is what keeps the
// answer true while the plan is applied.
func (d *Daemon) topologyUnchangedLocked(sessions []*tunnelSession, revision, epoch uint64) bool {
	return d.store.Revision() == revision && d.healthEpoch.Load() == epoch && slices.Equal(d.sessionList(), sessions)
}

// resolvePlan resolves a session's exact domains through the session's own
// resolver, so a name only the VPN's DNS knows resolves the way that VPN
// answers.
func (d *Daemon) resolvePlan(gen *generation, sp sessionPatterns) *syncPlan {
	plan := &syncPlan{session: sp.session, desired: make(map[netip.Addr]string), resolved: true}
	plan.entryIPs, plan.entryNets = sp.entries()
	exact, _ := sp.split()
	if len(exact) == 0 {
		return plan
	}

	results, err := d.hooks.resolveExact(gen.ctx, sp.session, exact)
	if err != nil {
		d.logger.Error("DNS resolution failed", "interface", sp.session.iface, "error", err)
		plan.resolved = false
	}
	for domain, ips := range results {
		d.logger.Debug("resolved domain", "domain", domain, "ips", len(ips))
		var named []netip.Addr
		for _, ip := range ips {
			addr := netIPToNetipAddr(ip)
			if !addr.IsValid() {
				continue
			}
			named = append(named, addr)
			// When two domains share an address, keep the first one seen as
			// the label shown for the route.
			if _, exists := plan.desired[addr]; !exists {
				plan.desired[addr] = domain
			}
		}
		// The resolver does not report TTLs, so the name lives its minimum.
		d.names.Add(domain, named, 0)
	}
	if len(plan.desired) == 0 {
		// Every exact domain failed to resolve. Keep the routes already
		// installed rather than tearing them down over a DNS outage.
		d.logger.Warn("no IPs resolved from domains", "interface", sp.session.iface)
		plan.resolved = false
	}
	return plan
}

// applyPlansLocked decides which tunnel gets each address and updates every
// tunnel's routes. It returns the number of routes wanted, and whether it
// stopped at syncSliceBudget with changes left, in which case the caller calls
// it again. sessions are every registered session in priority order and pol is
// the policy the plans were built from. The caller must hold mutationMu.
//
// Two tunnels can want one address (a CDN shared by two domain lists) or one
// network (the same CIDR in two lists). The higher-priority tunnel wins and
// the other records a refusal. A kernel route table has one entry per
// destination, so an address or network must never be added for one tunnel
// while another still holds it: tunnels that give one up are synced first, and
// only then do the others take it.
//
// IP and CIDR entries join the same contest. An IP entry is a host route like
// any resolved address (and labels it with the entry); a CIDR is a network
// route, claimed by prefix. Both are first checked against the LAN and refused
// when they would cut this machine off from it.
func (d *Daemon) applyPlansLocked(gen *generation, sessions []*tunnelSession, pol *routingPolicy, plans []*syncPlan) (total int, more bool) {
	planFor := make(map[*tunnelSession]*syncPlan, len(plans))
	for _, p := range plans {
		planFor[p.session] = p
	}
	guard := d.newLANGuard()

	// A list change (an edit, an import, an allow or revoke, a priority change)
	// can move a name to another tunnel or send it direct. Learned routes
	// follow the current ownership now rather than at expiry.
	d.reassignLearnedLocked(pol, sessions)

	// What each session holds and wants. Learned addresses are merged inside the
	// critical section: one learned after this point is added by its own mutation
	// after this sync, so a sync never removes a route a lookup has just installed.
	states := make([]sessionRouteState, 0, len(sessions))
	for _, s := range sessions { // priority order
		p := planFor[s]
		state := sessionRouteState{session: s, live: p != nil && p.resolved && d.mayMutateSession(gen, s)}
		active := s.manager.GetActiveRoutes()
		state.heldHosts = make(map[netip.Addr]bool, len(active))
		for ip, info := range active {
			state.heldHosts[ip] = info.IsProtected
		}
		for prefix := range s.manager.GetNetRoutes() {
			state.heldNets = append(state.heldNets, prefix)
		}
		if state.live {
			desired := p.desired
			for ip, domain := range d.learnedSnapshot(s) {
				if _, exists := desired[ip]; !exists {
					desired[ip] = domain
				}
			}
			entryIPs, entryNets := d.screenEntries(s, p, guard, desired)
			for _, ip := range entryIPs {
				desired[ip] = ip.String()
			}
			state.wantHosts, state.wantNets = desired, entryNets
		}
		states = append(states, state)
	}

	routePlans, deferred := planRoutes(states)
	for _, plan := range routePlans {
		s := plan.session
		conflicts := make(map[netip.Addr]string, len(plan.hostConflicts))
		for ip, winner := range plan.hostConflicts {
			conflicts[ip] = winner.iface
			d.noteConflict(s, winner, ip, planFor[s].desired[ip])
		}
		d.setConflicts(s, conflicts)
		netConflicts := make(map[netip.Prefix]string, len(plan.netConflicts))
		for prefix, winner := range plan.netConflicts {
			netConflicts[prefix] = winner.iface
			d.noteNetConflict(s, winner, prefix, prefix.String())
		}
		d.setNetConflicts(s, netConflicts)
		total += len(plan.hosts) + len(plan.nets)
	}

	// A list takes what it wants from the default VPN's exceptions, which the kernel
	// would otherwise refuse it, or which would outrank its network route.
	d.defaultVPN.yieldPlannedLocked(routePlans)

	for _, plan := range routePlans {
		if d.syncSession(plan.session, plan.firstHosts, plan.firstNets) {
			more = true
		}
	}
	// Addresses a tunnel gives up are released before another takes them, so
	// the second round waits until the first has finished everywhere.
	if more {
		return total, true
	}
	if deferred {
		for _, plan := range routePlans {
			if d.syncSession(plan.session, plan.hosts, plan.nets) {
				more = true
			}
		}
	}
	if !more {
		// What a VPN just gave up is the exceptions' to take.
		if problem := d.defaultVPN.refreshExceptionsLocked(); problem != "" {
			d.logger.Warn("default VPN exceptions", "problem", problem)
		}
	}
	return total, more
}

// reassignLearnedLocked moves each learned address to the session that owns its
// name now. A name whose owner changed is handed to the new owner, with its
// expiry, unless the address would be unsafe there; a name that should now go
// direct is dropped, which the next sync turns into a route removal. The
// caller must hold mutationMu.
func (d *Daemon) reassignLearnedLocked(pol *routingPolicy, sessions []*tunnelSession) {
	type entry struct {
		from   *tunnelSession
		ip     netip.Addr
		route  learnedRoute
		target *tunnelSession
	}
	var all []entry
	d.learnedMu.Lock()
	for _, s := range sessions {
		for ip, lr := range s.learned {
			all = append(all, entry{from: s, ip: ip, route: lr})
		}
	}
	d.learnedMu.Unlock()

	// Ownership and address safety are decided with no learned-map lock held;
	// mutationMu keeps the sessions and the config steady meanwhile. The LAN
	// is read once, and each target tunnel's checks are built once.
	var guard lanGuard
	haveGuard := false
	vetters := make(map[*tunnelSession]answerVetter)
	var moves []entry
	for _, e := range all {
		owner := pol.wildcardOwnerOf(sessions, e.route.domain)
		if owner == e.from {
			continue
		}
		if owner != nil {
			if !haveGuard {
				guard, haveGuard = d.newLANGuard(), true
			}
			vet, ok := vetters[owner]
			if !ok {
				vet = d.newAnswerVetter(owner, guard)
				vetters[owner] = vet
			}
			if vet.unsafeAddr(e.ip) != "" {
				owner = nil
			}
		}
		e.target = owner
		moves = append(moves, e)
	}
	if len(moves) == 0 {
		return
	}

	d.learnedMu.Lock()
	defer d.learnedMu.Unlock()
	for _, e := range moves {
		delete(e.from.learned, e.ip)
		if e.target == nil {
			continue
		}
		if _, exists := e.target.learned[e.ip]; !exists {
			e.target.learned[e.ip] = e.route
		}
	}
}

// syncSession brings one tunnel's routes to desired, for at most
// syncSliceBudget, and reports whether changes are left. A failure is logged
// only by the pass that finishes: an address that could not be added is tried
// again by the next pass and would be reported once per pass.
func (d *Daemon) syncSession(s *tunnelSession, desired map[netip.Addr]string, desiredNets map[netip.Prefix]string) (more bool) {
	more, err := s.manager.SyncRoutesWithin(desired, syncSliceBudget)
	if err != nil && !more {
		d.logger.Error("route sync failed", "interface", s.iface, "error", err)
	}
	if err := s.manager.SyncPrefixes(desiredNets); err != nil {
		d.logger.Error("network route sync failed", "interface", s.iface, "error", err)
	}
	return more
}

// noteConflict records, once per address and winner, that a lower-priority
// tunnel was refused an address a higher-priority one already routes.
func (d *Daemon) noteConflict(loser, winner *tunnelSession, ip netip.Addr, domain string) {
	d.dnsMu.Lock()
	known := loser.conflicts[ip] == winner.iface
	loser.conflicts[ip] = winner.iface
	d.dnsMu.Unlock()
	if known {
		return
	}

	d.logger.Warn("address already routed through another VPN",
		"domain", domain, "ip", ip, "winner", winner.iface, "refused", loser.iface)
	d.recordActivity(activity.Event{
		Kind:      activity.KindRefused,
		Name:      domain,
		Addresses: []activity.Address{{IP: ip.String(), Verdict: activity.ViaVPN}},
		Interface: winner.iface,
		Detail: fmt.Sprintf("already routed through %s; not routed through %s, which has lower priority",
			describeTunnel(winner), describeTunnel(loser)),
	})
}

// setConflicts replaces the addresses s lost in the sync that just ran.
func (d *Daemon) setConflicts(s *tunnelSession, conflicts map[netip.Addr]string) {
	d.dnsMu.Lock()
	defer d.dnsMu.Unlock()
	s.conflicts = conflicts
}

// describeTunnel names a tunnel the way a person knows it: its interface and
// the VPN client that owns it.
func describeTunnel(s *tunnelSession) string {
	name := s.client.Name
	if name == "" {
		name = "unidentified client"
	}
	return fmt.Sprintf("%s (%s)", s.iface, name)
}
