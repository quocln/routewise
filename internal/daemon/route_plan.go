package daemon

import "net/netip"

// sessionRouteState is what one session holds and wants, as the sync gathered it. It
// is all planRoutes looks at, so who gets which route can be decided, and tested,
// without a kernel, a lock or a clock.
type sessionRouteState struct {
	session *tunnelSession
	// live is false for a session that cannot be synced now. It keeps everything it
	// holds, and no address it holds is handed to another.
	live bool
	// heldHosts are the host routes the session has, true for a protected one (its VPN
	// DNS), which it keeps whatever happens. heldNets are its network routes.
	heldHosts map[netip.Addr]bool
	heldNets  []netip.Prefix
	// wantHosts maps each address the session should route to the domain it serves.
	// wantNets are the networks it should route.
	wantHosts map[netip.Addr]string
	wantNets  []netip.Prefix
}

// sessionRoutePlan is what one live session should route.
type sessionRoutePlan struct {
	session *tunnelSession
	// hosts and nets are where the session ends up.
	hosts map[netip.Addr]string
	nets  map[netip.Prefix]string
	// firstHosts and firstNets leave out what another session still holds. A kernel
	// table has one entry per destination, so those come only after the holder let go.
	firstHosts map[netip.Addr]string
	firstNets  map[netip.Prefix]string
	// hostConflicts and netConflicts name who won what this session asked for.
	hostConflicts map[netip.Addr]*tunnelSession
	netConflicts  map[netip.Prefix]*tunnelSession
}

// planRoutes decides which session gets each address and network. states must be in
// priority order: when two sessions want one destination, the first wins and the other
// records a conflict. deferred reports that some session must wait for another to give
// a destination up, so a second round is needed.
func planRoutes(states []sessionRouteState) (plans []sessionRoutePlan, deferred bool) {
	claimedHosts := make(map[netip.Addr]*tunnelSession)
	heldHosts := make(map[netip.Addr]*tunnelSession)
	claimedNets := make(map[netip.Prefix]*tunnelSession)
	heldNets := make(map[netip.Prefix]*tunnelSession)
	for _, state := range states {
		for ip, protected := range state.heldHosts {
			heldHosts[ip] = state.session
			if protected || !state.live {
				claimedHosts[ip] = state.session
			}
		}
		for _, prefix := range state.heldNets {
			heldNets[prefix] = state.session
			if !state.live {
				claimedNets[prefix] = state.session
			}
		}
	}

	for _, state := range states {
		if !state.live {
			continue
		}
		s := state.session
		plan := sessionRoutePlan{
			session:       s,
			hosts:         make(map[netip.Addr]string, len(state.wantHosts)),
			nets:          make(map[netip.Prefix]string, len(state.wantNets)),
			firstHosts:    make(map[netip.Addr]string, len(state.wantHosts)),
			firstNets:     make(map[netip.Prefix]string, len(state.wantNets)),
			hostConflicts: make(map[netip.Addr]*tunnelSession),
			netConflicts:  make(map[netip.Prefix]*tunnelSession),
		}
		for ip, domain := range state.wantHosts {
			if winner, taken := claimedHosts[ip]; taken && winner != s {
				plan.hostConflicts[ip] = winner
				continue
			}
			claimedHosts[ip] = s
			plan.hosts[ip] = domain
			if holder, held := heldHosts[ip]; held && holder != s {
				deferred = true
				continue
			}
			plan.firstHosts[ip] = domain
		}
		for _, prefix := range state.wantNets {
			if winner, taken := claimedNets[prefix]; taken && winner != s {
				plan.netConflicts[prefix] = winner
				continue
			}
			claimedNets[prefix] = s
			entry := prefix.String()
			plan.nets[prefix] = entry
			if holder, held := heldNets[prefix]; held && holder != s {
				deferred = true
				continue
			}
			plan.firstNets[prefix] = entry
		}
		plans = append(plans, plan)
	}
	return plans, deferred
}
