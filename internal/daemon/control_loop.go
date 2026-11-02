package daemon

import (
	"time"
)

const (
	// controlTick is how often the control loop looks for work that has come due.
	controlTick = time.Second
	// gatewayCheckEvery is how often the LAN gateway is read again, which is what
	// notices a change of network.
	gatewayCheckEvery = 5 * time.Second
	// enforceBurst, enforceBurstEvery and enforceEvery pace each tunnel's enforcement.
	// Clients re-assert most often right after connecting.
	enforceBurst      = 45 * time.Second
	enforceBurstEvery = 2 * time.Second
	enforceEvery      = 10 * time.Second
)

// controlLoop keeps what was decided in place against what the outside world does: a
// client re-adding its routes, a change of network, a route the kernel dropped. Every
// such check runs here, one at a time, so nothing but this goroutine has to wake up for
// them and they never pile up behind the mutation lock. Syncs are separate, because one
// can wait seconds on a DNS server.
func (d *Daemon) controlLoop(gen *generation) {
	ticker := time.NewTicker(d.hooks.controlEvery)
	defer ticker.Stop()
	var nextGateway, nextDefaultVPN time.Time
	for {
		select {
		case <-gen.ctx.Done():
			return
		case now := <-ticker.C:
			if !now.Before(nextGateway) {
				nextGateway = now.Add(gatewayCheckEvery)
				d.refreshGateway(gen)
			}
			if !now.Before(nextDefaultVPN) {
				nextDefaultVPN = now.Add(defaultVPNWatchEvery)
				d.watchDefaultVPN(gen)
			}
			d.enforceDueSessions(gen, now)
		}
	}
}

// watchDefaultVPN runs the role's checks that nothing else triggers: a route the
// kernel dropped, a server that moved, a network that came back.
func (d *Daemon) watchDefaultVPN(gen *generation) {
	if d.store.Policy().cfg.Routing.DefaultVPN != "" {
		d.tunnels.refreshTransports()
	}
	d.reconcileDefaultVPN(gen)
}

// enforceDueSessions runs each tunnel's enforcement that has come due.
func (d *Daemon) enforceDueSessions(gen *generation, now time.Time) {
	for _, s := range d.sessionList() {
		since := s.enforcingSince.Load()
		if since == nil || now.Before(s.nextEnforce) {
			continue
		}
		every := enforceEvery
		if now.Sub(*since) < enforceBurst {
			every = enforceBurstEvery
		}
		s.nextEnforce = now.Add(every)
		d.enforceSession(gen, s, now.Sub(*since))
	}
}

// enforceSession keeps one tunnel's split tunnel in place for as long as it stays
// connected: it removes catch-all routes the client re-adds and takes the default route
// back if the client reclaims it, for example after a network change or wake from sleep.
// It also keeps looking for the VPN's DNS servers, which some clients (wg-quick) publish
// only after their routes. connected is how long ago enforcement began.
func (d *Daemon) enforceSession(gen *generation, s *tunnelSession, connected time.Duration) {
	if !d.mayMutateSession(gen, s) || !d.tunnelUp(gen, s) {
		return
	}
	ran, err := d.withSessionMutation(gen, s, s.manager.EnforceSplitTunnel)
	if ran {
		errText := ""
		if err != nil {
			errText = err.Error()
		}
		if errText != s.enforceErr && errText != "" {
			d.logger.Warn("could not keep the split tunnel in place", "interface", s.iface, "error", err)
		}
		s.enforceErr = errText
	}

	hadDNS := d.sessionDNSKnown(s)
	d.ensureVPNDNS(gen, s, connected >= vpnDNSGuessDelay)
	if !hadDNS && d.sessionDNSKnown(s) {
		d.TriggerSync()
	}
}

// refreshGateway follows a change of network: Wi-Fi to another network, Ethernet
// plugged in or out. While a detected tunnel is up its enforcement does this instead.
func (d *Daemon) refreshGateway(gen *generation) {
	if !d.mayMutate(gen) || d.gatewayRefreshPaused(gen) {
		return
	}
	var refreshed bool
	ran, err := d.withGenerationMutation(gen, func() error {
		var refreshErr error
		refreshed, refreshErr = d.routeManager.RefreshGateway()
		return refreshErr
	})
	switch {
	case !ran:
	case err != nil:
		d.logger.Error("gateway refresh failed", "error", err)
	case refreshed:
		d.logger.Info("network changed, gateway refreshed", "new_gateway", d.routeManager.GetOriginalGateway())
	}
}
