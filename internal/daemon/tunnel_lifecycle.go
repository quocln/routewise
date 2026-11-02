package daemon

import (
	"slices"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/monitor"
	"github.com/quocln/routewise/internal/vpnclient"
)

// onVPNConnect starts managing a tunnel that just connected: it builds the
// tunnel's session, activates its inverted split tunnel, routes its DNS
// servers, and syncs. Only this tunnel's catch-alls are removed; another
// managed tunnel's routes are left alone.
func (d *Daemon) onVPNConnect(gen *generation, event monitor.VPNEvent) {
	if d.tunnels.isOwnedInterface(event.Interface) || !d.mayMutate(gen) {
		return
	}
	// A tunnel that reappears under a name RouteWise still tracks is a new
	// tunnel: give back what the old one held first.
	if d.sessions.get(event.Interface) != nil {
		d.onVPNDisconnect(gen, event.Interface)
		if !d.mayMutate(gen) {
			return
		}
	}
	d.rescanDNSWatch()

	// Every connect is a new detection: ask who owns the interface again
	// rather than trust an earlier answer for a name macOS may have reused. A
	// client that is not allowed after all (the admission check saw a stale
	// owner) is left alone, as the monitor would have left it.
	client, err := d.identifyFresh(event.Interface)
	if err != nil {
		d.logger.Warn("could not identify the VPN client", "interface", event.Interface, "error", err)
		client = vpnclient.Client{}
	} else if !slices.Contains(d.store.Policy().allowed, client.ID) {
		d.logger.Warn("not managing the tunnel: its client is not allowed",
			"interface", event.Interface, "client", client.Name, "path", client.ID)
		d.notePending(event.Interface, client, nil)
		return
	}
	s, err := d.newTunnelSession(gen, event.Interface, event.Gateway, client)
	if err != nil {
		d.logger.Error("could not start managing the tunnel", "interface", event.Interface, "error", err)
		return
	}
	d.recordActivity(activity.Event{Kind: activity.KindVPN, Name: client.Name, Interface: event.Interface, Detail: "connected"})

	additive := s.manager.Additive()
	ran, err := d.withGenerationMutation(gen, func() error {
		d.sessions.add(s)
		if additive {
			return nil
		}
		return s.manager.ActivateInvertedSplitTunnel()
	})
	if !ran {
		s.cancel()
		s.resolver.Close()
		return
	}

	if additive {
		d.logger.Info("additive routing mode - preserving existing VPN routes",
			"interface", event.Interface)
	} else if err != nil {
		d.logger.Error("failed to activate split tunnel", "interface", event.Interface, "error", err)
	} else {
		d.logger.Info("inverted split tunnel activated", "interface", event.Interface)

		// Enforcement starts only after this session successfully activated.
		now := time.Now()
		s.enforcingSince.Store(&now)
	}

	// A VPN that was already up when the daemon started put its servers into
	// the baseline, which would hide them from the guess. Without a clean
	// baseline, rely on the other checks alone.
	if time.Since(d.startedAt) < dnsBaselineGrace {
		d.dnsMu.Lock()
		d.dnsBaseline = nil
		d.dnsMu.Unlock()
	}

	// Route the VPN's DNS servers before the first sync resolves through them.
	d.ensureVPNDNS(gen, s, false)

	// Sync routes for configured domains. The Any VPN list may move to this
	// tunnel if it outranks the one that held it.
	d.syncRoutes(gen)
}

// onVPNDisconnect stops managing one tunnel: it forgets the tunnel's DNS
// state, gives its routes back, and re-syncs the tunnels that remain, since
// the Any VPN list may now belong to another one.
func (d *Daemon) onVPNDisconnect(gen *generation, iface string) {
	if d.tunnels.isOwnedInterface(iface) {
		return
	}
	d.rescanDNSWatch()
	// The name may be reused at once by a different VPN, which must be
	// identified from scratch.
	d.forgetClient(iface)
	s := d.sessions.get(iface)
	if s == nil {
		return
	}
	d.releaseSession(gen, s)
}

// releaseSession stops managing one session, detected or owned: it records
// the disconnect, forgets the session's DNS state, gives its routes back, and
// re-syncs the tunnels that remain, since the Any VPN list may now belong to
// another one.
func (d *Daemon) releaseSession(gen *generation, s *tunnelSession) {
	iface := s.iface
	d.recordActivity(activity.Event{Kind: activity.KindVPN, Name: s.client.Name, Interface: iface, Detail: "disconnected"})

	// Unregistering the session, rewriting the resolver files for the tunnels
	// that remain, and forgetting its VPN DNS and learned addresses touch no
	// routes, so they happen even while route state is degraded. Removing the
	// session and giving its routes back are one critical section: a wildcard
	// answer that lands between the two would otherwise see neither the
	// session nor its routes still in the kernel table, and could take an
	// address that is about to be deleted.
	var (
		cleanupRan bool
		cleanupErr error
	)
	d.mutationMu.Lock()
	owned := d.ownsGeneration(gen)
	if owned {
		d.sessions.remove(s)
		s.cancel()
		d.refreshResolverFilesLocked()
		if d.mayMutate(gen) {
			cleanupRan = true
			cleanupErr = deactivateAndCleanup(s.manager)
		}
	}
	d.mutationMu.Unlock()
	if !owned {
		return
	}

	switch {
	case !cleanupRan:
		// Route state is unverified, or shutdown began; either way the
		// session still owns routes. Keep them for the shutdown pass.
		d.sessions.retire(s.manager)
	case cleanupErr != nil:
		d.logger.Error("VPN disconnect cleanup failed", "interface", iface, "error", cleanupErr)
		d.sessions.retire(s.manager)
	default:
		d.logger.Info("routes cleaned up", "interface", iface)
	}
	s.resolver.Close()

	// With every detected tunnel gone, the configured servers are the
	// network's own.
	if !d.sessions.hasDetected() {
		d.captureDNSBaseline(gen.ctx)
	}
	d.rescanDNSWatch()
	d.syncRoutes(gen)
}

// tunnelUp reports whether the monitor still sees s's interface as a managed
// tunnel. The monitor learns of a disconnect before the event reaches the
// daemon, so this closes the window in which a stale session could still
// publish state.
func (d *Daemon) tunnelUp(gen *generation, s *tunnelSession) bool {
	// The monitor never sees a tunnel the helper owns; its session is live for
	// as long as it is registered.
	if s.owned {
		return d.sessions.isRegistered(s)
	}
	for _, t := range gen.monitor.Tunnels() {
		if t.Interface == s.iface {
			return true
		}
	}
	return false
}

// dnsRefreshLoop syncs routes when one is requested (see TriggerSync) and, as a
// safety net, every dns.cache_ttl.
func (d *Daemon) dnsRefreshLoop(gen *generation) {
	ticker := time.NewTicker(d.dnsCacheTTL)
	defer ticker.Stop()

	for {
		select {
		case <-gen.ctx.Done():
			return
		case <-ticker.C:
			if d.sessions.has() {
				d.logger.Debug("refreshing DNS and routes")
				d.syncRoutes(gen)
			}
		case <-d.syncTrigger:
			if d.sessions.has() {
				d.logger.Debug("triggered sync from API")
				d.syncRoutes(gen)
			}
		}
	}
}

// gatewayRefreshPaused reports whether the LAN gateway must not be re-read now.
// It is paused only while a detected tunnel is up: that tunnel's own enforcer
// re-reads the gateway when it reclaims the default route, and reading it from
// the routing table under a VPN's default route would give the VPN's gateway. A
// built-in tunnel never changes the default route and has no enforcer, so it
// does not pause the refresh: the gateway still has to follow a change of
// network.
func (d *Daemon) gatewayRefreshPaused(gen *generation) bool {
	return gen.monitor.IsConnected() || d.sessions.hasDetected()
}
