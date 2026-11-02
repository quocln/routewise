package daemon

import (
	"net/netip"
	"path/filepath"

	"fmt"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/route"
	"slices"
)

// The daemon's side of the default VPN: the settings it stores and the answers
// defaultVPNController asks of it.

// SetDefaultVPN changes the default VPN and its fallback, saves them, and moves the
// routes at the next sync. A nil argument keeps the stored value; an empty one clears
// it. Clearing the default clears the fallback too.
func (d *Daemon) SetDefaultVPN(client, fallback *string) error {
	d.mutationMu.Lock()
	defer d.mutationMu.Unlock()

	pol := d.store.Policy()
	next, nextFallback := pol.cfg.Routing.DefaultVPN, pol.cfg.Routing.DefaultVPNFallback
	if client != nil {
		next = *client
	}
	if fallback != nil {
		nextFallback = *fallback
	}
	if next == "" {
		if fallback != nil && *fallback != "" {
			return fmt.Errorf("%w: a fallback needs a default VPN", api.ErrRejected)
		}
		nextFallback = ""
	}
	if next != "" && pol.cfg.Routing.Mode == config.RoutingModeAdditive {
		return fmt.Errorf("%w: a default VPN needs inverted routing mode", api.ErrRejected)
	}
	for _, id := range []string{next, nextFallback} {
		if id != "" && !slices.Contains(pol.allowed, id) {
			return fmt.Errorf("%w: %s is not an allowed VPN", api.ErrRejected, id)
		}
	}
	if next != "" && next == nextFallback {
		return fmt.Errorf("%w: the default VPN cannot be its own fallback", api.ErrRejected)
	}
	if _, err := d.store.SetDefaultVPN(next, nextFallback); err != nil {
		return classifyConfigError(err)
	}
	d.logger.Info("default VPN setting changed", "default_vpn", next, "fallback", nextFallback)
	d.TriggerSync()
	return nil
}

func (d *Daemon) defaultVPNJournalPath() string {
	return filepath.Join(filepath.Dir(d.routeManager.JournalPath()), defaultVPNJournalName)
}

// reconcileDefaultVPN is reconcileDefaultVPNLocked for a caller without the lock.
func (d *Daemon) reconcileDefaultVPN(gen *generation) {
	d.mutationMu.Lock()
	defer d.mutationMu.Unlock()
	d.defaultVPN.reconcileLocked(gen)
}

// DefaultVPNStatus reports the setting and who carries the traffic now, or nil while no
// default VPN is set.
func (d *Daemon) DefaultVPNStatus() *api.DefaultVPNStatus { return d.defaultVPN.status() }

func (d *Daemon) policy() *routingPolicy             { return d.store.Policy() }
func (d *Daemon) isRegistered(s *tunnelSession) bool { return d.sessions.isRegistered(s) }
func (d *Daemon) routeTable() route.Table            { return d.routeManager.Table() }
func (d *Daemon) localInterface() string             { return d.routeManager.GetLocalInterface() }
func (d *Daemon) localPrefixes() []netip.Prefix      { return d.hooks.localPrefixes() }
func (d *Daemon) serverKnown(profileID string) bool  { return d.tunnels.serverKnown(profileID) }
func (d *Daemon) ipv6TransportNames() []string       { return d.tunnels.ipv6TransportNames(d.store.Policy()) }
func (d *Daemon) ipv6Allowed() bool                  { return d.allowIPv6.Load() }
