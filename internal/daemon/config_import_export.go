package daemon

import (
	"fmt"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
)

// ExportConfig returns the routing configuration in its portable form.
func (d *Daemon) ExportConfig() config.Export {
	cfg, _ := d.store.Snapshot()
	return config.NewExport(cfg, time.Now())
}

// ImportConfig replaces the routing configuration with an export, applying
// what it can at once: domain lists and allowed VPN clients take effect on
// the next sync and monitor check, and dns.use_vpn_dns and routing.allow_ipv6 switch immediately.
// It reports whether DNS servers, cache TTL, or routing mode changed, which
// the helper only reads at start.
func (d *Daemon) ImportConfig(e config.Export) (restartRequired bool, err error) {
	current, next, err := d.replaceConfig(e)
	if err != nil {
		return false, err
	}
	// History settings take effect now; the purge does DB I/O, so it runs
	// after every lock is released.
	d.applyHistorySettings(next.History.Enabled, next.History.RetentionDays)

	d.logger.Info("configuration imported",
		"domains", next.PatternCount(), "vpn_clients", len(next.VPNs), "restart_required", config.NeedsRestart(current, next))
	if gen := d.currentGeneration(); gen != nil {
		gen.monitor.Recheck()
	}
	d.TriggerSync()
	return config.NeedsRestart(current, next), nil
}

// replaceConfig swaps the stored configuration for the export and makes the
// built-in tunnels follow its profiles. It holds profileMu from the snapshot to
// the end of the reconcile: a profile imported in between would be missing from
// the snapshot the reconcile compares against, so the replace would drop it
// without anyone stopping its run or deleting its secret.
func (d *Daemon) replaceConfig(e config.Export) (current, next *config.Config, err error) {
	d.tunnels.profileMu.Lock()
	defer d.tunnels.profileMu.Unlock()

	current, _ = d.store.Snapshot()
	next, err = e.Apply(current)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", api.ErrRejected, err)
	}

	d.mutationMu.Lock()
	if _, err := d.store.Replace(next); err != nil {
		d.mutationMu.Unlock()
		return nil, nil, classifyConfigError(err)
	}
	d.applyUseVPNDNSLocked(next.DNS.UseVPNDNS)
	d.applyAllowIPv6Locked(next.Routing.AllowIPv6)
	d.mutationMu.Unlock()
	// Tunnels follow the imported profiles; this stops and starts tunnels, so
	// it runs holding only profileMu, which is outermost.
	d.reconcileProfiles(current.Profiles, next.Profiles)
	return current, next, nil
}
