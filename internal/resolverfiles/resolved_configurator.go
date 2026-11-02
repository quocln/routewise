package resolverfiles

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// LinkName is the dummy network link that carries RouteWise's split-DNS
// configuration under systemd-resolved. Other packages that read resolved's
// state use it to leave RouteWise's own link out.
const LinkName = "rw-dns"

// restartRetryDelay is how long the restart watcher waits before reconnecting
// to the system bus after losing it.
const restartRetryDelay = 5 * time.Second

// resolvedBackend is the operating-system side of the systemd-resolved
// configurator: the dummy link and resolved's per-link settings. The Linux
// implementation lives in resolved_backend_linux.go; tests supply their own.
type resolvedBackend interface {
	// Configure creates the link if it is missing and makes resolved send
	// routeDomains (and nothing else) to server over it. It is safe to repeat.
	Configure(server netip.AddrPort, routeDomains []string) error
	// Remove deletes the link, and with it everything resolved holds for it.
	// A link that is already gone is not an error.
	Remove() error
	// WatchRestart calls fn each time systemd-resolved appears on the system
	// bus, which is after it started or restarted, until ctx is cancelled.
	WatchRestart(ctx context.Context, fn func()) error
}

var _ Configurator = (*Resolved)(nil)

// Resolved is the systemd-resolved implementation of Configurator. It gives
// resolved one dummy link whose only DNS server is RouteWise's forwarder and
// whose routing domains are the forwarded domains, so resolved sends exactly
// those names to the forwarder and leaves every other name on the system's
// normal path. Resolved forgets per-link settings when it restarts, so a
// watcher re-applies them.
type Resolved struct {
	backend resolvedBackend
	server  netip.AddrPort
	logger  *slog.Logger

	mu      sync.Mutex
	desired []string           // what Apply last asked for; reapplied after a resolved restart
	active  []string           // what resolved is known to be routing
	cancel  context.CancelFunc // stops the restart watcher
}

func newResolved(backend resolvedBackend, server netip.AddrPort) *Resolved {
	return &Resolved{backend: backend, server: server, logger: slog.Default()}
}

// Active returns the domains resolved currently sends to the forwarder.
func (r *Resolved) Active() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.active)
}

// Apply makes the forwarded domains equal to domains. An empty set removes the
// link. Resolved takes every domain, so nothing is ever skipped.
func (r *Resolved) Apply(domains []string) (skipped []string, err error) {
	want := make(map[string]bool, len(domains))
	for _, d := range domains {
		d = strings.ToLower(d)
		if !domainRegex.MatchString(d) {
			return nil, fmt.Errorf("resolver domain %q is not a valid domain name", d)
		}
		want[d] = true
	}
	sorted := sortedKeys(want)

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(sorted) == 0 {
		return nil, r.removeLocked()
	}
	r.desired = sorted
	r.startWatcherLocked()
	if err := r.configureLocked(); err != nil {
		return nil, err
	}
	return nil, nil
}

// RemoveAll deletes the link, including one a previous process left behind,
// and stops watching for resolved restarts.
func (r *Resolved) RemoveAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.removeLocked()
}

// configureLocked pushes the desired state to resolved in full.
func (r *Resolved) configureLocked() error {
	if err := r.backend.Configure(r.server, r.desired); err != nil {
		r.active = nil
		return fmt.Errorf("configure systemd-resolved: %w", err)
	}
	r.active = slices.Clone(r.desired)
	return nil
}

func (r *Resolved) removeLocked() error {
	r.desired = nil
	r.active = nil
	cancel := r.cancel
	r.cancel = nil
	if cancel != nil {
		// A reapply already waiting for r.mu sees the cancelled context and
		// does nothing, so it cannot recreate the link after the removal.
		cancel()
	}
	if err := r.backend.Remove(); err != nil {
		return fmt.Errorf("remove systemd-resolved link: %w", err)
	}
	return nil
}

// startWatcherLocked starts the goroutine that reapplies the desired state when
// resolved restarts. One watcher serves every Apply until RemoveAll.
func (r *Resolved) startWatcherLocked() {
	if r.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go r.watchRestarts(ctx)
}

func (r *Resolved) watchRestarts(ctx context.Context) {
	for ctx.Err() == nil {
		err := r.backend.WatchRestart(ctx, func() { r.reapply(ctx) })
		if ctx.Err() != nil {
			return
		}
		r.logger.Warn("lost the systemd-resolved restart watch", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(restartRetryDelay):
		}
	}
}

// reapply restores the link's settings after resolved came back empty.
func (r *Resolved) reapply(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil || len(r.desired) == 0 {
		return
	}
	if err := r.configureLocked(); err != nil {
		r.logger.Warn("could not restore split DNS after systemd-resolved restarted", "error", err)
		return
	}
	r.logger.Info("restored split DNS after systemd-resolved restarted", "domains", r.desired)
}
