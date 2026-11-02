package daemon

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/vpnclient"
)

// clientCacheTTL bounds how long the owner of a tunnel that is not managed is
// trusted without asking again. utun names are reused as soon as a tunnel
// goes away, and nothing reports the end of a tunnel RouteWise does not track,
// so a stale answer must not live long. After it, the one process that was
// found is re-checked (vpnclient.Revalidate) instead of scanning every process.
// The owner of a managed tunnel is kept for as long as the monitor tracks the
// interface instead: its disconnect drops the entry (forgetClient), and only
// the allowlist is re-checked until then.
const clientCacheTTL = 3 * time.Second

// clientRescanInterval is how long a re-checked owner may stand in for a full
// identification of a tunnel that is not managed.
const clientRescanInterval = 10 * time.Minute

// Failed identifications are retried after identifyBackoffMin, doubling up to
// identifyBackoffMax while the tunnel stays as it is: an ownerless or
// unreadable tunnel otherwise costs a full process scan at every monitor check.
const (
	identifyBackoffMin = time.Second
	identifyBackoffMax = time.Minute
)

// pendingReportTTL is how long a detected-but-not-allowed tunnel stays in
// status after the monitor last saw it. The monitor re-checks every few
// seconds, so a tunnel that is still there keeps refreshing it.
const pendingReportTTL = 15 * time.Second

// cachedClient is the last identification of an interface: the owner found, or
// the failure and when to try again. It belongs to one link: a different
// interface index means the tunnel was recreated, which voids it.
type cachedClient struct {
	client  vpnclient.Client
	at      time.Time // when the owner was identified
	checked time.Time // when the owner was last confirmed
	index   int       // interface index; 0 when it cannot be read

	// A failed identification sets err; failures counts consecutive ones and
	// retryAt is the earliest time to scan again.
	err      error
	failures int
	retryAt  time.Time
}

// interfaceIndex returns iface's index, or 0 when it cannot be read.
func interfaceIndex(iface string) int {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return 0
	}
	return ifc.Index
}

type pendingTunnel struct {
	iface  string
	client vpnclient.Client
	seen   time.Time
}

// admitTunnel is the monitor's admission check: RouteWise manages a tunnel
// only when its client is on the allowlist. A tunnel from any other client,
// or one whose owner cannot be identified, is left alone and reported as
// pending so the user can allow it.
func (d *Daemon) admitTunnel(iface string) bool {
	// A utun the helper created for a built-in profile is never a detected or
	// pending VPN: it has its own owned session.
	if d.tunnels.isOwnedInterface(iface) {
		return false
	}
	client, err := d.clientFor(iface)
	allowed := err == nil && slices.Contains(d.store.Policy().allowed, client.ID)
	if allowed {
		d.clearPending(iface)
		return true
	}
	d.notePending(iface, client, err)
	return false
}

// clearPending forgets a tunnel that is managed after all.
func (d *Daemon) clearPending(iface string) {
	d.clientMu.Lock()
	defer d.clientMu.Unlock()
	delete(d.pending, iface)
}

// notePending records a detected tunnel RouteWise leaves alone. The log line
// and the activity event fire once per appearance of an (interface, client)
// pair, not at every monitor check, so two pending tunnels never take turns
// flooding the log.
func (d *Daemon) notePending(iface string, client vpnclient.Client, identifyErr error) {
	if identifyErr != nil {
		client = vpnclient.Client{Name: "unknown client"}
	}
	now := time.Now()

	d.clientMu.Lock()
	defer d.clientMu.Unlock()
	for other, p := range d.pending {
		if other != iface && now.Sub(p.seen) >= pendingReportTTL {
			delete(d.pending, other)
		}
	}
	prev, known := d.pending[iface]
	appeared := !known || now.Sub(prev.seen) >= pendingReportTTL || prev.client != client
	d.pending[iface] = &pendingTunnel{iface: iface, client: client, seen: now}
	if !appeared {
		return
	}
	d.logger.Info("full-tunnel VPN detected but not managed: its client is not allowed",
		"interface", iface, "client", client.Name, "path", client.ID, "identify_error", identifyErr)
	d.recordActivity(activity.Event{
		Kind:      activity.KindVPN,
		Name:      client.Name,
		Interface: iface,
		Detail:    "detected, not managed: allow this VPN client to route through RouteWise",
	})
}

// clientFor returns the program that owns iface. An owner on the allowlist is
// remembered until the interface's disconnect forgets it, so a managed tunnel
// costs no scan at the monitor's poll rate. Any other owner is trusted for
// clientCacheTTL, then confirmed by looking at its one process; a failed
// identification is not repeated before its backoff has passed. A different
// interface index starts over.
func (d *Daemon) clientFor(iface string) (vpnclient.Client, error) {
	index := interfaceIndex(iface)
	d.clientMu.Lock()
	cached, ok := d.clientCache[iface]
	d.clientMu.Unlock()
	if ok && cached.index == index {
		now := time.Now()
		if cached.err != nil {
			if now.Before(cached.retryAt) {
				return vpnclient.Client{}, cached.err
			}
		} else {
			managed := cached.client.ID != "" && slices.Contains(d.store.Policy().allowed, cached.client.ID)
			if managed || (now.Sub(cached.checked) < clientCacheTTL && now.Sub(cached.at) < clientRescanInterval) {
				return cached.client, nil
			}
			if now.Sub(cached.at) < clientRescanInterval && vpnclient.Revalidate(iface) == vpnclient.OwnerHolds {
				d.clientMu.Lock()
				if cur, still := d.clientCache[iface]; still && cur.at == cached.at {
					cur.checked = now
					d.clientCache[iface] = cur
				}
				d.clientMu.Unlock()
				return cached.client, nil
			}
		}
	}
	return d.identifyFresh(iface)
}

// identifyFresh asks for iface's owner, bypassing the cache. It is used for
// every new detection: a tunnel that appears under a name RouteWise saw before
// is a different tunnel until proven otherwise.
func (d *Daemon) identifyFresh(iface string) (vpnclient.Client, error) {
	ctx := d.baseCtx
	if ctx == nil {
		ctx = context.Background()
	}
	index := interfaceIndex(iface)
	client, err := d.hooks.identifyClient(ctx, iface)

	now := time.Now()
	d.clientMu.Lock()
	defer d.clientMu.Unlock()
	if err != nil {
		failures := 1
		if prev, ok := d.clientCache[iface]; ok && prev.err != nil && prev.index == index {
			failures = prev.failures + 1
		}
		d.clientCache[iface] = cachedClient{
			index: index, err: err, failures: failures, retryAt: now.Add(identifyBackoff(failures)),
		}
	} else {
		d.clientCache[iface] = cachedClient{client: client, at: now, checked: now, index: index}
	}
	return client, err
}

// identifyBackoff is the wait after the failures-th consecutive failure: 1 s,
// 2 s, 4 s and so on up to identifyBackoffMax.
func identifyBackoff(failures int) time.Duration {
	wait := identifyBackoffMin
	for i := 1; i < failures && wait < identifyBackoffMax; i++ {
		wait *= 2
	}
	return min(wait, identifyBackoffMax)
}

// forgetClient drops what is known about iface's owner, for when its tunnel
// disconnects or disappears from detection.
func (d *Daemon) forgetClient(iface string) {
	d.clientMu.Lock()
	defer d.clientMu.Unlock()
	delete(d.clientCache, iface)
}

// VPNClients reports the client of the highest-priority managed tunnel and
// every detected VPN RouteWise leaves alone because its client is not
// allowed, ordered by interface.
func (d *Daemon) VPNClients() (managed *api.VPNClient, pending []api.PendingVPN) {
	if sessions := d.sessionList(); len(sessions) > 0 && sessions[0].client.ID != "" {
		c := sessions[0].client
		managed = &api.VPNClient{ID: c.ID, Name: c.Name}
	}

	d.clientMu.Lock()
	defer d.clientMu.Unlock()
	for _, p := range d.pending {
		if time.Since(p.seen) < pendingReportTTL {
			pending = append(pending, api.PendingVPN{
				Interface: p.iface,
				Client:    api.VPNClient{ID: p.client.ID, Name: p.client.Name},
			})
		}
	}
	slices.SortFunc(pending, func(a, b api.PendingVPN) int { return strings.Compare(a.Interface, b.Interface) })
	return managed, pending
}

// AllowedVPNClients lists the clients RouteWise may manage.
func (d *Daemon) AllowedVPNClients() []api.VPNClient {
	ids := d.store.AllowedVPNClients()
	cfg, _ := d.store.Snapshot()
	out := make([]api.VPNClient, 0, len(ids))
	for _, id := range ids {
		if _, profileID, ok := config.ParseProfileClientID(id); ok {
			// A built-in VPN is named after its profile, not a path.
			if p, found := cfg.Profile(profileID); found {
				out = append(out, api.VPNClient{ID: id, Name: p.Name})
				continue
			}
		}
		c := vpnclient.FromPath(id)
		out = append(out, api.VPNClient{ID: c.ID, Name: c.Name})
	}
	return out
}

// SetVPNClientAllowed adds a VPN client to the allowlist or removes it, saves
// the change, and has the monitor re-evaluate at once: allowing a detected VPN
// starts managing it, and revoking the managed one hands its tunnel back.
func (d *Daemon) SetVPNClientAllowed(id string, allowed bool) error {
	if id == "" {
		return fmt.Errorf("%w: VPN client id is empty", api.ErrRejected)
	}
	if _, err := d.store.SetVPNClientAllowed(id, allowed); err != nil {
		return classifyConfigError(err)
	}
	d.logger.Info("VPN client allowlist changed", "client", id, "allowed", allowed)
	if gen := d.currentGeneration(); gen != nil {
		gen.monitor.Recheck()
	}
	// The allowlist is also the priority order, and a client's own list lives
	// and dies with it: learned routes are re-checked at the next sync.
	d.TriggerSync()
	return nil
}
