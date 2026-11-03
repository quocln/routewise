package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
)

// A built-in profile is "connected" only once it is proven to work. A profile
// that stopped working installs no routes: its entries go direct, with no
// failover to another tunnel. A profile that was just started holds its routes
// while it proves itself, for at most connectHoldLimit: a connection opened in
// that window waits for the tunnel, where going direct would keep it direct
// for its whole life (a browser reuses it on every reload). A tunnel still
// unproven after the limit lets its entries go direct while it keeps trying.
//
//   - WireGuard is proven by a completed handshake. It stays healthy while the
//     last handshake is no older than wgHandshakeFresh, which covers
//     WireGuard's rekey interval (120 s) with margin. The handshake window is
//     itself the hysteresis, so one check failing is enough to go unhealthy.
//   - Outline is proven by a probe every outlineProbeInterval: a DNS query
//     through the Shadowsocks server. outlineFailuresToDown consecutive failures
//     make it unhealthy and one success makes it healthy again, so a single
//     lost probe does not flap the routes.
const (
	// wgHandshakeFresh is how old the last handshake may be before the tunnel
	// counts as dead.
	wgHandshakeFresh = 180 * time.Second
	// wgCheckInterval is how often the device is asked for its last handshake.
	// The read is cheap, and a short interval makes the first handshake show up
	// promptly.
	wgCheckInterval = 5 * time.Second
	// wgFirstHandshakeTimeout is how long a new WireGuard tunnel may wait for
	// its first handshake before it is shown as an error. Handshakes are
	// retried throughout, so a server that answers later still connects.
	wgFirstHandshakeTimeout = 30 * time.Second
	// connectingCheckInterval is how often a tunnel waiting for its first proof
	// is checked during connectingFastWindow, so a handshake that completes in
	// a fraction of a second is seen in a fraction of a second.
	connectingCheckInterval = 250 * time.Millisecond
	connectingFastWindow    = 5 * time.Second
	// connectHoldLimit is how long a newly started tunnel keeps its routes
	// before it is proven. Long enough for a normal handshake, short enough
	// that a server that never answers does not stall its domains for long.
	connectHoldLimit = 10 * time.Second
	// outlineProbeInterval is how often an Outline tunnel is probed.
	outlineProbeInterval = 30 * time.Second
	// outlineFailuresToDown is how many probes in a row must fail.
	outlineFailuresToDown = 3
)

// errNotProvenYet reports that a tunnel has not worked yet, as opposed to
// having stopped working. A tunnel that was never proven stays "connecting"
// until wgFirstHandshakeTimeout has passed.
var errNotProvenYet = errors.New("not proven yet")

// overdueFirstProof turns "not proven yet" into a failure once the tunnel has
// waited longer than wgFirstHandshakeTimeout since startedAt, so a server that
// never answers shows as an error instead of connecting forever.
func overdueFirstProof(err error, startedAt, now time.Time) error {
	if !errors.Is(err, errNotProvenYet) || now.Sub(startedAt) < wgFirstHandshakeTimeout {
		return err
	}
	return fmt.Errorf("no handshake from the WireGuard server after %s; check the endpoint, the keys, and that UDP is not blocked (still retrying)",
		wgFirstHandshakeTimeout)
}

// checkHandshake judges a WireGuard tunnel by its last handshake at now. ok is
// false when no handshake has completed.
func checkHandshake(last time.Time, ok bool, now time.Time) error {
	if !ok {
		return fmt.Errorf("%w: waiting for the first WireGuard handshake", errNotProvenYet)
	}
	if age := now.Sub(last); age > wgHandshakeFresh {
		return fmt.Errorf("no WireGuard handshake for %s (a working tunnel renews it at least every %s)",
			age.Round(time.Second), wgHandshakeFresh)
	}
	return nil
}

// healthPolicy is how often a kind of tunnel is checked and how many failed
// checks in a row make it unhealthy.
type healthPolicy struct {
	interval time.Duration
	failures int
	// conclusive, if set, picks out failures that one check is enough to believe.
	conclusive func(error) bool
}

type healthState int

const (
	// healthConnecting: no check has succeeded yet.
	healthConnecting healthState = iota
	healthUp
	healthDown
)

// healthTracker turns a stream of check results into state changes. It holds no
// clock and does no I/O.
type healthTracker struct {
	policy healthPolicy
	state  healthState
	fails  int
}

func newHealthTracker(p healthPolicy) *healthTracker { return &healthTracker{policy: p} }

// observe records one check result and reports whether the state changed.
func (h *healthTracker) observe(err error) bool {
	switch {
	case err == nil:
		h.fails = 0
		if h.state == healthUp {
			return false
		}
		h.state = healthUp
		return true
	case errors.Is(err, errNotProvenYet) && h.state == healthConnecting:
		return false
	}
	h.fails++
	conclusive := h.policy.conclusive != nil && h.policy.conclusive(err)
	if (conclusive || h.fails >= h.policy.failures) && h.state != healthDown {
		h.state = healthDown
		return true
	}
	return false
}

// superviseHealth checks a running tunnel until the run is cancelled or the
// tunnel dies, and applies each health change: the owned session starts or
// stops routing, the profile's state follows, and the change is logged and
// recorded in the activity log. It returns true when ctx ended and false when
// the tunnel died.
func (d *Daemon) superviseHealth(ctx context.Context, gen *generation, run *profileRun, sess *tunnelSession, t builtinTunnel, p config.TunnelProfile, secret string) bool {
	policy := healthPolicyFor(p.Kind)
	tracker := newHealthTracker(policy)
	everUp := false
	lastReason := ""
	startedAt := d.hooks.tunnelNow()
	if sess.holding.Load() {
		// Install the list at once, so connections made while the tunnel
		// proves itself wait for it.
		d.ensureVPNDNS(gen, sess, false)
		d.syncRoutes(gen)
	}
	for {
		now := d.hooks.tunnelNow()
		err := overdueFirstProof(t.Check(ctx, now), startedAt, now)
		select {
		case <-ctx.Done():
			return true
		case <-t.Done():
			return false
		default:
		}

		if tracker.observe(err) {
			reason := ""
			if err != nil {
				// A check error comes from the network stack; it names no secret,
				// but is scrubbed like every other tunnel error.
				reason = redact(err.Error(), p.Kind, secret)
			}
			switch tracker.state {
			case healthUp:
				d.setOwnedHealth(gen, sess, true)
				d.tunnels.setState(run, api.ProfileConnected, "")
				detail := "connected"
				if everUp {
					detail = "healthy again; its entries route through the tunnel"
				}
				everUp = true
				d.logger.Info("built-in VPN is healthy", "profile", p.Name, "interface", sess.iface)
				d.recordActivity(activity.Event{Kind: activity.KindVPN, Name: p.Name, Interface: sess.iface, Detail: detail})
			case healthDown:
				d.setOwnedHealth(gen, sess, false)
				d.tunnels.setState(run, api.ProfileError, reason)
				d.logger.Warn("built-in VPN is unhealthy; its entries go direct", "profile", p.Name, "interface", sess.iface, "reason", reason)
				d.recordActivity(activity.Event{Kind: activity.KindVPN, Name: p.Name, Interface: sess.iface,
					Detail: "unhealthy, its entries go direct: " + reason})
			}
			lastReason = reason
		} else if tracker.state == healthDown && err != nil {
			// Still down: keep the shown reason current without another event.
			if reason := redact(err.Error(), p.Kind, secret); reason != lastReason {
				d.tunnels.setState(run, api.ProfileError, reason)
				lastReason = reason
			}
		}

		if sess.holding.Load() && tracker.state == healthConnecting &&
			d.hooks.tunnelNow().Sub(startedAt) >= connectHoldLimit {
			d.endConnectHold(gen, sess)
			d.logger.Info("built-in VPN not proven yet; its entries go direct while it keeps trying",
				"profile", p.Name, "interface", sess.iface, "after", connectHoldLimit)
			d.recordActivity(activity.Event{Kind: activity.KindVPN, Name: p.Name, Interface: sess.iface,
				Detail: "still connecting, its entries go direct until the tunnel works"})
		}

		select {
		case <-ctx.Done():
			return true
		case <-t.Done():
			return false
		case <-d.hooks.tunnelHealthAfter(nextHealthCheck(policy, tracker.state, err, sess.holding.Load(),
			d.hooks.tunnelNow().Sub(startedAt))):
		}
	}
}

// nextHealthCheck is the wait before the next check. A tunnel still waiting
// for its first proof is checked every connectingCheckInterval during
// connectingFastWindow, and a holding one is checked again by the end of its
// hold, so the hold ends on time even under Outline's long probe interval.
func nextHealthCheck(policy healthPolicy, state healthState, err error, holding bool, elapsed time.Duration) time.Duration {
	wait := policy.interval
	if state == healthConnecting && errors.Is(err, errNotProvenYet) && elapsed < connectingFastWindow {
		wait = min(wait, connectingCheckInterval)
	}
	if holding && state == healthConnecting {
		wait = min(wait, max(connectHoldLimit-elapsed, connectingCheckInterval))
	}
	return wait
}

// endConnectHold stops a still-unproven session from routing: its list and its
// DNS servers go, and its entries go direct until it is proven.
func (d *Daemon) endConnectHold(gen *generation, s *tunnelSession) {
	ran, _ := d.withGenerationMutation(gen, func() error {
		if !d.sessions.isRegistered(s) || !s.holding.Swap(false) {
			return nil
		}
		d.healthEpoch.Add(1)
		if !s.proven.Load() {
			d.clearOwnedDNSLocked(s)
		}
		return nil
	})
	if ran && d.sessions.isRegistered(s) {
		d.syncRoutes(gen)
	}
}

// setOwnedHealth marks an owned session proven or not and syncs, so its routes
// appear or go at once. A session that is no longer registered is left alone.
// An unproven session's DNS routes go with its other routes, and come back
// through the next sync once it is proven again.
func (d *Daemon) setOwnedHealth(gen *generation, s *tunnelSession, healthy bool) {
	ran, _ := d.withGenerationMutation(gen, func() error {
		if !d.sessions.isRegistered(s) {
			return nil
		}
		s.proven.Store(healthy)
		// The first verdict ends the connect hold either way.
		s.holding.Store(false)
		// A sync that was planned before this change must not be applied.
		d.healthEpoch.Add(1)
		if !healthy {
			d.clearOwnedDNSLocked(s)
		}
		return nil
	})
	if !ran || !d.sessions.isRegistered(s) {
		return
	}
	if healthy {
		d.ensureVPNDNS(gen, s, false)
	}
	d.syncRoutes(gen)
}
