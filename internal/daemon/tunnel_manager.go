package daemon

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/configdb"
	"github.com/quocln/routewise/internal/telemetry"
)

// Reconnect timing for built-in VPN profiles.
const (
	// tunnelBackoffMin and tunnelBackoffMax bound the delay between attempts:
	// it doubles from the first to the second and stops growing at the second.
	tunnelBackoffMin = time.Second
	tunnelBackoffMax = 60 * time.Second
	// tunnelStableAfter is how long a tunnel must stay up for its next failure
	// to start the backoff over.
	tunnelStableAfter = 30 * time.Second
	// tunnelStartTimeout bounds one attempt to bring a tunnel up, including
	// resolving its server and fetching a dynamic key.
	tunnelStartTimeout = 30 * time.Second
	// tunnelStopTimeout bounds how long the helper's shutdown waits for the
	// tunnel loops to tear down.
	tunnelStopTimeout = 15 * time.Second
)

// errNoCredentials marks a profile that has no stored secret. Retrying cannot
// help, so the supervisor stops until credentials are added.
var errNoCredentials = errors.New("the profile has no credentials")

// errProfileRemoved marks a run whose profile no longer exists. Retrying cannot
// help, so the supervisor ends and forgets itself.
var errProfileRemoved = errors.New("the profile was removed")

// SecretStore keeps profile secrets (a WireGuard .conf, an Outline key). Only
// the tunnel manager reads a secret back; nothing else in the helper does.
type SecretStore interface {
	ProfileSecret(id string) (string, error)
	HasProfileSecret(id string) (bool, error)
	SetProfileSecret(id, secret string) error
	DeleteProfileSecret(id string) error
}

// SetSecretStore gives the daemon its profile secret storage. Call it before
// Start.
func (d *Daemon) SetSecretStore(s SecretStore) { d.secrets = s }

// backoffDelay is the delay before reconnect attempt number attempt (0 is the
// first retry): 1s, 2s, 4s, ... up to 60s.
func backoffDelay(attempt int) time.Duration {
	return min(tunnelBackoffMin<<min(attempt, 6), tunnelBackoffMax)
}

// randomJitter adds up to a fifth of base, so profiles that failed together
// do not retry together.
func randomJitter(base time.Duration) time.Duration {
	return time.Duration(rand.Int64N(int64(base)/5 + 1))
}

// profileRun is the supervisor of one connected-or-connecting profile. The
// fields below finished are guarded by tunnelManager.mu.
type profileRun struct {
	id       string
	cancel   context.CancelFunc
	finished chan struct{}

	state   string
	lastErr string
	tunnel  builtinTunnel
	iface   string
	server  string
}

// tunnelManager owns the running built-in tunnels. Its mutex is a leaf lock:
// it is held only to read or replace the tables below, never across starting
// or stopping a tunnel, doing I/O, or taking any other lock. ctlMu is the
// opposite: the outermost lock, held across connect and disconnect so they
// serialize, and taken by no goroutine that already holds another lock.
//
// profileMu serializes profile imports and updates, whose uniqueness checks
// read other profiles and would otherwise let two concurrent imports of the
// same key both pass. It is held across those methods, which may take ctlMu
// (through a reconnect), so it is acquired before ctlMu and no other lock may be
// held when taking it.
type tunnelManager struct {
	profileMu sync.Mutex
	ctlMu     sync.Mutex

	mu   sync.Mutex
	runs map[string]*profileRun
	// ifaces maps each live utun to its profile, from the moment the tunnel
	// exists until it is torn down. It lets the monitor's admission check
	// recognize the helper's own interface before its session is registered.
	ifaces map[string]string
	// endpoints are the transport addresses of the running tunnels, by profile.
	endpoints map[string][]netip.Addr
	// ipv6Transport holds the running tunnels that connect over IPv6, by profile.
	ipv6Transport map[string]bool
	// outlineAddrs are the /32s in use by Outline utuns, by profile.
	outlineAddrs map[string]netip.Addr
	stopped      bool
}

func newTunnelManager() *tunnelManager {
	return &tunnelManager{
		runs:          make(map[string]*profileRun),
		ifaces:        make(map[string]string),
		endpoints:     make(map[string][]netip.Addr),
		ipv6Transport: make(map[string]bool),
		outlineAddrs:  make(map[string]netip.Addr),
	}
}

// outlineBase is the pool the Outline utun addresses come from.
var outlineBase = netip.MustParsePrefix("10.233.0.0/16")

// allocOutlineAddr hands profile id the lowest free /32 of 10.233.0.0/16
// (.0.0 and .0.1 stay unused). The same profile always gets its own address
// back while it holds one.
func (m *tunnelManager) allocOutlineAddr(id string) (netip.Addr, error) {
	return m.allocOutlineAddrAvoiding(id, nil)
}

// allocOutlineAddrAvoiding is allocOutlineAddr that also skips every address for
// which avoid reports true: an address on a directly connected network or
// already given to a WireGuard interface would be assigned twice, and a /32
// host route to it would hide the real host.
func (m *tunnelManager) allocOutlineAddrAvoiding(id string, avoid func(netip.Addr) bool) (netip.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.outlineAddrs[id]; ok {
		return a, nil
	}
	inUse := make(map[netip.Addr]bool, len(m.outlineAddrs))
	for _, a := range m.outlineAddrs {
		inUse[a] = true
	}
	for a := outlineBase.Addr().Next().Next(); outlineBase.Contains(a); a = a.Next() {
		if !inUse[a] && (avoid == nil || !avoid(a)) {
			m.outlineAddrs[id] = a
			return a, nil
		}
	}
	return netip.Addr{}, errors.New("no free tunnel address in 10.233.0.0/16: every address is in use, on a directly connected network, or a WireGuard profile's address")
}

func (m *tunnelManager) releaseOutlineAddr(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.outlineAddrs, id)
}

// isOwnedInterface reports whether iface is a utun the helper created for a
// built-in profile.
func (m *tunnelManager) isOwnedInterface(iface string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.ifaces[iface]
	return ok
}

// endpointOwners maps every running tunnel's transport address to the name of
// the profile it belongs to, for the endpoint-cover refusal.
func (d *Daemon) endpointOwners() map[netip.Addr]string {
	d.tunnels.mu.Lock()
	byProfile := make(map[string][]netip.Addr, len(d.tunnels.endpoints))
	for id, addrs := range d.tunnels.endpoints {
		byProfile[id] = addrs
	}
	d.tunnels.mu.Unlock()
	if len(byProfile) == 0 {
		return nil
	}
	pol := d.store.Policy()
	out := make(map[netip.Addr]string)
	for id, addrs := range byProfile {
		name := pol.profileName(id)
		for _, a := range addrs {
			out[a] = name
		}
	}
	return out
}

// setState records a run's state, unless the run was replaced meanwhile.
func (m *tunnelManager) setState(run *profileRun, state, errText string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runs[run.id] != run {
		return
	}
	run.state, run.lastErr = state, errText
}

// attach records a tunnel that now exists.
func (m *tunnelManager) attach(run *profileRun, t builtinTunnel) {
	endpoints, ipv6 := t.Endpoints(), t.IPv6Transport()
	m.mu.Lock()
	defer m.mu.Unlock()
	run.tunnel, run.iface, run.server = t, t.Name(), t.Server()
	m.ifaces[run.iface] = run.id
	m.endpoints[run.id] = endpoints
	m.ipv6Transport[run.id] = ipv6
}

// refreshTransports rereads where each running tunnel connects, since a WireGuard
// peer can roam. A read that finds nothing keeps what is known: forgetting a server
// would take its route away while the tunnel still uses it.
func (m *tunnelManager) refreshTransports() {
	type running struct {
		run    *profileRun
		tunnel builtinTunnel
		iface  string
	}
	m.mu.Lock()
	all := make([]running, 0, len(m.runs))
	for _, run := range m.runs {
		if run.tunnel != nil {
			all = append(all, running{run: run, tunnel: run.tunnel, iface: run.iface})
		}
	}
	m.mu.Unlock()
	for _, r := range all {
		endpoints, ipv6 := r.tunnel.Endpoints(), r.tunnel.IPv6Transport()
		m.mu.Lock()
		// Still the same tunnel: identified by its run and interface, because a
		// tunnel handle cannot be compared (the adapters hold slices).
		if m.runs[r.run.id] == r.run && r.run.iface == r.iface {
			if len(endpoints) > 0 {
				m.endpoints[r.run.id] = endpoints
			}
			m.ipv6Transport[r.run.id] = ipv6
		}
		m.mu.Unlock()
	}
}

// serverKnown reports whether a running tunnel's transport can be kept out of a
// tunnel: its IPv4 server is known, or it connects over IPv6, which the default
// VPN's IPv4 routes do not touch.
func (m *tunnelManager) serverKnown(profileID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.endpoints[profileID]) > 0 || m.ipv6Transport[profileID]
}

// ipv6TransportNames names the running tunnels that connect over IPv6.
func (m *tunnelManager) ipv6TransportNames(pol *routingPolicy) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for id, on := range m.ipv6Transport {
		if on {
			names = append(names, pol.profileName(id))
		}
	}
	slices.Sort(names)
	return names
}

// detach forgets a tunnel that is going away.
func (m *tunnelManager) detach(run *profileRun) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if run.iface != "" && m.ifaces[run.iface] == run.id {
		delete(m.ifaces, run.iface)
	}
	delete(m.endpoints, run.id)
	delete(m.ipv6Transport, run.id)
	run.tunnel, run.iface = nil, ""
}

// snapshotRun copies a run's visible state.
type runSnapshot struct {
	exists  bool
	state   string
	err     string
	iface   string
	server  string
	tunnel  builtinTunnel
	running bool
}

func (m *tunnelManager) snapshot(id string) runSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[id]
	if !ok {
		return runSnapshot{}
	}
	return runSnapshot{exists: true, state: run.state, err: run.lastErr, iface: run.iface, server: run.server, tunnel: run.tunnel}
}

// startRun makes profile id connect, replacing any run it already has.
// ctlMu serializes it with disconnects.
func (d *Daemon) startRun(id string) error {
	m := d.tunnels
	m.ctlMu.Lock()
	defer m.ctlMu.Unlock()
	// A removal that finished while this connect waited for ctlMu must win.
	if _, ok := d.store.Profile(id); !ok {
		return fmt.Errorf("%w: profile %q does not exist", api.ErrRejected, id)
	}
	d.stopRunLocked(id)

	ctx, cancel := context.WithCancel(context.Background())
	run := &profileRun{id: id, cancel: cancel, finished: make(chan struct{}), state: api.ProfileConnecting}
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		cancel()
		return errors.New("the helper is shutting down")
	}
	m.runs[id] = run
	m.mu.Unlock()
	go d.superviseProfile(ctx, run)
	return nil
}

// stopRun disconnects profile id and waits for its tunnel to be gone.
func (d *Daemon) stopRun(id string) {
	d.tunnels.ctlMu.Lock()
	defer d.tunnels.ctlMu.Unlock()
	d.stopRunLocked(id)
}

// stopRunLocked cancels a run and waits for it to tear its tunnel down. The
// caller must hold ctlMu.
func (d *Daemon) stopRunLocked(id string) {
	m := d.tunnels
	m.mu.Lock()
	run := m.runs[id]
	m.mu.Unlock()
	if run == nil {
		return
	}
	run.cancel()
	<-run.finished
	m.mu.Lock()
	if m.runs[id] == run {
		delete(m.runs, id)
	}
	m.mu.Unlock()
}

// stopAllTunnels tears down every built-in tunnel at shutdown and refuses new
// connections. It waits a bounded time: a stuck device must not hold the
// helper's exit.
func (d *Daemon) stopAllTunnels() {
	m := d.tunnels
	m.ctlMu.Lock()
	defer m.ctlMu.Unlock()
	m.mu.Lock()
	m.stopped = true
	runs := make([]*profileRun, 0, len(m.runs))
	for _, r := range m.runs {
		runs = append(runs, r)
	}
	m.mu.Unlock()

	deadline := time.NewTimer(tunnelStopTimeout)
	defer deadline.Stop()
	for _, r := range runs {
		r.cancel()
	}
	for _, r := range runs {
		select {
		case <-r.finished:
		case <-deadline.C:
			d.logger.Warn("a built-in tunnel did not stop within the shutdown bound", "profile", r.id)
			return
		}
	}
}

// autoConnectProfiles connects every profile marked auto-connect. It runs once
// at helper start, after the route runtime is up.
func (d *Daemon) autoConnectProfiles() {
	for _, p := range d.store.Profiles() {
		if !p.AutoConnect {
			continue
		}
		if err := d.connectProfile(p.ID); err != nil {
			d.logger.Warn("could not auto-connect the profile", "profile", p.Name, "error", err)
		}
	}
}

// connectProfile starts (or restarts) a profile's tunnel.
func (d *Daemon) connectProfile(id string) error {
	p, ok := d.store.Profile(id)
	if !ok {
		return fmt.Errorf("%w: profile %q does not exist", api.ErrRejected, id)
	}
	if d.currentGeneration() == nil {
		return errors.New("route management is not running, so a built-in VPN cannot connect")
	}
	if has := d.hasSecret(id); !has {
		return fmt.Errorf("%w: profile %q has no credentials; add them first", api.ErrRejected, p.Name)
	}
	return d.startRun(id)
}

func (d *Daemon) hasSecret(id string) bool {
	if d.secrets == nil {
		return false
	}
	has, err := d.secrets.HasProfileSecret(id)
	if err != nil {
		d.logger.Warn("could not check the profile's credentials", "profile", id, "error", err)
		return false
	}
	return has
}

// liveProfile is what a successful bring-up leaves running.
type liveProfile struct {
	gen     *generation
	sess    *tunnelSession
	tunnel  builtinTunnel
	profile config.TunnelProfile
	secret  string
}

// superviseProfile keeps one profile connected until its context ends: it
// starts the tunnel, registers the owned session, watches the tunnel's health,
// waits for the tunnel to die, and starts over with a growing delay. A server
// or endpoint name is resolved anew by every start, so a reconnect finds a
// changed address.
//
// The profile is "connecting" until the health checks prove it works (see
// tunnel_health.go); only then does its list route through the tunnel.
func (d *Daemon) superviseProfile(ctx context.Context, run *profileRun) {
	defer close(run.finished)
	defer telemetry.RepanicAfterCapture()
	attempt := 0
	for {
		if ctx.Err() != nil {
			return
		}
		d.tunnels.setState(run, api.ProfileConnecting, "")
		live, err := d.bringUpTraced(ctx, run)
		var failure string
		switch {
		case err == nil:
			startedAt := d.hooks.tunnelNow()
			if ended := d.superviseHealth(ctx, live.gen, run, live.sess, live.tunnel, live.profile, live.secret); ended {
				d.takeDownProfile(run, live.sess)
				d.tunnels.setState(run, api.ProfileDisconnected, "")
				return
			}
			if d.hooks.tunnelNow().Sub(startedAt) >= tunnelStableAfter {
				attempt = 0
			}
			d.takeDownProfile(run, live.sess)
			failure = "the tunnel stopped unexpectedly"
		case ctx.Err() != nil:
			return
		case errors.Is(err, errProfileRemoved):
			// Nothing to reconnect: forget the run so it does not linger in the
			// table with no way to stop it.
			d.tunnels.forget(run)
			return
		case errors.Is(err, errNoCredentials):
			d.tunnels.setState(run, api.ProfileNeedsCredentials, "")
			return
		default:
			failure = err.Error()
		}

		name := d.profileLabel(run.id)
		d.logger.Warn("built-in VPN is down", "profile", name, "error", failure, "attempt", attempt+1)
		d.recordActivity(activity.Event{Kind: activity.KindVPN, Name: name, Detail: "error: " + failure})
		d.tunnels.setState(run, api.ProfileError, failure)

		delay := backoffDelay(attempt) + d.hooks.tunnelJitter(backoffDelay(attempt))
		attempt++
		select {
		case <-ctx.Done():
			d.tunnels.setState(run, api.ProfileDisconnected, "")
			return
		case <-d.hooks.tunnelAfter(delay):
		}
	}
}

// forget drops a run from the table when its supervisor ends by itself.
func (m *tunnelManager) forget(run *profileRun) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runs[run.id] == run {
		delete(m.runs, run.id)
	}
}

// profileLabel is a profile's name for log and activity lines.
func (d *Daemon) profileLabel(id string) string {
	if p, ok := d.store.Profile(id); ok {
		return p.Name
	}
	return id
}

// bringUpProfile starts the tunnel and registers its owned session. On error
// nothing is left behind.
func (d *Daemon) bringUpProfile(ctx context.Context, run *profileRun) (*liveProfile, error) {
	gen := d.currentGeneration()
	if gen == nil {
		return nil, errors.New("route management is not running")
	}
	p, ok := d.store.Profile(run.id)
	if !ok {
		return nil, errProfileRemoved
	}
	if d.secrets == nil {
		return nil, errNoCredentials
	}
	secret, err := d.secrets.ProfileSecret(run.id)
	switch {
	case errors.Is(err, configdb.ErrNoSecret):
		return nil, errNoCredentials
	case err != nil:
		return nil, errors.New("the stored credentials could not be read")
	}

	req := tunnelStartRequest{Profile: p, Secret: secret}
	if k, ok := kindOf(p.Kind); ok && k.needsSyntheticAddress() {
		if req.Address, err = d.tunnels.allocOutlineAddrAvoiding(run.id, d.reservedAddrCollides()); err != nil {
			return nil, err
		}
	}
	startCtx, cancel := context.WithTimeout(ctx, tunnelStartTimeout)
	t, err := d.hooks.startTunnel(startCtx, req, d.logger)
	cancel()
	if err != nil {
		d.tunnels.releaseOutlineAddr(run.id)
		return nil, errors.New(redact(err.Error(), p.Kind, secret))
	}

	// The transport addresses are known before the session exists, so the very
	// first sync already keeps every list entry off them.
	d.tunnels.attach(run, t)
	sess, err := d.attachOwnedSession(gen, p, t)
	if err != nil {
		d.tunnels.detach(run)
		d.tunnels.releaseOutlineAddr(run.id)
		d.stopTunnel(p.Name, t)
		return nil, err
	}
	return &liveProfile{gen: gen, sess: sess, tunnel: t, profile: p, secret: secret}, nil
}

// takeDownProfile gives a profile's routes back and stops its tunnel. The
// transport addresses are forgotten first so the sync that follows the route
// teardown may route entries that were being kept off them.
func (d *Daemon) takeDownProfile(run *profileRun, s *tunnelSession) {
	m := d.tunnels
	m.mu.Lock()
	t := run.tunnel
	m.mu.Unlock()
	m.detach(run)
	d.releaseOwnedSession(d.currentGeneration(), s)
	m.releaseOutlineAddr(run.id)
	if t != nil {
		d.stopTunnel(d.profileLabel(run.id), t)
	}
}

func (d *Daemon) stopTunnel(name string, t builtinTunnel) {
	if err := t.Stop(); err != nil {
		d.logger.Warn("built-in tunnel did not stop cleanly", "profile", name, "error", err)
	}
}

// bringUpTraced is bringUpProfile inside a "vpn.connect" transaction tagged
// with the profile's kind. A start cancelled by a disconnect is not a failure.
func (d *Daemon) bringUpTraced(ctx context.Context, run *profileRun) (*liveProfile, error) {
	_, txn := telemetry.StartTransaction(ctx, "vpn.connect", "vpn.connect")
	if p, ok := d.store.Profile(run.id); ok {
		txn.SetTag("kind", p.Kind)
	}
	live, err := d.bringUpProfile(ctx, run)
	txn.Finish(err != nil && ctx.Err() == nil)
	return live, err
}
