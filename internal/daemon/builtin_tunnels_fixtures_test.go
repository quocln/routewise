package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/activity"
	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/configdb"
)

// Secrets the tests plant and then search for in every output.
var (
	wgPrivateKeyText = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))
	wgPublicKeyText  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	wgPresharedText  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))
	outlinePassword  = "OutlinePasswordMarker99"
)

// wireGuardConf is a valid .conf carrying the planted keys.
func wireGuardConf(endpoint string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.8.0.2/24
DNS = 10.8.0.1

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0
`, wgPrivateKeyText, wgPublicKeyText, wgPresharedText, endpoint)
}

// outlineAccessKey is a valid SIP002 key carrying the planted password.
func outlineAccessKey(host string) string {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:" + outlinePassword))
	return fmt.Sprintf("ss://%s@%s:8388#Travel", userinfo, host)
}

// allSecrets lists every planted secret substring.
func allSecrets() []string {
	return []string{wgPrivateKeyText, wgPresharedText, outlinePassword,
		base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:" + outlinePassword))}
}

// fakeSecrets is an in-memory SecretStore.
type fakeSecrets struct {
	mu sync.Mutex
	m  map[string]string
}

func newFakeSecrets() *fakeSecrets { return &fakeSecrets{m: map[string]string{}} }

func (f *fakeSecrets) ProfileSecret(id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.m[id]
	if !ok {
		return "", configdb.ErrNoSecret
	}
	return s, nil
}

func (f *fakeSecrets) HasProfileSecret(id string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.m[id]
	return ok, nil
}

func (f *fakeSecrets) SetProfileSecret(id, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[id] = secret
	return nil
}

func (f *fakeSecrets) DeleteProfileSecret(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, id)
	return nil
}

func (f *fakeSecrets) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.m)
}

// fakeTunnel stands in for a running WireGuard or Outline tunnel.
type fakeTunnel struct {
	name      string
	endpoints []netip.Addr
	done      chan struct{}
	once      sync.Once
	mu        sync.Mutex
	stopped   bool
	// allowed is what AllowedIPs reports; nil means unrestricted (Outline).
	allowed []netip.Prefix
	// ipv6Transport is what IPv6Transport reports.
	ipv6Transport bool
	// check decides each health check from the clock; nil means healthy.
	check  func(now time.Time) error
	checks int
}

// fakeTunnelHandle is what the starter hands the daemon. Like the real adapters
// it is a struct value holding a slice, so comparing two of them panics; a daemon
// handed a bare pointer would never find that out.
type fakeTunnelHandle struct {
	*fakeTunnel
	_ []netip.Prefix
}

func (t *fakeTunnel) AllowedIPs() []netip.Prefix { return t.allowed }
func (t *fakeTunnel) IPv6Transport() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ipv6Transport
}

func (t *fakeTunnel) Check(_ context.Context, now time.Time) error {
	t.mu.Lock()
	t.checks++
	f := t.check
	t.mu.Unlock()
	if f == nil {
		return nil
	}
	return f(now)
}

func (t *fakeTunnel) checkCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.checks
}

// setProbe makes every health check return err, the way an Outline probe does.
func (t *fakeTunnel) setProbe(err error) {
	t.mu.Lock()
	t.check = func(time.Time) error { return err }
	t.mu.Unlock()
}

// setHandshake makes health follow a WireGuard handshake time, judged by the
// production rule against the clock the daemon passes in.
func (t *fakeTunnel) setHandshake(at time.Time, ok bool) {
	t.mu.Lock()
	t.check = func(now time.Time) error { return checkHandshake(at, ok, now) }
	t.mu.Unlock()
}

func (t *fakeTunnel) Name() string          { return t.name }
func (t *fakeTunnel) Done() <-chan struct{} { return t.done }
func (t *fakeTunnel) Endpoints() []netip.Addr {
	return t.endpoints
}
func (t *fakeTunnel) Server() string { return "vpn.example.com:51820" }
func (t *fakeTunnel) Stats() *api.ProfileStats {
	return &api.ProfileStats{RxBytes: 1, TxBytes: 2}
}
func (t *fakeTunnel) Stop() error {
	t.mu.Lock()
	t.stopped = true
	t.mu.Unlock()
	t.once.Do(func() { close(t.done) })
	return nil
}
func (t *fakeTunnel) isStopped() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stopped
}

// die ends the tunnel the way a failed utun would, without Stop.
func (t *fakeTunnel) die() { t.once.Do(func() { close(t.done) }) }

// fakeStarter is the injected tunnel constructor. plan decides, for the n-th
// start of any profile, the endpoints it reports or the error it fails with.
type fakeStarter struct {
	mu     sync.Mutex
	starts []tunnelStartRequest
	live   map[string]*fakeTunnel
	ifaces map[string]string
	plan   func(n int, req tunnelStartRequest) ([]netip.Addr, error)
	// onStart can set up a new tunnel (health, allowed IPs) before it is returned.
	onStart func(req tunnelStartRequest, t *fakeTunnel)
}

func newFakeStarter() *fakeStarter {
	return &fakeStarter{live: map[string]*fakeTunnel{}, ifaces: map[string]string{}}
}

func (s *fakeStarter) start(_ context.Context, req tunnelStartRequest, _ *slog.Logger) (builtinTunnel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts = append(s.starts, req)
	var endpoints []netip.Addr
	if s.plan != nil {
		var err error
		if endpoints, err = s.plan(len(s.starts), req); err != nil {
			return nil, err
		}
	}
	iface, ok := s.ifaces[req.Profile.ID]
	if !ok {
		iface = fmt.Sprintf("utun%d", 20+len(s.ifaces))
		s.ifaces[req.Profile.ID] = iface
	}
	t := &fakeTunnel{name: iface, endpoints: endpoints, done: make(chan struct{})}
	if s.onStart != nil {
		s.onStart(req, t)
	}
	s.live[req.Profile.ID] = t
	return fakeTunnelHandle{fakeTunnel: t}, nil
}

func (s *fakeStarter) startCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.starts)
}

func (s *fakeStarter) tunnel(id string) *fakeTunnel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live[id]
}

func (s *fakeStarter) iface(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ifaces[id]
}

func (s *fakeStarter) request(n int) tunnelStartRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.starts[n]
}

// fakeClock is the reconnect clock: every wait is recorded and ends only when
// the test fires it.
type fakeClock struct {
	mu      sync.Mutex
	waits   []time.Duration
	pending []chan time.Time
	now     time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_800_000_000, 0)} }

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.waits = append(c.waits, d)
	c.pending = append(c.pending, ch)
	return ch
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fireAll ends every pending wait.
func (c *fakeClock) fireAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ch := range c.pending {
		ch <- time.Time{}
	}
	c.pending = nil
}

// pendingCount is how many waits are armed and not yet fired.
func (c *fakeClock) pendingCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// waitCount is how many waits were ever started.
func (c *fakeClock) waitCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waits)
}

// fire ends the oldest wait.
func (c *fakeClock) fire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 {
		return
	}
	c.pending[0] <- time.Time{}
	c.pending = c.pending[1:]
}

func (c *fakeClock) waited() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

// syncBuffer collects everything the daemon logs.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// builtinEnv is the two-detected-clients environment plus injected built-in
// tunnels, secrets, reconnect clock, and a captured log.
type builtinEnv struct {
	*tunnelEnv
	k       *fakeKernel
	secrets *fakeSecrets
	starter *fakeStarter
	clock   *fakeClock
	// health paces the health checks; clock paces reconnect backoff.
	health *fakeClock
	logs   *syncBuffer
}

func newBuiltinEnv(t *testing.T, k *fakeKernel, anyList, wgList, awsList []string) *builtinEnv {
	t.Helper()
	e := &builtinEnv{
		k: k, secrets: newFakeSecrets(), starter: newFakeStarter(), clock: newFakeClock(), health: newFakeClock(), logs: &syncBuffer{},
	}
	e.tunnelEnv = newKernelEnv(t, k, anyList, wgList, awsList, func(d *Daemon) {
		d.secrets = e.secrets
		d.hooks.startTunnel = e.starter.start
		d.hooks.tunnelAfter = e.clock.After
		d.hooks.tunnelHealthAfter = e.health.After
		d.hooks.tunnelNow = e.clock.Now
		d.hooks.tunnelJitter = func(time.Duration) time.Duration { return 0 }
		d.logger = slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	return e
}

func (e *builtinEnv) importWireGuard(t *testing.T, name, endpoint string) string {
	t.Helper()
	id, err := e.d.ProfileImport(api.ProfileImportParams{Kind: "wireguard", Name: name, WireguardConfig: wireGuardConf(endpoint)})
	if err != nil {
		t.Fatalf("import WireGuard: %v", err)
	}
	return id
}

func (e *builtinEnv) importOutline(t *testing.T, name, host string) string {
	t.Helper()
	id, err := e.d.ProfileImport(api.ProfileImportParams{Kind: "outline", Name: name, AccessKey: outlineAccessKey(host)})
	if err != nil {
		t.Fatalf("import Outline: %v", err)
	}
	return id
}

// connect connects a profile and waits for its owned session, returning the
// utun name.
func (e *builtinEnv) connect(t *testing.T, id string) string {
	t.Helper()
	if err := e.d.ProfileConnect(id); err != nil {
		t.Fatalf("connect %s: %v", id, err)
	}
	waitFor(t, "the tunnel of "+id+" to start", func() bool { return e.starter.iface(id) != "" })
	iface := e.starter.iface(id)
	waitForSession(t, e.d, iface)
	return iface
}

func (e *builtinEnv) setList(t *testing.T, id string, patterns ...string) {
	t.Helper()
	p, ok := e.d.store.Profile(id)
	if !ok {
		t.Fatalf("no profile %s", id)
	}
	if err := e.d.SetDomains(p.ClientID(), patterns, 0); err != nil {
		t.Fatalf("set list of %s: %v", id, err)
	}
}

func (e *builtinEnv) profileState(id string) api.ProfileInfo {
	for _, p := range e.d.ProfilesList() {
		if p.ID == id {
			return p
		}
	}
	return api.ProfileInfo{}
}

func (e *builtinEnv) waitState(t *testing.T, id, state string) {
	t.Helper()
	waitFor(t, fmt.Sprintf("profile %s to be %s", id, state), func() bool { return e.profileState(id).State == state })
}

// wireGuardConfWith builds a valid .conf with the given private key text and
// interface address, for the uniqueness tests.
func wireGuardConfWith(privateKey, address string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = 10.8.0.1

[Peer]
PublicKey = %s
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
`, privateKey, address, wgPublicKeyText)
}

// armed waits until loops health loops are each waiting for their next check.
func (e *builtinEnv) armed(t *testing.T, loops int) {
	t.Helper()
	waitFor(t, "the health loops to wait for their next check", func() bool { return e.health.pendingCount() >= loops })
}

// tick runs one more health check in each of loops health loops and waits until
// every loop has applied its result (a loop re-arms its wait only after that).
func (e *builtinEnv) tick(t *testing.T, loops int) {
	t.Helper()
	e.armed(t, loops)
	before := e.health.waitCount()
	e.health.fireAll()
	waitFor(t, "the health loops to apply the checks", func() bool { return e.health.waitCount() >= before+loops })
}

// activityDetails lists the details of the activity events of one kind about name.
func (e *builtinEnv) activityDetails(kind activity.Kind, name string) []string {
	var out []string
	for _, ev := range e.d.activity.List(0, 0) {
		if ev.Kind == kind && ev.Name == name {
			out = append(out, ev.Detail)
		}
	}
	return out
}

// hasActivity reports whether an event of kind about name has a detail containing sub.
func (e *builtinEnv) hasActivity(kind activity.Kind, name, sub string) bool {
	for _, detail := range e.activityDetails(kind, name) {
		if strings.Contains(detail, sub) {
			return true
		}
	}
	return false
}
