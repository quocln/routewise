package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quocln/routewise/internal/api"
	"github.com/quocln/routewise/internal/config"
	"github.com/quocln/routewise/internal/dnsproxy"
	"github.com/quocln/routewise/internal/monitor"
	"github.com/quocln/routewise/internal/resolverfiles"
	"github.com/quocln/routewise/internal/vpnclient"
)

func TestWritePIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	err := WritePIDFile(pidFile)
	if err != nil {
		t.Fatalf("WritePIDFile failed: %v", err)
	}

	// Verify file exists
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("could not read PID file: %v", err)
	}

	if len(data) == 0 {
		t.Error("PID file is empty")
	}
}

func TestRemovePIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// Create file first
	_ = WritePIDFile(pidFile)

	// Remove
	err := RemovePIDFile(pidFile)
	if err != nil {
		t.Fatalf("RemovePIDFile failed: %v", err)
	}

	// Verify removed
	_, err = os.Stat(pidFile)
	if !os.IsNotExist(err) {
		t.Error("PID file should not exist after removal")
	}

	// Removing non-existent file should not error
	err = RemovePIDFile(pidFile)
	if err != nil {
		t.Errorf("RemovePIDFile should not error for non-existent file: %v", err)
	}
}

func TestCheckPIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// Non-existent file
	pid, running := CheckPIDFile(pidFile)
	if running {
		t.Error("should not report running for non-existent file")
	}

	// Write current PID
	_ = WritePIDFile(pidFile)

	// Should find our process
	pid, running = CheckPIDFile(pidFile)
	if !running {
		t.Error("should report running for current process")
	}
	if pid != os.Getpid() {
		t.Errorf("expected PID %d, got %d", os.Getpid(), pid)
	}

	// Write non-existent PID
	err := os.WriteFile(pidFile, []byte("999999999\n"), 0644)
	if err != nil {
		t.Fatalf("could not write test PID: %v", err)
	}

	_, running = CheckPIDFile(pidFile)
	if running {
		t.Error("should not report running for non-existent PID")
	}
}

// TestCheckPIDFileReportsAProcessItMayNotSignal covers the everyday case of an
// unprivileged CLI looking at the root-owned helper: signalling is refused, but
// the helper is running and still owns the config file. Reading that refusal as
// "stopped" would let the CLI write a file the helper is about to overwrite.
func TestCheckPIDFileReportsAProcessItMayNotSignal(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "launchd.pid")

	// PID 1 always exists and is owned by root, so a non-root test run gets
	// EPERM here while a root test run gets success. Both mean "running". On
	// Windows the System process is always PID 4.
	want := 1
	if runtime.GOOS == "windows" {
		want = 4
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(want)+"\n"), 0644); err != nil {
		t.Fatalf("could not write test PID: %v", err)
	}

	pid, running := CheckPIDFile(pidFile)
	if pid != want {
		t.Errorf("expected PID %d, got %d", want, pid)
	}
	if !running {
		t.Error("a live process the caller cannot signal must still count as running")
	}
}

func TestNewDaemon(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		_, err := New(nil, nil)
		if err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("valid config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")
		cfg := &config.Config{
			Domains: []config.DomainRule{{Pattern: "example.com"}},
			DNS: config.DNSConfig{
				Servers:  []string{"8.8.8.8"},
				CacheTTL: 300,
			},
			Daemon: config.DaemonConfig{
				PollInterval: 1,
				PidFile:      filepath.Join(tmpDir, "test.pid"),
				LogLevel:     "info",
			},
		}

		d, err := New(cfg, config.YAMLFile(configPath))
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		isolateDNS(t, d)
		if d == nil {
			t.Fatal("daemon should not be nil")
		}
	})
}

func TestDaemonStatus(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	cfg := &config.Config{
		Domains: []config.DomainRule{{Pattern: "example.com"}},
		DNS: config.DNSConfig{
			Servers:  []string{"8.8.8.8"},
			CacheTTL: 300,
		},
		Daemon: config.DaemonConfig{
			PollInterval: 1,
			PidFile:      filepath.Join(tmpDir, "test.pid"),
			LogLevel:     "debug",
		},
	}

	d, err := New(cfg, config.YAMLFile(configPath))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)

	// Initial status
	status := d.GetStatus()
	if status.Running {
		t.Error("daemon should not be running initially")
	}
	if status.RouteCount != 0 {
		t.Errorf("expected 0 routes, got %d", status.RouteCount)
	}
}

func TestDaemonStartStop(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	cfg := &config.Config{
		Domains: []config.DomainRule{{Pattern: "example.com"}},
		DNS: config.DNSConfig{
			Servers:  []string{"8.8.8.8"},
			CacheTTL: 300,
		},
		Daemon: config.DaemonConfig{
			PollInterval: 1,
			PidFile:      filepath.Join(tmpDir, "test.pid"),
			LogLevel:     "error", // Reduce log noise
		},
	}

	d, err := New(cfg, config.YAMLFile(configPath))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)

	// Start
	err = d.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !d.IsRunning() {
		t.Error("daemon should be running after Start")
	}

	// PID file should exist
	_, exists := CheckPIDFile(cfg.Daemon.PidFile)
	if !exists {
		t.Error("PID file should exist after start")
	}

	// Double start should fail
	err = d.Start()
	if err == nil {
		t.Error("expected error on double start")
	}

	// Stop
	d.Stop()

	if d.IsRunning() {
		t.Error("daemon should not be running after Stop")
	}

	// PID file should be removed
	_, exists = CheckPIDFile(cfg.Daemon.PidFile)
	if exists {
		t.Error("PID file should be removed after stop")
	}

	// Double stop should be safe
	d.Stop() // Should not panic
}

func TestNetIPToNetipAddr(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"IPv4", "192.168.1.1", true},
		{"IPv6", "::1", true},
		{"nil", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip []byte
			if tt.input != "" {
				// Parse manually for test
				if tt.input == "192.168.1.1" {
					ip = []byte{192, 168, 1, 1}
				} else if tt.input == "::1" {
					ip = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
				}
			}

			addr := netIPToNetipAddr(ip)
			if addr.IsValid() != tt.valid {
				t.Errorf("IsValid() = %v, want %v", addr.IsValid(), tt.valid)
			}
		})
	}
}

// newTestDaemonConfig builds a minimal valid config rooted at a temp dir, so
// tests never touch a real PID file or the production journal path.
func newTestDaemonConfig(tmpDir string) *config.Config {
	return &config.Config{
		Domains: []config.DomainRule{{Pattern: "example.com"}},
		DNS: config.DNSConfig{
			Servers:  []string{"8.8.8.8"},
			CacheTTL: 300,
		},
		Daemon: config.DaemonConfig{
			PollInterval: 1,
			PidFile:      filepath.Join(tmpDir, "test.pid"),
			LogLevel:     "error",
		},
	}
}

// TestStartRecoversTransitionBeforeMonitorsStart proves that an incomplete
// transition journal left behind by a crashed prior process is compensated
// synchronously inside Start(), before Start() returns and therefore before
// the VPN monitor, event loop, DNS/gateway loops, or socket server begin
// running. It uses a hand-written journal with zero steps so compensation
// touches no real route/netstat command, keeping the test hermetic.
func TestStartRecoversTransitionBeforeMonitorsStart(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	cfg := newTestDaemonConfig(tmpDir)

	d, err := New(cfg, config.YAMLFile(configPath))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)

	journalPath := filepath.Join(tmpDir, "transition.json")
	journalJSON := fmt.Sprintf(`{
		"schema_version": 1,
		"generation_id": "test-gen",
		"previous_provider": "none",
		"target_provider": "tailscale",
		"phase": "activating",
		"pre_state": [],
		"steps": [],
		"created_at": %q,
		"updated_at": %q
	}`, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(journalPath, []byte(journalJSON), 0600); err != nil {
		t.Fatalf("write fake journal: %v", err)
	}
	d.routeManager.SetJournalPath(journalPath)

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer d.Stop()

	// The journal was written by an older release that still recorded
	// provider fields; they are ignored and the journal is compensated.
	if degraded, reason := d.routeManager.Degraded(); degraded {
		t.Errorf("expected a compensated zero-step journal to leave the daemon healthy, got: %s", reason)
	}

	// A zero-step journal compensates immediately by being removed; its
	// absence right after Start() returns confirms recovery ran
	// synchronously rather than being deferred to a background goroutine.
	if _, err := os.Stat(journalPath); !os.IsNotExist(err) {
		t.Errorf("expected the journal to be removed by recovery, stat err=%v", err)
	}
}

// TestStartWithNoJournalStaysHealthy confirms a clean startup (the common
// case: no crash occurred) never marks the route manager degraded.
func TestStartWithNoJournalStaysHealthy(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	cfg := newTestDaemonConfig(tmpDir)

	d, err := New(cfg, config.YAMLFile(configPath))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)
	d.routeManager.SetJournalPath(filepath.Join(tmpDir, "transition.json"))

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer d.Stop()

	if degraded, reason := d.routeManager.Degraded(); degraded {
		t.Errorf("expected a clean startup to stay healthy, got degraded: %s", reason)
	}
}

// fakeVPNWatcher stands in for the AWS tunnel monitor so a daemon test never
// shells out to the routing table or reacts to a VPN that happens to be up on
// the machine running the tests.
type fakeVPNWatcher struct {
	mu          sync.Mutex
	events      chan monitor.VPNEvent
	started     bool
	stopped     bool
	ctxDone     <-chan struct{}
	tunnels     map[string]netip.Addr
	stopEntered chan struct{}
	stopRelease chan struct{}
}

func newFakeVPNWatcher() *fakeVPNWatcher {
	return &fakeVPNWatcher{events: make(chan monitor.VPNEvent), tunnels: make(map[string]netip.Addr)}
}

func (f *fakeVPNWatcher) Start(ctx context.Context) {
	f.mu.Lock()
	f.started = true
	f.ctxDone = ctx.Done()
	f.mu.Unlock()
	<-ctx.Done()
}

func (f *fakeVPNWatcher) Stop() {
	f.mu.Lock()
	f.stopped = true
	stopEntered := f.stopEntered
	stopRelease := f.stopRelease
	f.mu.Unlock()
	if stopEntered != nil {
		close(stopEntered)
	}
	if stopRelease != nil {
		<-stopRelease
	}
}

func (f *fakeVPNWatcher) Events() <-chan monitor.VPNEvent { return f.events }

func (f *fakeVPNWatcher) Recheck() {}

func (f *fakeVPNWatcher) IsConnected() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.tunnels) > 0
}

func (f *fakeVPNWatcher) Tunnels() []monitor.Tunnel {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]monitor.Tunnel, 0, len(f.tunnels))
	for iface, gw := range f.tunnels {
		out = append(out, monitor.Tunnel{Interface: iface, Gateway: gw})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Interface < out[j].Interface })
	return out
}

func (f *fakeVPNWatcher) CurrentInterface() string {
	if t := f.Tunnels(); len(t) > 0 {
		return t[0].Interface
	}
	return ""
}

func (f *fakeVPNWatcher) CurrentGateway() netip.Addr {
	if t := f.Tunnels(); len(t) > 0 {
		return t[0].Gateway
	}
	return netip.Addr{}
}

// setConnected mirrors what the real VPN monitor would record once it observes
// a connected tunnel, so tests can exercise Daemon accessors that read through
// the current generation's monitor. Calling it for another interface adds a
// second tunnel.
func (f *fakeVPNWatcher) setConnected(iface string, gw netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tunnels[iface] = gw
}

// setDisconnected mirrors the monitor noticing that a tunnel went away.
func (f *fakeVPNWatcher) setDisconnected(iface string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.tunnels, iface)
}

func (f *fakeVPNWatcher) wasStarted() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started
}

func (f *fakeVPNWatcher) wasStopped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopped
}

// newTransitionTestDaemon builds a started daemon whose AWS runtime uses fake
// monitors, and returns the daemon plus the list of monitors it has built.
func newTransitionTestDaemon(t *testing.T) (*Daemon, func() []*fakeVPNWatcher) {
	t.Helper()

	tmpDir := t.TempDir()
	cfg := newTestDaemonConfig(tmpDir)
	d, err := New(cfg, config.YAMLFile(filepath.Join(tmpDir, "config.yaml")))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)
	d.routeManager.SetJournalPath(filepath.Join(tmpDir, "transition.json"))

	var mu sync.Mutex
	var built []*fakeVPNWatcher
	d.hooks.newMonitor = func(time.Duration) vpnWatcher {
		w := newFakeVPNWatcher()
		mu.Lock()
		built = append(built, w)
		mu.Unlock()
		return w
	}

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(d.Stop)

	return d, func() []*fakeVPNWatcher {
		mu.Lock()
		defer mu.Unlock()
		return append([]*fakeVPNWatcher(nil), built...)
	}
}

// TestDetachedGenerationCannotMutate covers the race the generation design
// exists to close: work already in flight when shutdown begins must not apply
// its effects to the routing table afterwards.
func TestDetachedGenerationCannotMutate(t *testing.T) {
	d, _ := newTransitionTestDaemon(t)

	gen := d.currentGeneration()
	if !d.mayMutate(gen) {
		t.Fatal("the live generation should be allowed to mutate")
	}

	d.Stop()

	if d.mayMutate(gen) {
		t.Error("a generation that no longer owns route state must not mutate")
	}
}

// TestOnVPNConnectIsANoOpForADetachedGeneration protects the invariant behind
// onVPNConnect's second mayMutate re-check: once a generation has been
// detached by shutdown, delivering a VPN-connect event to its
// handler directly must record no VPN state, install no routes, and leave
// the route manager healthy. It calls onVPNConnect itself (not through the
// event loop) so it exercises the handler body exactly, independent of
// eventLoop's own guard.
//
// This test is intentionally 100% safe regardless of whether either
// mayMutate guard inside onVPNConnect is present: the AWS generation here is
// fully detached (its context is cancelled and it no longer owns d.current)
// before onVPNConnect is ever called, so the pre-existing entry check alone
// already halts execution before SetVPNState or any exec-backed route call.
// It therefore proves total-guard regression (both checks removed) but does
// NOT, on its own, isolate the narrow race the second guard was added for -
// see the audit report for why that race is not independently testable
// without weakening the hermetic/no-real-exec constraint.
func TestOnVPNConnectIsANoOpForADetachedGeneration(t *testing.T) {
	d, _ := newTransitionTestDaemon(t)

	gen := d.currentGeneration()
	if gen == nil {
		t.Fatal("startup must produce a generation")
	}

	d.Stop()
	if d.mayMutate(gen) {
		t.Fatal("test setup: the generation must already be detached")
	}

	d.onVPNConnect(gen, monitor.VPNEvent{
		State:     monitor.VPNConnected,
		Interface: "utun9",
		Gateway:   netip.MustParseAddr("10.0.0.1"),
	})

	if s := d.sessions.get("utun9"); s != nil {
		t.Errorf("a detached generation must not be allowed to record VPN state, got a session for %q", s.iface)
	}
	if count := d.GetRouteCount(); count != 0 {
		t.Errorf("a detached generation must not install any routes, got %d", count)
	}
	if degraded, reason := d.Degraded(); degraded {
		t.Errorf("a no-op call must not leave the route manager degraded, reason: %s", reason)
	}
}

func TestGenerationMutationLeaseRejectsWorkerThatPassedAnEarlierCheck(t *testing.T) {
	d, _ := newTransitionTestDaemon(t)
	gen := d.currentGeneration()
	if gen == nil || !d.mayMutate(gen) {
		t.Fatal("test requires a live generation")
	}

	checked := make(chan struct{})
	release := make(chan struct{})
	result := make(chan bool, 1)
	called := make(chan struct{}, 1)
	go func() {
		// Reproduce the race precisely: the worker passes an advisory
		// ownership check, pauses through a complete shutdown, then reaches
		// the mutation boundary.
		if !d.mayMutate(gen) {
			result <- false
			return
		}
		close(checked)
		<-release
		ran, _ := d.withGenerationMutation(gen, func() error {
			called <- struct{}{}
			return nil
		})
		result <- ran
	}()

	<-checked
	d.Stop()
	close(release)

	if ran := <-result; ran {
		t.Fatal("a worker from the detached generation passed the mutation lease")
	}
	select {
	case <-called:
		t.Fatal("the stale worker's mutation callback executed after shutdown")
	default:
	}
}

// TestVPNDisconnectOnAFreshGenerationMutatesNothing delivers a disconnect
// event through the real event loop (not a direct handler call) on a
// generation that never connected, and proves the event loop consumes it
// without degrading route state and without stalling delivery of the next
// event on the same monitor channel.
//
// Asserting Degraded()/GetRouteCount() alone right after the send is not
// sufficient, since both are already zero before the event is even
// delivered: a test that only polled for them would pass identically whether
// or not eventLoop ever reached its VPNDisconnected case. A second "marker"
// event is sent right after the first so the test also proves eventLoop
// actually looped back and accepted a second event - i.e. the first event
// was drained, not left stuck. The marker is a connect event in additive
// mode against an all-wildcard domain set, so recording it is both
// observable (GetVPNInterface) and itself free of any exec call.
//
// This does NOT prove onVPNDisconnect's own body (DeactivateInvertedSplitTunnel,
// Cleanup) executed: verified by temporarily deleting the
// "d.onVPNDisconnect(gen)" call from handleVPNEvent's VPNDisconnected case -
// the test above still passed, because on a fresh generation both underlying
// calls are no-ops (DefaultRouteModified is false, activeRoutes is empty) and
// removing the dispatch call is not observably different from calling it.
// Proving the call happens would need activeRoutes or DefaultRouteModified
// populated first, which is only possible through a real route mutation
// (exec) - incompatible with this suite's hermetic constraint. Reported as an
// uncovered gap rather than worked around.
func TestVPNDisconnectOnAFreshGenerationMutatesNothing(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := newTestDaemonConfig(tmpDir)
	cfg.Routing.Mode = config.RoutingModeAdditive
	cfg.Domains = []config.DomainRule{{Pattern: "*.rw-test-disconnect-noop.invalid"}}
	d, err := New(cfg, config.YAMLFile(filepath.Join(tmpDir, "config.yaml")))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)
	d.routeManager.SetJournalPath(filepath.Join(tmpDir, "transition.json"))

	var built []*fakeVPNWatcher
	d.hooks.newMonitor = func(time.Duration) vpnWatcher {
		w := newFakeVPNWatcher()
		built = append(built, w)
		return w
	}
	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(d.Stop)
	if len(built) != 1 {
		t.Fatalf("expected exactly one AWS monitor, got %d", len(built))
	}

	built[0].events <- monitor.VPNEvent{
		State:     monitor.VPNDisconnected,
		Interface: "utun9",
		Timestamp: time.Now(),
	}
	// This send only completes once the disconnect above has been handled to
	// completion - see the comment above for why that is what makes the
	// assertions below meaningful rather than trivially true.
	markerGateway := netip.MustParseAddr("10.0.0.9")
	built[0].events <- monitor.VPNEvent{
		State:     monitor.VPNConnected,
		Interface: "utun77",
		Gateway:   markerGateway,
		Timestamp: time.Now(),
	}

	deadline := time.Now().Add(2 * time.Second)
	for d.sessions.get("utun77") == nil {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the marker connect event to be processed")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if degraded, reason := d.Degraded(); degraded {
		t.Errorf("a disconnect on a never-connected generation must not degrade route state: %s", reason)
	}
	if count := d.GetRouteCount(); count != 0 {
		t.Errorf("a disconnect with nothing installed must add no routes, got %d", count)
	}
}

// TestAdditiveModeVPNConnectSyncsRoutesWithoutActivatingSplitTunnel proves the
// additive-mode branch of onVPNConnect (used to coexist with another VPN
// client) records VPN state but never calls ActivateInvertedSplitTunnel, and
// that an all-wildcard domain config makes syncRoutes a no-op so the whole
// path stays hermetic. The wildcard pattern is unique to this test: dns.
// WildcardWarning (which syncRoutes' skip-logic keys off) only reports a
// pattern as a wildcard the first time it is seen per process - reusing a
// pattern already exercised elsewhere in this package would silently fall
// through to a real DNS resolution attempt.
func TestAdditiveModeVPNConnectSyncsRoutesWithoutActivatingSplitTunnel(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := newTestDaemonConfig(tmpDir)
	cfg.Routing.Mode = config.RoutingModeAdditive
	cfg.Domains = []config.DomainRule{{Pattern: "*.rw-test-additive-connect-noop.invalid"}}

	d, err := New(cfg, config.YAMLFile(filepath.Join(tmpDir, "config.yaml")))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)
	d.routeManager.SetJournalPath(filepath.Join(tmpDir, "transition.json"))

	var built []*fakeVPNWatcher
	d.hooks.newMonitor = func(time.Duration) vpnWatcher {
		w := newFakeVPNWatcher()
		built = append(built, w)
		return w
	}

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(d.Stop)
	if len(built) != 1 {
		t.Fatalf("expected exactly one AWS monitor, got %d", len(built))
	}

	built[0].events <- monitor.VPNEvent{
		State:     monitor.VPNConnected,
		Interface: "utun9",
		Gateway:   netip.MustParseAddr("10.0.0.1"),
		Timestamp: time.Now(),
	}

	deadline := time.Now().Add(2 * time.Second)
	for d.sessions.get("utun9") == nil {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the connect event to record VPN state")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if s := d.sessions.get("utun9"); s.manager.GetVPNInterface() != "utun9" || s.manager.GetVPNGateway() != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("the session must record its tunnel's interface and gateway, got %q %v", s.manager.GetVPNInterface(), s.manager.GetVPNGateway())
	}
	if degraded, reason := d.Degraded(); degraded {
		t.Errorf("additive-mode connect must not degrade route state: %s", reason)
	}
	if count := d.GetRouteCount(); count != 0 {
		t.Errorf("additive mode with only wildcard domains must add no routes, got %d", count)
	}
}

// TestGetVPNConnectedReflectsTheCurrentGenerationsMonitor covers the Daemon
// accessors that read straight through to gen.monitor - previously untested
// because fakeVPNWatcher hardcoded every getter to its zero value.
func TestGetVPNConnectedReflectsTheCurrentGenerationsMonitor(t *testing.T) {
	d, monitors := newTransitionTestDaemon(t)

	if d.GetVPNConnected() {
		t.Fatal("a monitor that has not observed a connection must report disconnected")
	}
	if iface := d.GetVPNInterface(); iface != "" {
		t.Errorf("interface = %q, want empty before any connection", iface)
	}

	built := monitors()
	gw := netip.MustParseAddr("10.0.0.1")
	built[0].setConnected("utun9", gw)

	if !d.GetVPNConnected() {
		t.Error("GetVPNConnected must reflect the current generation's monitor once connected")
	}
	if iface := d.GetVPNInterface(); iface != "utun9" {
		t.Errorf("interface = %q, want utun9", iface)
	}
	if status := d.GetStatus(); status.VPNGateway != gw {
		t.Errorf("status gateway = %v, want %v", status.VPNGateway, gw)
	}
}

// TestDomainWrapperMethodsDelegateToTheStore covers the thin Daemon-level
// ListDomains/AddDomain/RemoveDomain/SetDomains wrappers, which were
// previously exercised only indirectly through ConfigStore's own tests.
func TestDomainWrapperMethodsDelegateToTheStore(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := newTestDaemonConfig(tmpDir)
	cfg.Domains = []config.DomainRule{{Pattern: "example.com"}}

	d, err := New(cfg, config.YAMLFile(filepath.Join(tmpDir, "config.yaml")))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)

	if got, _, _ := d.ListDomains(""); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("ListDomains = %v, want the single configured domain", got)
	}

	if err := d.AddDomain("", "api.example.com"); err != nil {
		t.Fatalf("AddDomain failed: %v", err)
	}
	if got, _, _ := d.ListDomains(""); len(got) != 2 {
		t.Errorf("ListDomains after add = %v, want 2 entries", got)
	}

	if err := d.RemoveDomain("", "api.example.com"); err != nil {
		t.Fatalf("RemoveDomain failed: %v", err)
	}
	if got, _, _ := d.ListDomains(""); len(got) != 1 {
		t.Errorf("ListDomains after remove = %v, want 1 entry", got)
	}

	err = d.RemoveDomain("", "never-added.example.com")
	if err == nil {
		t.Fatal("expected removing an absent domain to fail")
	}
	if !errors.Is(err, api.ErrRejected) {
		t.Errorf("a not-found removal must be attributable to the request, got %v", err)
	}

	_, rev, _ := d.ListDomains("")
	if err := d.SetDomains("", []string{"replaced.example.com"}, rev); err != nil {
		t.Fatalf("SetDomains failed: %v", err)
	}
	if got, _, _ := d.ListDomains(""); len(got) != 1 || got[0] != "replaced.example.com" {
		t.Errorf("ListDomains after SetDomains = %v, want only replaced.example.com", got)
	}

	if err := d.SetDomains("", []string{"stale.example.com"}, rev); err == nil {
		t.Fatal("expected a stale revision to be rejected")
	} else if !errors.Is(err, api.ErrRejected) {
		t.Errorf("a stale-revision rejection must be attributable to the request, got %v", err)
	}
}

// TestDomainMutationPersistFailureIsReportedNotSwallowed mirrors
// TestConfigStore_PersistFailureLeavesStoreUnchanged (config_store_test.go)
// one layer up: it drives the failure through the Daemon API surface
// (AddDomain, not store.AddDomain) to prove classifyConfigError preserves
// ErrPersistFailed rather than remapping every store error to api.ErrRejected.
func TestDomainMutationPersistFailureIsReportedNotSwallowed(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("root ignores directory permissions, and Windows has none to chmod")
	}

	dir := t.TempDir()
	cfg := newTestDaemonConfig(dir)
	cfg.Domains = []config.DomainRule{{Pattern: "example.com"}}

	d, err := New(cfg, config.YAMLFile(filepath.Join(dir, "config.yaml")))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)

	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	err = d.AddDomain("", "api.example.com")
	if err == nil {
		t.Fatal("expected AddDomain to fail when the config cannot be written")
	}
	if !errors.Is(err, ErrPersistFailed) {
		t.Errorf("error = %v, want it to wrap ErrPersistFailed so the CLI can tell a write failure apart from a bad request", err)
	}
	if errors.Is(err, api.ErrRejected) {
		t.Error("a persist failure is not the caller's fault and must not also satisfy api.ErrRejected")
	}
	if got, _, _ := d.ListDomains(""); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("ListDomains = %v, want the failed mutation discarded", got)
	}
}

// TestGetActiveRoutesIsAnEmptySliceNotNilWhenNothingIsRouted protects the API
// wire contract: with zero active routes, GetActiveRoutes must still return a
// non-nil, zero-length slice, since json.Marshal of a nil slice encodes as
// `null` while callers of the routes.list RPC expect `[]`.
func TestGetActiveRoutesIsAnEmptySliceNotNilWhenNothingIsRouted(t *testing.T) {
	tmpDir := t.TempDir()
	d, err := New(newTestDaemonConfig(tmpDir), config.YAMLFile(filepath.Join(tmpDir, "config.yaml")))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	isolateDNS(t, d)

	routes := d.GetActiveRoutes()
	if routes == nil {
		t.Fatal("GetActiveRoutes must return an empty slice, not nil, so it marshals to [] not null")
	}
	if len(routes) != 0 {
		t.Errorf("GetActiveRoutes = %v, want none before any route is added", routes)
	}
}

// isolateDNS points a test daemon's resolver files at a temporary directory
// and its forwarder at a free loopback port, so no test touches /etc/resolver
// or competes for the production forwarder port.
func isolateDNS(t *testing.T, d *Daemon) {
	t.Helper()
	d.resolverFiles = resolverfiles.New(t.TempDir(), dnsproxy.ListenHost, dnsproxy.ListenPort)
	// Tests never empty the DNS cache of the machine they run on.
	d.hooks.flushSystemDNS = func(context.Context) error { return nil }
	d.forwarder = dnsproxy.NewAt("127.0.0.1:0", dnsproxy.Config{
		Upstreams: d.upstreamsFor,
		Matches:   d.matchesWildcard,
		OnMatch:   d.onWildcardAnswer,
		Logger:    d.logger,
	})
	// Tests never capture packets (that needs root).
	d.dnsWatcher = nil
	// Tests never ask lsof which program owns a tunnel.
	d.hooks.identifyClient = func(context.Context, string) (vpnclient.Client, error) {
		return vpnclient.Client{}, errors.New("client identification is disabled in tests")
	}
	// Tests never read the machine's real DNS configuration.
	d.hooks.vpnNameservers = func(context.Context, string, bool) ([]netip.Addr, bool, error) { return nil, false, nil }
	d.hooks.systemNameservers = func(context.Context) ([]netip.Addr, error) { return nil, nil }
}
