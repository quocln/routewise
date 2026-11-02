package telemetry

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/quocln/routewise/internal/config"
)

// fakeTransport records what the SDK would send; no test touches the network.
type fakeTransport struct {
	mu     sync.Mutex
	events []*sentry.Event
}

func (f *fakeTransport) Flush(time.Duration) bool              { return true }
func (f *fakeTransport) FlushWithContext(context.Context) bool { return true }
func (f *fakeTransport) Configure(sentry.ClientOptions)        {}
func (f *fakeTransport) Close()                                {}
func (f *fakeTransport) SendEvent(e *sentry.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

// snapshot returns the recorded events as JSON, the form the server sees.
func (f *fakeTransport) snapshot(t *testing.T) (errs, txns []string, logs []sentry.Log) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.events {
		logs = append(logs, e.Logs...)
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case e.Type == "transaction":
			txns = append(txns, string(raw))
		case len(e.Logs) == 0:
			errs = append(errs, string(raw))
		}
	}
	return
}

func testConfig(tc config.TelemetryConfig) *config.Config {
	cfg := config.DefaultConfig()
	cfg.Domains = []config.DomainRule{{Pattern: "*.corp.example.com"}}
	cfg.Profiles = []config.TunnelProfile{{ID: "0a1b2c3d", Kind: config.ProfileKindWireGuard, Name: "Berlin Office"}}
	cfg.Telemetry = tc
	return cfg
}

func newTestManager(t *testing.T) (*Manager, *fakeTransport) {
	t.Helper()
	ft := &fakeTransport{}
	m := New(Options{Version: "9.9", Environment: "test", Transport: func() sentry.Transport { return ft }})
	t.Cleanup(m.Close)
	return m, ft
}

const goodDSN = "https://pubkey@rustrak.example.test/3"

func logger(m *Manager) *slog.Logger {
	return slog.New(m.WrapHandler(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelInfo})))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestErrorRecordsBecomeScrubbedEvents(t *testing.T) {
	m, ft := newTestManager(t)
	m.Apply(testConfig(config.TelemetryConfig{DSN: goodDSN, Errors: true, TracesSampleRate: 1}))
	if !m.Active() {
		t.Fatal("expected reporting to be active")
	}

	log := logger(m).With("profile", "Berlin Office")
	log.Error("tunnel to 10.8.0.1 failed for wiki.corp.example.com",
		"server", "vpn.example.com:51820", "err", "dial tcp 192.168.1.5:443: refused", "attempt", 3)
	m.Flush()

	errs, _, _ := ft.snapshot(t)
	if len(errs) != 1 {
		t.Fatalf("events = %d, want 1: %v", len(errs), errs)
	}
	ev := errs[0]
	for _, leak := range []string{"10.8.0.1", "corp.example.com", "vpn.example.com", "192.168.1.5", "Berlin Office"} {
		if strings.Contains(ev, leak) {
			t.Errorf("event leaks %q: %s", leak, ev)
		}
	}
	for _, want := range []string{`"release":"routewise-helper@9.9"`, `"environment":"test"`, `"attempt":"3"`, Redacted} {
		if !strings.Contains(ev, want) {
			t.Errorf("event lacks %q: %s", want, ev)
		}
	}
	if !strings.Contains(ev, `"user":{}`) {
		t.Errorf("event carries user data: %s", ev)
	}
	for _, absent := range []string{`"server_name"`, `"request"`, "wiki"} {
		if strings.Contains(ev, absent) {
			t.Errorf("event carries %s: %s", absent, ev)
		}
	}
	if !strings.Contains(ev, `"stacktrace"`) {
		t.Errorf("event has no stack trace: %s", ev)
	}
}

func TestKindFlagsGateEachKind(t *testing.T) {
	cases := []struct {
		name               string
		tc                 config.TelemetryConfig
		wantErrs, wantLogs int
		wantTxns           int
	}{
		{"errors only", config.TelemetryConfig{Errors: true}, 1, 0, 0},
		{"logs only", config.TelemetryConfig{Logs: true}, 0, 2, 0},
		{"traces only", config.TelemetryConfig{Traces: true}, 0, 0, 1},
		{"all", config.TelemetryConfig{Errors: true, Logs: true, Traces: true}, 1, 2, 1},
		{"sessions only is off", config.TelemetryConfig{Sessions: true}, 0, 0, 0},
		{"no kinds", config.TelemetryConfig{}, 0, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, ft := newTestManager(t)
			c.tc.DSN, c.tc.TracesSampleRate = goodDSN, 1
			m.Apply(testConfig(c.tc))

			l := logger(m)
			l.Info("not forwarded")
			l.Warn("a warning")
			l.Error("an error")
			_, txn := m.StartTransaction(context.Background(), "rpc", "domains.add")
			txn.Finish(false)
			m.Flush()

			errs, txns, logs := ft.snapshot(t)
			if len(errs) != c.wantErrs || len(txns) != c.wantTxns || len(logs) != c.wantLogs {
				t.Errorf("errors=%d logs=%d transactions=%d, want %d/%d/%d",
					len(errs), len(logs), len(txns), c.wantErrs, c.wantLogs, c.wantTxns)
			}
		})
	}
}

func TestWarnIsALogNotAnEvent(t *testing.T) {
	m, ft := newTestManager(t)
	m.Apply(testConfig(config.TelemetryConfig{DSN: goodDSN, Errors: true, Logs: true, TracesSampleRate: 1}))
	logger(m).Warn("resolver slow for lookup.corp.example.com", "ip", "10.1.2.3")
	m.Flush()

	errs, _, logs := ft.snapshot(t)
	if len(errs) != 0 || len(logs) != 1 {
		t.Fatalf("events=%d logs=%d, want 0 and 1", len(errs), len(logs))
	}
	raw, _ := json.Marshal(logs[0])
	if strings.Contains(string(raw), "corp.example.com") || strings.Contains(string(raw), "10.1.2.3") {
		t.Errorf("log leaks: %s", raw)
	}
}

func TestTransactionsAreScrubbedAndTagged(t *testing.T) {
	m, ft := newTestManager(t)
	m.Apply(testConfig(config.TelemetryConfig{DSN: goodDSN, Traces: true, TracesSampleRate: 1}))

	_, txn := m.StartTransaction(context.Background(), "vpn.connect", "vpn.connect")
	txn.SetTag("kind", "wireguard")
	txn.SetTag("note", "Berlin Office at 10.0.0.9")
	txn.Finish(true)
	m.Flush()

	_, txns, _ := ft.snapshot(t)
	if len(txns) != 1 {
		t.Fatalf("transactions = %d", len(txns))
	}
	tx := txns[0]
	for _, want := range []string{`"transaction":"vpn.connect"`, `"op":"vpn.connect"`, `"kind":"wireguard"`, `"internal_error"`} {
		if !strings.Contains(tx, want) {
			t.Errorf("transaction lacks %s: %s", want, tx)
		}
	}
	if strings.Contains(tx, "Berlin") || strings.Contains(tx, "10.0.0.9") || strings.Contains(tx, `"server_name"`) {
		t.Errorf("transaction leaks: %s", tx)
	}
}

func TestReapplyFollowsConfigurationChanges(t *testing.T) {
	m, ft := newTestManager(t)
	tc := config.TelemetryConfig{DSN: goodDSN, Errors: true, TracesSampleRate: 1}
	m.Apply(testConfig(tc))
	logger(m).Error("first")

	tc.Errors = false
	m.Apply(testConfig(tc)) // every helper kind off: disabled
	if m.Active() {
		t.Error("turning every kind off must disable reporting")
	}
	logger(m).Error("second")

	tc.Errors, tc.DSN = true, ""
	m.Apply(testConfig(tc))
	if m.Active() {
		t.Error("an empty DSN must disable reporting")
	}

	tc.DSN = goodDSN
	m.Apply(testConfig(tc))
	logger(m).Error("third")
	m.Flush()
	time.Sleep(50 * time.Millisecond) // the replaced client flushes in the background

	errs, _, _ := ft.snapshot(t)
	if len(errs) != 2 {
		t.Errorf("events = %d, want the first and third only: %v", len(errs), errs)
	}
}

func TestRenamedProfileIsScrubbedWithoutReinitialising(t *testing.T) {
	m, ft := newTestManager(t)
	tc := config.TelemetryConfig{DSN: goodDSN, Errors: true, TracesSampleRate: 1}
	m.Apply(testConfig(tc))
	cfg := testConfig(tc)
	cfg.Profiles[0].Name = "Tokyo Lab"
	m.Apply(cfg)
	logger(m).Error("profile Tokyo Lab and Berlin Office failed")
	m.Flush()

	errs, _, _ := ft.snapshot(t)
	if len(errs) != 1 || strings.Contains(errs[0], "Tokyo") {
		t.Errorf("events: %v", errs)
	}
}

func TestCapturePanicReportsAndRepanics(t *testing.T) {
	m, ft := newTestManager(t)
	m.Apply(testConfig(config.TelemetryConfig{DSN: goodDSN, Errors: true, TracesSampleRate: 1}))

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("the panic must propagate")
			}
		}()
		defer m.RepanicAfterCapture()
		panic("crash while dialing 10.9.8.7")
	}()

	errs, _, _ := ft.snapshot(t)
	if len(errs) != 1 || strings.Contains(errs[0], "10.9.8.7") || !strings.Contains(errs[0], `"level":"fatal"`) {
		t.Errorf("events: %v", errs)
	}
}

func TestRepanicWithReportingOffStillPropagates(t *testing.T) {
	m, _ := newTestManager(t)
	defer func() {
		if recover() == nil {
			t.Error("the panic must propagate")
		}
	}()
	defer m.RepanicAfterCapture()
	panic("boom")
}

func TestHandlerKeepsNextHandlerBehaviourAndGroups(t *testing.T) {
	m, ft := newTestManager(t)
	m.Apply(testConfig(config.TelemetryConfig{DSN: goodDSN, Errors: true, TracesSampleRate: 1}))
	var out strings.Builder
	l := slog.New(m.WrapHandler(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelError})))

	l.Info("quiet") // below the next handler's level and below WARN
	l.WithGroup("tunnel").Error("down", slog.Group("peer", "n", 2), "id", "x")
	m.Flush()

	if strings.Contains(out.String(), "quiet") || !strings.Contains(out.String(), "tunnel.peer.n=2") {
		t.Errorf("next handler output: %q", out.String())
	}
	errs, _, _ := ft.snapshot(t)
	if len(errs) != 1 || !strings.Contains(errs[0], `"tunnel.peer.n":"2"`) || !strings.Contains(errs[0], `"tunnel.id":"x"`) {
		t.Errorf("events: %v", errs)
	}
}

func TestSkipAttrKeepsARecordLocal(t *testing.T) {
	m, ft := newTestManager(t)
	m.Apply(testConfig(config.TelemetryConfig{DSN: goodDSN, Errors: true, TracesSampleRate: 1}))
	logger(m).Error("sdk trouble", SkipAttr, true)
	m.Flush()
	if errs, _, _ := ft.snapshot(t); len(errs) != 0 {
		t.Errorf("a skipped record was reported: %v", errs)
	}
}

func TestNoopTransactionIsSafe(t *testing.T) {
	m := New(Options{})
	_, txn := m.StartTransaction(context.Background(), "rpc", "x")
	txn.SetTag("a", "b")
	txn.Finish(true)
	var nilTxn *Transaction
	nilTxn.SetTag("a", "b")
	nilTxn.Finish(false)
}
