// Package telemetry reports the helper's errors, WARN+ logs and performance
// traces to a Sentry-protocol server. Everything leaves through a scrubber
// that removes domains, addresses and profile names first.
//
// Sessions (release health) are not supported by sentry-go, so the helper
// ignores that kind; it only acts on errors, logs and traces.
package telemetry

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/quocln/routewise/internal/config"
)

// serverName is sent instead of the machine's hostname.
const serverName = "routewise-helper"

// flushTimeout bounds how long a crash or a shutdown waits for delivery.
const flushTimeout = 2 * time.Second

// Options configures a Manager.
type Options struct {
	// Version is the helper's version.
	Version string
	// Environment is "production" or "development" and so on.
	Environment string
	// Transport replaces the network transport; tests use it.
	Transport func() sentry.Transport
}

// state is one initialised SDK client with the settings it was made from.
type state struct {
	client *sentry.Client
	hub    *sentry.Hub
	cfg    config.TelemetryConfig
	// logger sends server logs; nil when logs are off.
	logger sentry.Logger
}

// Manager owns the SDK client. It is re-initialised whenever the telemetry
// settings change and disabled when nothing is to be sent.
type Manager struct {
	scrub *Scrubber

	mu      sync.Mutex // serialises Apply
	opts    Options
	applied config.TelemetryConfig
	cur     atomic.Pointer[state]
}

// New returns a disabled Manager.
func New(opts Options) *Manager {
	return &Manager{scrub: NewScrubber(), opts: opts}
}

// Default is the helper's manager.
var Default = New(Options{Environment: "production"})

// SetBuild records the version and environment used by later Apply calls.
func (m *Manager) SetBuild(version, environment string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.opts.Version, m.opts.Environment = version, environment
}

// Scrubber returns the manager's scrubber.
func (m *Manager) Scrubber() *Scrubber { return m.scrub }

// Apply makes cfg's telemetry settings and private values live. It never
// blocks on the network: a replaced client is flushed in the background. The
// scrubber's terms follow every call, so a renamed profile is covered at once.
func (m *Manager) Apply(cfg *config.Config) {
	if cfg == nil {
		return
	}
	m.scrub.SetTerms(TermsFromConfig(cfg))

	m.mu.Lock()
	defer m.mu.Unlock()
	tc := cfg.Telemetry
	if tc == m.applied && (m.cur.Load() != nil) == tc.Enabled() {
		return
	}
	m.applied = tc

	var next *state
	if tc.Enabled() {
		next = m.newState(tc)
		if next == nil {
			// The store validates the DSN, so this is not expected; treat a
			// client error as off rather than failing a config change.
			m.applied = config.TelemetryConfig{}
		}
	}
	if old := m.cur.Swap(next); old != nil {
		go old.client.Flush(flushTimeout)
	}
}

// newState creates a client for tc, or nil when the SDK rejects it.
func (m *Manager) newState(tc config.TelemetryConfig) *state {
	opts := sentry.ClientOptions{
		Dsn:              tc.DSN,
		Release:          "routewise-helper@" + m.opts.Version,
		Environment:      m.opts.Environment,
		ServerName:       serverName,
		SendDefaultPII:   false,
		AttachStacktrace: true,
		// sentry-go has no switch for logs: they are sent only through the
		// logger created below when Logs is on, and BeforeSendLog drops them
		// otherwise.
		EnableTracing: tc.Traces,
		BeforeSend: func(e *sentry.Event, _ *sentry.EventHint) *sentry.Event {
			if !tc.Errors {
				return nil
			}
			ScrubEvent(m.scrub, e)
			return e
		},
		BeforeSendTransaction: func(e *sentry.Event, _ *sentry.EventHint) *sentry.Event {
			if !tc.Traces {
				return nil
			}
			ScrubEvent(m.scrub, e)
			return e
		},
		BeforeSendLog: func(l *sentry.Log) *sentry.Log {
			if !tc.Logs {
				return nil
			}
			ScrubLog(m.scrub, l)
			return l
		},
		BeforeBreadcrumb: func(b *sentry.Breadcrumb, _ *sentry.BreadcrumbHint) *sentry.Breadcrumb {
			ScrubBreadcrumb(m.scrub, b)
			return b
		},
	}
	if tc.Traces {
		opts.TracesSampleRate = tc.TracesSampleRate
	}
	if m.opts.Transport != nil {
		opts.Transport = m.opts.Transport()
	}
	client, err := sentry.NewClient(opts)
	if err != nil {
		return nil
	}
	st := &state{client: client, hub: sentry.NewHub(client, sentry.NewScope()), cfg: tc}
	if tc.Logs {
		st.logger = sentry.NewLogger(sentry.SetHubOnContext(context.Background(), st.hub))
	}
	return st
}

// Active reports whether events are being sent.
func (m *Manager) Active() bool { return m.cur.Load() != nil }

// Close flushes what is pending, for at most flushTimeout, and disables the
// manager.
func (m *Manager) Close() {
	m.mu.Lock()
	m.applied = config.TelemetryConfig{}
	old := m.cur.Swap(nil)
	m.mu.Unlock()
	if old != nil {
		old.client.Flush(flushTimeout)
	}
}

// Flush waits up to flushTimeout for pending events.
func (m *Manager) Flush() {
	if s := m.cur.Load(); s != nil {
		s.client.Flush(flushTimeout)
	}
}

// CapturePanic reports a recovered panic value and flushes.
func (m *Manager) CapturePanic(r any) {
	s := m.cur.Load()
	if s == nil || !s.cfg.Errors {
		return
	}
	s.hub.Recover(r)
	s.client.Flush(flushTimeout)
}

// RepanicAfterCapture is deferred at the top of a goroutine: it reports a
// panic, flushes, and panics again so the helper still crashes and launchd
// restarts it. It must be the deferred function itself for recover to work.
func (m *Manager) RepanicAfterCapture() {
	if r := recover(); r != nil {
		m.CapturePanic(r)
		panic(r)
	}
}

// Transaction is a running trace. A zero Transaction is a no-op, so callers
// need not check whether tracing is on.
type Transaction struct{ span *sentry.Span }

// StartTransaction begins a transaction with the given operation and name.
// When tracing is off it returns a no-op Transaction.
func (m *Manager) StartTransaction(ctx context.Context, op, name string) (context.Context, *Transaction) {
	s := m.cur.Load()
	if s == nil || !s.cfg.Traces {
		return ctx, &Transaction{}
	}
	ctx = sentry.SetHubOnContext(ctx, s.hub)
	span := sentry.StartTransaction(ctx, name, sentry.WithOpName(op), sentry.WithTransactionSource(sentry.SourceCustom))
	return span.Context(), &Transaction{span: span}
}

// SetTag attaches a tag to the transaction.
func (t *Transaction) SetTag(key, value string) {
	if t != nil && t.span != nil {
		t.span.SetTag(key, value)
	}
}

// Finish ends the transaction; failed marks it as an internal error.
func (t *Transaction) Finish(failed bool) {
	if t == nil || t.span == nil {
		return
	}
	if failed {
		t.span.Status = sentry.SpanStatusInternalError
	} else {
		t.span.Status = sentry.SpanStatusOK
	}
	t.span.Finish()
}

// Apply is Default.Apply.
func Apply(cfg *config.Config) { Default.Apply(cfg) }

// Close is Default.Close.
func Close() { Default.Close() }

// RepanicAfterCapture is Default.RepanicAfterCapture; defer it directly.
func RepanicAfterCapture() {
	if r := recover(); r != nil {
		Default.CapturePanic(r)
		panic(r)
	}
}

// StartTransaction is Default.StartTransaction.
func StartTransaction(ctx context.Context, op, name string) (context.Context, *Transaction) {
	return Default.StartTransaction(ctx, op, name)
}
