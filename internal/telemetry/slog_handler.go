package telemetry

import (
	"context"
	"log/slog"
	"strings"

	"github.com/getsentry/sentry-go"
)

// SkipAttr marks a record that must not be forwarded to the server. A caller
// logging from inside the reporting path adds it, which keeps a failure to
// report from being reported again.
const SkipAttr = "telemetry.skip"

// handler forwards records to the next handler and, when reporting is on, ERROR
// records as error events and WARN and above as server logs. It never blocks:
// the SDK queues the work, and a failure inside it is swallowed.
type handler struct {
	next   slog.Handler
	m      *Manager
	attrs  []slog.Attr // already prefixed with their group path
	groups []string
}

// WrapHandler returns h extended to report through m.
func (m *Manager) WrapHandler(h slog.Handler) slog.Handler {
	return &handler{next: h, m: m}
}

// WrapHandler wraps h with the default manager.
func WrapHandler(h slog.Handler) slog.Handler { return Default.WrapHandler(h) }

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l) || (l >= slog.LevelWarn && h.m.Active())
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if h.next.Enabled(ctx, r.Level) {
		err = h.next.Handle(ctx, r)
	}
	if r.Level >= slog.LevelWarn {
		h.forward(ctx, r)
	}
	return err
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := *h
	out.next = h.next.WithAttrs(attrs)
	out.attrs = append(append([]slog.Attr(nil), h.attrs...), prefixAttrs(h.groups, attrs)...)
	return &out
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	out := *h
	out.next = h.next.WithGroup(name)
	out.groups = append(append([]string(nil), h.groups...), name)
	return &out
}

func prefixAttrs(groups []string, attrs []slog.Attr) []slog.Attr {
	if len(groups) == 0 {
		return attrs
	}
	prefix := strings.Join(groups, ".") + "."
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = slog.Attr{Key: prefix + a.Key, Value: a.Value}
	}
	return out
}

// forward reports one WARN+ record. A panic in the SDK or in an attribute's
// String method must never reach the logging caller.
func (h *handler) forward(ctx context.Context, r slog.Record) {
	defer func() { _ = recover() }()
	s := h.m.cur.Load()
	if s == nil || (!s.cfg.Errors && !s.cfg.Logs) {
		return
	}
	attrs := make(map[string]string, len(h.attrs)+r.NumAttrs())
	skip := false
	collect := func(prefix string, a slog.Attr) {}
	collect = func(prefix string, a slog.Attr) {
		a.Value = a.Value.Resolve()
		if a.Value.Kind() == slog.KindGroup {
			p := prefix + a.Key
			if a.Key != "" {
				p += "."
			}
			for _, g := range a.Value.Group() {
				collect(p, g)
			}
			return
		}
		if prefix+a.Key == SkipAttr {
			skip = true
			return
		}
		attrs[prefix+a.Key] = a.Value.String()
	}
	for _, a := range h.attrs {
		collect("", a)
	}
	prefix := ""
	if len(h.groups) > 0 {
		prefix = strings.Join(h.groups, ".") + "."
	}
	r.Attrs(func(a slog.Attr) bool { collect(prefix, a); return true })
	if skip {
		return
	}

	if r.Level >= slog.LevelError && s.cfg.Errors {
		s.hub.WithScope(func(scope *sentry.Scope) {
			scope.SetLevel(sentry.LevelError)
			if len(attrs) > 0 {
				fields := make(map[string]interface{}, len(attrs))
				for k, v := range attrs {
					fields[k] = v
				}
				scope.SetContext("log_attributes", fields)
			}
			s.hub.CaptureMessage(r.Message)
		})
	}
	if s.cfg.Logs && s.logger != nil {
		entry := s.logger.Warn()
		if r.Level >= slog.LevelError {
			entry = s.logger.Error()
		}
		for k, v := range attrs {
			entry = entry.String(k, v)
		}
		entry.Emit(r.Message)
	}
}
