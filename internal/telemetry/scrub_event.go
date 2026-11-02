package telemetry

import (
	"fmt"

	"github.com/getsentry/sentry-go"
	"github.com/getsentry/sentry-go/attribute"
)

// ScrubEvent removes private values from an error or transaction event and
// drops the fields that identify the machine or the caller.
func ScrubEvent(s *Scrubber, e *sentry.Event) {
	e.Request = nil
	e.User = sentry.User{}
	e.ServerName = ""
	e.Message = s.String(e.Message)
	e.Transaction = s.String(e.Transaction)
	e.Logger = s.String(e.Logger)
	for i := range e.Exception {
		e.Exception[i].Value = s.String(e.Exception[i].Value)
		scrubStacktrace(e.Exception[i].Stacktrace)
	}
	for i := range e.Threads {
		scrubStacktrace(e.Threads[i].Stacktrace)
	}
	for _, b := range e.Breadcrumbs {
		ScrubBreadcrumb(s, b)
	}
	for k, v := range e.Tags {
		e.Tags[k] = s.String(v)
	}
	for k, v := range e.Contexts {
		e.Contexts[k] = scrubMap(s, v)
	}
	for _, sp := range e.Spans {
		if sp == nil {
			continue
		}
		sp.Name = s.String(sp.Name)
		sp.Description = s.String(sp.Description)
		for k, v := range sp.Tags {
			sp.Tags[k] = s.String(v)
		}
		sp.Data = scrubMap(s, sp.Data)
	}
}

// scrubStacktrace drops absolute build paths, which carry the developer's
// account name; the module-relative file name stays.
func scrubStacktrace(st *sentry.Stacktrace) {
	if st == nil {
		return
	}
	for i := range st.Frames {
		st.Frames[i].AbsPath = ""
	}
}

// ScrubBreadcrumb scrubs a breadcrumb in place.
func ScrubBreadcrumb(s *Scrubber, b *sentry.Breadcrumb) {
	if b == nil {
		return
	}
	b.Message = s.String(b.Message)
	b.Data = scrubMap(s, b.Data)
}

// ScrubLog scrubs a log record's body and attributes in place.
func ScrubLog(s *Scrubber, l *sentry.Log) {
	l.Body = s.String(l.Body)
	for k, v := range l.Attributes {
		switch v.Type() {
		case attribute.STRING:
			l.Attributes[k] = attribute.StringValue(s.String(v.AsString()))
		case attribute.STRINGSLICE:
			in := v.AsStringSlice()
			out := make([]string, len(in))
			for i, x := range in {
				out[i] = s.String(x)
			}
			l.Attributes[k] = attribute.StringSliceValue(out)
		}
	}
}

func scrubMap(s *Scrubber, m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = scrubValue(s, v)
	}
	return out
}

// scrubValue scrubs the strings inside a value of any shape. A value of
// another type is rendered with %v and replaced only if the rendering changes.
func scrubValue(s *Scrubber, v interface{}) interface{} {
	switch x := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return v
	case string:
		return s.String(x)
	case []string:
		out := make([]string, len(x))
		for i, e := range x {
			out[i] = s.String(e)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, e := range x {
			out[i] = scrubValue(s, e)
		}
		return out
	case map[string]interface{}:
		return scrubMap(s, x)
	case map[string]string:
		out := make(map[string]string, len(x))
		for k, e := range x {
			out[k] = s.String(e)
		}
		return out
	case error:
		return s.String(x.Error())
	default:
		text := fmt.Sprint(v)
		if scrubbed := s.String(text); scrubbed != text {
			return scrubbed
		}
		return v
	}
}
