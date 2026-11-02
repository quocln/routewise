package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// DefaultTracesSampleRate is the share of transactions sent when
// telemetry.traces_sample_rate is left unset.
const DefaultTracesSampleRate = 0.2

// TelemetryConfig controls error reporting to a Sentry-protocol server. An
// empty DSN turns every kind off. The DSN carries a public key and is kept out
// of exports and of the public settings.
type TelemetryConfig struct {
	// DSN is http(s)://<public key>@<host>[:port]/<project id>.
	DSN string `yaml:"dsn,omitempty" mapstructure:"dsn"`
	// Errors reports errors and panics.
	Errors bool `yaml:"errors" mapstructure:"errors"`
	// Sessions reports release-health sessions. The helper's SDK has none, so
	// only the app acts on it; the helper stores it for the app to read.
	Sessions bool `yaml:"sessions" mapstructure:"sessions"`
	// Logs reports WARN and above log records.
	Logs bool `yaml:"logs" mapstructure:"logs"`
	// Traces reports performance transactions.
	Traces bool `yaml:"traces" mapstructure:"traces"`
	// TracesSampleRate is the share of transactions sent, 0 to 1. Unset (0)
	// means DefaultTracesSampleRate.
	TracesSampleRate float64 `yaml:"traces_sample_rate" mapstructure:"traces_sample_rate"`
}

// Enabled reports whether the helper has anything to send: a DSN and at least
// one kind its SDK supports (errors, logs, traces).
func (t TelemetryConfig) Enabled() bool {
	return t.DSN != "" && (t.Errors || t.Logs || t.Traces)
}

// errInvalidDSN deliberately never carries the value: a DSN holds a key.
var errInvalidDSN = errors.New("telemetry.dsn must be http(s)://<key>@<host>[:port]/<project id>")

// ValidateDSN checks a DSN. Empty is valid and means off. The error never
// contains the DSN.
func ValidateDSN(dsn string) error {
	if dsn == "" {
		return nil
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return errInvalidDSN
	}
	if u.User == nil || u.User.Username() == "" || u.Hostname() == "" {
		return errInvalidDSN
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errInvalidDSN
	}
	project, found := strings.CutPrefix(u.Path, "/")
	if !found || project == "" || strings.Contains(project, "/") {
		return errInvalidDSN
	}
	return nil
}

// ValidateTracesSampleRate checks a sample rate in [0, 1].
func ValidateTracesSampleRate(rate float64) error {
	// Written so NaN fails too.
	if !(rate >= 0 && rate <= 1) {
		return fmt.Errorf("telemetry.traces_sample_rate must be between 0 and 1")
	}
	return nil
}

// Validate checks the telemetry section.
func (t TelemetryConfig) Validate() error {
	if err := ValidateDSN(t.DSN); err != nil {
		return err
	}
	return ValidateTracesSampleRate(t.TracesSampleRate)
}
