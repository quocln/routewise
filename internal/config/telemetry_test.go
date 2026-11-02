package config

import (
	"encoding/json"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateDSN(t *testing.T) {
	good := []string{
		"",
		"https://abc123@rustrak.example.com/1",
		"http://key@10.0.0.5:8080/42",
		"https://key@[::1]:9000/7",
		"https://pub:secret@host.example/3",
		"https://key@host.example/my-project",
	}
	bad := map[string]string{
		"no scheme":        "key@host/1",
		"bad scheme":       "ftp://key@host/1",
		"no user":          "https://host.example/1",
		"empty user":       "https://@host.example/1",
		"no host":          "https:///1",
		"no path":          "https://key@host.example",
		"root path":        "https://key@host.example/",
		"nested path":      "https://key@host.example/a/1",
		"trailing slash":   "https://key@host.example/1/",
		"query":            "https://key@host.example/1?x=1",
		"fragment":         "https://key@host.example/1#x",
		"not a url":        "%%%",
		"whitespace only":  "   ",
		"scheme only":      "https://",
		"opaque":           "https:key@host/1",
		"path prefix only": "https://key@host.example//",
	}
	for _, dsn := range good {
		if err := ValidateDSN(dsn); err != nil {
			t.Errorf("ValidateDSN(%q) = %v, want ok", dsn, err)
		}
	}
	for name, dsn := range bad {
		err := ValidateDSN(dsn)
		if err == nil {
			t.Errorf("%s: ValidateDSN(%q) accepted", name, dsn)
			continue
		}
		if dsn != "" && strings.Contains(err.Error(), dsn) {
			t.Errorf("%s: error repeats the DSN: %v", name, err)
		}
	}
}

func TestTracesSampleRateBoundsAndDefault(t *testing.T) {
	for _, r := range []float64{0, 0.2, 1} {
		if err := ValidateTracesSampleRate(r); err != nil {
			t.Errorf("rate %v: %v", r, err)
		}
	}
	for _, r := range []float64{-0.1, 1.01, math.NaN(), math.Inf(1)} {
		if err := ValidateTracesSampleRate(r); err == nil {
			t.Errorf("rate %v accepted", r)
		}
	}
	c := &Config{}
	c.ApplyDefaults()
	if c.Telemetry.TracesSampleRate != DefaultTracesSampleRate {
		t.Errorf("unset rate = %v, want %v", c.Telemetry.TracesSampleRate, DefaultTracesSampleRate)
	}
	c.Telemetry.TracesSampleRate = 0.7
	c.ApplyDefaults()
	if c.Telemetry.TracesSampleRate != 0.7 {
		t.Errorf("a set rate was overwritten: %v", c.Telemetry.TracesSampleRate)
	}
}

func TestConfigValidateChecksTelemetry(t *testing.T) {
	c := DefaultConfig()
	c.Domains = []DomainRule{{Pattern: "example.com"}}
	c.Telemetry.DSN = "https://k@h.example/1"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Telemetry.DSN = "garbage"
	if err := c.Validate(); err == nil {
		t.Error("an invalid DSN passed Validate")
	}
	c.Telemetry.DSN = ""
	c.Telemetry.TracesSampleRate = 3
	if err := c.Validate(); err == nil {
		t.Error("an out-of-range rate passed Validate")
	}
}

func TestEnabledNeedsADSNAndAHelperKind(t *testing.T) {
	on := TelemetryConfig{DSN: "https://k@h/1", Errors: true}
	if !on.Enabled() {
		t.Error("errors with a DSN is enabled")
	}
	if (TelemetryConfig{DSN: "https://k@h/1", Sessions: true}).Enabled() {
		t.Error("sessions alone is not something the helper can send")
	}
	if (TelemetryConfig{Errors: true, Logs: true, Traces: true}).Enabled() {
		t.Error("no DSN means off")
	}
}

func TestExportNeverCarriesTheDSNAndApplyKeepsIt(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domains = []DomainRule{{Pattern: "example.com"}}
	cfg.Telemetry.DSN = "https://secretkey@h.example/1"
	cfg.Telemetry.Logs = false

	raw, err := marshalExport(NewExport(cfg, time.Unix(0, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "secretkey") || strings.Contains(strings.ToLower(raw), "dsn") {
		t.Errorf("export: %s", raw)
	}
	exp, err := ParseExport([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	next, err := exp.Apply(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if next.Telemetry != cfg.Telemetry {
		t.Errorf("import changed telemetry: %+v -> %+v", cfg.Telemetry, next.Telemetry)
	}
}

func TestTelemetryYAMLRoundTrip(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Domains = []DomainRule{{Pattern: "example.com"}}
	cfg.Telemetry = TelemetryConfig{DSN: "https://k@h.example/5", Errors: true, Traces: true, TracesSampleRate: 0.4}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// Load starts from the defaults, so the unset kinds stay as saved (false).
	if got.Telemetry != cfg.Telemetry {
		t.Errorf("telemetry = %+v, want %+v", got.Telemetry, cfg.Telemetry)
	}
}

func marshalExport(e Export) (string, error) {
	b, err := json.Marshal(e)
	return string(b), err
}
