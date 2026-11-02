package daemon

import (
	"github.com/quocln/routewise/internal/api"
)

// Telemetry reports the error-reporting settings, DSN included. Only the
// private telemetry.get method returns it.
func (d *Daemon) Telemetry() api.TelemetrySettings {
	t := d.store.Telemetry()
	return api.TelemetrySettings{
		DSN: t.DSN, Errors: t.Errors, Sessions: t.Sessions, Logs: t.Logs, Traces: t.Traces,
		TracesSampleRate: t.TracesSampleRate,
	}
}

// SetTelemetry changes the settings p names. The commit re-initialises the
// reporting SDK (see ConfigStore.OnCommit). The log line records which kinds
// are on, never the DSN.
func (d *Daemon) SetTelemetry(p api.SetTelemetryParams) error {
	if _, err := d.store.SetTelemetry(p); err != nil {
		return classifyConfigError(err)
	}
	t := d.store.Telemetry()
	d.logger.Info("telemetry settings changed",
		"dsn_set", t.DSN != "", "errors", t.Errors, "sessions", t.Sessions,
		"logs", t.Logs, "traces", t.Traces, "traces_sample_rate", t.TracesSampleRate)
	return nil
}
