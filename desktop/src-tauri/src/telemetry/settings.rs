//! The error reporting settings the helper stores (`telemetry.get`) and what
//! the Sentry client is started with. The DSN is a secret: it lives only in
//! these structs, and neither implements `Debug` in a way that prints it.

use std::fmt;

use serde::Deserialize;

/// The helper's answer to `telemetry.get` and `telemetry.set`. An empty `dsn`
/// means reporting is off.
#[derive(Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetrySettings {
    pub dsn: String,
    pub errors: bool,
    pub sessions: bool,
    pub logs: bool,
    pub traces: bool,
    pub traces_sample_rate: f64,
}

impl fmt::Debug for TelemetrySettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelemetrySettings").field("dsn", &"<hidden>").finish_non_exhaustive()
    }
}

/// What the client runs with. Two equal configs mean the running client
/// already does what is asked, so nothing restarts.
#[derive(Clone, PartialEq)]
pub struct Config {
    pub dsn: String,
    pub errors: bool,
    pub sessions: bool,
    pub logs: bool,
    /// 0 turns performance traces off.
    pub traces_sample_rate: f32,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("errors", &self.errors)
            .field("sessions", &self.sessions)
            .field("logs", &self.logs)
            .field("traces_sample_rate", &self.traces_sample_rate)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// The client's setup for `settings`, or None when nothing should run: no
    /// DSN, or every kind off.
    pub fn from_settings(settings: &TelemetrySettings) -> Option<Self> {
        let dsn = settings.dsn.trim();
        let rate = if settings.traces && settings.traces_sample_rate.is_finite() {
            settings.traces_sample_rate.clamp(0.0, 1.0) as f32
        } else {
            0.0
        };
        let active = settings.errors || settings.sessions || settings.logs || rate > 0.0;
        (!dsn.is_empty() && active).then(|| Self {
            dsn: dsn.to_string(),
            errors: settings.errors,
            sessions: settings.sessions,
            logs: settings.logs,
            traces_sample_rate: rate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> TelemetrySettings {
        TelemetrySettings {
            dsn: "https://public@example.invalid/1".into(),
            errors: true,
            sessions: false,
            logs: false,
            traces: false,
            traces_sample_rate: 0.5,
        }
    }

    #[test]
    fn empty_dsn_runs_nothing() {
        assert!(Config::from_settings(&TelemetrySettings { dsn: "  ".into(), ..settings() }).is_none());
    }

    #[test]
    fn all_kinds_off_runs_nothing() {
        let off = TelemetrySettings { errors: false, ..settings() };
        assert!(Config::from_settings(&off).is_none());
    }

    #[test]
    fn traces_without_a_rate_is_nothing_to_run() {
        let s = TelemetrySettings { errors: false, traces: true, traces_sample_rate: 0.0, ..settings() };
        assert!(Config::from_settings(&s).is_none());
    }

    #[test]
    fn traces_off_means_no_sample_rate() {
        assert_eq!(Config::from_settings(&settings()).unwrap().traces_sample_rate, 0.0);
    }

    #[test]
    fn rate_is_clamped() {
        let s = TelemetrySettings { traces: true, traces_sample_rate: 7.0, ..settings() };
        assert_eq!(Config::from_settings(&s).unwrap().traces_sample_rate, 1.0);
    }

    #[test]
    fn debug_output_never_prints_the_dsn() {
        let s = settings();
        let config = Config::from_settings(&s).unwrap();
        assert!(!format!("{s:?}{config:?}").contains("example.invalid"));
    }

    #[test]
    fn parses_the_helper_answer() {
        let json = r#"{"dsn":"","errors":false,"sessions":true,"logs":false,"traces":true,"tracesSampleRate":0.25}"#;
        let parsed: TelemetrySettings = serde_json::from_str(json).unwrap();
        assert!(parsed.sessions && parsed.traces);
        assert_eq!(parsed.traces_sample_rate, 0.25);
    }
}
