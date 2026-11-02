//! The client is process-wide state, so each test takes the lock, starts from
//! a stopped client and a fake transport, and stops it again at the end.

use std::sync::{Arc, Mutex, MutexGuard};

use sentry::protocol::{Envelope, EnvelopeItem, ItemContainer, Log};
use sentry::test::TestTransport;
use sentry::TransportFactory;

use super::client::{self, apply_inner, apply_with, hub, next_seq, set_known_names_ordered, Identity};
use super::scrubber::PLACEHOLDER as R;
use super::settings::TelemetrySettings;
use super::{logging, tracing, ui};

static SERIAL: Mutex<()> = Mutex::new(());

/// A stopped client, a fake transport, and the lock that keeps tests apart.
struct Fixture {
    _lock: MutexGuard<'static, ()>,
    transport: Arc<TestTransport>,
}

impl Fixture {
    fn new() -> Self {
        let lock = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        client::shutdown();
        client::set_known_names(&[]);
        Self { _lock: lock, transport: TestTransport::new() }
    }

    fn apply(&self, settings: &TelemetrySettings) {
        let factory: Arc<dyn TransportFactory> = Arc::new(self.transport.clone());
        apply_with(settings, &Identity::for_version("1.2.3"), Some(factory));
    }

    fn apply_ordered(&self, seq: u64, settings: &TelemetrySettings) {
        let factory: Arc<dyn TransportFactory> = Arc::new(self.transport.clone());
        apply_inner(Some(seq), settings, &Identity::for_version("1.2.3"), Some(factory));
    }

    /// Everything the client has sent so far, flushed first.
    fn sent(&self) -> Vec<Envelope> {
        if let Some(client) = hub().client() {
            client.flush(None);
        }
        self.transport.fetch_and_clear_envelopes()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        client::shutdown();
    }
}

fn settings() -> TelemetrySettings {
    TelemetrySettings {
        dsn: "https://public@example.invalid/1".into(),
        errors: true,
        sessions: false,
        logs: false,
        traces: false,
        traces_sample_rate: 0.0,
    }
}

fn logs_in(envelopes: &[Envelope]) -> Vec<Log> {
    envelopes
        .iter()
        .flat_map(|e| e.items())
        .filter_map(|item| match item {
            EnvelopeItem::ItemContainer(ItemContainer::Logs(logs)) => Some(logs.clone()),
            _ => None,
        })
        .flatten()
        .collect()
}

fn transactions_in(envelopes: &[Envelope]) -> Vec<String> {
    envelopes
        .iter()
        .flat_map(|e| e.items())
        .filter_map(|item| match item {
            EnvelopeItem::Transaction(t) => t.name.clone(),
            _ => None,
        })
        .collect()
}

fn warn_record(args: std::fmt::Arguments<'_>, level: log::Level) -> log::Record<'_> {
    log::Record::builder().level(level).target("routewise").args(args).build()
}

#[test]
fn an_empty_dsn_or_all_kinds_off_runs_nothing() {
    let f = Fixture::new();
    f.apply(&TelemetrySettings { dsn: String::new(), ..settings() });
    assert!(!client::is_running());
    f.apply(&TelemetrySettings { errors: false, ..settings() });
    assert!(!client::is_running());
}

#[test]
fn an_invalid_dsn_runs_nothing() {
    let f = Fixture::new();
    f.apply(&TelemetrySettings { dsn: "not a dsn".into(), ..settings() });
    assert!(!client::is_running());
    assert!(hub().client().is_none());
}

#[test]
fn error_events_are_scrubbed_tagged_and_sent() {
    let f = Fixture::new();
    client::set_known_names(&["Work VPN".to_string()]);
    f.apply(&settings());
    hub().capture_message("Work VPN to vpn.example.net failed", sentry::Level::Error);

    let events: Vec<_> = f.sent().iter().filter_map(|e| e.event().cloned()).collect();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.message.as_deref(), Some(format!("{R} to {R} failed").as_str()));
    assert_eq!(event.release.as_deref(), Some("routewise-app@1.2.3"));
    assert!(event.server_name.is_none() && event.user.is_none());
    assert_eq!(event.tags["shell"], "tauri");
}

#[test]
fn errors_off_sends_no_events() {
    let f = Fixture::new();
    f.apply(&TelemetrySettings { errors: false, logs: true, ..settings() });
    hub().capture_message("boom", sentry::Level::Error);
    assert!(f.sent().iter().all(|e| e.event().is_none()));
}

#[test]
fn the_same_settings_do_not_restart_and_changed_ones_do() {
    let f = Fixture::new();
    f.apply(&settings());
    let first = hub().client().unwrap();
    f.apply(&settings());
    assert!(Arc::ptr_eq(&first, &hub().client().unwrap()));
    f.apply(&TelemetrySettings { logs: true, ..settings() });
    assert!(!Arc::ptr_eq(&first, &hub().client().unwrap()));
}

#[test]
fn an_older_on_never_wins_over_a_newer_off() {
    let f = Fixture::new();
    let (older, newer) = (next_seq(), next_seq());
    f.apply_ordered(newer, &TelemetrySettings { errors: false, ..settings() });
    f.apply_ordered(older, &settings());
    assert!(!client::is_running() && hub().client().is_none());
}

#[test]
fn an_older_off_never_wins_over_a_newer_on() {
    let f = Fixture::new();
    let (older, newer) = (next_seq(), next_seq());
    f.apply_ordered(newer, &settings());
    f.apply_ordered(older, &TelemetrySettings { errors: false, ..settings() });
    assert!(client::is_running() && client::errors_enabled());
}

#[test]
fn an_older_names_snapshot_never_replaces_a_newer_one() {
    let _f = Fixture::new();
    let (older, newer) = (next_seq(), next_seq());
    set_known_names_ordered(newer, &["Acme Corp VPN".to_string()]);
    set_known_names_ordered(older, &[]);
    assert!(client::scrubber().scrub("connect Acme Corp VPN").contains(R));
}

#[test]
fn clearing_the_dsn_or_every_kind_stops() {
    let f = Fixture::new();
    f.apply(&settings());
    f.apply(&TelemetrySettings { dsn: String::new(), ..settings() });
    assert!(!client::is_running() && hub().client().is_none());
    f.apply(&settings());
    f.apply(&TelemetrySettings { errors: false, ..settings() });
    assert!(!client::is_running() && !client::errors_enabled());
}

#[test]
fn a_session_is_reported_when_sessions_are_on() {
    let f = Fixture::new();
    f.apply(&TelemetrySettings { errors: false, sessions: true, ..settings() });
    client::shutdown();
    let sessions = f
        .transport
        .fetch_and_clear_envelopes()
        .iter()
        .flat_map(|e| e.items())
        .filter(|item| matches!(item, EnvelopeItem::SessionUpdate(_)))
        .count();
    assert!(sessions >= 1, "no session update was sent");
}

#[test]
fn no_session_is_reported_when_sessions_are_off() {
    let f = Fixture::new();
    f.apply(&settings());
    client::shutdown();
    let envelopes = f.transport.fetch_and_clear_envelopes();
    assert!(envelopes.iter().flat_map(|e| e.items()).all(|i| !matches!(i, EnvelopeItem::SessionUpdate(_))));
}

#[test]
fn warnings_and_errors_become_scrubbed_logs_and_errors_become_events() {
    let f = Fixture::new();
    f.apply(&TelemetrySettings { logs: true, ..settings() });
    logging::forward(&warn_record(format_args!("cannot reach 10.0.0.9"), log::Level::Warn));
    logging::forward(&warn_record(format_args!("tunnel to vpn.example.net lost"), log::Level::Error));
    logging::forward(&warn_record(format_args!("just info 10.0.0.1"), log::Level::Info));

    let sent = f.sent();
    let bodies: Vec<String> = logs_in(&sent).into_iter().map(|l| l.body).collect();
    assert_eq!(bodies, [format!("cannot reach {R}"), format!("tunnel to {R} lost")]);
    let events: Vec<_> = sent.iter().filter_map(|e| e.event()).collect();
    assert_eq!(events.len(), 1);
}

#[test]
fn each_log_kind_is_honoured() {
    let f = Fixture::new();
    f.apply(&settings()); // errors on, logs off
    logging::forward(&warn_record(format_args!("warn line"), log::Level::Warn));
    logging::forward(&warn_record(format_args!("error line"), log::Level::Error));
    let sent = f.sent();
    assert!(logs_in(&sent).is_empty());
    assert_eq!(sent.iter().filter_map(|e| e.event()).count(), 1);
}

#[test]
fn only_traced_calls_make_transactions_at_the_chosen_rate() {
    let f = Fixture::new();
    f.apply(&TelemetrySettings { traces: true, traces_sample_rate: 1.0, ..settings() });
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let ok: Result<u8, ()> = tracing::measure("profiles.connect", async { Ok(1) }).await;
        assert_eq!(ok, Ok(1));
        let failed: Result<u8, ()> = tracing::measure("domains.add", async { Err(()) }).await;
        assert!(failed.is_err());
        let _ = tracing::measure("status.get", async { Ok::<_, ()>(0) }).await;
    });
    let names = transactions_in(&f.sent());
    assert_eq!(names, ["profiles.connect", "domains.add"]);
}

#[test]
fn a_zero_rate_makes_no_transactions() {
    let f = Fixture::new();
    f.apply(&settings());
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let _ = tracing::measure("profiles.connect", async { Ok::<_, ()>(()) }).await;
    });
    assert!(transactions_in(&f.sent()).is_empty());
}

#[test]
fn webview_errors_are_scrubbed_and_sent_only_when_errors_are_on() {
    let f = Fixture::new();
    let report = || ui::UiErrorReport {
        kind: ui::UiErrorKind::Error,
        message: "fetch api.example.com failed".into(),
        stack: Some("at https://app.example.com/main.js:1:2".into()),
        component_stack: None,
    };
    f.apply(&TelemetrySettings { errors: false, logs: true, ..settings() });
    ui::report_ui_error(report());
    assert!(f.sent().iter().all(|e| e.event().is_none()));

    f.apply(&settings());
    ui::report_ui_error(report());
    let events: Vec<_> = f.sent().iter().filter_map(|e| e.event().cloned()).collect();
    assert_eq!(events.len(), 1);
    let exception = &events[0].exception.values[0];
    assert_eq!(exception.value.as_deref(), Some(format!("fetch {R} failed").as_str()));
    assert_eq!(events[0].extra["stack"], format!("at https://{R}/main.js:1:2"));
    assert_eq!(events[0].tags["source"], "webview");
}
