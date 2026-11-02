//! The two commands the webview uses to report: `report_ui_error` for errors
//! it caught, and `log_ui` for lines it wants in the app log. Both take text
//! the webview wrote, so it is size-limited here, and everything that goes on
//! to the client is scrubbed by the client's own hooks.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use log::Level;
use sentry::protocol::{Event, Exception, Mechanism, Value};
use serde::Deserialize;

use super::client::{errors_enabled, hub};

const MAX_MESSAGE_CHARS: usize = 2_000;
const MAX_STACK_CHARS: usize = 16_000;
const MAX_COMPONENT_STACK_CHARS: usize = 8_000;
/// A render error that repeats on every frame must not flood the server.
const MAX_REPORTS_PER_WINDOW: usize = 10;
const REPORT_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UiErrorKind {
    Error,
    Unhandledrejection,
    Render,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiErrorReport {
    pub kind: UiErrorKind,
    pub message: String,
    pub stack: Option<String>,
    pub component_stack: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UiLogLevel {
    Warn,
    Error,
}

#[derive(Debug, Deserialize)]
pub struct UiLogEntry {
    pub level: UiLogLevel,
    pub message: String,
}

static REPORT_TIMES: Mutex<VecDeque<Instant>> = Mutex::new(VecDeque::new());

/// Reports an error the webview caught. Does nothing while error reporting is
/// off or after too many reports in a short time.
#[tauri::command]
pub fn report_ui_error(report: UiErrorReport) {
    if errors_enabled() && within_rate_limit(&REPORT_TIMES, Instant::now()) {
        hub().capture_event(ui_error_event(report));
    }
}

/// Logs a line the webview wrote through the process logger, which writes it
/// to the app log file and forwards it to error reporting when Logs (and, for
/// errors, Errors) is on.
#[tauri::command]
pub fn log_ui(entry: UiLogEntry) {
    let level = level_of(entry.level);
    log::log!(target: "webview", level, "{}", truncate(entry.message, MAX_MESSAGE_CHARS));
}

fn level_of(level: UiLogLevel) -> Level {
    match level {
        UiLogLevel::Warn => Level::Warn,
        UiLogLevel::Error => Level::Error,
    }
}

fn ui_error_event(report: UiErrorReport) -> Event<'static> {
    let (ty, mechanism) = match report.kind {
        UiErrorKind::Error => ("Error", "onerror"),
        UiErrorKind::Unhandledrejection => ("UnhandledRejection", "onunhandledrejection"),
        UiErrorKind::Render => ("RenderError", "react.error-boundary"),
    };
    let mut event = Event {
        level: sentry::Level::Error,
        logger: Some("webview".into()),
        exception: vec![Exception {
            ty: ty.into(),
            value: Some(truncate(report.message, MAX_MESSAGE_CHARS)),
            mechanism: Some(Mechanism {
                ty: mechanism.into(),
                handled: Some(report.kind == UiErrorKind::Render),
                ..Default::default()
            }),
            ..Default::default()
        }]
        .into(),
        ..Default::default()
    };
    event.tags.insert("source".into(), "webview".into());
    if let Some(stack) = report.stack {
        event.extra.insert("stack".into(), Value::String(truncate(stack, MAX_STACK_CHARS)));
    }
    if let Some(stack) = report.component_stack {
        let stack = truncate(stack, MAX_COMPONENT_STACK_CHARS);
        event.extra.insert("componentStack".into(), Value::String(stack));
    }
    event
}

/// Records one report at `now` and says whether it fits the limit.
fn within_rate_limit(times: &Mutex<VecDeque<Instant>>, now: Instant) -> bool {
    let mut times = times.lock().unwrap_or_else(|e| e.into_inner());
    while times.front().is_some_and(|t| now.duration_since(*t) >= REPORT_WINDOW) {
        times.pop_front();
    }
    if times.len() >= MAX_REPORTS_PER_WINDOW {
        return false;
    }
    times.push_back(now);
    true
}

/// `text` cut to at most `max` characters.
fn truncate(mut text: String, max: usize) -> String {
    if let Some((index, _)) = text.char_indices().nth(max) {
        text.truncate(index);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_what_the_webview_sends() {
        let report: UiErrorReport = serde_json::from_str(
            r#"{"kind":"unhandledrejection","message":"boom","stack":"at x","componentStack":"in App"}"#,
        )
        .unwrap();
        assert_eq!(report.kind, UiErrorKind::Unhandledrejection);
        assert_eq!(report.component_stack.as_deref(), Some("in App"));
        let entry: UiLogEntry = serde_json::from_str(r#"{"level":"warn","message":"m"}"#).unwrap();
        assert_eq!(entry.level, UiLogLevel::Warn);
    }

    #[test]
    fn refuses_an_unknown_kind_or_level() {
        assert!(serde_json::from_str::<UiErrorReport>(r#"{"kind":"crash","message":"m"}"#).is_err());
        assert!(serde_json::from_str::<UiLogEntry>(r#"{"level":"info","message":"m"}"#).is_err());
    }

    #[test]
    fn truncates_on_character_boundaries() {
        assert_eq!(truncate("héllo".into(), 2), "hé");
        assert_eq!(truncate("abc".into(), 10), "abc");
    }

    #[test]
    fn event_carries_kind_message_and_limited_stacks() {
        let event = ui_error_event(UiErrorReport {
            kind: UiErrorKind::Render,
            message: "m".repeat(MAX_MESSAGE_CHARS + 50),
            stack: Some("s".repeat(MAX_STACK_CHARS + 50)),
            component_stack: Some("in App".into()),
        });
        let exception = &event.exception.values[0];
        assert_eq!(exception.ty, "RenderError");
        assert_eq!(exception.value.as_ref().unwrap().len(), MAX_MESSAGE_CHARS);
        assert_eq!(event.extra["stack"].as_str().unwrap().len(), MAX_STACK_CHARS);
        assert_eq!(event.extra["componentStack"], "in App");
        assert_eq!(event.tags["source"], "webview");
    }

    #[test]
    fn rate_limit_allows_a_burst_then_refuses_until_the_window_passes() {
        let times = Mutex::new(VecDeque::new());
        let start = Instant::now();
        for _ in 0..MAX_REPORTS_PER_WINDOW {
            assert!(within_rate_limit(&times, start));
        }
        assert!(!within_rate_limit(&times, start));
        assert!(within_rate_limit(&times, start + REPORT_WINDOW));
    }

    #[test]
    fn webview_log_levels_keep_their_meaning() {
        assert_eq!(level_of(UiLogLevel::Warn), Level::Warn);
        assert_eq!(level_of(UiLogLevel::Error), Level::Error);
    }
}
