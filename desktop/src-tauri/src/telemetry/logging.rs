//! Forwards the app's warning and error log lines to error reporting: every
//! one as a structured log when Logs is on, and error lines as events when
//! Errors is on. Nothing below warning is forwarded.
//!
//! The logger wraps the app's own logger, which keeps printing as before, and
//! is installed once at startup. While no client runs a forwarded line costs
//! two atomic loads.

use std::cell::Cell;

use log::{Level, LevelFilter, Log, Metadata, Record};

use super::client::{errors_enabled, hub, logs_enabled};

/// Libraries on the reporting path. A line they log must never be reported
/// in turn, or a failing send would report its own failure forever.
const OWN_TARGETS: &[&str] = &["sentry", "ureq", "rustls", "webpki", "hyper"];

thread_local! {
    static FORWARDING: Cell<bool> = const { Cell::new(false) };
}

struct ReportingLogger<L: Log> {
    dest: L,
}

impl<L: Log> Log for ReportingLogger<L> {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.dest.enabled(metadata) || is_candidate(metadata)
    }

    fn log(&self, record: &Record<'_>) {
        forward(record);
        self.dest.log(record);
    }

    fn flush(&self) {
        self.dest.flush();
    }
}

fn is_candidate(metadata: &Metadata<'_>) -> bool {
    metadata.level() <= Level::Warn && !OWN_TARGETS.iter().any(|t| metadata.target().starts_with(t))
}

/// Sends `record` to the client when its kind is switched on.
pub(super) fn forward(record: &Record<'_>) {
    if !is_candidate(record.metadata()) || !(logs_enabled() || errors_enabled()) {
        return;
    }
    if FORWARDING.with(|f| f.replace(true)) {
        return;
    }
    let hub = hub();
    if hub.client().is_some() {
        if logs_enabled() {
            hub.capture_log(sentry_log::log_from_record(record));
        }
        if errors_enabled() && record.level() == Level::Error {
            hub.capture_event(sentry_log::event_from_record(record));
        }
    }
    FORWARDING.with(|f| f.set(false));
}

/// Makes `dest` the process logger and forwards warnings and errors to error
/// reporting as well. The level stays at least `warn` so the lines reach it
/// even when the app's own logger is quieter.
pub fn install_logger(dest: impl Log + 'static, dest_max: LevelFilter) {
    let max = dest_max.max(LevelFilter::Warn);
    match log::set_boxed_logger(Box::new(ReportingLogger { dest })) {
        Ok(()) => log::set_max_level(max),
        Err(e) => eprintln!("routewise: could not install the logger: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_warnings_and_errors_are_candidates() {
        let meta = |level, target| Metadata::builder().level(level).target(target).build();
        assert!(is_candidate(&meta(Level::Error, "routewise")));
        assert!(is_candidate(&meta(Level::Warn, "routewise")));
        assert!(!is_candidate(&meta(Level::Info, "routewise")));
        assert!(!is_candidate(&meta(Level::Debug, "routewise")));
    }

    #[test]
    fn libraries_on_the_reporting_path_are_never_candidates() {
        for target in ["sentry_core::client", "ureq::unversioned", "rustls::client", "hyper_util"] {
            let meta = Metadata::builder().level(Level::Error).target(target).build();
            assert!(!is_candidate(&meta), "{target}");
        }
    }
}
