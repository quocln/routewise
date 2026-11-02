//! The one Sentry client of the app: started, restarted or closed to match the
//! settings the helper holds, with every payload scrubbed before it leaves.
//!
//! The client is bound to the process-wide main hub and everything that
//! reports (panics, logs, traces) goes through that hub explicitly. A thread's
//! own hub is a copy taken the first time the thread uses it, so it would keep
//! pointing at a client that was since replaced or closed.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};
use std::time::Duration;

use sentry::protocol::SessionStatus;
use sentry::{Client, ClientOptions, Hub, SessionMode, TransportFactory};

use super::payload::{scrub_breadcrumb, scrub_event, scrub_log};
use super::scrubber::PrivacyScrubber;
use super::settings::{Config, TelemetrySettings};

/// How long closing or flushing waits for the queue to reach the server.
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// What every event is tagged with.
#[derive(Clone)]
pub struct Identity {
    /// `routewise-app@<version>`.
    pub release: String,
    pub environment: &'static str,
}

impl Identity {
    pub fn for_version(version: &str) -> Self {
        Self {
            release: format!("routewise-app@{version}"),
            environment: if cfg!(debug_assertions) { "development" } else { "production" },
        }
    }
}

struct Running {
    config: Config,
    client: Arc<Client>,
}

static STATE: Mutex<Option<Running>> = Mutex::new(None);
static IDENTITY: OnceLock<Identity> = OnceLock::new();
static SCRUBBER: RwLock<Option<Arc<PrivacyScrubber>>> = RwLock::new(None);
static ERRORS_ON: AtomicBool = AtomicBool::new(false);
static LOGS_ON: AtomicBool = AtomicBool::new(false);
/// Mirrors `STATE.is_some()`, written only while `STATE` is locked, so hot
/// paths can ask without waiting for a client being closed.
static RUNNING: AtomicBool = AtomicBool::new(false);
/// Source of the numbers that order settings and name updates.
static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);
/// Newest settings update applied so far; guarded by the `STATE` lock.
static APPLIED_SEQ: AtomicU64 = AtomicU64::new(0);
/// Newest names update applied so far; guarded by the `SCRUBBER` write lock.
static NAMES_SEQ: AtomicU64 = AtomicU64::new(0);

fn lock_state() -> MutexGuard<'static, Option<Running>> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// The process-wide hub the client is bound to.
pub fn hub() -> Arc<Hub> {
    Hub::main()
}

/// Records what releases are tagged with. The first call wins.
pub fn set_identity(identity: Identity) {
    let _ = IDENTITY.set(identity);
}

/// The current scrubber: the built-in patterns plus the names set last.
pub fn scrubber() -> Arc<PrivacyScrubber> {
    if let Some(s) = SCRUBBER.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        return s.clone();
    }
    let fresh = Arc::new(PrivacyScrubber::default());
    SCRUBBER.write().unwrap_or_else(|e| e.into_inner()).get_or_insert(fresh).clone()
}

/// Takes the next ticket for an update. Take it when the update's source is
/// observed, not when its (possibly slow) processing finishes: the highest
/// ticket then wins whatever order the processing completes in.
pub fn next_seq() -> u64 {
    NEXT_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Replaces the names the scrubber redacts, whatever was set before.
#[cfg(test)]
pub fn set_known_names(names: &[String]) {
    *SCRUBBER.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(PrivacyScrubber::new(names)));
}

/// Like `set_known_names`, but ignored when a newer update (by `seq`) was
/// already applied.
pub fn set_known_names_ordered(seq: u64, names: &[String]) {
    let fresh = Arc::new(PrivacyScrubber::new(names));
    let mut slot = SCRUBBER.write().unwrap_or_else(|e| e.into_inner());
    if seq < NAMES_SEQ.load(Ordering::Relaxed) {
        return;
    }
    NAMES_SEQ.store(seq, Ordering::Relaxed);
    *slot = Some(fresh);
}

/// Whether error events are being sent.
pub fn errors_enabled() -> bool {
    ERRORS_ON.load(Ordering::Relaxed)
}

/// Whether log records are being sent.
pub fn logs_enabled() -> bool {
    LOGS_ON.load(Ordering::Relaxed)
}

/// True while a client is running. Never waits.
pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

/// True when running with `settings` would change what the client does.
pub fn differs_from(settings: &TelemetrySettings) -> bool {
    lock_state().as_ref().map(|r| &r.config) != Config::from_settings(settings).as_ref()
}

/// Brings the client in line with `settings`, unless a newer update (by `seq`,
/// from `next_seq`) was already applied. Saving the same values again does
/// nothing. Blocks while a running client is closed (up to `FLUSH_TIMEOUT`),
/// so call it off the async runtime.
pub fn apply(seq: u64, settings: &TelemetrySettings) {
    match IDENTITY.get() {
        Some(identity) => apply_inner(Some(seq), settings, identity, None),
        None => log::debug!("error reporting settings arrived before the app identity was set"),
    }
}

/// Applies unconditionally, with a chosen transport.
#[cfg(test)]
pub(super) fn apply_with(
    settings: &TelemetrySettings,
    identity: &Identity,
    transport: Option<Arc<dyn TransportFactory>>,
) {
    apply_inner(None, settings, identity, transport);
}

pub(super) fn apply_inner(
    seq: Option<u64>,
    settings: &TelemetrySettings,
    identity: &Identity,
    transport: Option<Arc<dyn TransportFactory>>,
) {
    let wanted = Config::from_settings(settings);
    let mut state = lock_state();
    if let Some(seq) = seq {
        if seq < APPLIED_SEQ.load(Ordering::Relaxed) {
            return;
        }
        APPLIED_SEQ.store(seq, Ordering::Relaxed);
    }
    if state.as_ref().map(|r| &r.config) == wanted.as_ref() {
        return;
    }
    if let Some(old) = state.take() {
        RUNNING.store(false, Ordering::Relaxed);
        stop(old);
        log::info!("error reporting stopped");
    }
    let Some(config) = wanted else { return };
    let Some(client) = build_client(&config, identity, transport) else {
        log::warn!("error reporting not started: the DSN is not valid");
        return;
    };

    ERRORS_ON.store(config.errors, Ordering::Relaxed);
    LOGS_ON.store(config.logs, Ordering::Relaxed);
    super::panic::install();
    let hub = hub();
    hub.bind_client(Some(client.clone()));
    hub.configure_scope(|scope| {
        scope.set_tag("shell", "tauri");
        scope.set_tag("os", std::env::consts::OS);
        scope.set_tag("arch", std::env::consts::ARCH);
    });
    if config.sessions {
        hub.start_session();
    }
    *state = Some(Running { config, client });
    RUNNING.store(true, Ordering::Relaxed);
    log::info!("error reporting started");
}

/// Closes the client, e.g. when the app quits.
pub fn shutdown() {
    let mut state = lock_state();
    if let Some(old) = state.take() {
        RUNNING.store(false, Ordering::Relaxed);
        stop(old);
    }
}

fn stop(running: Running) {
    ERRORS_ON.store(false, Ordering::Relaxed);
    LOGS_ON.store(false, Ordering::Relaxed);
    let hub = hub();
    hub.end_session_with_status(SessionStatus::Exited);
    hub.bind_client(None);
    running.client.close(Some(FLUSH_TIMEOUT));
}

fn build_client(
    config: &Config,
    identity: &Identity,
    transport: Option<Arc<dyn TransportFactory>>,
) -> Option<Arc<Client>> {
    let dsn = config.dsn.parse().ok()?;
    let mut options = ClientOptions::default();
    options.dsn = Some(dsn);
    options.release = Some(identity.release.clone().into());
    options.environment = Some(identity.environment.into());
    options.send_default_pii = false;
    // Nothing carries the machine's name: it is not set, and the payloads that
    // skip `before_send` (traces, logs) never get one.
    options.server_name = None;
    options.auto_session_tracking = config.sessions;
    options.session_mode = SessionMode::Application;
    options.shutdown_timeout = FLUSH_TIMEOUT;
    // The scrub is the last step: nothing leaves without it.
    options.before_send = Some(Arc::new(|event| errors_enabled().then(|| scrub_event(&scrubber(), event))));
    options.before_breadcrumb = Some(Arc::new(|crumb| Some(scrub_breadcrumb(&scrubber(), crumb))));
    options.before_send_log = Some(Arc::new(|log| Some(scrub_log(&scrubber(), log))));
    options.transport = transport;
    if config.traces_sample_rate > 0.0 {
        options = options.traces_sample_rate(config.traces_sample_rate);
    }
    let client = Arc::new(Client::from(sentry::apply_defaults(options)));
    client.is_enabled().then_some(client)
}
