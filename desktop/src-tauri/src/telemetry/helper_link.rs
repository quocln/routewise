//! Keeps error reporting in step with the settings the helper holds.
//!
//! The settings live in the helper's database, so reporting can only start
//! once the helper has answered. At startup the shell asks (retrying with a
//! growing pause while the helper is unreachable); afterwards it watches the
//! webview's own `telemetry.get` and `telemetry.set` calls, which is how a
//! change made in Settings reaches the client without another round trip.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::Value;

use super::client::{self, Identity};
use super::settings::{Config, TelemetrySettings};
use super::{names, tracing};
use crate::rpc::transport::Transport;
use crate::rpc::client::STANDARD_TIMEOUT;
use crate::rpc::{Backoff, RpcClient, RpcError};

/// JSON-RPC "method not found": a helper that predates error reporting.
const METHOD_NOT_FOUND: i64 = -32601;
const FIRST_RETRY: Duration = Duration::from_secs(1);
const LONGEST_RETRY: Duration = Duration::from_secs(30);

/// RPC methods after which the names the scrubber redacts may have changed.
const NAME_CHANGING_METHODS: &[&str] = &[
    "domains.add", "domains.remove", "domains.set", "profiles.import", "profiles.update",
    "profiles.remove", "config.import", "settings.set", "vpn.setAllowed",
];

static HELPER: OnceLock<Arc<RpcClient>> = OnceLock::new();
/// Set once settings have been applied from any source, which ends the
/// startup retries.
static SETTLED: AtomicBool = AtomicBool::new(false);

/// Starts error reporting for this run: tags releases with `version` and loads
/// the settings from the helper in the background. Call once, from setup,
/// inside the async runtime's reach.
pub fn start(transport: Arc<dyn Transport>, version: &str) {
    client::set_identity(Identity::for_version(version));
    tracing::mark_launch_start();
    let helper = Arc::new(RpcClient::new(transport, Backoff::default()));
    if HELPER.set(helper.clone()).is_err() {
        return;
    }
    tauri::async_runtime::spawn(load_until_settled(helper));
}

/// Looks at the outcome of a call the webview made and reacts: new settings
/// reach the client, a successful status ends the launch transaction, and a
/// change to a list of names refreshes the scrubber.
pub fn observe_rpc(method: &str, result: &Result<Value, RpcError>) {
    let Ok(value) = result else { return };
    match method {
        "telemetry.get" | "telemetry.set" => {
            let (seq, value) = (client::next_seq(), value.clone());
            tauri::async_runtime::spawn(async move { apply_value(seq, value).await });
        }
        "status.get" => tracing::record_launch(),
        m if NAME_CHANGING_METHODS.contains(&m) && client::is_running() => {
            let seq = client::next_seq();
            tauri::async_runtime::spawn(async move { refresh_names(seq).await });
        }
        _ => {}
    }
}

async fn load_until_settled(helper: Arc<RpcClient>) {
    let mut pause = FIRST_RETRY;
    while !SETTLED.load(Ordering::Relaxed) {
        // Ticket taken before asking: an answer that was overtaken by a
        // change made from Settings in the meantime is dropped.
        let seq = client::next_seq();
        match helper.call("telemetry.get", None, STANDARD_TIMEOUT).await {
            Ok(value) => return apply_value(seq, value).await,
            Err(RpcError::Remote { code: METHOD_NOT_FOUND, .. }) => {
                log::info!("the helper does not support error reporting");
                return;
            }
            Err(e) => log::debug!("could not load error reporting settings: {e}"),
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(LONGEST_RETRY);
    }
}

/// Reads the helper's settings answer and makes the client match.
async fn apply_value(seq: u64, value: Value) {
    let settings: TelemetrySettings = match serde_json::from_value(value) {
        Ok(settings) => settings,
        Err(e) => return log::warn!("could not read the error reporting settings: {e}"),
    };
    SETTLED.store(true, Ordering::Relaxed);
    if client::differs_from(&settings) && Config::from_settings(&settings).is_some() {
        // Names first, so the first event already has them.
        refresh_names(seq).await;
    }
    if let Err(e) = tauri::async_runtime::spawn_blocking(move || client::apply(seq, &settings)).await {
        log::warn!("applying the error reporting settings failed: {e}");
    }
}

async fn refresh_names(seq: u64) {
    if let Some(helper) = HELPER.get() {
        client::set_known_names_ordered(seq, &names::load(helper).await);
    }
}
