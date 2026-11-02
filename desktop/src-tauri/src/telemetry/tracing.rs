//! Performance transactions for the few helper calls worth timing: connecting
//! and disconnecting a built-in VPN, calls that change settings or domain
//! lists, and the launch up to the first helper status.
//!
//! Transaction names are RPC method names and fixed labels, never params, a
//! domain, a profile or a VPN name, so they need no scrubbing: a dotted method
//! name such as `domains.add` would only look like a host to the scrubber.
//! Transactions are not bound to any scope, so concurrent calls never nest.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::SystemTime;

use sentry::protocol::SpanStatus;
use sentry::TransactionContext;

use super::client::hub;

/// RPC methods that change state. Reads are not worth a transaction.
const MUTATING_METHODS: &[&str] = &[
    "domains.add", "domains.remove", "domains.set", "settings.set", "vpn.setAllowed",
    "config.import", "profiles.import", "profiles.update", "profiles.remove", "prefs.set",
    "telemetry.set",
];

static LAUNCHED_AT: OnceLock<SystemTime> = OnceLock::new();
static LAUNCH_RECORDED: AtomicBool = AtomicBool::new(false);

/// Operation name for a method, or None when the call is not traced.
pub fn operation(method: &str) -> Option<&'static str> {
    match method {
        "profiles.connect" => Some("vpn.connect"),
        "profiles.disconnect" => Some("vpn.disconnect"),
        m if MUTATING_METHODS.contains(&m) => Some("rpc.mutate"),
        _ => None,
    }
}

/// Runs `call` inside a transaction named `method` when the method is traced
/// and a client is running; the transaction ends with the call's outcome.
pub async fn measure<T, E, F>(method: &str, call: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    let hub = hub();
    let Some(op) = operation(method).filter(|_| hub.client().is_some()) else {
        return call.await;
    };
    let transaction = hub.start_transaction(TransactionContext::new(method, op));
    let result = call.await;
    transaction.set_status(if result.is_ok() { SpanStatus::Ok } else { SpanStatus::InternalError });
    transaction.finish();
    result
}

/// Notes when the app started: the launch transaction begins there.
pub fn mark_launch_start() {
    let _ = LAUNCHED_AT.set(SystemTime::now());
}

/// Records the launch as one transaction. Call when the first helper status
/// has loaded; it records once, and only while a client is running.
pub fn record_launch() {
    let hub = hub();
    if hub.client().is_none() || LAUNCH_RECORDED.swap(true, Ordering::Relaxed) {
        return;
    }
    let start = LAUNCHED_AT.get().copied().unwrap_or_else(SystemTime::now);
    let ctx = TransactionContext::new("app.launch", "app.start");
    let transaction = hub.start_transaction_with_timestamp(ctx, start);
    transaction.set_status(SpanStatus::Ok);
    transaction.finish();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traced_operations() {
        assert_eq!(operation("profiles.connect"), Some("vpn.connect"));
        assert_eq!(operation("profiles.disconnect"), Some("vpn.disconnect"));
        assert_eq!(operation("domains.add"), Some("rpc.mutate"));
        assert_eq!(operation("telemetry.set"), Some("rpc.mutate"));
        assert_eq!(operation("status.get"), None);
        assert_eq!(operation("activity.list"), None);
    }
}
