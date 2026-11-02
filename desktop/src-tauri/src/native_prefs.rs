//! The few preferences the shell itself reads and writes through the helper's
//! `prefs.get` / `prefs.set`, the same keys the webview uses.

use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::rpc::{RpcClient, RpcError};

pub const KEEP_WINDOW_ON_TOP: &str = "keepWindowOnTop";
pub const LAST_UPDATE_CHECK: &str = "lastUpdateCheck";

const TIMEOUT: Duration = Duration::from_secs(5);

/// All stored preferences. A helper that cannot be reached is an error, so
/// callers can tell "unset" from "unknown".
pub async fn read_all(client: &RpcClient) -> Result<Map<String, Value>, RpcError> {
    let reply = client.call("prefs.get", None, TIMEOUT).await?;
    match reply.get("prefs") {
        Some(Value::Object(prefs)) => Ok(prefs.clone()),
        _ => Err(RpcError::protocol("prefs.get: no prefs object")),
    }
}

pub async fn write(client: &RpcClient, key: &str, value: Value) -> Result<(), RpcError> {
    client.call("prefs.set", Some(&json!({ "key": key, "value": value })), TIMEOUT).await.map(|_| ())
}

/// A boolean preference, or `default` when it is unset or not a boolean.
pub fn bool_or(prefs: &Map<String, Value>, key: &str, default: bool) -> bool {
    prefs.get(key).and_then(Value::as_bool).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn booleans_fall_back_to_the_default() {
        let prefs = json!({ "a": false, "b": "yes" });
        let prefs = prefs.as_object().unwrap();
        assert!(!bool_or(prefs, "a", true));
        assert!(bool_or(prefs, "b", true));
        assert!(bool_or(prefs, "missing", true));
    }
}
