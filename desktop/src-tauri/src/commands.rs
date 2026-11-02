//! The commands the webview may invoke. The webview never touches the socket:
//! every call goes through the Rust core.

use std::sync::Arc;

use serde_json::Value;
use tauri::{AppHandle, Emitter, State};

use crate::rpc::streams::{stream_client, StreamEvent, StreamKind, Streams};
use crate::rpc::{timeout_for, Backoff, RpcClient, RpcError};
use crate::rpc::transport::Transport;

/// State shared by the commands.
pub struct AppState {
    transport: Arc<dyn Transport>,
    client: RpcClient,
    pub streams: Streams,
}

impl AppState {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self {
            client: RpcClient::new(transport.clone(), Backoff::default()),
            transport,
            streams: Streams::default(),
        }
    }

    /// The window's connection to the helper, for the shell's own calls.
    pub fn client(&self) -> &RpcClient {
        &self.client
    }
}

/// A method name is `group.action`, letters only. Anything else is refused
/// before it reaches the helper.
fn validate_method(method: &str) -> Result<(), RpcError> {
    let ok = method.len() <= 64
        && method.split_once('.').is_some_and(|(group, action)| {
            [group, action].iter().all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphabetic()))
        });
    if ok {
        Ok(())
    } else {
        Err(RpcError::InvalidRequest { message: "malformed method name".into() })
    }
}

/// Calls a helper method and returns its result.
#[tauri::command]
pub async fn rpc(
    state: State<'_, AppState>,
    method: String,
    params: Option<Value>,
) -> Result<Value, RpcError> {
    validate_method(&method)?;
    log::debug!("rpc {method}");
    let result = crate::telemetry::measure(
        &method,
        state.client.call(&method, params.as_ref(), timeout_for(params.as_ref())),
    )
    .await;
    crate::telemetry::observe_rpc(&method, &result);
    result.map(|value| redact_secrets(&method, value))
}

/// What the webview shows for a stored error reporting DSN: only that one is set.
const DSN_SET: &str = "[set]";

/// The DSN is a secret the shell needs and the webview does not: the webview
/// gets a marker for a stored one, never the value.
fn redact_secrets(method: &str, mut value: Value) -> Value {
    if matches!(method, "telemetry.get" | "telemetry.set") {
        if let Some(dsn) = value.get_mut("dsn").filter(|d| d.as_str().is_some_and(|s| !s.is_empty())) {
            *dsn = Value::String(DSN_SET.into());
        }
    }
    value
}

/// Starts streaming a long-poll list to the webview as events named by
/// `StreamKind::event_name`.
#[tauri::command]
pub fn stream_start(
    app: AppHandle,
    state: State<'_, AppState>,
    stream: StreamKind,
    params: Option<Value>,
) -> Result<(), RpcError> {
    let client = stream_client(state.transport.clone());
    state.streams.start(stream, params, client, move |event: StreamEvent| {
        if let Err(e) = app.emit(stream.event_name(), event) {
            log::warn!("emit {} failed: {e}", stream.event_name());
        }
    })
}

/// Stops a stream. Stopping one that is not running is not an error.
#[tauri::command]
pub fn stream_stop(state: State<'_, AppState>, stream: StreamKind) {
    state.streams.stop(stream);
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{redact_secrets, validate_method, DSN_SET};

    #[test]
    fn accepts_helper_method_names() {
        for m in ["status.get", "vpn.setAllowed", "activity.list"] {
            assert!(validate_method(m).is_ok(), "{m}");
        }
    }

    #[test]
    fn a_stored_dsn_never_reaches_the_webview() {
        let set = json!({ "dsn": "https://public@example.invalid/1", "errors": true });
        assert_eq!(redact_secrets("telemetry.get", set.clone())["dsn"], DSN_SET);
        assert_eq!(redact_secrets("telemetry.set", set)["dsn"], DSN_SET);
        assert_eq!(redact_secrets("telemetry.get", json!({ "dsn": "" }))["dsn"], "");
        assert_eq!(redact_secrets("status.get", json!({ "dsn": "x" }))["dsn"], "x");
    }

    #[test]
    fn rejects_malformed_method_names() {
        for m in ["", "status", "status.", ".get", "a.b.c", "status.get\n", "sta tus.get", "../x.y"] {
            assert!(validate_method(m).is_err(), "{m:?}");
        }
    }
}
