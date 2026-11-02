//! Long-poll streams. A stream turns the helper's `activity.list` and
//! `access.list` long polls into a sequence of events for the webview. It runs
//! only between `start` and `stop`, so nothing polls while no view listens.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tauri::async_runtime::JoinHandle;

use super::client::{timeout_for, RpcClient};
use super::error::RpcError;
use super::transport::Transport;

/// How long the helper may hold one poll (its maximum is 20 s).
const WAIT_MS: u64 = 20_000;
/// Pause after a failed poll, doubling up to the cap.
const RETRY_INITIAL: Duration = Duration::from_millis(500);
const RETRY_MAX: Duration = Duration::from_secs(10);

/// The helper's streamable lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StreamKind {
    Activity,
    Access,
}

impl StreamKind {
    pub fn method(self) -> &'static str {
        match self {
            Self::Activity => "activity.list",
            Self::Access => "access.list",
        }
    }

    /// Name of the Tauri event the webview listens to.
    pub fn event_name(self) -> &'static str {
        match self {
            Self::Activity => "rpc-stream://activity",
            Self::Access => "rpc-stream://access",
        }
    }

    /// The request key and the result key of the stream's cursor.
    fn cursor_keys(self) -> (&'static str, &'static str) {
        match self {
            Self::Activity => ("since", "latest"),
            Self::Access => ("afterId", "latestId"),
        }
    }
}

/// One event delivered to the webview.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum StreamEvent {
    /// A poll result. `initial` is true for the first result after the stream
    /// starts or recovers: the view replaces what it shows instead of appending.
    Data { initial: bool, data: Value },
    /// A poll failed; the stream keeps retrying.
    Error { error: RpcError },
}

/// Params of the next poll. The first poll takes the caller's params as they
/// are; later ones continue from the cursor and wait for news.
fn poll_params(kind: StreamKind, base: &Map<String, Value>, cursor: Option<&Value>) -> Value {
    let mut params = base.clone();
    if let Some(cursor) = cursor {
        let (request_key, _) = kind.cursor_keys();
        params.insert(request_key.into(), cursor.clone());
        params.insert("waitMs".into(), json!(WAIT_MS));
        // A continuing poll wants everything newer, not just the last page.
        if kind == StreamKind::Activity {
            params.remove("limit");
        }
    }
    Value::Object(params)
}

/// Whether a poll result holds anything to show.
fn has_items(kind: StreamKind, result: &Value) -> bool {
    let key = match kind {
        StreamKind::Activity => "events",
        StreamKind::Access => "entries",
    };
    result.get(key).and_then(Value::as_array).is_some_and(|a| !a.is_empty())
}

/// Polls the helper until the task is aborted, calling `emit` for each event.
pub async fn run_stream<F>(client: RpcClient, kind: StreamKind, base: Map<String, Value>, emit: F)
where
    F: Fn(StreamEvent),
{
    let (_, result_key) = kind.cursor_keys();
    let mut cursor: Option<Value> = None;
    let mut retry = RETRY_INITIAL;

    loop {
        let params = poll_params(kind, &base, cursor.as_ref());
        match client.call(kind.method(), Some(&params), timeout_for(Some(&params))).await {
            Ok(result) => {
                retry = RETRY_INITIAL;
                let initial = cursor.is_none();
                match result.get(result_key) {
                    Some(next) => cursor = Some(next.clone()),
                    None => {
                        emit(StreamEvent::Error {
                            error: RpcError::protocol(format!("{} result has no {result_key}", kind.method())),
                        });
                        tokio::time::sleep(retry).await;
                        continue;
                    }
                }
                if initial || has_items(kind, &result) {
                    emit(StreamEvent::Data { initial, data: result });
                }
            }
            Err(error) => {
                // The helper may have restarted and reset its counters, so the
                // next success starts over from a fresh first poll.
                cursor = None;
                emit(StreamEvent::Error { error });
                tokio::time::sleep(retry).await;
                retry = (retry * 2).min(RETRY_MAX);
            }
        }
    }
}

/// The running streams, at most one per kind.
#[derive(Default)]
pub struct Streams {
    tasks: std::sync::Mutex<HashMap<StreamKind, JoinHandle<()>>>,
}

impl Streams {
    /// Starts a stream, replacing a running one of the same kind (a view whose
    /// filters changed restarts it with new params). The stream needs its own
    /// client, because a long poll holds its connection.
    pub fn start<F>(
        &self,
        kind: StreamKind,
        params: Option<Value>,
        client: RpcClient,
        emit: F,
    ) -> Result<(), RpcError>
    where
        F: Fn(StreamEvent) + Send + 'static,
    {
        let base = match params {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(map)) => map,
            Some(_) => {
                return Err(RpcError::InvalidRequest { message: "stream params must be an object".into() })
            }
        };
        // Tauri's runtime, not `tokio::spawn`: the command that starts a stream
        // runs on the main thread, which is outside any Tokio runtime.
        let handle = tauri::async_runtime::spawn(run_stream(client, kind, base, emit));
        if let Some(previous) = self.lock().insert(kind, handle) {
            previous.abort();
        }
        Ok(())
    }

    pub fn stop(&self, kind: StreamKind) {
        if let Some(handle) = self.lock().remove(&kind) {
            handle.abort();
        }
    }

    pub fn stop_all(&self) {
        for (_, handle) in self.lock().drain() {
            handle.abort();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<StreamKind, JoinHandle<()>>> {
        // A poisoned lock only means a task panicked; the map is still valid.
        self.tasks.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Makes a client for one stream on `transport`.
pub fn stream_client(transport: Arc<dyn Transport>) -> RpcClient {
    RpcClient::new(transport, super::client::Backoff::default())
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::super::client::tests::{client_for, ok_reply, serve};
    use super::*;

    /// The `stream_start` command calls this on the main thread, where no Tokio
    /// runtime is current; starting must not depend on one.
    #[test]
    fn starts_from_a_thread_without_a_runtime() {
        let streams = Streams::default();
        let client = stream_client(Arc::new(super::super::transport::UnixTransport::new("/nonexistent.sock")));
        streams.start(StreamKind::Activity, None, client, |_| {}).unwrap();
        streams.stop_all();
    }

    fn object(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn first_poll_uses_base_params_untouched() {
        let base = object(json!({"limit": 200}));
        assert_eq!(poll_params(StreamKind::Activity, &base, None), json!({"limit": 200}));
    }

    #[test]
    fn later_activity_poll_continues_from_cursor_and_drops_limit() {
        let base = object(json!({"limit": 200}));
        let p = poll_params(StreamKind::Activity, &base, Some(&json!(41)));
        assert_eq!(p, json!({"since": 41, "waitMs": 20000}));
    }

    #[test]
    fn later_access_poll_keeps_filters() {
        let base = object(json!({"limit": 100, "verdict": "vpn"}));
        let p = poll_params(StreamKind::Access, &base, Some(&json!(9)));
        assert_eq!(p, json!({"limit": 100, "verdict": "vpn", "afterId": 9, "waitMs": 20000}));
    }

    #[tokio::test]
    async fn streams_initial_result_then_only_new_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let polls = Arc::new(AtomicUsize::new(0));
        let seen = polls.clone();
        let _server = serve(&path, move |req| {
            let n = seen.fetch_add(1, Ordering::SeqCst);
            assert_eq!(req["method"], "activity.list");
            Some(match n {
                0 => ok_reply(&req, json!({"latest": 5, "events": [{"seq": 5}]})),
                1 => {
                    assert_eq!(req["params"]["since"], 5);
                    assert_eq!(req["params"]["waitMs"], 20000);
                    // Nothing happened during the wait: no event is emitted.
                    ok_reply(&req, json!({"latest": 5, "events": []}))
                }
                _ => ok_reply(&req, json!({"latest": 6, "events": [{"seq": 6}]})),
            })
        });

        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let task = tokio::spawn(run_stream(
            client_for(&path),
            StreamKind::Activity,
            object(json!({"limit": 10})),
            move |e| sink.lock().unwrap().push(e),
        ));
        for _ in 0..200 {
            if events.lock().unwrap().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();

        let events = events.lock().unwrap();
        assert_eq!(events[0], StreamEvent::Data { initial: true, data: json!({"latest": 5, "events": [{"seq": 5}]}) });
        assert_eq!(events[1], StreamEvent::Data { initial: false, data: json!({"latest": 6, "events": [{"seq": 6}]}) });
    }

    #[tokio::test]
    async fn reports_errors_and_recovers_with_a_fresh_initial_poll() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.sock");
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let task = tokio::spawn(run_stream(
            client_for(&path),
            StreamKind::Access,
            Map::new(),
            move |e| sink.lock().unwrap().push(e),
        ));
        for _ in 0..200 {
            if !events.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
        assert!(matches!(
            events.lock().unwrap()[0],
            StreamEvent::Error { error: RpcError::Unavailable { .. } }
        ));
    }

    #[tokio::test]
    async fn start_replaces_and_stop_aborts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.sock");
        let streams = Streams::default();
        streams.start(StreamKind::Activity, None, client_for(&path), |_| {}).unwrap();
        streams.start(StreamKind::Activity, None, client_for(&path), |_| {}).unwrap();
        assert_eq!(streams.lock().len(), 1);
        streams.stop(StreamKind::Activity);
        assert!(streams.lock().is_empty());
        assert!(matches!(
            streams.start(StreamKind::Access, Some(json!([1])), client_for(&path), |_| {}),
            Err(RpcError::InvalidRequest { .. })
        ));
    }
}
