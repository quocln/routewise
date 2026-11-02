//! A JSON-RPC client for the helper: newline-delimited JSON over one
//! connection, one request in flight at a time, reconnecting when the
//! connection is lost.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use super::error::RpcError;
use super::message::{Request, Response};
use super::transport::{BoxStream, Transport};

/// Deadline of an ordinary request.
pub const STANDARD_TIMEOUT: Duration = Duration::from_secs(30);
/// Slack beyond the helper's own hold time for a long-poll request.
const LONG_POLL_MARGIN: Duration = Duration::from_secs(5);
/// The largest response line accepted. The helper's largest answers (access
/// history, 5000 rows) are well under this.
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Deadline of a request the helper may hold for `wait_ms` before answering.
pub fn long_poll_timeout(wait_ms: u64) -> Duration {
    Duration::from_millis(wait_ms) + LONG_POLL_MARGIN
}

/// Deadline for a request with these params: a long poll when they carry
/// `waitMs`, an ordinary request otherwise.
pub fn timeout_for(params: Option<&Value>) -> Duration {
    params
        .and_then(|p| p.get("waitMs"))
        .and_then(Value::as_u64)
        .filter(|ms| *ms > 0)
        .map_or(STANDARD_TIMEOUT, long_poll_timeout)
}

/// Pauses between attempts to open a connection.
#[derive(Debug, Clone)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
    /// How many times a call tries to connect before giving up.
    pub attempts: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self { initial: Duration::from_millis(100), max: Duration::from_secs(2), attempts: 3 }
    }
}

impl Backoff {
    fn delay(&self, failed: u32) -> Duration {
        self.initial.saturating_mul(1 << failed.min(16)).min(self.max)
    }
}

type Conn = BufReader<BoxStream>;

/// Why one exchange on an open connection failed.
enum ExchangeError {
    /// The connection broke before a full response arrived.
    Io(String),
    /// A response arrived but is not the answer to this request.
    Rpc(RpcError),
}

pub struct RpcClient {
    transport: Arc<dyn Transport>,
    backoff: Backoff,
    next_id: AtomicU64,
    conn: Mutex<Option<Conn>>,
}

impl RpcClient {
    pub fn new(transport: Arc<dyn Transport>, backoff: Backoff) -> Self {
        Self { transport, backoff, next_id: AtomicU64::new(1), conn: Mutex::new(None) }
    }

    /// Sends one request and waits for its answer.
    ///
    /// A connection the helper closed while idle (it drops idle clients after
    /// 30 s) is only noticed on use; the call then retries once on a fresh
    /// connection. A call that times out drops the connection, because its
    /// late answer would otherwise be read as the answer to the next call.
    pub async fn call(
        &self,
        method: &str,
        params: Option<&Value>,
        timeout: Duration,
    ) -> Result<Value, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let line = Request::new(id, method, params).to_line()?;

        let mut slot = self.conn.lock().await;
        let mut reused = slot.is_some();
        loop {
            let conn = match slot.as_mut() {
                Some(conn) => conn,
                None => {
                    reused = false;
                    slot.insert(self.connect().await?)
                }
            };
            match tokio::time::timeout(timeout, exchange(conn, &line, id)).await {
                Err(_) => {
                    *slot = None;
                    return Err(RpcError::Timeout { seconds: timeout.as_secs() });
                }
                Ok(Ok(response)) => return response.into_result(id),
                Ok(Err(ExchangeError::Io(message))) => {
                    *slot = None;
                    if !reused {
                        return Err(RpcError::unavailable(message));
                    }
                    reused = false;
                }
                Ok(Err(ExchangeError::Rpc(error))) => {
                    *slot = None;
                    return Err(error);
                }
            }
        }
    }

    /// Opens a connection, pausing between failed attempts.
    async fn connect(&self) -> Result<Conn, RpcError> {
        let mut last = String::new();
        for failed in 0..self.backoff.attempts.max(1) {
            if failed > 0 {
                tokio::time::sleep(self.backoff.delay(failed - 1)).await;
            }
            match self.transport.connect().await {
                Ok(stream) => return Ok(BufReader::new(stream)),
                Err(e) => last = e.to_string(),
            }
        }
        Err(RpcError::unavailable(last))
    }
}

/// Writes the request line and reads one response line.
async fn exchange(conn: &mut Conn, line: &[u8], id: u64) -> Result<Response, ExchangeError> {
    let io = |e: std::io::Error| ExchangeError::Io(e.to_string());
    conn.get_mut().write_all(line).await.map_err(io)?;
    conn.get_mut().flush().await.map_err(io)?;

    let mut buf = Vec::new();
    let read = (&mut *conn)
        .take(MAX_RESPONSE_BYTES)
        .read_until(b'\n', &mut buf)
        .await
        .map_err(io)?;
    if read == 0 {
        return Err(ExchangeError::Io("helper closed the connection".into()));
    }
    if buf.last() != Some(&b'\n') {
        return Err(if read as u64 >= MAX_RESPONSE_BYTES {
            ExchangeError::Rpc(RpcError::protocol("response too large"))
        } else {
            ExchangeError::Io("helper closed the connection mid-response".into())
        });
    }
    log::trace!("response for request {id} received");
    Response::parse(&buf).map_err(ExchangeError::Rpc)
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    use std::path::Path;
    use std::sync::atomic::AtomicUsize;

    use serde_json::json;
    use tokio::net::UnixListener;

    use super::super::transport::UnixTransport;
    use super::*;

    pub fn fast_backoff() -> Backoff {
        Backoff { initial: Duration::from_millis(5), max: Duration::from_millis(20), attempts: 3 }
    }

    pub fn client_for(path: &Path) -> RpcClient {
        RpcClient::new(Arc::new(UnixTransport::new(path)), fast_backoff())
    }

    /// Serves `handler(request) -> reply line` on every connection until dropped.
    /// A handler returning `None` closes the connection without answering.
    pub fn serve<F>(path: &Path, handler: F) -> tokio::task::JoinHandle<()>
    where
        F: Fn(Value) -> Option<String> + Send + Sync + 'static,
    {
        let listener = UnixListener::bind(path).unwrap();
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let handler = handler.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stream);
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let request: Value = serde_json::from_str(&line).unwrap();
                        // Handlers may sleep to play a slow helper; off the runtime,
                        // so the client's own timers keep running meanwhile.
                        let handler = handler.clone();
                        let reply = tokio::task::spawn_blocking(move || handler(request)).await.unwrap();
                        match reply {
                            Some(reply) => {
                                let w = reader.get_mut();
                                w.write_all(reply.as_bytes()).await.unwrap();
                                w.write_all(b"\n").await.unwrap();
                            }
                            None => return,
                        }
                    }
                });
            }
        })
    }

    pub fn ok_reply(request: &Value, result: Value) -> String {
        json!({"jsonrpc": "2.0", "result": result, "id": request["id"]}).to_string()
    }

    #[tokio::test]
    async fn round_trips_a_request() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let _server = serve(&path, |req| {
            assert_eq!(req["method"], "status.get");
            assert!(req.get("params").is_none());
            Some(ok_reply(&req, json!({"running": true})))
        });
        let client = client_for(&path);
        let result = client.call("status.get", None, Duration::from_secs(2)).await.unwrap();
        assert_eq!(result, json!({"running": true}));
    }

    #[tokio::test]
    async fn sends_params_and_increments_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let _server = serve(&path, |req| Some(ok_reply(&req, req.clone())));
        let client = client_for(&path);
        let params = json!({"host": "example.com"});
        let a = client.call("routes.check", Some(&params), Duration::from_secs(2)).await.unwrap();
        let b = client.call("routes.check", Some(&params), Duration::from_secs(2)).await.unwrap();
        assert_eq!(a["params"], params);
        assert_eq!(b["id"].as_u64().unwrap(), a["id"].as_u64().unwrap() + 1);
    }

    #[tokio::test]
    async fn maps_helper_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let _server = serve(&path, |req| {
            Some(
                json!({"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found"},"id":req["id"]})
                    .to_string(),
            )
        });
        let err = client_for(&path).call("nope", None, Duration::from_secs(2)).await.unwrap_err();
        assert_eq!(err, RpcError::Remote { code: -32601, message: "method not found".into() });
    }

    #[tokio::test]
    async fn missing_socket_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let client = client_for(&dir.path().join("absent.sock"));
        let err = client.call("status.get", None, Duration::from_secs(1)).await.unwrap_err();
        assert!(matches!(err, RpcError::Unavailable { .. }), "{err:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn times_out_and_recovers_on_a_new_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let _server = serve(&path, move |req| {
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(300));
            }
            Some(ok_reply(&req, json!("late-or-fresh")))
        });
        let client = client_for(&path);
        let err = client.call("status.get", None, Duration::from_millis(50)).await.unwrap_err();
        assert_eq!(err, RpcError::Timeout { seconds: 0 });
        // The slow answer must not be mistaken for this call's answer.
        let ok = client.call("status.get", None, Duration::from_secs(2)).await.unwrap();
        assert_eq!(ok, json!("late-or-fresh"));
    }

    #[tokio::test]
    async fn retries_once_when_a_reused_connection_was_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        // Answer the first request, then close the connection on the second.
        let _server = serve(&path, move |req| match seen.fetch_add(1, Ordering::SeqCst) {
            1 => None,
            _ => Some(ok_reply(&req, json!("ok"))),
        });
        let client = client_for(&path);
        client.call("status.get", None, Duration::from_secs(2)).await.unwrap();
        let again = client.call("status.get", None, Duration::from_secs(2)).await.unwrap();
        assert_eq!(again, json!("ok"));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn fresh_connection_closed_without_answer_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let _server = serve(&path, |_| None);
        let err = client_for(&path).call("status.get", None, Duration::from_secs(2)).await.unwrap_err();
        assert!(matches!(err, RpcError::Unavailable { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn invalid_json_reply_is_a_protocol_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let _server = serve(&path, |_| Some("not json".into()));
        let err = client_for(&path).call("status.get", None, Duration::from_secs(2)).await.unwrap_err();
        assert!(matches!(err, RpcError::Protocol { .. }), "{err:?}");
    }

    #[test]
    fn timeout_follows_wait_ms() {
        assert_eq!(timeout_for(None), STANDARD_TIMEOUT);
        assert_eq!(timeout_for(Some(&json!({"limit": 5}))), STANDARD_TIMEOUT);
        assert_eq!(timeout_for(Some(&json!({"waitMs": 20000}))), Duration::from_secs(25));
    }

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        let b = Backoff { initial: Duration::from_millis(100), max: Duration::from_millis(500), attempts: 5 };
        assert_eq!(b.delay(0), Duration::from_millis(100));
        assert_eq!(b.delay(1), Duration::from_millis(200));
        assert_eq!(b.delay(5), Duration::from_millis(500));
    }
}
