//! Quitting. Built-in VPNs live only as long as the app: before it exits it
//! disconnects every one the helper is running, so nothing keeps tunnelling
//! once the user has closed the app. VPN apps the helper manages are left alone.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;

use crate::profiles::parse_profiles;
use crate::rpc::transport::Transport;
use crate::rpc::{Backoff, RpcClient};

/// The longest quitting waits for the helper. One that does not answer must
/// not keep the app, or a logout, from finishing.
pub const QUIT_TIMEOUT: Duration = Duration::from_secs(5);
/// Deadline of one request while quitting.
const CALL_TIMEOUT: Duration = Duration::from_secs(4);

/// Asks the helper to disconnect every running built-in VPN, all at once, and
/// returns the ids it asked. A failure is logged and does not hold up the others.
pub async fn disconnect_running(transport: &Arc<dyn Transport>) -> Vec<String> {
    let lister = RpcClient::new(transport.clone(), Backoff::default());
    let running: Vec<_> = match lister.call("profiles.list", None, CALL_TIMEOUT).await.and_then(parse_profiles) {
        Ok(profiles) => profiles.into_iter().filter(|p| p.is_running()).collect(),
        Err(e) => {
            log::warn!("quit: could not list built-in VPNs: {e}");
            return Vec::new();
        }
    };
    if running.is_empty() {
        return Vec::new();
    }
    log::info!("quit: disconnecting {} built-in VPN(s)", running.len());

    // One connection each: a client sends one request at a time, and a slow
    // teardown must not queue the others behind it.
    let mut tasks = JoinSet::new();
    for profile in &running {
        let client = RpcClient::new(transport.clone(), Backoff::default());
        let id = profile.id.clone();
        let name = profile.display_name().to_string();
        tasks.spawn(async move {
            let params = serde_json::json!({ "id": id });
            if let Err(e) = client.call("profiles.disconnect", Some(&params), CALL_TIMEOUT).await {
                log::warn!("quit: could not disconnect \"{name}\": {e}");
            }
        });
    }
    while tasks.join_next().await.is_some() {}
    running.into_iter().map(|p| p.id).collect()
}

/// Set once the built-in VPNs were disconnected for this quit, so the exit that
/// follows the tray's Quit does not ask the helper a second time.
static DISCONNECTED: AtomicBool = AtomicBool::new(false);

/// `disconnect_running_within`, once per process: the tray's Quit runs it
/// before exiting, and the app's exit runs it for every other way out (Cmd+Q,
/// logout, shutdown), which macOS does not let the app cancel.
pub async fn disconnect_once(transport: &Arc<dyn Transport>, timeout: Duration) {
    if DISCONNECTED.swap(true, Ordering::SeqCst) {
        return;
    }
    disconnect_running_within(transport, timeout).await;
}

/// `disconnect_running`, abandoned after `timeout`. Abandoned requests that
/// were already sent still reach the helper.
pub async fn disconnect_running_within(transport: &Arc<dyn Transport>, timeout: Duration) {
    if tokio::time::timeout(timeout, disconnect_running(transport)).await.is_err() {
        log::warn!("quit: the helper did not finish disconnecting in time");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Mutex;
    use std::time::Instant;

    use serde_json::{json, Value};

    use super::*;
    use crate::rpc::client::tests::{ok_reply, serve};
    use crate::rpc::transport::UnixTransport;

    const PROFILES: &str = r#"[
        {"id": "up", "name": "Work", "state": "connected"},
        {"id": "coming", "name": "Home", "state": "connecting"},
        {"id": "failing", "name": "Lab", "state": "error"},
        {"id": "off", "name": "Idle", "state": "disconnected"},
        {"id": "bare", "name": "New", "state": "needsCredentials"}
    ]"#;

    fn transport_for(path: &std::path::Path) -> Arc<dyn Transport> {
        Arc::new(UnixTransport::new(path))
    }

    /// A helper that lists `PROFILES` and records the id of each disconnect.
    fn helper(
        path: &std::path::Path,
        disconnect_delay: Duration,
    ) -> (tokio::task::JoinHandle<()>, Arc<Mutex<Vec<String>>>) {
        let disconnected = Arc::new(Mutex::new(Vec::new()));
        let seen = disconnected.clone();
        let server = serve(path, move |req: Value| match req["method"].as_str() {
            Some("profiles.list") => Some(ok_reply(&req, serde_json::from_str(PROFILES).unwrap())),
            Some("profiles.disconnect") => {
                std::thread::sleep(disconnect_delay);
                seen.lock().unwrap().push(req["params"]["id"].as_str().unwrap().to_string());
                Some(ok_reply(&req, json!({"success": true})))
            }
            other => panic!("unexpected call {other:?}"),
        });
        (server, disconnected)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnects_only_the_profiles_the_helper_is_running() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let (_server, disconnected) = helper(&path, Duration::ZERO);

        let asked = disconnect_running(&transport_for(&path)).await;

        let mut done = disconnected.lock().unwrap().clone();
        done.sort();
        assert_eq!(done, ["coming", "failing", "up"]);
        assert_eq!(asked, ["up", "coming", "failing"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn does_nothing_when_no_profile_is_running() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let _server = serve(&path, |req| match req["method"].as_str() {
            Some("profiles.list") => Some(ok_reply(&req, json!([{"id": "a", "state": "disconnected"}]))),
            other => panic!("unexpected call {other:?}"),
        });
        assert!(disconnect_running(&transport_for(&path)).await.is_empty());
    }

    #[tokio::test]
    async fn gives_up_quickly_when_the_helper_is_away() {
        let dir = tempfile::tempdir().unwrap();
        let started = Instant::now();
        disconnect_running_within(&transport_for(&dir.path().join("absent.sock")), QUIT_TIMEOUT).await;
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_helper_that_stalls_cannot_hold_the_quit_past_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let (_server, _disconnected) = helper(&path, Duration::from_secs(3));

        let started = Instant::now();
        disconnect_running_within(&transport_for(&path), Duration::from_millis(300)).await;
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_slow_teardown_does_not_queue_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let (_server, disconnected) = helper(&path, Duration::from_millis(300));

        let started = Instant::now();
        disconnect_running(&transport_for(&path)).await;
        // Three teardowns of 300 ms each finish together, not one after another.
        assert!(started.elapsed() < Duration::from_millis(800), "{:?}", started.elapsed());
        assert_eq!(disconnected.lock().unwrap().len(), 3);
    }
}
