//! "Send test event" in Settings: a harmless event that checks the DSN end to
//! end.

use std::time::Duration;

use sentry::protocol::Event;
use serde::Serialize;

use super::client::{errors_enabled, hub};

const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// What happened to the test event.
#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum TestEventOutcome {
    /// Sent; `eventId` is the event's id, for finding it on the server.
    #[serde(rename_all = "camelCase")]
    Sent { event_id: String },
    /// Errors reporting is off or no DSN is set.
    NotRunning,
    /// The client refused the event.
    Dropped,
}

fn test_event() -> Event<'static> {
    let mut event = Event {
        level: sentry::Level::Info,
        message: Some("RouteWise test event".into()),
        ..Default::default()
    };
    event.tags.insert("kind".into(), "test".into());
    event
}

/// Captures the test event and waits for it to be sent, off the async runtime.
#[tauri::command]
pub async fn telemetry_send_test_event() -> TestEventOutcome {
    if !errors_enabled() {
        return TestEventOutcome::NotRunning;
    }
    let hub = hub();
    let Some(client) = hub.client() else {
        return TestEventOutcome::NotRunning;
    };
    let id = hub.capture_event(test_event());
    if id.is_nil() {
        return TestEventOutcome::Dropped;
    }
    let _ = tauri::async_runtime::spawn_blocking(move || client.flush(Some(FLUSH_TIMEOUT))).await;
    TestEventOutcome::Sent { event_id: id.simple().to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_event_is_tagged_and_harmless() {
        let event = test_event();
        assert_eq!(event.level, sentry::Level::Info);
        assert_eq!(event.tags.get("kind").map(String::as_str), Some("test"));
        assert!(event.exception.is_empty());
    }

    #[test]
    fn outcomes_serialize_for_the_webview() {
        let sent = TestEventOutcome::Sent { event_id: "abc".into() };
        assert_eq!(serde_json::to_value(sent).unwrap(), serde_json::json!({ "outcome": "sent", "eventId": "abc" }));
        assert_eq!(
            serde_json::to_value(TestEventOutcome::NotRunning).unwrap(),
            serde_json::json!({ "outcome": "notRunning" })
        );
    }
}
