//! A release build aborts on panic, so the event has to be on its way before
//! the hook returns. The test re-runs itself as a child process that panics
//! with an abort in the hook chain (what `panic = "abort"` does after the
//! hooks), over a transport that is slow to deliver, and checks the parent
//! finds the event in the child's output file.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use sentry::{Envelope, Transport, TransportFactory};

use super::client::{apply_with, Identity};
use super::settings::TelemetrySettings;

const CHILD_OUTPUT: &str = "ROUTEWISE_PANIC_TEST_OUTPUT";
const TEST_NAME: &str = "telemetry::panic_tests::panic_event_is_flushed_before_the_process_aborts";
/// Slower than the process takes to die without a flush.
const DELIVERY_DELAY: Duration = Duration::from_millis(300);

/// Delivers each event to a file after a delay, like a slow network would.
struct SlowFileTransport {
    path: PathBuf,
    pending: Mutex<Vec<JoinHandle<()>>>,
}

impl Transport for SlowFileTransport {
    fn send_envelope(&self, envelope: Envelope) {
        let Some(line) = envelope.event().map(|e| {
            let exception = &e.exception.values[0];
            format!("{}:{}\n", exception.ty, exception.value.clone().unwrap_or_default())
        }) else {
            return;
        };
        let path = self.path.clone();
        let handle = thread::spawn(move || {
            thread::sleep(DELIVERY_DELAY);
            let mut file = OpenOptions::new().create(true).append(true).open(path).unwrap();
            file.write_all(line.as_bytes()).unwrap();
        });
        self.pending.lock().unwrap().push(handle);
    }

    fn flush(&self, _timeout: Duration) -> bool {
        let handles = std::mem::take(&mut *self.pending.lock().unwrap());
        handles.into_iter().for_each(|h| h.join().unwrap());
        true
    }
}

impl TransportFactory for SlowFileTransport {
    fn create_transport_with_options(&self, _: sentry::TransportOptions) -> Arc<dyn Transport> {
        Arc::new(SlowFileTransport { path: self.path.clone(), pending: Mutex::new(Vec::new()) })
    }
}

fn run_child(output: &Path) -> ! {
    let settings = TelemetrySettings {
        dsn: "https://public@example.invalid/1".into(),
        errors: true,
        sessions: false,
        logs: false,
        traces: false,
        traces_sample_rate: 0.0,
    };
    let factory = SlowFileTransport { path: output.to_path_buf(), pending: Mutex::new(Vec::new()) };
    apply_with(&settings, &Identity::for_version("0.0.0"), Some(Arc::new(factory)));

    // What `panic = "abort"` does once every hook has run.
    let hooks = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        hooks(info);
        std::process::abort();
    }));
    panic!("boom at vpn.example.net");
}

#[test]
fn panic_event_is_flushed_before_the_process_aborts() {
    if let Ok(output) = std::env::var(CHILD_OUTPUT) {
        run_child(Path::new(&output));
    }

    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("events.txt");
    let status = Command::new(std::env::current_exe().unwrap())
        .args([TEST_NAME, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_OUTPUT, &output)
        .output()
        .unwrap()
        .status;

    assert!(!status.success(), "the child was expected to abort");
    let delivered = std::fs::read_to_string(&output).unwrap_or_default();
    assert_eq!(delivered, "panic:boom at [redacted]\n");
}
