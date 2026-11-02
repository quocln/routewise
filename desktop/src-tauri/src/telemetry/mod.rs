//! Error reporting: the Rust core owns the single Sentry client, so the DSN
//! never has to enter the webview. The webview reports through
//! `ui::report_ui_error` and `ui::log_ui`.
//!
//! What is sent is the user's choice, held by the helper (`telemetry.get`):
//! errors and crashes, sessions, warning and error logs, performance traces.
//! Every payload is scrubbed of addresses, domain names, the user's folder
//! name and every name the app knows before it leaves (`scrubber`, `payload`).

mod client;
mod helper_link;
mod logging;
mod names;
mod panic;
mod payload;
mod scrubber;
mod settings;
pub mod test_event;
mod tracing;
pub mod ui;

#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod panic_tests;
#[cfg(test)]
mod payload_tests;
#[cfg(test)]
mod scrubber_tests;

pub use client::shutdown;
pub use helper_link::{observe_rpc, start};
pub use logging::install_logger;
pub use tracing::measure;
