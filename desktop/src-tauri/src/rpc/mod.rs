//! Thin proxy to the RouteWise helper: a JSON-RPC client over a local socket
//! and the long-poll streams built on it.

pub mod client;
pub mod error;
pub mod message;
// Also built under test everywhere, so its retry rule runs on any host.
#[cfg(any(windows, test))]
pub mod pipe_transport;
pub mod streams;
pub mod transport;

pub use client::{timeout_for, Backoff, RpcClient};
pub use error::RpcError;
