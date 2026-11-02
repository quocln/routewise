//! The error a caller of the helper sees. It is serialised to the webview, so
//! its shape is part of the TypeScript client's contract (`RpcError` in
//! `src/lib/rpc/rpc-error.ts`).

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum RpcError {
    /// The helper could not be reached: not installed, not running, or the
    /// connection dropped and could not be re-established.
    #[error("helper unavailable: {message}")]
    Unavailable { message: String },

    /// The helper did not answer within the deadline.
    #[error("helper did not answer within {seconds}s")]
    Timeout { seconds: u64 },

    /// The helper answered with something that is not a valid JSON-RPC response.
    #[error("invalid helper response: {message}")]
    Protocol { message: String },

    /// The helper understood the request and refused or failed it.
    #[error("{message}")]
    Remote { code: i64, message: String },

    /// The caller supplied a request the app refuses to send.
    #[error("invalid request: {message}")]
    InvalidRequest { message: String },
}

impl RpcError {
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable { message: message.into() }
    }

    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol { message: message.into() }
    }
}
