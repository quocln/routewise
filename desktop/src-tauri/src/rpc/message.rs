//! JSON-RPC 2.0 message shapes.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::RpcError;

/// A request line sent to the helper.
#[derive(Serialize)]
pub struct Request<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    // Absent params are omitted: the helper's argument-less methods expect that.
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a Value>,
    id: u64,
}

impl<'a> Request<'a> {
    pub fn new(id: u64, method: &'a str, params: Option<&'a Value>) -> Self {
        Self { jsonrpc: "2.0", method, params, id }
    }

    /// Serialises the request as one newline-terminated line.
    pub fn to_line(&self) -> Result<Vec<u8>, RpcError> {
        let mut line = serde_json::to_vec(self)
            .map_err(|e| RpcError::InvalidRequest { message: e.to_string() })?;
        line.push(b'\n');
        Ok(line)
    }
}

// Debug never prints params, for any method: profiles.import, profiles.update
// and telemetry.set carry credentials, and a list of such methods would go
// stale. A stray `{:?}` therefore cannot leak one.
impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("id", &self.id)
            .field("params", &if self.params.is_some() { "<redacted>" } else { "<none>" })
            .finish()
    }
}

#[derive(Deserialize)]
struct WireError {
    code: i64,
    message: String,
}

/// A response line received from the helper.
#[derive(Deserialize)]
pub struct Response {
    id: Value,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<WireError>,
}

impl Response {
    pub fn parse(line: &[u8]) -> Result<Self, RpcError> {
        serde_json::from_slice(line).map_err(|e| RpcError::protocol(e.to_string()))
    }

    /// Resolves the response for the request with `id`: its result, or the
    /// helper's error. A response to another request is a protocol error.
    pub fn into_result(self, id: u64) -> Result<Value, RpcError> {
        if self.id != id {
            return Err(RpcError::protocol(format!("response id does not match request {id}")));
        }
        match self.error {
            Some(e) => Err(RpcError::Remote { code: e.code, message: e.message }),
            // The helper omits a null result.
            None => Ok(self.result.unwrap_or(Value::Null)),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn request_line_omits_absent_params_and_ends_with_newline() {
        let line = Request::new(7, "status.get", None).to_line().unwrap();
        assert_eq!(line, b"{\"jsonrpc\":\"2.0\",\"method\":\"status.get\",\"id\":7}\n");
    }

    #[test]
    fn request_line_carries_params() {
        let params = json!({"pattern": "example.com"});
        let line = Request::new(1, "domains.add", Some(&params)).to_line().unwrap();
        let value: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(value["params"], params);
        assert_eq!(value["id"], 1);
    }

    #[test]
    fn debug_output_never_contains_params() {
        let params = json!({"wireguardConfig": "PrivateKey = hunter2"});
        let shown = format!("{:?}", Request::new(1, "profiles.import", Some(&params)));
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("profiles.import"));
    }

    #[test]
    fn success_response_yields_result() {
        let r = Response::parse(br#"{"jsonrpc":"2.0","result":{"running":true},"id":3}"#).unwrap();
        assert_eq!(r.into_result(3).unwrap(), json!({"running": true}));
    }

    #[test]
    fn missing_result_is_null() {
        let r = Response::parse(br#"{"jsonrpc":"2.0","id":3}"#).unwrap();
        assert_eq!(r.into_result(3).unwrap(), Value::Null);
    }

    #[test]
    fn error_response_maps_to_remote() {
        let r = Response::parse(
            br#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"unauthorized"},"id":3}"#,
        )
        .unwrap();
        assert_eq!(
            r.into_result(3).unwrap_err(),
            RpcError::Remote { code: -32001, message: "unauthorized".into() }
        );
    }

    #[test]
    fn mismatched_id_is_a_protocol_error() {
        let r = Response::parse(br#"{"jsonrpc":"2.0","result":1,"id":4}"#).unwrap();
        assert!(matches!(r.into_result(3), Err(RpcError::Protocol { .. })));
    }

    #[test]
    fn garbage_is_a_protocol_error() {
        assert!(matches!(Response::parse(b"not json"), Err(RpcError::Protocol { .. })));
    }
}
