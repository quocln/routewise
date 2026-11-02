//! The built-in VPN profiles as the helper lists them (`profiles.list`), reduced
//! to what the tray and the quit sequence need. Secrets never appear in the
//! list, and nothing here asks for them.

use serde::Deserialize;
use serde_json::Value;

use crate::rpc::RpcError;

/// Where a profile is in its life, as the helper reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileState {
    Disconnected,
    Connecting,
    Connected,
    /// Not working; the helper keeps retrying.
    Error,
    NeedsCredentials,
    /// A state a newer helper adds; treated as not connected.
    Unknown,
}

impl ProfileState {
    fn parse(raw: &str) -> Self {
        match raw {
            "disconnected" => Self::Disconnected,
            "connecting" => Self::Connecting,
            "connected" => Self::Connected,
            "error" => Self::Error,
            "needsCredentials" => Self::NeedsCredentials,
            _ => Self::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Error => "Error",
            Self::NeedsCredentials => "Needs credentials",
            Self::Unknown => "Unknown",
        }
    }
}

/// One entry of `profiles.list`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Profile {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    state: String,
}

impl Profile {
    pub fn state(&self) -> ProfileState {
        ProfileState::parse(&self.state)
    }

    /// The name to show: the profile's own, or its id when it has none.
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.id
        } else {
            &self.name
        }
    }

    /// Up, coming up, or failing and retrying: the helper is running it, so
    /// the user can turn it off and quitting must.
    pub fn is_running(&self) -> bool {
        matches!(self.state(), ProfileState::Connected | ProfileState::Connecting | ProfileState::Error)
    }
}

/// Reads a `profiles.list` result: a bare array, or an object holding it.
pub fn parse_profiles(value: Value) -> Result<Vec<Profile>, RpcError> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum List {
        Bare(Vec<Profile>),
        Wrapped { profiles: Vec<Profile> },
    }
    match serde_json::from_value::<List>(value) {
        Ok(List::Bare(profiles) | List::Wrapped { profiles }) => Ok(profiles),
        Err(e) => Err(RpcError::protocol(format!("profiles.list: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn reads_a_bare_array_and_a_wrapped_object() {
        let entry = json!({"id": "a1", "name": "Work", "state": "connected", "kind": "wireguard", "dns": []});
        let bare = parse_profiles(json!([entry.clone()])).unwrap();
        let wrapped = parse_profiles(json!({"profiles": [entry]})).unwrap();
        assert_eq!(bare, wrapped);
        assert_eq!(bare[0].state(), ProfileState::Connected);
    }

    #[test]
    fn rejects_a_list_that_is_neither() {
        assert!(matches!(parse_profiles(json!("nope")), Err(RpcError::Protocol { .. })));
    }

    #[test]
    fn unknown_and_missing_states_are_not_running() {
        let profiles = parse_profiles(json!([{"id": "a"}, {"id": "b", "state": "hibernating"}])).unwrap();
        assert!(profiles.iter().all(|p| p.state() == ProfileState::Unknown && !p.is_running()));
    }

    #[test]
    fn running_covers_connected_connecting_and_error() {
        let running = |state: &str| parse_profiles(json!([{"id": "a", "state": state}])).unwrap()[0].is_running();
        assert!(running("connected") && running("connecting") && running("error"));
        assert!(!running("disconnected") && !running("needsCredentials"));
    }

    #[test]
    fn falls_back_to_the_id_for_an_empty_name() {
        let p = &parse_profiles(json!([{"id": "a1"}])).unwrap()[0];
        assert_eq!(p.display_name(), "a1");
    }
}
