//! The names the scrubber must redact on top of its patterns: domain list
//! entries, profile names and their servers, and VPN client names. They come
//! from the helper; a call that fails just contributes nothing.

use std::time::Duration;

use serde_json::Value;

use crate::rpc::RpcClient;

const TIMEOUT: Duration = Duration::from_secs(10);

/// Every name the helper holds that identifies the user's setup.
pub async fn load(client: &RpcClient) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(domains) = client.call("domains.list", None, TIMEOUT).await {
        names.extend(strings_at(&domains, "pattern"));
    }
    if let Ok(profiles) = client.call("profiles.list", None, TIMEOUT).await {
        names.extend(strings_at(&profiles, "name"));
        for server in strings_at(&profiles, "server") {
            // `host:port`: the whole value and the host alone.
            if let Some((host, _port)) = server.rsplit_once(':') {
                names.push(host.to_string());
            }
            names.push(server);
        }
    }
    if let Ok(settings) = client.call("settings.get", None, TIMEOUT).await {
        if let Some(clients) = settings.get("allowedVpnClients") {
            names.extend(strings_at(clients, "name"));
        }
    }
    names
}

/// The string field `key` of every object in the JSON array `list`.
fn strings_at(list: &Value, key: &str) -> Vec<String> {
    list.as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.get(key)?.as_str().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn collects_a_field_from_every_object() {
        let list = json!([{"name": "Work VPN"}, {"name": 3}, {"other": "x"}, {"name": "Home"}]);
        assert_eq!(strings_at(&list, "name"), ["Work VPN", "Home"]);
    }

    #[test]
    fn a_value_that_is_not_a_list_has_no_names() {
        assert!(strings_at(&json!({"name": "x"}), "name").is_empty());
        assert!(strings_at(&Value::Null, "name").is_empty());
    }
}
