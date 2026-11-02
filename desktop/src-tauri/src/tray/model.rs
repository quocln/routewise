//! What the tray menu shows, as plain data. Building it is pure, so the menu's
//! content and the rules for its rows are tested without a window system.

use std::collections::HashMap;

use serde::Deserialize;

use crate::navigation::Tab;
use crate::profiles::{Profile, ProfileState};
use crate::rpc::RpcError;

pub const ID_QUIT: &str = "quit";
const ID_REFRESH: &str = "refresh";
const ID_RETRY: &str = "retry";
const ID_MANAGE_PENDING: &str = "manage-pending";
const ID_UNIDENTIFIED: &str = "unidentified";
const TAB_PREFIX: &str = "tab:";
const TUNNEL_PREFIX: &str = "tunnel:";
const PENDING_PREFIX: &str = "pending:";
const ID_STATUS: &str = "status";
const ID_DETAIL: &str = "detail";
const ID_GROUP: &str = "group";
const ID_ERROR: &str = "error";
const PROFILE_PREFIX: &str = "vpn:";

/// The longest action error shown in the menu; longer ones are cut.
const MAX_ERROR_CHARS: usize = 90;

/// The part of `status.get` the menu reads. A field the helper leaves out
/// (it omits empty ones) is its zero value.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Status {
    pub running: bool,
    pub vpn_connected: bool,
    pub vpn_interface: Option<String>,
    pub route_count: u32,
    pub tunnels: Vec<Tunnel>,
    pub degraded: bool,
    pub degraded_reason: Option<String>,
    pub pending_vpns: Vec<PendingVpn>,
    /// The older single-VPN form of `pending_vpns`.
    pub pending_vpn: Option<PendingVpn>,
}

impl Status {
    /// Detected full-tunnel VPNs RouteWise is not managing.
    pub fn pending(&self) -> Vec<&PendingVpn> {
        if self.pending_vpns.is_empty() {
            self.pending_vpn.iter().collect()
        } else {
            self.pending_vpns.iter().collect()
        }
    }
}

/// A VPN the helper detected whose client is not allowed yet.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct PendingVpn {
    pub interface: String,
    pub client: PendingClient,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct PendingClient {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Tunnel {
    pub interface: String,
    pub client: Client,
    pub route_count: u32,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Client {
    pub name: String,
}

/// What a poll of the helper found.
#[derive(Debug, Clone)]
pub struct Observation {
    /// `None` until the first answer.
    pub status: Option<Result<Status, RpcError>>,
    pub profiles: Vec<Profile>,
}

impl Observation {
    pub fn waiting() -> Self {
        Self { status: None, profiles: Vec::new() }
    }
}

/// What a click on a profile row does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowAction {
    Connect,
    Disconnect,
    /// Nothing: it is switching, needs credentials, or the helper is away.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRow {
    pub id: String,
    pub name: String,
    pub state_text: String,
    pub action: RowAction,
}

/// A line of the status block: label then detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLine {
    pub label: String,
    pub detail: String,
}

/// The menu bar icon: a warning while the
/// helper is degraded, a green globe while a VPN is up, and a slashed globe
/// otherwise, the helper being away included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuBarIcon {
    Disconnected,
    Connected,
    Degraded,
}

pub fn menu_bar_icon(status: &Option<Result<Status, RpcError>>) -> MenuBarIcon {
    match status {
        Some(Ok(s)) if s.degraded => MenuBarIcon::Degraded,
        Some(Ok(s)) if s.vpn_connected => MenuBarIcon::Connected,
        _ => MenuBarIcon::Disconnected,
    }
}

/// Short-lived states of the shell itself that the menu shows.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Busy {
    pub quitting: bool,
    /// The helper is being installed (an admin prompt is up).
    pub installing: bool,
    /// A requested status refresh is in flight.
    pub refreshing: bool,
}

/// What a click on a menu item asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuAction<'a> {
    Tab(Tab),
    Refresh,
    Retry,
    Quit,
    Profile(&'a str),
}

/// Everything the menu shows. Equal models draw equal menus, so the menu is
/// only rebuilt when the model changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayModel {
    pub icon: MenuBarIcon,
    pub status: StatusLine,
    pub profiles: Vec<ProfileRow>,
    /// The last failed connect or disconnect, until the next one succeeds.
    pub action_error: Option<String>,
    pub busy: Busy,
    /// One line per detected VPN RouteWise is not managing.
    pub pending: Vec<String>,
    /// Whether a pending VPN's client is known, so it can be managed.
    pub pending_manageable: bool,
    /// One line per connected tunnel, with its route count.
    pub tunnels: Vec<String>,
    /// Whether "Retry Connection" is offered.
    pub can_retry: bool,
}

/// One line of the native menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Item { id: String, text: String, enabled: bool },
    /// The CPU, memory, disk and network rows, whose text changes without the
    /// model changing: see `system_stats`.
    SystemStats,
    Separator,
}

impl Entry {
    fn item(id: impl Into<String>, text: impl Into<String>, enabled: bool) -> Self {
        Self::Item { id: id.into(), text: text.into(), enabled }
    }
}

fn plural(count: u32, noun: &str) -> String {
    format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
}

/// What the menu says about the helper's state, in the words of the window's
/// status header.
pub fn present_status(status: &Option<Result<Status, RpcError>>) -> StatusLine {
    let line = |label: &str, detail: String| StatusLine { label: label.into(), detail };
    let status = match status {
        None => return line("Connecting", "Reaching the helper".into()),
        Some(Err(RpcError::Unavailable { .. })) => return line("Helper not running", String::new()),
        Some(Err(_)) => return line("Helper error", String::new()),
        Some(Ok(status)) => status,
    };
    if status.degraded {
        let reason = status.degraded_reason.clone().filter(|r| !r.is_empty());
        return line("Needs attention", reason.unwrap_or_else(|| "Route compensation could not be verified".into()));
    }
    if !status.running {
        return line("Helper stopped", "The routing helper is not running".into());
    }
    if !status.vpn_connected {
        let pending = status.pending().len() as u32;
        let detail = if pending > 0 {
            format!("{} waiting for approval", plural(pending, "VPN"))
        } else {
            "Waiting for a VPN to connect".into()
        };
        return line("No VPN", detail);
    }
    let names: Vec<&str> = status
        .tunnels
        .iter()
        .map(|t| if t.client.name.is_empty() { t.interface.as_str() } else { t.client.name.as_str() })
        .collect();
    let place = if names.is_empty() {
        status.vpn_interface.clone().filter(|i| !i.is_empty()).unwrap_or_else(|| "VPN".into())
    } else {
        names.join(", ")
    };
    let label = if status.tunnels.len() > 1 {
        format!("{} VPNs connected", status.tunnels.len())
    } else {
        "VPN connected".into()
    };
    StatusLine { label, detail: format!("{place} \u{00B7} {}", plural(status.route_count, "route")) }
}

fn profile_row(profile: &Profile, pending: &HashMap<String, bool>, helper_up: bool) -> ProfileRow {
    let switching = pending.get(&profile.id).copied();
    let state_text = match switching {
        Some(true) => "Connecting\u{2026}".to_string(),
        Some(false) => "Disconnecting\u{2026}".to_string(),
        None => profile.state().label().to_string(),
    };
    let action = if !helper_up || switching.is_some() || profile.state() == ProfileState::NeedsCredentials {
        RowAction::None
    } else if profile.is_running() {
        RowAction::Disconnect
    } else {
        RowAction::Connect
    };
    ProfileRow { id: profile.id.clone(), name: profile.display_name().to_string(), state_text, action }
}

/// Cuts `message` to `MAX_ERROR_CHARS` characters, with an ellipsis.
pub fn shorten(message: &str) -> String {
    let flat: String = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= MAX_ERROR_CHARS {
        return flat;
    }
    let cut: String = flat.chars().take(MAX_ERROR_CHARS - 1).collect();
    format!("{cut}\u{2026}")
}

/// A tunnel's line: its client (or interface), the interface, its routes.
fn tunnel_line(tunnel: &Tunnel) -> String {
    let name = if tunnel.client.name.is_empty() { tunnel.interface.as_str() } else { tunnel.client.name.as_str() };
    if tunnel.interface.is_empty() || tunnel.interface == name {
        format!("{name} \u{00B7} {}", plural(tunnel.route_count, "route"))
    } else {
        format!("{name} \u{00B7} {} \u{00B7} {}", tunnel.interface, plural(tunnel.route_count, "route"))
    }
}

fn pending_line(vpn: &PendingVpn) -> String {
    let who = if vpn.client.name.is_empty() { "A".to_string() } else { format!("{} VPN", vpn.client.name) };
    let place = if vpn.interface.is_empty() { String::new() } else { format!(" on {}", vpn.interface) };
    format!("{who}{place} detected, not managed")
}

impl TrayModel {
    /// `pending` maps a profile id to the connect state being requested.
    pub fn build(
        observed: &Observation,
        pending: &HashMap<String, bool>,
        action_error: Option<&str>,
        busy: Busy,
    ) -> Self {
        let helper_up = matches!(observed.status, Some(Ok(_)));
        // With the helper away its last list is stale; the group is hidden.
        let profiles = if helper_up {
            observed.profiles.iter().map(|p| profile_row(p, pending, helper_up)).collect()
        } else {
            Vec::new()
        };
        let status = match &observed.status {
            _ if busy.installing => StatusLine { label: "Installing helper\u{2026}".into(), detail: String::new() },
            _ => present_status(&observed.status),
        };
        let (pending_lines, pending_manageable, tunnels) = match &observed.status {
            Some(Ok(s)) => {
                let pending = s.pending();
                (
                    pending.iter().map(|p| pending_line(p)).collect(),
                    pending.iter().any(|p| !p.client.id.is_empty()),
                    s.tunnels.iter().map(tunnel_line).collect(),
                )
            }
            _ => (Vec::new(), false, Vec::new()),
        };
        Self {
            icon: menu_bar_icon(&observed.status),
            status,
            profiles,
            action_error: action_error.map(shorten),
            busy,
            pending: pending_lines,
            pending_manageable,
            tunnels,
            // Offered while the helper cannot be reached; not while it is being
            // installed or before the first answer.
            can_retry: matches!(observed.status, Some(Err(_))) && !busy.installing,
        }
    }

    pub fn action_for(&self, profile_id: &str) -> RowAction {
        self.profiles.iter().find(|r| r.id == profile_id).map_or(RowAction::None, |r| r.action)
    }

    /// The menu, top to bottom.
    pub fn entries(&self) -> Vec<Entry> {
        let quitting = self.busy.quitting;
        let mut entries = vec![Entry::item(ID_STATUS, format!("RouteWise: {}", self.status.label), false)];
        if !self.status.detail.is_empty() {
            entries.push(Entry::item(ID_DETAIL, self.status.detail.clone(), false));
        }
        for (i, line) in self.pending.iter().enumerate() {
            entries.push(Entry::item(format!("{PENDING_PREFIX}{i}"), format!("\u{26A0} {line}"), false));
        }
        if !self.pending.is_empty() {
            // The window's banner has the button; this opens it on the VPN tab.
            entries.push(if self.pending_manageable {
                Entry::item(ID_MANAGE_PENDING, "Manage this VPN\u{2026}", !quitting)
            } else {
                Entry::item(ID_UNIDENTIFIED, "RouteWise cannot identify the VPN's client", false)
            });
        }
        for (i, line) in self.tunnels.iter().enumerate() {
            entries.push(Entry::item(format!("{TUNNEL_PREFIX}{i}"), line.clone(), false));
        }
        if self.can_retry {
            entries.push(Entry::item(ID_RETRY, "Retry Connection", !quitting));
        }
        entries.push(Entry::Separator);
        entries.push(Entry::SystemStats);
        if !self.profiles.is_empty() {
            entries.push(Entry::Separator);
            entries.push(Entry::item(ID_GROUP, "Built-in VPNs", false));
            for row in &self.profiles {
                let enabled = row.action != RowAction::None;
                entries.push(Entry::item(
                    format!("{PROFILE_PREFIX}{}", row.id),
                    format!("{}  \u{00B7}  {}", row.name, row.state_text),
                    enabled,
                ));
            }
        }
        entries.push(Entry::Separator);
        for (tab, text) in TAB_ITEMS {
            entries.push(Entry::item(format!("{TAB_PREFIX}{}", tab.as_str()), text, !quitting));
        }
        entries.push(Entry::Separator);
        if let Some(error) = &self.action_error {
            entries.push(Entry::item(ID_ERROR, error.clone(), false));
        }
        let refresh = if self.busy.refreshing { "Refreshing\u{2026}" } else { "Refresh Status" };
        entries.push(Entry::item(ID_REFRESH, refresh, !quitting && !self.busy.refreshing));
        entries.push(Entry::Separator);
        let quit = if quitting { "Quitting\u{2026}" } else { "Quit RouteWise" };
        entries.push(Entry::item(ID_QUIT, quit, !quitting));
        entries
    }
}

/// The menu items that open the window, and the tab each one shows.
const TAB_ITEMS: [(Tab, &str); 5] = [
    (Tab::Domains, "Manage Domains\u{2026}"),
    (Tab::Vpn, "Manage VPNs\u{2026}"),
    (Tab::Routes, "View Routes\u{2026}"),
    (Tab::Activity, "View Activity\u{2026}"),
    (Tab::Settings, "Settings\u{2026}"),
];

/// What a menu item id asks for, when it is one of the actionable items.
pub fn action_of(item_id: &str) -> Option<MenuAction<'_>> {
    match item_id {
        ID_QUIT => Some(MenuAction::Quit),
        ID_REFRESH => Some(MenuAction::Refresh),
        ID_RETRY => Some(MenuAction::Retry),
        ID_MANAGE_PENDING => Some(MenuAction::Tab(Tab::Vpn)),
        other => other
            .strip_prefix(PROFILE_PREFIX)
            .filter(|id| !id.is_empty())
            .map(MenuAction::Profile)
            .or_else(|| other.strip_prefix(TAB_PREFIX).and_then(Tab::parse).map(MenuAction::Tab)),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::profiles::parse_profiles;

    fn status(value: serde_json::Value) -> Option<Result<Status, RpcError>> {
        Some(Ok(serde_json::from_value(value).unwrap()))
    }

    fn observed(status_json: serde_json::Value, profiles: serde_json::Value) -> Observation {
        Observation { status: status(status_json), profiles: parse_profiles(profiles).unwrap() }
    }

    fn texts(model: &TrayModel) -> Vec<String> {
        model
            .entries()
            .into_iter()
            .map(|e| match e {
                Entry::Item { text, .. } => text,
                Entry::SystemStats => "<system stats>".into(),
                Entry::Separator => "---".into(),
            })
            .collect()
    }

    #[test]
    fn says_so_while_waiting_for_and_without_the_helper() {
        assert_eq!(present_status(&None).label, "Connecting");
        let gone = Some(Err(RpcError::unavailable("no socket")));
        assert_eq!(present_status(&gone), StatusLine { label: "Helper not running".into(), detail: String::new() });
        let broken = Some(Err(RpcError::Timeout { seconds: 5 }));
        assert_eq!(present_status(&broken).label, "Helper error");
    }

    #[test]
    fn the_icon_follows_degraded_then_connected() {
        assert_eq!(menu_bar_icon(&None), MenuBarIcon::Disconnected);
        assert_eq!(menu_bar_icon(&Some(Err(RpcError::unavailable("no socket")))), MenuBarIcon::Disconnected);
        assert_eq!(menu_bar_icon(&status(json!({"running": true, "vpnConnected": false}))), MenuBarIcon::Disconnected);
        assert_eq!(menu_bar_icon(&status(json!({"running": true, "vpnConnected": true}))), MenuBarIcon::Connected);
        let degraded = status(json!({"running": true, "vpnConnected": true, "degraded": true}));
        assert_eq!(menu_bar_icon(&degraded), MenuBarIcon::Degraded);
    }

    #[test]
    fn describes_connected_tunnels_and_routes() {
        let one = status(json!({"running": true, "vpnConnected": true, "routeCount": 1,
            "tunnels": [{"interface": "utun4", "client": {"id": "/a", "name": "AWS VPN"}, "routeCount": 1}]}));
        let line = present_status(&one);
        assert_eq!((line.label.as_str(), line.detail.as_str()), ("VPN connected", "AWS VPN \u{00B7} 1 route"));

        let two = status(json!({"running": true, "vpnConnected": true, "routeCount": 5,
            "tunnels": [{"interface": "utun4", "client": {"name": ""}}, {"interface": "utun5", "client": {"name": "Work"}}]}));
        let line = present_status(&two);
        assert_eq!((line.label.as_str(), line.detail.as_str()), ("2 VPNs connected", "utun4, Work \u{00B7} 5 routes"));
    }

    #[test]
    fn describes_idle_degraded_and_stopped_helpers() {
        let idle = present_status(&status(json!({"running": true, "pendingVpns": [{"interface": "utun9"}]})));
        assert_eq!((idle.label.as_str(), idle.detail.as_str()), ("No VPN", "1 VPN waiting for approval"));
        let waiting = present_status(&status(json!({"running": true})));
        assert_eq!(waiting.detail, "Waiting for a VPN to connect");
        let degraded = present_status(&status(json!({"running": true, "degraded": true, "degradedReason": "stuck"})));
        assert_eq!((degraded.label.as_str(), degraded.detail.as_str()), ("Needs attention", "stuck"));
        assert_eq!(present_status(&status(json!({"running": false}))).label, "Helper stopped");
    }

    #[test]
    fn lists_profiles_between_the_status_and_the_actions() {
        let model = TrayModel::build(
            &observed(
                json!({"running": true}),
                json!([{"id": "a", "name": "Work", "state": "connected"}, {"id": "b", "name": "", "state": "disconnected"}]),
            ),
            &HashMap::new(),
            None,
            Busy::default(),
        );
        assert_eq!(
            texts(&model),
            [
                "RouteWise: No VPN",
                "Waiting for a VPN to connect",
                "---",
                "<system stats>",
                "---",
                "Built-in VPNs",
                "Work  \u{00B7}  Connected",
                "b  \u{00B7}  Disconnected",
                "---",
                "Manage Domains\u{2026}",
                "Manage VPNs\u{2026}",
                "View Routes\u{2026}",
                "View Activity\u{2026}",
                "Settings\u{2026}",
                "---",
                "Refresh Status",
                "---",
                "Quit RouteWise",
            ]
        );
        assert_eq!(model.action_for("a"), RowAction::Disconnect);
        assert_eq!(model.action_for("b"), RowAction::Connect);
        assert_eq!(model.action_for("missing"), RowAction::None);
    }

    #[test]
    fn omits_the_group_when_there_are_no_profiles() {
        let model = TrayModel::build(&observed(json!({"running": true}), json!([])), &HashMap::new(), None, Busy::default());
        assert!(!texts(&model).contains(&"Built-in VPNs".to_string()));
    }

    #[test]
    fn hides_profiles_while_the_helper_is_away() {
        let stale = Observation {
            status: Some(Err(RpcError::unavailable("gone"))),
            profiles: parse_profiles(json!([{"id": "a", "state": "connected"}])).unwrap(),
        };
        let model = TrayModel::build(&stale, &HashMap::new(), None, Busy::default());
        assert!(model.profiles.is_empty());
    }

    #[test]
    fn a_switching_row_says_so_and_cannot_be_clicked() {
        let obs = observed(json!({"running": true}), json!([{"id": "a", "name": "Work", "state": "disconnected"}]));
        let connecting = TrayModel::build(&obs, &HashMap::from([("a".to_string(), true)]), None, Busy::default());
        assert_eq!(connecting.profiles[0].state_text, "Connecting\u{2026}");
        assert_eq!(connecting.profiles[0].action, RowAction::None);
        let disconnecting = TrayModel::build(&obs, &HashMap::from([("a".to_string(), false)]), None, Busy::default());
        assert_eq!(disconnecting.profiles[0].state_text, "Disconnecting\u{2026}");
        let entry = connecting.entries().into_iter().find(|e| matches!(e, Entry::Item { id, .. } if id == "vpn:a"));
        assert!(matches!(entry, Some(Entry::Item { enabled: false, .. })));
    }

    #[test]
    fn a_profile_without_credentials_cannot_be_toggled_and_an_erroring_one_can_be_turned_off() {
        let obs = observed(
            json!({"running": true}),
            json!([{"id": "a", "state": "needsCredentials"}, {"id": "b", "state": "error"}, {"id": "c", "state": "connecting"}]),
        );
        let model = TrayModel::build(&obs, &HashMap::new(), None, Busy::default());
        assert_eq!(model.action_for("a"), RowAction::None);
        assert_eq!(model.action_for("b"), RowAction::Disconnect);
        assert_eq!(model.action_for("c"), RowAction::Disconnect);
    }

    #[test]
    fn shows_a_shortened_action_error() {
        let long = format!("Could not connect Work: {}", "x".repeat(200));
        let model = TrayModel::build(&observed(json!({"running": true}), json!([])), &HashMap::new(), Some(&long), Busy::default());
        let error = model.action_error.clone().unwrap();
        assert_eq!(error.chars().count(), MAX_ERROR_CHARS);
        assert!(error.ends_with('\u{2026}'));
        assert!(texts(&model).contains(&error));
        assert_eq!(shorten("a\n  b"), "a b");
    }

    #[test]
    fn quitting_disables_the_actions() {
        let model = TrayModel::build(&observed(json!({"running": true}), json!([])), &HashMap::new(), None, Busy { quitting: true, ..Busy::default() });
        let entries = model.entries();
        assert!(entries.contains(&Entry::item(ID_QUIT, "Quitting\u{2026}", false)));
        assert!(entries.contains(&Entry::item("tab:vpn", "Manage VPNs\u{2026}", false)));
        assert!(entries.contains(&Entry::item(ID_REFRESH, "Refresh Status", false)));
    }

    #[test]
    fn equal_observations_build_equal_models() {
        let obs = observed(json!({"running": true}), json!([{"id": "a", "state": "connected"}]));
        let pending = HashMap::new();
        assert_eq!(TrayModel::build(&obs, &pending, None, Busy::default()), TrayModel::build(&obs.clone(), &pending, None, Busy::default()));
    }

    #[test]
    fn reads_what_a_menu_item_asks_for() {
        assert_eq!(action_of("vpn:abc"), Some(MenuAction::Profile("abc")));
        assert_eq!(action_of("vpn:"), None);
        assert_eq!(action_of("tab:routes"), Some(MenuAction::Tab(Tab::Routes)));
        assert_eq!(action_of("tab:nope"), None);
        assert_eq!(action_of("refresh"), Some(MenuAction::Refresh));
        assert_eq!(action_of("retry"), Some(MenuAction::Retry));
        assert_eq!(action_of("quit"), Some(MenuAction::Quit));
        assert_eq!(action_of("manage-pending"), Some(MenuAction::Tab(Tab::Vpn)));
        assert_eq!(action_of("status"), None);
    }

    #[test]
    fn every_tab_item_opens_its_tab() {
        let model = TrayModel::build(&observed(json!({"running": true}), json!([])), &HashMap::new(), None, Busy::default());
        let tabs: Vec<Tab> = model
            .entries()
            .iter()
            .filter_map(|e| match e {
                Entry::Item { id, enabled: true, .. } => match action_of(id) {
                    Some(MenuAction::Tab(tab)) => Some(tab),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(tabs, [Tab::Domains, Tab::Vpn, Tab::Routes, Tab::Activity, Tab::Settings]);
    }

    #[test]
    fn lists_each_tunnel_with_its_routes() {
        let model = TrayModel::build(
            &observed(
                json!({"running": true, "vpnConnected": true, "routeCount": 4, "tunnels": [
                    {"interface": "utun4", "client": {"name": "AWS VPN"}, "routeCount": 3},
                    {"interface": "utun5", "client": {"name": ""}, "routeCount": 1}]}),
                json!([]),
            ),
            &HashMap::new(),
            None,
            Busy::default(),
        );
        assert_eq!(model.tunnels, ["AWS VPN \u{00B7} utun4 \u{00B7} 3 routes", "utun5 \u{00B7} 1 route"]);
        assert!(texts(&model).contains(&"utun5 \u{00B7} 1 route".to_string()));
    }

    #[test]
    fn offers_to_manage_a_detected_vpn_only_when_its_client_is_known() {
        let known = json!({"running": true, "pendingVpns": [{"interface": "utun9", "client": {"id": "/a", "name": "Corp"}}]});
        let model = TrayModel::build(&observed(known, json!([])), &HashMap::new(), None, Busy::default());
        assert_eq!(model.pending, ["Corp VPN on utun9 detected, not managed"]);
        let all = texts(&model);
        assert!(all.contains(&"\u{26A0} Corp VPN on utun9 detected, not managed".to_string()));
        assert!(model.entries().contains(&Entry::item(ID_MANAGE_PENDING, "Manage this VPN\u{2026}", true)));

        // The single-VPN form works too; an unidentified client cannot be managed.
        let unknown = json!({"running": true, "pendingVpn": {"interface": "utun9", "client": {"id": "", "name": ""}}});
        let model = TrayModel::build(&observed(unknown, json!([])), &HashMap::new(), None, Busy::default());
        assert_eq!(model.pending, ["A on utun9 detected, not managed"]);
        assert!(!model.pending_manageable);
        assert!(model.entries().iter().all(|e| !matches!(e, Entry::Item { id, .. } if id == ID_MANAGE_PENDING)));
    }

    #[test]
    fn retry_is_offered_only_while_the_helper_cannot_be_reached() {
        let gone = Observation { status: Some(Err(RpcError::unavailable("no socket"))), profiles: Vec::new() };
        let model = TrayModel::build(&gone, &HashMap::new(), None, Busy::default());
        assert!(texts(&model).contains(&"Retry Connection".to_string()));

        let installing = TrayModel::build(&gone, &HashMap::new(), None, Busy { installing: true, ..Busy::default() });
        assert!(!texts(&installing).contains(&"Retry Connection".to_string()));
        assert_eq!(installing.status.label, "Installing helper\u{2026}");

        let up = TrayModel::build(&observed(json!({"running": true}), json!([])), &HashMap::new(), None, Busy::default());
        assert!(!texts(&up).contains(&"Retry Connection".to_string()));
        let waiting = TrayModel::build(&Observation::waiting(), &HashMap::new(), None, Busy::default());
        assert!(!texts(&waiting).contains(&"Retry Connection".to_string()));
    }

    #[test]
    fn a_refresh_in_flight_reads_refreshing_and_cannot_be_repeated() {
        let busy = Busy { refreshing: true, ..Busy::default() };
        let model = TrayModel::build(&observed(json!({"running": true}), json!([])), &HashMap::new(), None, busy);
        assert!(model.entries().contains(&Entry::item(ID_REFRESH, "Refreshing\u{2026}", false)));
    }
}
