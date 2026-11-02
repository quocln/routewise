//! The tray menu: the helper's status, tunnels and pending VPNs, the machine's
//! CPU, memory, disk and network figures, the built-in VPNs with a connect
//! toggle, the tab shortcuts, Refresh, Retry and Quit. It polls the helper at a
//! modest pace and redraws the native menu only when what it shows changes, so a
//! tray-only app stays small.

mod model;
pub mod system_stats;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{json, Value};
use tauri::menu::{Menu, MenuBuilder, MenuItem, MenuItemBuilder};
use tauri::image::Image;
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{AppHandle, Emitter, Manager, Runtime};

use crate::profiles::{parse_profiles, ProfileState};
use crate::notify::{self, ConnectionNotifier};
use crate::quit::{disconnect_once, QUIT_TIMEOUT};
use crate::rpc::transport::Transport;
use crate::rpc::{Backoff, RpcClient, RpcError};
use crate::helper_service::{
    helper_install, helper_service_status, install_in_progress, ACTION_CHANGED, IN_PROGRESS,
};
use crate::navigation::open_tab;
use crate::window::MAIN_WINDOW;
use model::{action_of, Busy, Entry, MenuAction, MenuBarIcon, Observation, RowAction, Status, TrayModel, ID_QUIT};
use system_stats::{rows, Reading, Sampler, SystemStatsHistory, ROW_COUNT, SAMPLE_EVERY};

/// The events the window listens to, so it asks for neither.
const HELPER_STATUS_EVENT: &str = "helper://status";
const SYSTEM_STATS_EVENT: &str = "system://stats";

const TRAY_ID: &str = "main";
/// Pause between polls with only the menu to keep current, with the window open, and
/// while a profile is coming up.
const POLL_IDLE: Duration = Duration::from_secs(4);
const POLL_WINDOW_OPEN: Duration = Duration::from_secs(2);
const POLL_BUSY: Duration = Duration::from_secs(1);
/// Deadline of one poll request.
const POLL_TIMEOUT: Duration = Duration::from_secs(5);
/// Deadline of a connect or disconnect: the helper brings a tunnel up or down
/// before it answers.
const ACTION_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a fresh install gets to start the helper before it is polled.
const INSTALL_SETTLE: Duration = Duration::from_millis(1500);

#[derive(Default)]
struct State {
    observed: Option<Observation>,
    /// Profile id to the connect state being requested, while it is in flight.
    pending: HashMap<String, bool>,
    action_error: Option<String>,
    busy: Busy,
    /// What the native menu currently shows.
    shown: Option<TrayModel>,
    notifier: ConnectionNotifier,
    /// What the window was last told.
    status_feed: StatusFeed,
}

/// Turns each poll into what the window should hear, which is only a change: most polls
/// find nothing new, and the window need not wake up for them.
#[derive(Default)]
struct StatusFeed {
    last: Option<Value>,
}

impl StatusFeed {
    /// The event payload for this poll's status, or None if the window knows it already.
    fn next(&mut self, status: Option<Value>) -> Option<Value> {
        let payload = json!({ "status": status });
        if self.last.as_ref() == Some(&payload) {
            return None;
        }
        self.last = Some(payload.clone());
        Some(payload)
    }
}

/// The tray's state and its own connection to the helper, so polling never
/// queues behind the window's calls.
pub struct Tray {
    client: RpcClient,
    transport: Arc<dyn Transport>,
    state: Mutex<State>,
}

/// What the helper says right now, or why it could not be asked, and its status as it
/// came, for the window.
async fn observe(client: &RpcClient) -> (Observation, Option<Value>) {
    let raw = client.call("status.get", None, POLL_TIMEOUT).await;
    let raw_status = raw.as_ref().ok().cloned();
    let status = raw
        .and_then(|v| serde_json::from_value::<Status>(v).map_err(|e| RpcError::protocol(format!("status.get: {e}"))));
    // With the helper away there is nothing to list; skip a second round of retries.
    let profiles = if status.is_ok() {
        match client.call("profiles.list", None, POLL_TIMEOUT).await.and_then(parse_profiles) {
            Ok(profiles) => profiles,
            Err(e) => {
                log::debug!("tray: could not list built-in VPNs: {e}");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    (Observation { status: Some(status), profiles }, raw_status)
}

/// How long to wait before polling again: a profile coming up is watched more closely,
/// and a person looking at the window expects it to keep up.
fn poll_delay(observed: &Observation, window_open: bool) -> Duration {
    if observed.profiles.iter().any(|p| p.state() == ProfileState::Connecting) {
        POLL_BUSY
    } else if window_open {
        POLL_WINDOW_OPEN
    } else {
        POLL_IDLE
    }
}

/// Whether the window is on screen, so has something to keep current.
fn window_open<R: Runtime>(app: &AppHandle<R>) -> bool {
    app.get_webview_window(MAIN_WINDOW).is_some_and(|w| w.is_visible().unwrap_or(false))
}

/// The idle icon: a black glyph that macOS tints as a template, so it follows
/// the menu bar.
#[cfg(target_os = "macos")]
const DISCONNECTED_ICON: (&[u8], bool) = (include_bytes!("../../icons/tray-disconnected.png"), true);
/// Other desktops do not tint, and a black glyph vanishes on a dark panel, so
/// the glyph is mid-grey there.
#[cfg(not(target_os = "macos"))]
const DISCONNECTED_ICON: (&[u8], bool) = (include_bytes!("../../icons/tray-disconnected-linux.png"), false);

/// The image for a menu bar icon, and whether macOS should tint it as a
/// template. The coloured states keep their colour.
fn icon_image(icon: MenuBarIcon) -> tauri::Result<(Image<'static>, bool)> {
    let (bytes, template): (&[u8], bool) = match icon {
        MenuBarIcon::Disconnected => DISCONNECTED_ICON,
        MenuBarIcon::Connected => (include_bytes!("../../icons/tray-connected.png"), false),
        MenuBarIcon::Degraded => (include_bytes!("../../icons/tray-degraded.png"), false),
    };
    Ok((Image::from_bytes(bytes)?, template))
}

fn set_icon<R: Runtime>(tray: &TrayIcon<R>, icon: MenuBarIcon) -> tauri::Result<()> {
    let (image, template) = icon_image(icon)?;
    tray.set_icon(Some(image))?;
    tray.set_icon_as_template(template)
}

/// The system figures' menu rows, kept so they can be updated in place, and
/// their latest text for when the menu is rebuilt.
struct SystemStatsRows<R: Runtime> {
    items: Mutex<Vec<MenuItem<R>>>,
    texts: Mutex<[String; ROW_COUNT]>,
}

impl<R: Runtime> SystemStatsRows<R> {
    fn new() -> Self {
        Self { items: Mutex::new(Vec::new()), texts: Mutex::new(rows(&Reading::default())) }
    }

    /// Stores new text and shows it. The menu calls hop to the main thread, so
    /// this runs outside the locks and off the async runtime.
    fn show(&self, texts: [String; ROW_COUNT]) {
        let previous = {
            let mut current = self.texts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::replace(&mut *current, texts.clone())
        };
        let items = self.items.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        for (i, item) in items.iter().enumerate() {
            if previous[i] != texts[i] {
                if let Err(e) = item.set_text(&texts[i]) {
                    log::debug!("could not update a system stats row: {e}");
                }
            }
        }
    }
}

/// Reads the machine's figures for as long as the app runs. On its own thread
/// because reading them blocks, and so does a menu update while the main thread
/// is busy.
fn start_system_stats<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    let spawned = std::thread::Builder::new().name("tray-system-stats".to_string()).spawn(move || {
        let mut sampler = Sampler::new();
        loop {
            let reading = sampler.sample();
            app.state::<SystemStatsHistory>().push(reading);
            app.state::<SystemStatsRows<R>>().show(rows(&reading));
            if window_open(&app) {
                if let Err(e) = app.emit(SYSTEM_STATS_EVENT, reading) {
                    log::debug!("could not push the system figures: {e}");
                }
            }
            std::thread::sleep(SAMPLE_EVERY);
        }
    });
    if let Err(e) = spawned {
        log::warn!("could not start reading the system figures: {e}");
    }
}

fn build_menu<R: Runtime>(app: &AppHandle<R>, entries: Vec<Entry>) -> tauri::Result<Menu<R>> {
    let stats = app.state::<SystemStatsRows<R>>();
    let mut builder = MenuBuilder::new(app);
    for entry in entries {
        builder = match entry {
            Entry::Separator => builder.separator(),
            Entry::SystemStats => {
                let texts = stats.texts.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
                let mut items = Vec::with_capacity(ROW_COUNT);
                for (i, text) in texts.iter().enumerate() {
                    items.push(MenuItemBuilder::with_id(format!("stats:{i}"), text).enabled(false).build(app)?);
                    builder = builder.item(&items[i]);
                }
                *stats.items.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = items;
                builder
            }
            Entry::Item { id, text, enabled } => {
                let mut item = MenuItemBuilder::with_id(&id, text).enabled(enabled);
                if id == ID_QUIT {
                    item = item.accelerator("CmdOrCtrl+Q");
                }
                builder.item(&item.build(app)?)
            }
        };
    }
    builder.build()
}

impl Tray {
    fn new(transport: Arc<dyn Transport>) -> Self {
        Self { client: RpcClient::new(transport.clone(), Backoff::default()), transport, state: Mutex::new(State::default()) }
    }

    /// A panic while the lock is held leaves plain data behind; carry on with it.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn model(&self) -> TrayModel {
        let state = self.lock();
        let observed = state.observed.clone().unwrap_or_else(Observation::waiting);
        // An install started from the window shows here too.
        let busy = Busy { installing: install_in_progress(), ..state.busy };
        TrayModel::build(&observed, &state.pending, state.action_error.as_deref(), busy)
    }

    /// Redraws the native menu when the model differs from what it shows.
    fn render<R: Runtime>(&self, app: &AppHandle<R>) {
        let model = self.model();
        let shown_icon = match self.lock().shown.as_ref() {
            Some(shown) if *shown == model => return,
            shown => shown.map(|m| m.icon),
        };
        // Built outside the lock: the menu calls hop to the main thread, which
        // may itself be waiting on the lock in a menu event.
        let Some(tray) = app.tray_by_id(TRAY_ID) else { return };
        if shown_icon != Some(model.icon) {
            if let Err(e) = set_icon(&tray, model.icon) {
                log::warn!("could not update the tray icon: {e}");
            }
        }
        match build_menu(app, model.entries()).and_then(|menu| tray.set_menu(Some(menu))) {
            Ok(()) => self.lock().shown = Some(model),
            Err(e) => log::warn!("could not update the tray menu: {e}"),
        }
    }

    /// Stores a poll's result and posts the "VPN Connected" notice when it
    /// shows a tunnel coming up.
    fn record<R: Runtime>(&self, app: &AppHandle<R>, observed: Observation) {
        let notice = {
            let mut state = self.lock();
            let reading = match &observed.status {
                Some(Ok(s)) => Some((s.vpn_connected, s.vpn_interface.as_deref())),
                _ => None,
            };
            let notice = state.notifier.observe(reading);
            state.observed = Some(observed);
            notice
        };
        if let Some(notice) = notice {
            notify::send(app, &notice);
        }
    }

    async fn refresh<R: Runtime>(&self, app: &AppHandle<R>) -> Duration {
        let (observed, status) = observe(&self.client).await;
        let delay = poll_delay(&observed, window_open(app));
        self.record(app, observed);
        self.render(app);
        self.push_status(app, status);
        delay
    }

    /// Tells the window about a status it has not heard yet.
    fn push_status<R: Runtime>(&self, app: &AppHandle<R>, status: Option<Value>) {
        let payload = self.lock().status_feed.next(status);
        if let Some(payload) = payload {
            if let Err(e) = app.emit(HELPER_STATUS_EVENT, payload) {
                log::debug!("could not push the helper status: {e}");
            }
        }
    }

    /// Re-polls the helper now, with "Refreshing…" in the menu meanwhile.
    fn refresh_now<R: Runtime>(self: &Arc<Self>, app: &AppHandle<R>) {
        {
            let mut state = self.lock();
            if state.busy.refreshing {
                return;
            }
            state.busy.refreshing = true;
        }
        self.render(app);
        let (tray, app) = (self.clone(), app.clone());
        tauri::async_runtime::spawn(async move {
            tray.refresh(&app).await;
            tray.lock().busy.refreshing = false;
            tray.render(&app);
        });
    }

    /// Installs the helper when it is not installed, asking for the admin
    /// password, then polls it. A helper that is installed is only polled, so
    /// this is both the launch check and "Retry Connection". A cancelled prompt
    /// is reported once and not asked again.
    fn ensure_helper<R: Runtime>(self: &Arc<Self>, app: &AppHandle<R>) {
        let (tray, app) = (self.clone(), app.clone());
        tauri::async_runtime::spawn(async move {
            let installed = match helper_service_status().await {
                Ok(status) => status.installed,
                Err(e) => {
                    log::warn!("could not probe the helper service: {e}");
                    true
                }
            };
            if installed {
                tray.refresh(&app).await;
                return;
            }
            let result = helper_install(app.clone()).await;
            // Another install or uninstall holds the right: it reports for itself.
            if result.as_ref().err().is_some_and(|e| e == IN_PROGRESS) {
                return;
            }
            {
                let mut state = tray.lock();
                state.action_error = result.as_ref().err().map(|e| match e.as_str() {
                    "cancelled" => "Helper install cancelled".to_string(),
                    other => format!("Helper install: {other}"),
                });
            }
            if result.is_ok() {
                tokio::time::sleep(INSTALL_SETTLE).await;
            }
            tray.refresh(&app).await;
        });
    }

    /// Connects or disconnects the profile behind a row. The row reads
    /// "Connecting…" or "Disconnecting…" at once; a failure stays in the menu
    /// until the next attempt.
    fn toggle<R: Runtime>(self: &Arc<Self>, app: &AppHandle<R>, profile_id: &str) {
        let (method, target) = match self.model().action_for(profile_id) {
            RowAction::Connect => ("profiles.connect", true),
            RowAction::Disconnect => ("profiles.disconnect", false),
            RowAction::None => return,
        };
        let name = self
            .lock()
            .observed
            .as_ref()
            .and_then(|o| o.profiles.iter().find(|p| p.id == profile_id))
            .map(|p| p.display_name().to_string())
            .unwrap_or_else(|| profile_id.to_string());
        self.lock().pending.insert(profile_id.to_string(), target);
        self.render(app);

        let (tray, app, id) = (self.clone(), app.clone(), profile_id.to_string());
        tauri::async_runtime::spawn(async move {
            let params = json!({ "id": id });
            let result = tray.client.call(method, Some(&params), ACTION_TIMEOUT).await;
            {
                let mut state = tray.lock();
                state.action_error = result.err().map(|e| {
                    format!("Could not {} {name}: {e}", if target { "connect" } else { "disconnect" })
                });
            }
            // The row keeps its pending text until the list shows the new state.
            let (observed, status) = observe(&tray.client).await;
            tray.record(&app, observed);
            tray.push_status(&app, status);
            tray.lock().pending.remove(&id);
            tray.render(&app);
        });
    }

    /// Disconnects the built-in VPNs, waiting a bounded time, then exits.
    fn quit<R: Runtime>(self: &Arc<Self>, app: &AppHandle<R>) {
        {
            let mut state = self.lock();
            if state.busy.quitting {
                return;
            }
            state.busy.quitting = true;
        }
        self.render(app);
        let (tray, app) = (self.clone(), app.clone());
        tauri::async_runtime::spawn(async move {
            disconnect_once(&tray.transport, QUIT_TIMEOUT).await;
            app.exit(0);
        });
    }
}

/// Adds the tray icon and starts keeping its menu current.
pub fn build_tray<R: Runtime>(app: &AppHandle<R>, transport: Arc<dyn Transport>) -> tauri::Result<()> {
    app.manage(SystemStatsRows::<R>::new());
    app.manage(SystemStatsHistory::default());
    let tray = Arc::new(Tray::new(transport));
    let initial = tray.model();
    let menu = build_menu(app, initial.entries())?;
    let (icon, template) = icon_image(initial.icon)?;

    let for_events = tray.clone();
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .icon_as_template(template)
        .tooltip("RouteWise")
        .menu(&menu)
        .on_menu_event(move |app, event| match action_of(event.id.as_ref()) {
            Some(MenuAction::Tab(tab)) => open_tab(app, tab),
            Some(MenuAction::Refresh) => for_events.refresh_now(app),
            Some(MenuAction::Retry) => for_events.ensure_helper(app),
            Some(MenuAction::Quit) => for_events.quit(app),
            Some(MenuAction::Profile(profile_id)) => for_events.toggle(app, profile_id),
            None => {}
        })
        .build(app)?;
    let shown = tray.model();
    tray.lock().shown = Some(shown);

    // Redraw when an install or uninstall starts or ends, wherever it came from.
    let (watcher, watched_app) = (tray.clone(), app.clone());
    tauri::async_runtime::spawn(async move {
        loop {
            ACTION_CHANGED.notified().await;
            watcher.render(&watched_app);
        }
    });

    start_system_stats(app);

    // Once per launch: install the helper when it is missing.
    tray.ensure_helper(app);

    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let delay = tray.refresh(&app).await;
            tokio::time::sleep(delay).await;
        }
    });
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {


    use super::*;
    use crate::rpc::client::tests::{client_for, ok_reply, serve};

    #[tokio::test]
    async fn observes_status_and_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let _server = serve(&path, |req: Value| match req["method"].as_str() {
            Some("status.get") => Some(ok_reply(&req, json!({"running": true, "vpnConnected": false}))),
            Some("profiles.list") => Some(ok_reply(&req, json!([{"id": "a", "name": "Work", "state": "connecting"}]))),
            other => panic!("unexpected call {other:?}"),
        });
        let (observed, raw) = observe(&client_for(&path)).await;
        assert!(matches!(observed.status, Some(Ok(ref s)) if s.running));
        assert_eq!(observed.profiles.len(), 1);
        assert_eq!(poll_delay(&observed, false), POLL_BUSY);
        assert_eq!(poll_delay(&observed, true), POLL_BUSY);
        assert_eq!(raw, Some(json!({"running": true, "vpnConnected": false})));
    }

    #[tokio::test]
    async fn observing_without_a_helper_lists_nothing_and_polls_idly() {
        let dir = tempfile::tempdir().unwrap();
        let (observed, raw) = observe(&client_for(&dir.path().join("absent.sock"))).await;
        assert!(matches!(observed.status, Some(Err(RpcError::Unavailable { .. }))));
        assert!(observed.profiles.is_empty());
        assert_eq!(poll_delay(&observed, false), POLL_IDLE);
        assert_eq!(poll_delay(&observed, true), POLL_WINDOW_OPEN);
        assert_eq!(raw, None);
    }

    #[tokio::test]
    async fn a_malformed_status_is_a_protocol_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let _server = serve(&path, |req: Value| Some(ok_reply(&req, json!("nope"))));
        let (observed, _) = observe(&client_for(&path)).await;
        assert!(matches!(observed.status, Some(Err(RpcError::Protocol { .. }))));
    }

    #[test]
    fn the_window_hears_only_about_a_change() {
        let mut feed = StatusFeed::default();
        let up = json!({"running": true});
        assert_eq!(feed.next(Some(up.clone())), Some(json!({"status": up})));
        assert_eq!(feed.next(Some(up.clone())), None);
        assert_eq!(feed.next(None), Some(json!({"status": null})));
        assert_eq!(feed.next(None), None);
        assert_eq!(feed.next(Some(up.clone())), Some(json!({"status": up})));
    }
}
