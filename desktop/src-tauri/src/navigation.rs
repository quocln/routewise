//! Asking the main window to show a tab. The window may not exist yet, and a
//! window created for the request has no listener when the request is made, so
//! the requested tab is remembered until the webview reads it
//! (`take_pending_tab`, once at mount) and also emitted as `navigate://tab` for
//! a window that is already open.

use std::sync::{Mutex, MutexGuard};

use serde_json::json;
use tauri::{AppHandle, Emitter, Manager, Runtime, State};

use crate::window::{open_main_window_then, MAIN_WINDOW};

/// The event an open window listens to.
pub const NAVIGATE_EVENT: &str = "navigate://tab";

/// The tabs of the main window, by the names the webview uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Domains,
    Vpn,
    Routes,
    Activity,
    Settings,
}

impl Tab {
    pub fn as_str(self) -> &'static str {
        match self {
            Tab::Domains => "domains",
            Tab::Vpn => "vpn",
            Tab::Routes => "routes",
            Tab::Activity => "activity",
            Tab::Settings => "settings",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        [Tab::Domains, Tab::Vpn, Tab::Routes, Tab::Activity, Tab::Settings].into_iter().find(|t| t.as_str() == name)
    }
}

/// The tab asked for and not yet read by the webview.
#[derive(Default)]
pub struct PendingTab(Mutex<Option<Tab>>);

impl PendingTab {
    fn lock(&self) -> MutexGuard<'_, Option<Tab>> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn set(&self, tab: Tab) {
        *self.lock() = Some(tab);
    }

    pub fn take(&self) -> Option<Tab> {
        self.lock().take()
    }
}

/// Shows the main window on `tab`, creating the window when it is closed.
pub fn open_tab<R: Runtime>(app: &AppHandle<R>, tab: Tab) {
    // Remembered before the window opens, so a webview that mounts after the
    // emit below still finds it.
    app.state::<PendingTab>().set(tab);
    open_main_window_then(app, move |app| {
        if let Err(e) = app.emit_to(MAIN_WINDOW, NAVIGATE_EVENT, json!({ "tab": tab.as_str() })) {
            log::debug!("could not send the tab request: {e}");
        }
    });
}

/// The tab asked for since the webview last looked, if any.
#[tauri::command]
pub fn take_pending_tab(pending: State<'_, PendingTab>) -> Option<&'static str> {
    pending.take().map(Tab::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_names_round_trip_and_unknown_names_are_refused() {
        for name in ["domains", "vpn", "routes", "activity", "settings"] {
            assert_eq!(Tab::parse(name).map(Tab::as_str), Some(name));
        }
        assert_eq!(Tab::parse("Domains"), None);
        assert_eq!(Tab::parse(""), None);
    }

    #[test]
    fn a_remembered_tab_is_read_once_and_the_latest_wins() {
        let pending = PendingTab::default();
        assert_eq!(pending.take(), None);
        pending.set(Tab::Vpn);
        pending.set(Tab::Settings);
        assert_eq!(pending.take(), Some(Tab::Settings));
        assert_eq!(pending.take(), None);
    }
}
