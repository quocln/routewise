//! The main window. RouteWise lives in the menu bar: the window is created
//! when opened and destroyed when closed, so a closed window costs no webview
//! process, and the app has no Dock icon while it is closed.

use tauri::{AppHandle, Manager, Runtime, WebviewWindowBuilder};

use crate::commands::AppState;
use crate::native_prefs as prefs;

pub const MAIN_WINDOW: &str = "main";

/// Shows the main window, creating it when it is closed. The work runs on its
/// own task: building a window from inside a tray-menu or single-instance
/// handler can deadlock on Windows, so no caller does it inline.
pub fn open_main_window<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move { show_main_window(&app) });
}

/// Runs `then` once the main window is open, on the same task, so work that
/// needs the window (a tab request) never races its creation.
pub fn open_main_window_then<R: Runtime>(app: &AppHandle<R>, then: impl FnOnce(&AppHandle<R>) + Send + 'static) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        show_main_window(&app);
        then(&app);
    });
}

/// Whether the command line says the system started the app at login, in which
/// case there is no window until the user asks for one.
// macOS always shows its menu-bar icon, so its first launch needs no window.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn started_at_login(args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>) -> bool {
    args.into_iter().skip(1).any(|a| a.as_ref() == crate::login_item::AUTOSTART_ARG)
}

fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    set_dock_visible(app, true);
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }
    let Some(config) = app.config().app.windows.iter().find(|w| w.label == MAIN_WINDOW) else {
        log::error!("tauri.conf.json defines no `{MAIN_WINDOW}` window");
        return;
    };
    let built = WebviewWindowBuilder::from_config(app, config).and_then(|b| b.build());
    match built {
        Ok(window) => {
            let _ = window.set_focus();
            apply_saved_keep_on_top(app);
        }
        Err(e) => log::error!("could not open the main window: {e}"),
    }
}

/// With no window the app is an accessory: menu bar only, no Dock icon.
pub fn set_dock_visible<R: Runtime>(app: &AppHandle<R>, visible: bool) {
    #[cfg(target_os = "macos")]
    {
        let policy = if visible {
            tauri::ActivationPolicy::Regular
        } else {
            tauri::ActivationPolicy::Accessory
        };
        if let Err(e) = app.set_activation_policy(policy) {
            log::warn!("could not set the activation policy: {e}");
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (app, visible);
}

/// Whether the window floats above others when the preference is unset.
const KEEP_ON_TOP_DEFAULT: bool = true;

/// Applies the saved `keepWindowOnTop` preference to the new window. It is read
/// from the helper, so it lands a moment after the window appears; an
/// unreachable helper leaves the default.
fn apply_saved_keep_on_top<R: Runtime>(app: &AppHandle<R>) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let wanted = match prefs::read_all(app.state::<AppState>().client()).await {
            Ok(stored) => prefs::bool_or(&stored, prefs::KEEP_WINDOW_ON_TOP, KEEP_ON_TOP_DEFAULT),
            Err(e) => {
                log::debug!("keep-on-top: using the default: {e}");
                KEEP_ON_TOP_DEFAULT
            }
        };
        if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
            if let Err(e) = window.set_always_on_top(wanted) {
                log::warn!("could not set keep on top: {e}");
            }
        }
    });
}

/// Applies the preference to the open main window. With no window there is
/// nothing to do: the next one reads the saved value.
#[tauri::command]
pub fn window_set_keep_on_top<R: Runtime>(app: AppHandle<R>, enabled: bool) -> Result<(), String> {
    match app.get_webview_window(MAIN_WINDOW) {
        Some(window) => window.set_always_on_top(enabled).map_err(|e| format!("could not set keep on top: {e}")),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_autostart_flag_marks_a_launch_at_login() {
        assert!(started_at_login(["routewise-desktop", "--autostart"]));
        assert!(!started_at_login(["routewise-desktop"]));
        // The program name is not a flag.
        assert!(!started_at_login(["--autostart"]));
    }
}
