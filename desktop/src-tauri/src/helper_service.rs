//! Installing, removing and probing the privileged helper daemon. What runs
//! with admin rights is per platform (an AppleScript prompt on macOS, pkexec
//! on Linux, the UAC prompt on Windows); the single-flight guard and the
//! commands the webview and the tray call are shared.

use std::sync::atomic::{AtomicU8, Ordering};

use serde::Serialize;
use tauri::{AppHandle, Runtime};
use tokio::sync::Notify;

#[cfg(target_os = "linux")]
use crate::helper_service_linux as os;
#[cfg(target_os = "macos")]
use crate::helper_service_macos as os;
#[cfg(windows)]
use crate::helper_service_windows as os;

/// Shown when the app has no bundled helper to install, with the way each
/// platform gets one.
#[cfg(target_os = "macos")]
pub const MISSING_RESOURCES: &str =
    "The helper files are not bundled with this build. Install it with `sudo make install`.";
#[cfg(target_os = "linux")]
pub const MISSING_RESOURCES: &str =
    "The helper files are not bundled with this build. Reinstall the .deb package, or build the app with `make desktop-linux`.";
#[cfg(windows)]
pub const MISSING_RESOURCES: &str =
    "The helper files are not bundled with this build. Reinstall RouteWise with its installer.";

/// The message for an install or uninstall asked for while another runs.
pub const IN_PROGRESS: &str = "already in progress";

/// The message for an admin prompt the user dismissed.
pub const CANCELLED: &str = "cancelled";

const IDLE: u8 = 0;
const INSTALLING: u8 = 1;
const UNINSTALLING: u8 = 2;

/// The privileged action running right now, process-wide: whichever of the
/// window and the tray starts one, a second request is refused until it ends.
static ACTION: AtomicU8 = AtomicU8::new(IDLE);
/// Signalled whenever `ACTION` changes, so the tray can redraw.
pub static ACTION_CHANGED: Notify = Notify::const_new();

/// Holds the right to run a privileged action; released on drop, panics included.
struct ActionGuard;

impl ActionGuard {
    fn acquire(kind: u8) -> Result<Self, String> {
        ACTION.compare_exchange(IDLE, kind, Ordering::AcqRel, Ordering::Acquire).map_err(|_| IN_PROGRESS.to_string())?;
        ACTION_CHANGED.notify_one();
        Ok(Self)
    }
}

impl Drop for ActionGuard {
    fn drop(&mut self) {
        ACTION.store(IDLE, Ordering::Release);
        ACTION_CHANGED.notify_one();
    }
}

/// True while the helper is being installed (by the window or the tray).
pub fn install_in_progress() -> bool {
    ACTION.load(Ordering::Acquire) == INSTALLING
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct HelperServiceStatus {
    pub installed: bool,
    pub running: bool,
}

/// Joins a blocking task, whose panic is an error rather than a crash.
async fn blocking<T: Send + 'static>(job: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(job).await.map_err(|e| format!("task failed: {e}"))?
}

#[tauri::command]
pub async fn helper_service_status() -> Result<HelperServiceStatus, String> {
    blocking(|| Ok(os::probe())).await
}

#[tauri::command]
pub async fn helper_install<R: Runtime>(app: AppHandle<R>) -> Result<(), String> {
    let guard = ActionGuard::acquire(INSTALLING)?;
    blocking(move || {
        let _guard = guard;
        os::install(&app)
    })
    .await
}

#[tauri::command]
pub async fn helper_uninstall<R: Runtime>(app: AppHandle<R>) -> Result<(), String> {
    let guard = ActionGuard::acquire(UNINSTALLING)?;
    blocking(move || {
        let _guard = guard;
        os::uninstall(&app)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_privileged_action_is_refused_until_the_first_ends() {
        // The only test touching the shared flag.
        let first = ActionGuard::acquire(INSTALLING).expect("idle");
        assert!(install_in_progress());
        assert_eq!(ActionGuard::acquire(INSTALLING).err().as_deref(), Some(IN_PROGRESS));
        assert_eq!(ActionGuard::acquire(UNINSTALLING).err().as_deref(), Some(IN_PROGRESS));
        drop(first);
        assert!(!install_in_progress());
        let second = ActionGuard::acquire(UNINSTALLING).expect("released");
        assert!(!install_in_progress());
        drop(second);
    }
}
