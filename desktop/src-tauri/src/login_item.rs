//! Launch at login. macOS uses `SMAppService.mainApp`: the registration lives
//! with the OS, which also shows it in System Settings. Linux writes an XDG autostart entry (`login_item_linux`) and
//! Windows a Run-key value (`login_item_windows`).

#[cfg(target_os = "macos")]
mod os {
    use objc2_service_management::{SMAppService, SMAppServiceStatus};

    pub fn is_enabled() -> Result<bool, String> {
        // SAFETY: plain Objective-C message sends with no arguments.
        let status = unsafe { SMAppService::mainAppService().status() };
        Ok(status == SMAppServiceStatus::Enabled)
    }

    pub fn set_enabled(enabled: bool) -> Result<(), String> {
        // SAFETY: as above; the NSError is only read for its description.
        let result = unsafe {
            let service = SMAppService::mainAppService();
            if enabled {
                service.registerAndReturnError()
            } else {
                service.unregisterAndReturnError()
            }
        };
        result.map_err(|e| e.localizedDescription().to_string())
    }
}

#[cfg(target_os = "linux")]
use crate::login_item_linux as os;

#[cfg(windows)]
use crate::login_item_windows as os;

/// The argument the Linux autostart entry and the Windows Run value pass, so
/// the app can tell a launch at login from one the user made.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub const AUTOSTART_ARG: &str = "--autostart";

#[tauri::command]
pub fn launch_at_login_get() -> Result<bool, String> {
    os::is_enabled()
}

#[tauri::command]
pub fn launch_at_login_set(enabled: bool) -> Result<(), String> {
    os::set_enabled(enabled)
}
