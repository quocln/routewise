//! The helper on Windows: it installs itself as the `RouteWise` service
//! (`routewise.exe service install|uninstall`), so the app only runs the
//! bundled executable elevated through the UAC prompt and reads the service
//! control manager to see the result. Compiled on every host under test so the
//! pure parts are covered wherever the tests run.
#![cfg_attr(not(windows), allow(dead_code))]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tauri::{AppHandle, Manager, Runtime};

use crate::helper_service::{HelperServiceStatus, CANCELLED, MISSING_RESOURCES};

/// The service the helper registers.
const SERVICE_NAME: &str = "RouteWise";
/// `ShellExecuteExW` fails with this when the user dismisses the UAC prompt.
const ERROR_CANCELLED: u32 = 1223;
/// Win32 `ERROR_SERVICE_DOES_NOT_EXIST`.
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
/// Installing waits for the service to reach Running, which takes seconds.
#[cfg(windows)]
const INSTALL_TIMEOUT_MS: u32 = 180_000;

/// The folder name the helper installs itself into, under Program Files.
const INSTALLED_HELPER: &str = r"RouteWise\routewise.exe";

/// What the user sees for an elevated run that failed. The elevated process
/// has no console to report to, so the way to see its output is to run it by hand.
fn failure_message(helper: &Path, action: &str, code: u32) -> String {
    format!(
        "the helper installer exited with status {code}; run \"{}\" service {action} from an administrator prompt to see why",
        helper.display()
    )
}

/// The message for a `ShellExecuteExW` that did not start the process:
/// `cancelled` when the UAC prompt was dismissed.
fn launch_failure_message(error: u32) -> String {
    if error == ERROR_CANCELLED {
        CANCELLED.to_string()
    } else {
        format!("could not start the helper installer (Windows error {error})")
    }
}

/// A path as Win32 shell calls want it: Tauri may hand back the `\\?\` form,
/// which `ShellExecuteExW` does not accept. A `\\?\UNC\` share path is kept.
fn plain_path(path: &Path) -> PathBuf {
    match path.to_str() {
        Some(s) if s.starts_with(r"\\?\") && !s.starts_with(r"\\?\UNC\") => PathBuf::from(&s[4..]),
        _ => path.to_path_buf(),
    }
}

/// Where `service install` puts the helper: `<Program Files>\RouteWise`. The
/// 64-bit folder is preferred, as the helper (a native process) asks Windows
/// for its own Program Files.
fn installed_helper(program_w6432: Option<OsString>, program_files: Option<OsString>) -> Option<PathBuf> {
    let absolute = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
    absolute(program_w6432).or_else(|| absolute(program_files)).map(|p| p.join(INSTALLED_HELPER))
}

/// The bundled helper executable, which must exist.
fn bundled_helper<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    let dir = app.path().resource_dir().map_err(|_| MISSING_RESOURCES.to_string())?;
    let helper = plain_path(&dir.join("helper").join("routewise.exe"));
    if helper.is_file() {
        Ok(helper)
    } else {
        Err(MISSING_RESOURCES.to_string())
    }
}

pub fn install<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    run_service(&bundled_helper(app)?, "install")
}

/// The bundled helper removes the installed one: an installed helper cannot
/// delete the executable it is running from. The installed copy (writable only
/// by administrators) stands in when the bundle is not there.
pub fn uninstall<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let helper = match bundled_helper(app) {
        Ok(helper) => helper,
        Err(missing) => installed_helper(std::env::var_os("ProgramW6432"), std::env::var_os("ProgramFiles"))
            .filter(|p| p.is_file())
            .ok_or(missing)?,
    };
    run_service(&helper, "uninstall")
}

#[cfg(windows)]
pub use win32::probe;

/// Runs `helper service <action>` elevated and waits for it.
#[cfg(windows)]
fn run_service(helper: &Path, action: &str) -> Result<(), String> {
    match win32::run_elevated(helper, &format!("service {action}"), INSTALL_TIMEOUT_MS)? {
        0 => Ok(()),
        code => Err(failure_message(helper, action, code)),
    }
}

#[cfg(not(windows))]
fn run_service(helper: &Path, action: &str) -> Result<(), String> {
    Err(failure_message(helper, action, 1))
}

/// Without Windows there is no service to look at.
#[cfg(not(windows))]
pub fn probe() -> HelperServiceStatus {
    HelperServiceStatus { installed: false, running: false }
}

#[cfg(windows)]
mod win32 {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::{mem, ptr, thread};

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_CONNECT,
        SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
    };
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    use super::{launch_failure_message, HelperServiceStatus, ERROR_SERVICE_DOES_NOT_EXIST, SERVICE_NAME};
    use crate::helper_service::IN_PROGRESS;

    /// Set while an elevated helper process is running, which can outlast the
    /// wait for it: a second one must not start beside it.
    static ELEVATED_RUNNING: AtomicBool = AtomicBool::new(false);

    /// Holds `ELEVATED_RUNNING`; released on drop.
    struct ElevatedSlot;

    impl ElevatedSlot {
        fn take() -> Option<Self> {
            ELEVATED_RUNNING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).ok().map(|_| Self)
        }
    }

    impl Drop for ElevatedSlot {
        fn drop(&mut self) {
            ELEVATED_RUNNING.store(false, Ordering::Release);
        }
    }

    /// Apartment-threaded COM on the calling thread until dropped, which
    /// `ShellExecuteExW` asks of its caller.
    struct ComApartment(bool);

    impl ComApartment {
        fn enter() -> Self {
            // SAFETY: a null reserved pointer is required. A negative result
            // (the thread already has another model) leaves COM as it was and
            // is not undone.
            let hr = unsafe { CoInitializeEx(ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32) };
            Self(hr >= 0)
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: balances the successful CoInitializeEx on this thread.
                unsafe { CoUninitialize() };
            }
        }
    }

    fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
        s.as_ref().encode_wide().chain(Some(0)).collect()
    }

    /// A service control manager or service handle, closed on drop.
    struct ScHandle(SC_HANDLE);

    impl Drop for ScHandle {
        fn drop(&mut self) {
            // SAFETY: the handle came from OpenSCManagerW/OpenServiceW and is closed once.
            unsafe { CloseServiceHandle(self.0) };
        }
    }

    /// Whether the service exists and is running. Both questions need no
    /// administrator rights.
    pub fn probe() -> super::HelperServiceStatus {
        let none = HelperServiceStatus { installed: false, running: false };
        // SAFETY: null machine and database names mean the local active database.
        let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
        if scm.is_null() {
            log::warn!("could not open the service control manager (Windows error {})", unsafe { GetLastError() });
            return none;
        }
        let scm = ScHandle(scm);
        let name = wide(SERVICE_NAME);
        // SAFETY: `name` is nul-terminated and `scm` is open.
        let service = unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
        if service.is_null() {
            let error = unsafe { GetLastError() };
            if error != ERROR_SERVICE_DOES_NOT_EXIST {
                log::warn!("could not open the {SERVICE_NAME} service (Windows error {error})");
            }
            return none;
        }
        let service = ScHandle(service);
        // SAFETY: SERVICE_STATUS is plain data the call fills in.
        let mut status: SERVICE_STATUS = unsafe { mem::zeroed() };
        let queried = unsafe { QueryServiceStatus(service.0, &mut status) } != 0;
        HelperServiceStatus { installed: true, running: queried && status.dwCurrentState == SERVICE_RUNNING }
    }

    /// Runs `file parameters` through the `runas` verb (the UAC prompt), hidden,
    /// and waits up to `timeout_ms` for it. Returns its exit code. A process
    /// still running after the wait is reported as an error but keeps the slot
    /// until it exits, so a retry cannot overlap it.
    pub fn run_elevated(file: &Path, parameters: &str, timeout_ms: u32) -> Result<u32, String> {
        let slot = ElevatedSlot::take().ok_or_else(|| IN_PROGRESS.to_string())?;
        let verb = wide("runas");
        let file = wide(file);
        let parameters = wide(parameters);
        // SAFETY: an all-zero SHELLEXECUTEINFOW is valid (null pointers, zero flags).
        let mut info: SHELLEXECUTEINFOW = unsafe { mem::zeroed() };
        info.cbSize = mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        // NOASYNC: this thread has no message loop to finish the launch for it.
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = parameters.as_ptr();
        info.nShow = SW_HIDE;
        let launched = {
            let _com = ComApartment::enter();
            // SAFETY: the strings outlive the call; `info` is initialised above.
            unsafe { ShellExecuteExW(&mut info) != 0 }
        };
        if !launched {
            return Err(launch_failure_message(unsafe { GetLastError() }));
        }
        let process: HANDLE = info.hProcess;
        if process.is_null() {
            return Err("the helper installer did not start a process".to_string());
        }
        // SAFETY: `process` is a process handle ShellExecuteExW left open for us.
        if unsafe { WaitForSingleObject(process, timeout_ms) } != WAIT_OBJECT_0 {
            // The installer is still running: a watcher owns the handle and the
            // slot until it exits.
            let process = process as usize;
            let watcher = thread::Builder::new().name("helper-install-watch".into()).spawn(move || {
                // SAFETY: the handle is closed once, after the process ended.
                unsafe {
                    WaitForSingleObject(process as HANDLE, INFINITE);
                    CloseHandle(process as HANDLE);
                }
                drop(slot);
            });
            if let Err(e) = watcher {
                log::warn!("could not watch the running helper installer: {e}");
            }
            return Err("the helper installer is still running; wait for it to finish before trying again".to_string());
        }
        let mut code = 0u32;
        // SAFETY: the process ended; the handle is read once and closed once.
        let result = unsafe {
            if GetExitCodeProcess(process, &mut code) == 0 {
                Err(format!("could not read the helper installer's result (Windows error {})", GetLastError()))
            } else {
                Ok(code)
            }
        };
        unsafe { CloseHandle(process) };
        drop(slot);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<OsString> {
        Some(s.into())
    }

    #[test]
    fn a_dismissed_uac_prompt_is_cancelled() {
        assert_eq!(launch_failure_message(1223), "cancelled");
        assert!(launch_failure_message(5).contains("Windows error 5"));
    }

    #[test]
    fn a_failed_run_says_how_to_see_why() {
        let text = failure_message(Path::new(r"C:\Program Files\RouteWise\helper\routewise.exe"), "install", 1);
        assert!(text.contains("status 1"));
        assert!(text.contains(r#""C:\Program Files\RouteWise\helper\routewise.exe" service install"#));
    }

    #[test]
    fn the_verbatim_prefix_is_dropped_except_for_shares() {
        assert_eq!(plain_path(Path::new(r"\\?\C:\App\helper\routewise.exe")), Path::new(r"C:\App\helper\routewise.exe"));
        assert_eq!(plain_path(Path::new(r"C:\App\routewise.exe")), Path::new(r"C:\App\routewise.exe"));
        assert_eq!(plain_path(Path::new(r"\\?\UNC\host\share\x")), Path::new(r"\\?\UNC\host\share\x"));
    }

    #[test]
    fn the_installed_helper_is_under_the_native_program_files() {
        let (native, x86) = if cfg!(windows) { (r"C:\pf64", r"C:\pf86") } else { ("/pf64", "/pf86") };
        let path = installed_helper(os(native), os(x86)).unwrap();
        assert_eq!(path, PathBuf::from(native).join(INSTALLED_HELPER));
        let path = installed_helper(None, os(x86)).unwrap();
        assert_eq!(path, PathBuf::from(x86).join(INSTALLED_HELPER));
        assert_eq!(installed_helper(os("relative"), None), None);
        assert_eq!(installed_helper(None, None), None);
    }
}
