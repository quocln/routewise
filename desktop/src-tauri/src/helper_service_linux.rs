//! The helper on Linux: the helper installs itself as a systemd service
//! (`routewise service install|uninstall`), so the app only runs the bundled
//! binary as root through pkexec. Compiled on every host under test so the
//! pure parts are covered wherever the tests run.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use tauri::{AppHandle, Manager, Runtime};

use crate::helper_service::{HelperServiceStatus, CANCELLED, MISSING_RESOURCES};

const UNIT_NAME: &str = "routewise.service";
/// Written by `service install`; its presence is what "installed" means.
const UNIT_PATH: &str = "/etc/systemd/system/routewise.service";
/// Where `service install` puts the helper: root-owned, so uninstall prefers it.
const INSTALLED_BINARY: &str = "/usr/lib/routewise/routewise";

/// pkexec's exit status for an authentication dialog the user dismissed.
const PKEXEC_DISMISSED: i32 = 126;
/// pkexec's exit status for authorization that was refused or could not be asked.
const PKEXEC_NOT_AUTHORIZED: i32 = 127;
const NOT_AUTHORIZED: &str =
    "Not authorized to change the helper. Approve the administrator prompt, and check that a polkit agent is running.";
const MAX_MESSAGE_CHARS: usize = 300;

pub fn probe() -> HelperServiceStatus {
    let installed = Path::new(UNIT_PATH).exists();
    let running = Command::new("systemctl")
        .args(["is-active", "--quiet", UNIT_NAME])
        .status()
        .is_ok_and(|s| s.success());
    HelperServiceStatus { installed, running }
}

/// The message to show for a failed pkexec run: `cancelled` for a dismissed
/// dialog, a plain refusal for 127, otherwise the first line of the output.
fn failure_message(code: Option<i32>, output: &str) -> String {
    match code {
        Some(PKEXEC_DISMISSED) => CANCELLED.to_string(),
        Some(PKEXEC_NOT_AUTHORIZED) => NOT_AUTHORIZED.to_string(),
        _ => match output.lines().map(str::trim).find(|l| !l.is_empty()) {
            Some(line) => line.chars().take(MAX_MESSAGE_CHARS).collect(),
            None => match code {
                Some(code) => format!("the helper installer exited with status {code}"),
                None => "the helper installer was stopped".to_string(),
            },
        },
    }
}

/// Runs `pkexec <helper> service <action>` and waits for it.
fn run_service(helper: &Path, action: &str) -> Result<(), String> {
    let out = Command::new("pkexec")
        .arg(helper)
        .args(["service", action])
        .output()
        .map_err(|e| format!("could not run pkexec: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let mut text = String::from_utf8_lossy(&out.stderr).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stdout));
    Err(failure_message(out.status.code(), &text))
}

/// Where a private copy of the helper goes: the user's runtime directory, else
/// their cache directory.
fn private_base(runtime_dir: Option<OsString>, cache_home: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let absolute = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
    absolute(runtime_dir)
        .or_else(|| absolute(cache_home))
        .or_else(|| absolute(home).map(|h| h.join(".cache")))
}

/// The helper copied to a directory only the user can enter, removed on drop.
/// An AppImage is mounted through FUSE for its owner alone, so root cannot
/// read the bundled binary in place.
struct PrivateCopy {
    dir: PathBuf,
    helper: PathBuf,
}

impl PrivateCopy {
    fn new(source: &Path, base: &Path) -> io::Result<Self> {
        fs::create_dir_all(base)?;
        let dir = base.join(format!("routewise-helper-{}", std::process::id()));
        // A leftover from a crashed run of this process id.
        let _ = fs::remove_dir_all(&dir);
        DirBuilder::new().mode(0o700).create(&dir)?;
        let copy = Self { helper: dir.join("routewise"), dir };
        // From here a failure drops `copy`, which removes the directory.
        let mut from = File::open(source)?;
        let mut to = OpenOptions::new().write(true).create_new(true).mode(0o700).open(&copy.helper)?;
        io::copy(&mut from, &mut to)?;
        to.sync_all()?;
        Ok(copy)
    }
}

impl Drop for PrivateCopy {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The bundled helper binary, which must exist.
fn bundled_helper<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    let helper = app.path().resource_dir().map_err(|_| MISSING_RESOURCES.to_string())?.join("helper/routewise");
    if helper.is_file() {
        Ok(helper)
    } else {
        Err(MISSING_RESOURCES.to_string())
    }
}

/// Runs the bundled helper's `service <action>` as root. From an AppImage the
/// binary is copied out of the mount first.
fn run_bundled<R: Runtime>(app: &AppHandle<R>, action: &str) -> Result<(), String> {
    let helper = bundled_helper(app)?;
    if std::env::var_os("APPIMAGE").is_none() {
        return run_service(&helper, action);
    }
    let base = private_base(
        std::env::var_os("XDG_RUNTIME_DIR"),
        std::env::var_os("XDG_CACHE_HOME"),
        std::env::var_os("HOME"),
    )
    .ok_or("There is no folder to stage the helper in.")?;
    let copy = PrivateCopy::new(&helper, &base).map_err(|e| format!("could not stage the helper: {e}"))?;
    run_service(&copy.helper, action)
}

pub fn install<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    run_bundled(app, "install")
}

/// The installed helper removes itself when it can: it is root-owned and
/// matches the running service.
pub fn uninstall<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let installed = Path::new(INSTALLED_BINARY);
    if installed.is_file() {
        run_service(installed, "uninstall")
    } else {
        run_bundled(app, "uninstall")
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn a_dismissed_dialog_is_cancelled() {
        assert_eq!(failure_message(Some(126), "Error executing command as another user: Not authorized"), CANCELLED);
    }

    #[test]
    fn a_refusal_says_so_plainly() {
        assert_eq!(failure_message(Some(127), "Error executing command as another user: No authentication agent"), NOT_AUTHORIZED);
    }

    #[test]
    fn other_failures_keep_their_first_line_cut_short() {
        assert_eq!(failure_message(Some(1), "\n  systemctl: failed\nmore"), "systemctl: failed");
        assert_eq!(failure_message(Some(2), ""), "the helper installer exited with status 2");
        assert_eq!(failure_message(None, " "), "the helper installer was stopped");
        assert_eq!(failure_message(Some(1), &"x".repeat(1000)).len(), MAX_MESSAGE_CHARS);
    }

    fn os(s: &str) -> Option<OsString> {
        Some(s.into())
    }

    #[test]
    fn the_private_copy_lives_in_the_runtime_dir_then_the_cache_dir() {
        assert_eq!(private_base(os("/run/user/1000"), os("/c"), os("/home/u")), Some("/run/user/1000".into()));
        assert_eq!(private_base(None, os("/c"), os("/home/u")), Some("/c".into()));
        assert_eq!(private_base(None, None, os("/home/u")), Some("/home/u/.cache".into()));
        // A relative value is not a location.
        assert_eq!(private_base(os("run"), os("rel"), os("home")), None);
        assert_eq!(private_base(None, None, None), None);
    }

    #[test]
    fn the_private_copy_is_owner_only_and_removed_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("bundled");
        fs::write(&source, b"binary").unwrap();
        let base = tmp.path().join("run/user");
        let copy = PrivateCopy::new(&source, &base).unwrap();
        let (dir, helper) = (copy.dir.clone(), copy.helper.clone());
        assert_eq!(fs::read(&helper).unwrap(), b"binary");
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&helper).unwrap().permissions().mode() & 0o777, 0o700);
        drop(copy);
        assert!(!dir.exists());
    }

    #[test]
    fn a_missing_source_leaves_no_directory_behind() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(PrivateCopy::new(&tmp.path().join("absent"), tmp.path()).is_err());
        let leftovers: Vec<_> = fs::read_dir(tmp.path()).unwrap().flatten().collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }
}
