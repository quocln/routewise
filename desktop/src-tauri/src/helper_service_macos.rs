//! The helper on macOS: install and uninstall run one AppleScript that asks for
//! the admin password, like the SwiftUI app; the bundled files come from the
//! app's resource directory.

use std::path::{Path, PathBuf};
use std::process::Command;

use tauri::{AppHandle, Manager, Runtime};

use crate::helper_script::{self as script, HELPER_LABEL, HELPER_PATH};
use crate::helper_service::{HelperServiceStatus, MISSING_RESOURCES};

/// Runs a program to completion, returning its success and combined output.
fn run(program: &str, args: &[&str]) -> Result<(bool, String), String> {
    let out = Command::new(program).args(args).output().map_err(|e| format!("could not run {program}: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

pub fn probe() -> HelperServiceStatus {
    let installed = Path::new(HELPER_PATH).exists();
    // The system domain must be named: plain `launchctl list` shows user services only.
    let running = run("/bin/launchctl", &["print", &format!("system/{HELPER_LABEL}")])
        .is_ok_and(|(ok, out)| ok && script::is_running(&out));
    HelperServiceStatus { installed, running }
}

/// The bundled helper binary and starter config, each of which must exist.
fn bundled_files<R: Runtime>(app: &AppHandle<R>) -> Result<[PathBuf; 2], String> {
    let dir = app.path().resource_dir().map_err(|_| MISSING_RESOURCES.to_string())?.join("helper");
    let files = ["com.routewise.helper", "config.yaml"].map(|n| dir.join(n));
    if files.iter().all(|f| f.is_file()) {
        Ok(files)
    } else {
        Err(MISSING_RESOURCES.to_string())
    }
}

fn utf8(path: &Path) -> Result<&str, String> {
    path.to_str().ok_or_else(|| "The app's location has a name that cannot be used.".to_string())
}

/// Runs an admin-privileged AppleScript, mapping failures to a short message.
fn run_admin(script_text: &str) -> Result<(), String> {
    match run("/usr/bin/osascript", &["-e", script_text])? {
        (true, _) => Ok(()),
        (false, out) => Err(script::failure_message(&out)),
    }
}

pub fn install<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let [helper, config] = bundled_files(app)?;
    run_admin(&script::install_script(utf8(&helper)?, utf8(&config)?))
}

pub fn uninstall<R: Runtime>(_app: &AppHandle<R>) -> Result<(), String> {
    run_admin(&script::uninstall_script())
}
