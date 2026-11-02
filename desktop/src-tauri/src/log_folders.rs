//! Reveals the newest app or helper log in the file manager (Finder on macOS),
//! or opens the folder when there is no log yet.

use std::path::{Path, PathBuf};

use crate::app_log;
use crate::app_log_files;

/// Where the helper writes its daily logs: `routewise-YYYY-MM-DD.log` files
/// straight in `/var/log` on macOS, in their own folder on Linux and under
/// `%ProgramData%` on Windows.
#[cfg(target_os = "macos")]
const HELPER_LOG_DIR: &str = "/var/log";
#[cfg(target_os = "linux")]
const HELPER_LOG_DIR: &str = "/var/log/routewise";

/// `%ProgramData%\RouteWise\logs`, where the helper's service writes.
#[cfg(any(windows, test))]
fn windows_helper_log_dir(program_data: Option<std::ffi::OsString>) -> PathBuf {
    let base = program_data.map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("RouteWise").join("logs")
}

fn helper_log_dir() -> PathBuf {
    #[cfg(windows)]
    return windows_helper_log_dir(std::env::var_os("ProgramData"));
    #[cfg(not(windows))]
    PathBuf::from(HELPER_LOG_DIR)
}

/// The helper's newest daily log, `routewise-YYYY-MM-DD.log`; the date sorts like the day.
fn newest_helper_log(names: &[String]) -> Option<&str> {
    names.iter().map(String::as_str).filter(|n| n.starts_with("routewise-") && n.ends_with(".log")).max()
}

type Newest = fn(&[String]) -> Option<&str>;

fn reveal(dir: &Path, newest: Newest) -> Result<(), String> {
    let names: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().filter_map(|e| e.file_name().into_string().ok()).collect())
        .unwrap_or_default();
    show(dir, newest(&names).map(|name| dir.join(name)))
}

/// Selects `file` in Finder, or opens `dir` when there is no file.
#[cfg(target_os = "macos")]
fn show(dir: &Path, file: Option<PathBuf>) -> Result<(), String> {
    let mut command = std::process::Command::new("/usr/bin/open");
    match file {
        // `open -R` selects the file in Finder.
        Some(file) => command.arg("-R").arg(file),
        None => command.arg(dir),
    };
    command.status().map_err(|e| format!("could not open Finder: {e}")).and_then(|s| {
        if s.success() {
            Ok(())
        } else {
            Err("Finder could not open the log folder.".to_string())
        }
    })
}

/// Selects `file` in the file manager (Explorer on Windows), or opens `dir`
/// when there is no file or the file manager does not answer the reveal
/// request (on Linux it needs D-Bus).
#[cfg(not(target_os = "macos"))]
fn show(dir: &Path, file: Option<PathBuf>) -> Result<(), String> {
    if let Some(file) = file {
        match tauri_plugin_opener::reveal_item_in_dir(&file) {
            Ok(()) => return Ok(()),
            Err(e) => log::debug!("could not reveal {}: {e}", file.display()),
        }
    }
    tauri_plugin_opener::open_path(dir, None::<&str>).map_err(|e| format!("could not open the log folder: {e}"))
}

/// Opens the log folder for `which` (`app` or `helper`).
#[tauri::command]
pub async fn open_log_folder(which: String) -> Result<(), String> {
    let (dir, newest): (PathBuf, Newest) = match which.as_str() {
        "app" => {
            let dir = app_log::log_dir().ok_or("The log folder is unknown.")?;
            // Finder cannot open a folder that does not exist yet.
            std::fs::create_dir_all(&dir).map_err(|e| format!("could not create the log folder: {e}"))?;
            (dir, app_log_files::newest)
        }
        "helper" => (helper_log_dir(), newest_helper_log),
        _ => return Err("unknown log folder".to_string()),
    };
    tauri::async_runtime::spawn_blocking(move || reveal(&dir, newest))
        .await
        .map_err(|e| format!("task failed: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::{newest_helper_log, windows_helper_log_dir};

    #[test]
    fn picks_the_latest_helper_log() {
        let names = ["routewise.log", "routewise-2026-10-28.log", "routewise-2026-10-29.log", "system.log"]
            .map(String::from);
        assert_eq!(newest_helper_log(&names), Some("routewise-2026-10-29.log"));
        assert_eq!(newest_helper_log(&["system.log".to_string()]), None);
    }

    #[test]
    fn the_windows_helper_logs_sit_under_program_data() {
        let base = if cfg!(windows) { r"D:\Data" } else { "/data" };
        let expected = std::path::PathBuf::from(base).join("RouteWise").join("logs");
        assert_eq!(windows_helper_log_dir(Some(base.into())), expected);
        // An unset or relative variable falls back to the standard folder.
        let fallback = std::path::PathBuf::from(r"C:\ProgramData").join("RouteWise").join("logs");
        assert_eq!(windows_helper_log_dir(None), fallback);
        assert_eq!(windows_helper_log_dir(Some("relative".into())), fallback);
    }
}
