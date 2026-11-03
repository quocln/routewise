//! Save and open dialogs. The text file pickers do their file I/O here, so the
//! webview needs no file-system permission and never sees those paths. The VPN
//! program picker is the one that returns a path: it is what the helper is asked
//! to identify, and only ever names a program the user just chose.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;

/// The largest file `open_text_file` reads.
const MAX_READ_BYTES: u64 = 1024 * 1024;
const MAX_EXTENSIONS: usize = 8;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct OpenedFile {
    pub name: String,
    pub contents: String,
}

/// Extensions the picker filters on: short, plain, and without a dot.
fn clean_extensions(extensions: &[String]) -> Vec<&str> {
    extensions
        .iter()
        .map(|e| e.trim_start_matches('.'))
        .filter(|e| !e.is_empty() && e.len() <= 16 && e.chars().all(|c| c.is_ascii_alphanumeric()))
        .take(MAX_EXTENSIONS)
        .collect()
}

fn file_name_of(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Reads a UTF-8 text file of at most `max` bytes.
fn read_limited(path: &Path, max: u64) -> Result<OpenedFile, String> {
    let file = File::open(path).map_err(|e| format!("Could not open the file: {}", e.kind()))?;
    // One byte past the limit tells a file that fits from one that does not,
    // without trusting its reported size.
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).map_err(|e| format!("Could not read the file: {}", e.kind()))?;
    if bytes.len() as u64 > max {
        return Err("That file is larger than 1 MiB.".to_string());
    }
    let contents = String::from_utf8(bytes).map_err(|_| "That file is not UTF-8 text.".to_string())?;
    Ok(OpenedFile { name: file_name_of(path), contents })
}

fn pick_path(file: tauri_plugin_dialog::FilePath) -> Result<PathBuf, String> {
    file.into_path().map_err(|_| "That location cannot be used.".to_string())
}

/// Asks where to save `contents` and writes it. Returns the saved file's name,
/// or `None` when the user cancelled.
#[tauri::command]
pub async fn save_text_file(
    app: AppHandle,
    default_name: String,
    contents: String,
    filter_name: String,
    extensions: Vec<String>,
) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let exts = clean_extensions(&extensions);
        let chosen = app
            .dialog()
            .file()
            .set_file_name(file_name_of(Path::new(&default_name)))
            .add_filter(filter_name, &exts)
            .blocking_save_file();
        let Some(chosen) = chosen else { return Ok(None) };
        let path = pick_path(chosen)?;
        fs::write(&path, contents).map_err(|e| format!("Could not save the file: {}", e.kind()))?;
        Ok(Some(file_name_of(&path)))
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

/// Asks for a text file and reads it. `None` when the user cancelled.
#[tauri::command]
pub async fn open_text_file(
    app: AppHandle,
    filter_name: String,
    extensions: Vec<String>,
) -> Result<Option<OpenedFile>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let exts = clean_extensions(&extensions);
        let chosen = app.dialog().file().add_filter(filter_name, &exts).blocking_pick_file();
        let Some(chosen) = chosen else { return Ok(None) };
        read_limited(&pick_path(chosen)?, MAX_READ_BYTES).map(Some)
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

/// Where the program picker opens: where VPN apps are installed.
fn programs_folder() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    return Some(PathBuf::from("/Applications"));
    #[cfg(target_os = "linux")]
    return Some(PathBuf::from("/usr/bin"));
    #[cfg(windows)]
    return std::env::var_os("ProgramFiles").map(PathBuf::from);
}

/// Asks for a VPN app or program. `None` when the user cancelled. macOS treats
/// an app bundle as a file here, so the same picker takes an app or a binary.
#[tauri::command]
pub async fn pick_vpn_program(app: AppHandle) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut dialog = app.dialog().file();
        if let Some(folder) = programs_folder() {
            dialog = dialog.set_directory(folder);
        }
        #[cfg(windows)]
        {
            dialog = dialog.add_filter("Programs", &["exe"]);
        }
        let Some(chosen) = dialog.blocking_pick_file() else { return Ok(None) };
        Ok(Some(pick_path(chosen)?.to_string_lossy().into_owned()))
    })
    .await
    .map_err(|e| format!("task failed: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &tempfile::TempDir, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join("domains.txt");
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn reads_text_within_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let file = read_limited(&write(&dir, "héllo\n".as_bytes()), 100).unwrap();
        assert_eq!(file, OpenedFile { name: "domains.txt".into(), contents: "héllo\n".into() });
    }

    #[test]
    fn a_file_exactly_at_the_limit_is_read_and_one_over_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_limited(&write(&dir, &[b'a'; 10]), 10).is_ok());
        let err = read_limited(&write(&dir, &[b'a'; 11]), 10).unwrap_err();
        assert!(err.contains("1 MiB"));
    }

    #[test]
    fn non_utf8_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_limited(&write(&dir, &[0xff, 0xfe]), 10).unwrap_err().contains("UTF-8"));
    }

    #[test]
    fn a_missing_file_does_not_leak_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_limited(&dir.path().join("nope.txt"), 10).unwrap_err();
        assert!(!err.contains(dir.path().to_str().unwrap()));
    }

    #[test]
    fn extensions_are_cleaned() {
        let exts = ["txt".to_string(), ".json".to_string(), "".to_string(), "a/b".to_string(), "x y".to_string()];
        assert_eq!(clean_extensions(&exts), vec!["txt", "json"]);
    }
}
