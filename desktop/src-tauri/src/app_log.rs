//! The app log: every `log` record and every line other modules write goes to
//! stderr (env_logger filtering) and to one file per local day in
//! `~/Library/Logs/RouteWise` (macOS), `~/.local/state/RouteWise/logs`
//! (Linux) or `%LOCALAPPDATA%\RouteWise\logs` (Windows), one line per message:
//! `ISO8601 time  LEVEL  category  message`. Never pass secrets.

#[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Local, NaiveDate};
use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::app_log_files as files;

/// The default filter: quiet dependencies, this crate at info. `RUST_LOG` overrides.
const DEFAULT_FILTER: &str = "warn,routewise_desktop_lib=info";

/// Owner-only: the log names the user's VPN clients. (On Windows the file
/// inherits the access list of the user's own profile folder.)
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

static GLOBAL: OnceLock<AppLog> = OnceLock::new();

/// Appends lines to the day's file, opening the next one after midnight.
pub struct AppLog {
    dir: PathBuf,
    open: Mutex<Option<(NaiveDate, File)>>,
}

/// `~/Library/Logs/RouteWise`.
#[cfg(any(target_os = "macos", test))]
fn macos_log_dir(home: Option<OsString>) -> Option<PathBuf> {
    home.map(|h| PathBuf::from(h).join("Library/Logs/RouteWise"))
}

/// `$XDG_STATE_HOME/RouteWise/logs`, else `~/.local/state/RouteWise/logs`. A
/// relative `XDG_STATE_HOME` is not a location and is ignored, as the spec says.
#[cfg(any(target_os = "linux", test))]
fn linux_log_dir(state_home: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let absolute = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
    absolute(state_home)
        .or_else(|| absolute(home).map(|h| h.join(".local/state")))
        .map(|s| s.join("RouteWise/logs"))
}

/// `%LOCALAPPDATA%\RouteWise\logs`. A relative value is not a location.
#[cfg(any(windows, test))]
fn windows_log_dir(local_app_data: Option<OsString>) -> Option<PathBuf> {
    local_app_data.map(PathBuf::from).filter(|p| p.is_absolute()).map(|d| d.join("RouteWise").join("logs"))
}

/// The folder of the daily app logs, where the platform keeps user logs.
pub fn log_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    return macos_log_dir(std::env::var_os("HOME"));
    #[cfg(target_os = "linux")]
    return linux_log_dir(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"));
    #[cfg(windows)]
    return windows_log_dir(std::env::var_os("LOCALAPPDATA"));
}

/// A log line must stay one line.
fn single_line(message: &str) -> String {
    message.replace(['\r', '\n'], " ")
}

fn format_line(at: DateTime<Local>, level: Level, category: &str, message: &str) -> String {
    format!("{}  {level}  {category}  {}\n", at.format("%Y-%m-%dT%H:%M:%S%:z"), single_line(message))
}

impl AppLog {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, open: Mutex::new(None) }
    }

    fn open_day(&self, day: NaiveDate) -> std::io::Result<File> {
        fs::create_dir_all(&self.dir)?;
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, FILE_MODE);
        options.open(self.dir.join(files::file_name(day)))
    }

    /// Appends one line stamped `at`, into the file of its local day.
    pub fn write_at(&self, at: DateTime<Local>, level: Level, category: &str, message: &str) -> std::io::Result<()> {
        let day = at.date_naive();
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        if open.as_ref().map(|(d, _)| *d) != Some(day) {
            *open = Some((day, self.open_day(day)?));
        }
        let Some((_, file)) = open.as_mut() else { return Ok(()) };
        let result = file.write_all(format_line(at, level, category, message).as_bytes());
        if result.is_err() {
            // Reopen on the next line rather than keep writing to a dead descriptor.
            *open = None;
        }
        result
    }

    /// Deletes dated files older than the retention window.
    pub fn prune(&self, today: NaiveDate) {
        let Ok(entries) = fs::read_dir(&self.dir) else { return };
        let names: Vec<String> = entries.flatten().filter_map(|e| e.file_name().into_string().ok()).collect();
        for name in files::expired(names.iter().map(String::as_str), today, files::RETENTION_DAYS) {
            if let Err(e) = fs::remove_file(self.dir.join(name)) {
                log::warn!("could not delete old log {name}: {e}");
            }
        }
    }
}

/// Writes a line to the app log file; `category` is a short word such as
/// `ui`, `rpc`, `connection` or `update`. A failure to write is reported once
/// to stderr and otherwise ignored: logging must never break the caller.
pub fn write(level: Level, category: &str, message: &str) {
    let Some(log) = GLOBAL.get() else { return };
    if let Err(e) = log.write_at(Local::now(), level, category, message) {
        eprintln!("could not write the app log: {e}");
    }
}

/// The log category for a module path.
fn category_for(target: &str) -> &'static str {
    if target.contains("rpc") {
        "rpc"
    } else if target.contains("update") {
        "update"
    } else if target.contains("tray") || target.contains("helper") || target.contains("quit") {
        "connection"
    } else {
        "ui"
    }
}

/// Sends records to stderr through env_logger and, when this crate's filter
/// lets them in, to the app log file.
struct Tee {
    stderr: env_logger::Logger,
}

impl Log for Tee {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.stderr.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        self.stderr.log(record);
        write(record.level(), category_for(record.target()), &record.args().to_string());
    }

    fn flush(&self) {
        self.stderr.flush();
    }
}

/// Opens the app log, prunes old files, and returns the app's logger (stderr
/// and the app log file) with its level, for the caller to install. Call once
/// at startup.
pub fn init() -> (impl Log + 'static, LevelFilter) {
    let stderr = env_logger::Builder::new().parse_filters(DEFAULT_FILTER).parse_default_env().build();
    let max: LevelFilter = stderr.filter();
    if let Some(dir) = log_dir() {
        let log = AppLog::new(dir);
        log.prune(Local::now().date_naive());
        let _ = GLOBAL.set(log);
    }
    (Tee { stderr }, max)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(d: u32, h: u32) -> DateTime<Local> {
        Local.with_ymd_and_hms(2026, 10, d, h, 30, 0).single().unwrap()
    }

    #[test]
    fn lines_land_in_the_file_of_their_day() {
        let dir = tempfile::tempdir().unwrap();
        let log = AppLog::new(dir.path().join("logs"));
        log.write_at(at(28, 23), Level::Warn, "ui", "late").unwrap();
        log.write_at(at(29, 0), Level::Error, "rpc", "after\nmidnight").unwrap();
        let first = fs::read_to_string(dir.path().join("logs/app-2026-10-28.log")).unwrap();
        let second = fs::read_to_string(dir.path().join("logs/app-2026-10-29.log")).unwrap();
        assert!(first.ends_with("  WARN  ui  late\n"), "{first}");
        assert!(second.ends_with("  ERROR  rpc  after midnight\n"), "{second}");
    }

    #[test]
    fn appends_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        AppLog::new(dir.path().to_path_buf()).write_at(at(29, 1), Level::Info, "ui", "one").unwrap();
        AppLog::new(dir.path().to_path_buf()).write_at(at(29, 2), Level::Info, "ui", "two").unwrap();
        let text = fs::read_to_string(dir.path().join("app-2026-10-29.log")).unwrap();
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn prune_removes_only_expired_log_files() {
        let dir = tempfile::tempdir().unwrap();
        for n in ["app-2026-10-01.log", "app-2026-10-20.log", "other.txt"] {
            fs::write(dir.path().join(n), "x").unwrap();
        }
        AppLog::new(dir.path().to_path_buf()).prune(NaiveDate::from_ymd_opt(2026, 10, 29).unwrap());
        assert!(!dir.path().join("app-2026-10-01.log").exists());
        assert!(dir.path().join("app-2026-10-20.log").exists());
        assert!(dir.path().join("other.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        AppLog::new(dir.path().to_path_buf()).write_at(at(29, 1), Level::Info, "ui", "x").unwrap();
        let mode = fs::metadata(dir.path().join("app-2026-10-29.log")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn each_platform_keeps_its_logs_in_its_own_place() {
        let os = |s: &str| Some(OsString::from(s));
        assert_eq!(macos_log_dir(os("/Users/u")), Some("/Users/u/Library/Logs/RouteWise".into()));
        assert_eq!(macos_log_dir(None), None);
        // XDG paths must be absolute, and Windows does not call "/state" that.
        if cfg!(unix) {
            assert_eq!(linux_log_dir(os("/state"), os("/home/u")), Some("/state/RouteWise/logs".into()));
            assert_eq!(linux_log_dir(None, os("/home/u")), Some("/home/u/.local/state/RouteWise/logs".into()));
            assert_eq!(linux_log_dir(os("state"), os("/home/u")), Some("/home/u/.local/state/RouteWise/logs".into()));
            assert_eq!(linux_log_dir(None, None), None);
        }
        let local = if cfg!(windows) { r"C:\Users\u\AppData\Local" } else { "/local" };
        assert_eq!(windows_log_dir(os(local)), Some(PathBuf::from(local).join("RouteWise").join("logs")));
        assert_eq!(windows_log_dir(os("relative")), None);
        assert_eq!(windows_log_dir(None), None);
    }

    #[test]
    fn modules_map_to_categories() {
        assert_eq!(category_for("routewise_desktop_lib::rpc::client"), "rpc");
        assert_eq!(category_for("routewise_desktop_lib::updates"), "update");
        assert_eq!(category_for("routewise_desktop_lib::tray"), "connection");
        assert_eq!(category_for("tao::platform"), "ui");
    }
}
