//! Update checks against the project's GitHub releases: the `update_check`
//! command, the hourly background loop that announces a newer release, and
//! opening the release page. Nothing is downloaded or installed.

use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_opener::OpenerExt;

use crate::commands::AppState;
use crate::native_prefs as prefs;
use crate::update_release::{self as release, UpdateInfo};

pub const EVENT_AVAILABLE: &str = "updates://available";
/// The newest successful check, kept for the app's lifetime so a window opened
/// after an automatic check (or reopened) still learns of the finding.
#[derive(Default)]
pub struct LastUpdateResult(Mutex<Option<UpdateInfo>>);

impl LastUpdateResult {
    fn set(&self, info: UpdateInfo) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(info);
    }

    fn get(&self) -> Option<UpdateInfo> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

const TICK: Duration = Duration::from_secs(60 * 60);
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// Fetches the latest release; `None` when the project has none (HTTP 404).
fn fetch_latest() -> Result<Option<release::Release>, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(HTTP_TIMEOUT))
        .http_status_as_error(false)
        .build()
        .into();
    let mut response = agent
        .get(release::RELEASES_API)
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "RouteWise")
        .call()
        .map_err(|e| format!("Could not reach GitHub: {e}"))?;
    match response.status().as_u16() {
        200 => {
            let body = response.body_mut().read_to_string().map_err(|e| format!("Could not read the update response: {e}"))?;
            release::parse_release(&body).map(Some)
        }
        404 => Ok(None),
        code => Err(format!("GitHub answered HTTP {code}")),
    }
}

async fn check(current: String) -> Result<UpdateInfo, String> {
    let latest = tauri::async_runtime::spawn_blocking(fetch_latest).await.map_err(|e| format!("task failed: {e}"))??;
    Ok(match latest {
        Some(r) => release::info_for(&current, r),
        None => release::no_release(&current),
    })
}

/// Checks, then records the time: a failed check counts too, so the next
/// automatic one waits the full interval.
async fn check_and_record(app: &AppHandle) -> Result<UpdateInfo, String> {
    let result = check(app.package_info().version.to_string()).await;
    let now = Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
    if let Err(e) = prefs::write(app.state::<AppState>().client(), prefs::LAST_UPDATE_CHECK, now).await {
        log::warn!("could not record the update check time: {e}");
    }
    match &result {
        Ok(info) => app.state::<LastUpdateResult>().set(info.clone()),
        Err(e) => log::error!("update check failed: {e}"),
    }
    result
}

/// The newest successful check since launch, or `None` before any.
#[tauri::command]
pub fn update_last_result(last: tauri::State<'_, LastUpdateResult>) -> Option<UpdateInfo> {
    last.get()
}

#[tauri::command]
pub async fn update_check(app: AppHandle) -> Result<UpdateInfo, String> {
    check_and_record(&app).await
}

/// Opens a release page of this project in the default browser.
#[tauri::command]
pub fn open_release_page(app: AppHandle, url: String) -> Result<(), String> {
    if !release::is_release_url(&url) {
        return Err("That address is not a RouteWise release page.".to_string());
    }
    app.opener().open_url(url, None::<&str>).map_err(|e| format!("Could not open the browser: {e}"))
}

/// When the last check ran, or `None` when unknown. A helper that cannot be
/// reached yields an error so the loop skips the round rather than check blind.
async fn last_check(app: &AppHandle) -> Result<Option<DateTime<Utc>>, String> {
    let stored = prefs::read_all(app.state::<AppState>().client()).await.map_err(|e| e.to_string())?;
    Ok(stored
        .get(prefs::LAST_UPDATE_CHECK)
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc)))
}

/// Every hour, checks when a day has passed since the last check and tells the
/// webview about a newer release.
pub fn start_background_checks(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match last_check(&app).await {
                Ok(last) if release::is_due(last, Utc::now()) => match check_and_record(&app).await {
                    Ok(info) if info.update_available => {
                        if let Err(e) = app.emit(EVENT_AVAILABLE, info) {
                            log::warn!("emit {EVENT_AVAILABLE} failed: {e}");
                        }
                    }
                    _ => {}
                },
                Ok(_) => {}
                Err(e) => log::debug!("update check skipped: {e}"),
            }
            tokio::time::sleep(TICK).await;
        }
    });
}
