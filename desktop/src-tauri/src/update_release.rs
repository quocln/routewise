//! What an update check reports: the GitHub release JSON, the version
//! comparison, the answer for the webview, and which URLs it may open.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Where the releases live. The only host and path the app opens for updates.
pub const RELEASES_API: &str = "https://api.github.com/repos/quocln/routewise/releases/latest";
const RELEASE_HOST: &str = "github.com";
/// The path segments every openable page starts with.
const RELEASE_REPO: [&str; 2] = ["quocln", "routewise"];
/// Time between automatic checks.
pub const CHECK_INTERVAL_HOURS: i64 = 24;

/// The fields of a GitHub release that the app uses.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Release {
    pub tag_name: String,
    pub html_url: String,
    pub published_at: Option<String>,
    pub body: Option<String>,
}

/// The shape the webview receives (`UpdateInfo` in the native contract).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub release_url: Option<String>,
    pub published_at: Option<String>,
    pub notes: Option<String>,
}

pub fn parse_release(json: &str) -> Result<Release, String> {
    serde_json::from_str(json).map_err(|e| format!("Unexpected update response: {e}"))
}

/// A tag's version: `v1.2.0` is `1.2.0`.
fn version_of(tag: &str) -> &str {
    tag.strip_prefix('v').unwrap_or(tag)
}

/// The first three numeric components, zero-padded; non-numeric ones are dropped.
fn components(version: &str) -> [u64; 3] {
    let mut out = [0; 3];
    for (slot, n) in out.iter_mut().zip(version.split('.').filter_map(|p| p.parse::<u64>().ok())) {
        *slot = n;
    }
    out
}

/// True when `current` is older than `target`, comparing `x.y.z`.
pub fn is_outdated(current: &str, target: &str) -> bool {
    components(version_of(current)) < components(version_of(target))
}

/// The answer when GitHub has no release yet.
pub fn no_release(current: &str) -> UpdateInfo {
    UpdateInfo {
        current_version: current.to_string(),
        latest_version: None,
        update_available: false,
        release_url: None,
        published_at: None,
        notes: None,
    }
}

pub fn info_for(current: &str, release: Release) -> UpdateInfo {
    let latest = version_of(&release.tag_name).to_string();
    UpdateInfo {
        current_version: current.to_string(),
        update_available: is_outdated(current, &latest),
        latest_version: Some(latest),
        release_url: Some(release.html_url),
        published_at: release.published_at,
        notes: release.body.filter(|b| !b.trim().is_empty()),
    }
}

/// True when `url` is a page of this project's GitHub repository: https, the
/// host exactly, no userinfo or port, the repository's path, and no dot
/// segments (plain or percent-encoded) that a browser would resolve elsewhere.
pub fn is_release_url(url: &str) -> bool {
    if url.chars().any(|c| c.is_control() || c.is_whitespace() || c == '\\') {
        return false;
    }
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let Some(path_at) = rest.find('/') else { return false };
    let (authority, tail) = rest.split_at(path_at);
    if authority != RELEASE_HOST {
        return false;
    }
    let path = tail.split(['?', '#']).next().unwrap_or_default();
    let mut segments = path.split('/').skip(1);
    if !RELEASE_REPO.iter().all(|want| segments.next() == Some(want)) {
        return false;
    }
    // The repository's own name must be followed by a slash: `/routewise` alone is not a page.
    if path.matches('/').count() < 3 {
        return false;
    }
    !path.split('/').any(is_dot_segment)
}

/// `.` or `..`, written plainly or with percent-encoded dots.
fn is_dot_segment(segment: &str) -> bool {
    let plain = segment.replace("%2e", ".").replace("%2E", ".");
    plain == "." || plain == ".."
}

/// Whether an automatic check is due: never checked, or a full interval ago.
pub fn is_due(last_check: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    match last_check {
        None => true,
        // A time in the future (a clock that was ahead) never blocks checks.
        Some(at) => at > now || now - at >= Duration::hours(CHECK_INTERVAL_HOURS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE: &str = r#"{"id":1,"tag_name":"v1.2.0","html_url":"https://github.com/quocln/routewise/releases/tag/v1.2.0",
        "published_at":"2026-10-01T10:00:00Z","body":"Fixes","draft":false}"#;

    #[test]
    fn compares_versions_numerically() {
        assert!(is_outdated("1.0.0", "1.0.1"));
        assert!(is_outdated("0.9.9", "v1.0"));
        assert!(is_outdated("1.9", "1.10.0"));
        assert!(!is_outdated("1.0.0", "1.0.0"));
        assert!(!is_outdated("2.0.0", "1.9.9"));
        assert!(!is_outdated("1.0.0", "garbage"));
        assert!(!is_outdated("1.0", "1.0.0"));
    }

    #[test]
    fn a_newer_release_is_available() {
        let info = info_for("1.0.0", parse_release(RELEASE).unwrap());
        assert_eq!(info.latest_version.as_deref(), Some("1.2.0"));
        assert!(info.update_available);
        assert_eq!(info.notes.as_deref(), Some("Fixes"));
        assert!(info.release_url.as_deref().is_some_and(is_release_url));
    }

    #[test]
    fn the_current_release_is_not_an_update() {
        let info = info_for("1.2.0", parse_release(RELEASE).unwrap());
        assert!(!info.update_available);
        assert_eq!(info.latest_version.as_deref(), Some("1.2.0"));
    }

    #[test]
    fn missing_optional_fields_are_none() {
        let release = parse_release(r#"{"tag_name":"v2","html_url":"https://github.com/quocln/routewise/x","body":" "}"#).unwrap();
        let info = info_for("1.0.0", release);
        assert_eq!((info.published_at, info.notes), (None, None));
    }

    #[test]
    fn bad_json_is_an_error() {
        assert!(parse_release("{}").is_err());
        assert!(parse_release("<html>").is_err());
    }

    #[test]
    fn no_release_serializes_with_nulls_in_camel_case() {
        let json = serde_json::to_value(no_release("1.0.0")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"currentVersion":"1.0.0","latestVersion":null,"updateAvailable":false,
                "releaseUrl":null,"publishedAt":null,"notes":null})
        );
    }

    #[test]
    fn only_project_urls_are_openable() {
        assert!(is_release_url("https://github.com/quocln/routewise/releases/tag/v1"));
        assert!(is_release_url("https://github.com/quocln/routewise/releases?page=2#top"));
        for bad in [
            "http://github.com/quocln/routewise/",
            "https://github.com/quocln/routewise",
            "https://github.com/quocln/routewise-evil/",
            "https://github.com.evil.com/quocln/routewise/",
            "https://evil.com/https://github.com/quocln/routewise/",
            "file:///etc/passwd",
            "https://github.com/quocln/routewise/ x",
            "https://github.com/quocln/routewise/\n",
            "https://github.com/quocln/routewise/../../attacker/phish",
            "https://github.com/quocln/routewise/releases/../../../attacker/x",
            "https://github.com/quocln/routewise/%2e%2e/%2E%2e/attacker/x",
            "https://github.com/quocln/routewise/./x/%2e",
            "https://github.com/quocln/../attacker/routewise/x",
            "https://user@github.com/quocln/routewise/x",
            "https://github.com@evil.com/quocln/routewise/x",
            "https://github.com:8443/quocln/routewise/x",
            "https://GITHUB.com/quocln/routewise/x",
            "https://github.com?/quocln/routewise/x",
            "https://github.com/Vochinh/routewise/x",
            "",
        ] {
            assert!(!is_release_url(bad), "{bad:?}");
        }
    }

    #[test]
    fn checks_are_due_after_a_day() {
        let now = Utc::now();
        assert!(is_due(None, now));
        assert!(!is_due(Some(now - Duration::hours(23)), now));
        assert!(is_due(Some(now - Duration::hours(24)), now));
    }

    #[test]
    fn a_check_time_in_the_future_is_due() {
        let now = Utc::now();
        assert!(is_due(Some(now + Duration::days(30)), now));
    }
}
