//! Naming, selecting and expiring the app's daily log files
//! (`app-YYYY-MM-DD.log`), as plain functions over names and dates.

use chrono::{Duration, NaiveDate};

const PREFIX: &str = "app-";
const EXTENSION: &str = ".log";
/// Days of logs kept, today included.
pub const RETENTION_DAYS: i64 = 14;

/// `app-2026-10-28.log` for a local day.
pub fn file_name(day: NaiveDate) -> String {
    format!("{PREFIX}{}{EXTENSION}", day.format("%Y-%m-%d"))
}

/// The day a file name stands for, or `None` for a file that is not one of ours.
pub fn day_of(name: &str) -> Option<NaiveDate> {
    let stem = name.strip_prefix(PREFIX)?.strip_suffix(EXTENSION)?;
    // Exactly YYYY-MM-DD: chrono alone would also take `2026-1-2`.
    let shaped = stem.len() == 10 && stem.bytes().enumerate().all(|(i, b)| matches!(i, 4 | 7) == (b == b'-'));
    if shaped {
        NaiveDate::parse_from_str(stem, "%Y-%m-%d").ok()
    } else {
        None
    }
}

/// The newest of our log files among `names`; the date sorts like the day.
pub fn newest(names: &[String]) -> Option<&str> {
    names.iter().map(String::as_str).filter(|n| day_of(n).is_some()).max()
}

/// The files older than the retention window as of `today`. Names that are not
/// ours are never returned.
pub fn expired<'a>(names: impl IntoIterator<Item = &'a str>, today: NaiveDate, retention_days: i64) -> Vec<&'a str> {
    let cutoff = today - Duration::days(retention_days.max(1) - 1);
    names.into_iter().filter(|n| day_of(n).is_some_and(|d| d < cutoff)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    #[test]
    fn names_round_trip() {
        assert_eq!(file_name(day(2026, 1, 5)), "app-2026-01-05.log");
        assert_eq!(day_of("app-2026-01-05.log"), Some(day(2026, 1, 5)));
    }

    #[test]
    fn foreign_names_have_no_day() {
        for n in ["routewise-2026-01-05.log", "app-2026-1-5.log", "app-2026-13-01.log", "app-2026-01-05.txt", "app-.log", ""] {
            assert_eq!(day_of(n), None, "{n}");
        }
    }

    #[test]
    fn newest_ignores_foreign_files() {
        let names = ["app-2026-01-05.log", "notes.txt", "app-2026-02-01.log", "zzz.log"].map(String::from);
        assert_eq!(newest(&names), Some("app-2026-02-01.log"));
        assert_eq!(newest(&["notes.txt".to_string()]), None);
    }

    #[test]
    fn expiry_keeps_the_window_and_foreign_files() {
        let names = ["app-2026-10-15.log", "app-2026-10-16.log", "app-2026-10-29.log", "keep.txt", "app-bad.log"];
        // 14 days with today: Oct 16 is the oldest kept.
        assert_eq!(expired(names, day(2026, 10, 29), 14), vec!["app-2026-10-15.log"]);
        assert!(expired(names, day(2026, 10, 29), 0).len() >= 2, "retention is at least one day");
    }
}
