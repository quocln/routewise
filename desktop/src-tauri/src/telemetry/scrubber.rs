//! Replaces everything that could identify the user's traffic or setup with
//! `[redacted]`: IPv4 and IPv6 addresses (with or without a CIDR suffix),
//! domain names (wildcards included), the user's folder name in a path, and
//! every name the app knows about (domain list entries, profile names and
//! servers, VPN client names).
//!
//! One regular expression does all of it in a single left-to-right pass, so a
//! replacement is never scanned again: a known name such as "red" cannot match
//! inside an earlier `[redacted]`. Immutable once built, so it is safe to share
//! between threads.

use std::collections::BTreeSet;

use fancy_regex::{escape, Regex};
use serde_json::Value;

pub const PLACEHOLDER: &str = "[redacted]";

/// Names shorter than this are not matched literally. A one or two letter
/// profile name would shred every word that contains it.
const MINIMUM_NAME_LENGTH: usize = 3;

/// File extensions that look like a top-level domain: `main.rs`, `Info.plist`,
/// `routewise.db`. A dotted name ending in one is not a host.
const FILE_EXTENSIONS: &[&str] = &[
    "swift", "m", "h", "mm", "c", "cpp", "plist", "db", "log", "yaml", "yml", "json", "txt", "md",
    "sock", "conf", "pid", "lock", "dylib", "png", "framework", "xcframework", "entitlements",
    "strings", "swiftmodule", "swiftdoc", "xcassets", "o", "a", "d", "tmp", "bundle", "rs",
    "toml", "rlib", "js", "mjs", "cjs", "ts", "tsx", "jsx", "css", "html", "map",
];

/// Dotted names that are the app's own, not a user's host.
const SAFE_NAMES: &[&str] = &["routewise.app"];

/// Prefixes of reverse-DNS identifiers (bundle ids, log subsystems, queue labels).
const SAFE_PREFIXES: &[&str] = &["com.routewise.", "com.apple.", "org.swift."];

// IPv6: the full eight-group form, or a compressed form containing "::".
// Plain times such as 12:30:45 have neither, so they are left alone.
const IPV6: &str = r"(?<![\w:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{0,4}::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{0,4})(?:/\d{1,3})?(?![\w:])";
const IPV4: &str = r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w])";
// Labels, then a top-level label that is all lower or all upper case, so
// `ClientError.rpcError` is not a host.
const DOMAIN: &str = r"(?<![\w.\-])(?:\*\.)?(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+(?:(?-i:[a-z]{2,24}|[A-Z]{2,24}))(?![\w\-])";
// The name after `/Users/`, `/home/` or Windows' `C:\Users\` (either slash, and
// the doubled backslashes of a path inside JSON text). A Windows profile folder
// may contain spaces ("John Smith"), so after a backslash the name runs to the
// next separator or quote rather than the next space.
const USER_FOLDER: &str = r#"(?<=\\Users\\|\\\\Users\\\\)[^\\/"'\r\n]+|(?<=/Users/|/home/)[^\\/\s"']+"#;

pub struct PrivacyScrubber {
    /// None only when no pattern could be built: everything is then redacted.
    regex: Option<Regex>,
}

impl Default for PrivacyScrubber {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl PrivacyScrubber {
    /// `known_names` are redacted wherever they appear, whole-word and
    /// case-insensitively. Duplicates and short names are dropped.
    pub fn new(known_names: &[String]) -> Self {
        let unique: BTreeSet<&str> = known_names
            .iter()
            .map(|n| n.trim())
            .filter(|n| n.chars().count() >= MINIMUM_NAME_LENGTH)
            .collect();
        // Longest first, so "work vpn" wins over "work".
        let mut names: Vec<&str> = unique.into_iter().collect();
        names.sort_by_key(|n| std::cmp::Reverse(n.chars().count()));

        Self { regex: Self::build(&names).or_else(|| Self::build(&[])) }
    }

    fn build(names: &[&str]) -> Option<Regex> {
        let mut alternatives: Vec<String> = Vec::new();
        if !names.is_empty() {
            let escaped: Vec<String> = names.iter().map(|n| escape(n).into_owned()).collect();
            // Group 1 marks a known-name match, which is always redacted.
            alternatives.push(format!(
                r"(?<![\p{{L}}\p{{N}}_])({})(?![\p{{L}}\p{{N}}_])",
                escaped.join("|")
            ));
        }
        alternatives.extend([IPV6, IPV4, DOMAIN, USER_FOLDER].map(String::from));
        Regex::new(&format!("(?i){}", alternatives.join("|"))).ok()
    }

    /// `text` with everything sensitive replaced.
    pub fn scrub(&self, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        let Some(regex) = &self.regex else { return PLACEHOLDER.to_string() };
        let mut result = String::with_capacity(text.len());
        let mut cursor = 0;
        for caps in regex.captures_iter(text) {
            // A search that blew its backtracking budget cannot be trusted to
            // have found everything: redact the whole text.
            let Ok(caps) = caps else { return PLACEHOLDER.to_string() };
            let Some(whole) = caps.get(0) else { continue };
            result.push_str(&text[cursor..whole.start()]);
            let is_known_name = caps.get(1).is_some();
            if !is_known_name && is_kept(whole.as_str()) {
                result.push_str(whole.as_str());
            } else {
                result.push_str(PLACEHOLDER);
            }
            cursor = whole.end();
        }
        result.push_str(&text[cursor..]);
        result
    }

    /// Scrubs every string inside a JSON value. Object keys are scrubbed too:
    /// a key can be a domain.
    pub fn scrub_value(&self, value: Value) -> Value {
        match value {
            Value::String(s) => Value::String(self.scrub(&s)),
            Value::Array(items) => Value::Array(items.into_iter().map(|v| self.scrub_value(v)).collect()),
            Value::Object(map) => Value::Object(map.into_iter().map(|(k, v)| (self.scrub(&k), self.scrub_value(v))).collect()),
            other => other,
        }
    }
}

/// Dotted matches that are code or the app's own identifiers, not hosts. A
/// known name or an address is never kept.
fn is_kept(matched: &str) -> bool {
    let lower = matched.to_lowercase();
    if !lower.contains('.') || lower.contains(':') || lower.contains('/') {
        return false;
    }
    if SAFE_NAMES.contains(&lower.as_str()) || SAFE_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return true;
    }
    lower.rsplit('.').next().is_some_and(|last| FILE_EXTENSIONS.contains(&last))
}
