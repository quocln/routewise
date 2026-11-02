use serde_json::json;

use super::scrubber::{PrivacyScrubber, PLACEHOLDER as R};

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn redacts_addresses_and_hosts() {
    let scrubber = PrivacyScrubber::default();
    let cases = [
        ("dial 10.1.2.3 failed", format!("dial {R} failed")),
        ("route 192.168.0.0/16 added", format!("route {R} added")),
        ("peer 2001:db8::1 down", format!("peer {R} down")),
        ("peer fe80::1/64 down", format!("peer {R} down")),
        ("loopback ::1", format!("loopback {R}")),
        ("resolve example.com failed", format!("resolve {R} failed")),
        ("rule *.example.com added", format!("rule {R} added")),
        ("GET https://api.corp.example.org/v1/x", format!("GET https://{R}/v1/x")),
        ("host Example.COM", format!("host {R}")),
        ("server vpn.corp.example.net:51820", format!("server {R}:51820")),
        ("/Users/kevin/Library/Logs", format!("/Users/{R}/Library/Logs")),
        ("/home/kevin/.local/state/RouteWise", format!("/home/{R}/.local/state/RouteWise")),
        (r"C:\Users\kevin\AppData\Local\RouteWise\logs", format!(r"C:\Users\{R}\AppData\Local\RouteWise\logs")),
        (r"C:\Users\John Smith\AppData\Local", format!(r"C:\Users\{R}\AppData\Local")),
        (r"c:\users\Kevin\x", format!(r"c:\users\{R}\x")),
        ("D:/USERS/kevin/Desktop", format!("D:/USERS/{R}/Desktop")),
        (r#"{"path":"C:\\Users\\kevin\\x"}"#, format!(r#"{{"path":"C:\\Users\\{R}\\x"}}"#)),
    ];
    for (input, expected) in cases {
        assert_eq!(scrubber.scrub(input), expected, "{input}");
    }
}

#[test]
fn keeps_code_and_app_identifiers() {
    let scrubber = PrivacyScrubber::default();
    let untouched = [
        "Foo.swift:42", "Info.plist", "routewise.db", "app-2026-10-28.log", "com.routewise.app",
        "com.routewise.helper", "com.apple.security", "RouteWise.app", "ClientError.rpcError",
        "version 9.31.0", "at 12:30:45", "Foo::bar", "plain words only",
        // Rust and webview code paths in stack traces.
        "src/rpc/client.rs:42", "chunks/main-1a2b.js:1:2",
    ];
    for text in untouched {
        assert_eq!(scrubber.scrub(text), text);
    }
}

#[test]
fn redacts_known_names_whole_word_and_case_insensitively() {
    let scrubber = PrivacyScrubber::new(&names(&["Work VPN", "Acme", "wg.internal", "ab"]));
    assert_eq!(scrubber.scrub("connect Work VPN now"), format!("connect {R} now"));
    assert_eq!(scrubber.scrub("profile acme failed"), format!("profile {R} failed"));
    assert_eq!(scrubber.scrub("Acmeville stays"), "Acmeville stays");
    assert_eq!(scrubber.scrub("server wg.internal"), format!("server {R}"));
    // Too short to match literally.
    assert_eq!(scrubber.scrub("ab and cab"), "ab and cab");
}

#[test]
fn known_name_that_looks_like_a_file_is_still_redacted() {
    let scrubber = PrivacyScrubber::new(&names(&["notes.txt"]));
    assert_eq!(scrubber.scrub("open notes.txt"), format!("open {R}"));
}

#[test]
fn replacement_is_not_rescanned() {
    let scrubber = PrivacyScrubber::new(&names(&["red", "acted", "example.com"]));
    assert_eq!(scrubber.scrub("example.com and red"), format!("{R} and {R}"));
}

#[test]
fn longest_known_name_wins() {
    let scrubber = PrivacyScrubber::new(&names(&["work", "work vpn"]));
    assert_eq!(scrubber.scrub("on work vpn"), format!("on {R}"));
}

#[test]
fn names_with_regex_metacharacters_match_literally() {
    let scrubber = PrivacyScrubber::new(&names(&["a+b(c)", "x|y|z"]));
    assert_eq!(scrubber.scrub("a+b(c) and x|y|z but not xyz"), format!("{R} and {R} but not xyz"));
}

#[test]
fn scrubs_nested_values() {
    let scrubber = PrivacyScrubber::new(&names(&["Acme"]));
    let scrubbed = scrubber.scrub_value(json!({
        "host": "a.example.com",
        "list": ["10.0.0.1", "Acme", 3],
        "inner": {"k": "ok", "example.org": true}
    }));
    assert_eq!(scrubbed["host"], R);
    assert_eq!(scrubbed["list"][0], R);
    assert_eq!(scrubbed["list"][1], R);
    assert_eq!(scrubbed["list"][2], 3);
    assert_eq!(scrubbed["inner"]["k"], "ok");
    assert_eq!(scrubbed["inner"][R], true);
}

#[test]
fn empty_text_stays_empty() {
    assert_eq!(PrivacyScrubber::default().scrub(""), "");
}

#[test]
fn long_text_is_scrubbed_end_to_end() {
    let text = format!("{} then vpn.example.net", "word ".repeat(20_000));
    let out = PrivacyScrubber::default().scrub(&text);
    assert!(out.ends_with(&format!("then {R}")), "{}", &out[out.len() - 30..]);
}
