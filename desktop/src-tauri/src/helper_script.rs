//! The pure parts of installing the privileged helper: shell and AppleScript
//! quoting, the install and uninstall scripts, and reading `launchctl` and
//! `osascript` output. Nothing here touches the system, so it is all tested.

use crate::helper_service::CANCELLED;

pub const HELPER_LABEL: &str = "com.routewise.helper";
pub const HELPER_PATH: &str = "/Library/PrivilegedHelperTools/com.routewise.helper";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.routewise.helper.plist";
const CONFIG_DIR: &str = "/Library/Application Support/RouteWise";
const CONFIG_PATH: &str = "/Library/Application Support/RouteWise/config.yaml";
const CONFIG_DB_PATH: &str = "/Library/Application Support/RouteWise/routewise.db";

/// osascript's error number for "User canceled".
const USER_CANCELLED_CODE: &str = "(-128)";
/// Quoted in the script, so the plist text is never expanded by the shell.
const PLIST_DELIMITER: &str = "ROUTEWISE_PLIST_END";
const MAX_MESSAGE_CHARS: usize = 300;

/// Quotes `s` as one POSIX shell word: single quotes, with each embedded
/// single quote closed, escaped and reopened.
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Quotes `s` as the body of an AppleScript string literal. Only backslash
/// and double quote are special inside one.
pub fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Wraps a shell script as an AppleScript that runs it as root.
fn as_admin_script(shell: &str) -> String {
    format!("do shell script \"{}\" with administrator privileges", applescript_escape(shell))
}

/// The launch daemon definition.
/// It is written by the root script itself rather than copied from the app
/// bundle, which the user can write to.
fn launchd_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{HELPER_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{HELPER_PATH}</string>
        <string>start</string>
        <string>--foreground</string>
        <string>--config</string>
        <string>{CONFIG_PATH}</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/var/log/routewise.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/routewise.log</string>
</dict>
</plist>
"#
    )
}

/// Shell lines that stop the script unless `path` is a regular file and not a
/// symlink (which `cp` would follow to read any file root can).
fn require_plain_file(path: &str) -> String {
    let p = sh_quote(path);
    let message = sh_quote(&format!("refusing to install: {path} is not a regular file"));
    format!("if [ ! -f {p} ] || [ -L {p} ]; then echo {message} >&2; exit 1; fi\n")
}

/// The privileged install. The service is stopped first, the new helper is
/// copied beside the old one and moved over it (a running binary is replaced,
/// never rewritten), and the bundled config is copied only when the helper has
/// no config yet (its database, or the YAML it imports on first start), so the
/// user's saved domains survive a reinstall.
pub fn install_script(helper: &str, config: &str) -> String {
    let (helper_src, config_src) = (sh_quote(helper), sh_quote(config));
    let (helper_dst, plist_dst) = (sh_quote(HELPER_PATH), sh_quote(PLIST_PATH));
    let (helper_new, plist_new) = (sh_quote(&format!("{HELPER_PATH}.new")), sh_quote(&format!("{PLIST_PATH}.new")));
    let (config_dir, config_dst, config_db) =
        (sh_quote(CONFIG_DIR), sh_quote(CONFIG_PATH), sh_quote(CONFIG_DB_PATH));
    let checks = format!("{}{}", require_plain_file(helper), require_plain_file(config));
    let plist = launchd_plist();
    let shell = format!(
        "set -e\n\
         {checks}\
         launchctl unload {plist_dst} 2>/dev/null || true\n\
         mkdir -p /Library/PrivilegedHelperTools\n\
         mkdir -p {config_dir}\n\
         rm -f {helper_new}\n\
         cp {helper_src} {helper_new}\n\
         chmod 755 {helper_new}\n\
         chown root:wheel {helper_new}\n\
         mv -f {helper_new} {helper_dst}\n\
         rm -f {plist_new}\n\
         cat > {plist_new} <<'{PLIST_DELIMITER}'\n\
         {plist}\
         {PLIST_DELIMITER}\n\
         chmod 644 {plist_new}\n\
         chown root:wheel {plist_new}\n\
         mv -f {plist_new} {plist_dst}\n\
         if [ ! -f {config_db} ] && [ ! -f {config_dst} ]; then\n\
         cp {config_src} {config_dst}\n\
         chmod 644 {config_dst}\n\
         chown root:staff {config_dst}\n\
         fi\n\
         launchctl load {plist_dst}\n"
    );
    as_admin_script(&shell)
}

/// The privileged uninstall: stops the service, removes resolver files the app
/// wrote, then the helper and its plist. The config stays.
pub fn uninstall_script() -> String {
    let (helper, plist) = (sh_quote(HELPER_PATH), sh_quote(PLIST_PATH));
    let shell = format!(
        "launchctl unload {plist} 2>/dev/null || true\n\
         for f in /etc/resolver/*; do [ -f \"$f\" ] && head -n 1 \"$f\" | grep -q '^# Managed by RouteWise' && rm -f \"$f\"; done; true\n\
         rm -f {helper}\n\
         rm -f {plist}\n"
    );
    as_admin_script(&shell)
}

/// True when `launchctl print` output shows a running process (`pid = <n>`).
pub fn is_running(launchctl_print: &str) -> bool {
    launchctl_print.match_indices("pid").any(|(at, _)| {
        let before = launchctl_print[..at].chars().next_back();
        if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
            return false;
        }
        let rest = launchctl_print[at + 3..].trim_start();
        rest.strip_prefix('=')
            .is_some_and(|r| r.trim_start().chars().next().is_some_and(|c| c.is_ascii_digit()))
    })
}

/// The message to show for a failed osascript run: `cancelled` for a dismissed
/// prompt, otherwise its first line of output, cut short.
pub fn failure_message(output: &str) -> String {
    if output.contains(USER_CANCELLED_CODE) {
        return CANCELLED.to_string();
    }
    let line = output.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("osascript did not run");
    line.chars().take(MAX_MESSAGE_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_quotes_are_closed_and_reopened() {
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
        assert_eq!(sh_quote("$(rm -rf /); `x`"), "'$(rm -rf /); `x`'");
    }

    #[test]
    fn applescript_escapes_quotes_and_backslashes() {
        assert_eq!(applescript_escape(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    /// Undoes `applescript_escape`, as AppleScript does when it reads the literal.
    fn applescript_unescape(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            out.push(if c == '\\' { chars.next().expect("dangling backslash") } else { c });
        }
        out
    }

    #[test]
    fn hostile_paths_stay_inside_their_quotes() {
        let hostile = "/Apps/Evil\"; do shell script \"rm -rf ~\" -- '$(x)'\\/helper";
        let script = install_script(hostile, "/c");
        let literal = script
            .strip_prefix("do shell script \"")
            .and_then(|s| s.strip_suffix("\" with administrator privileges"))
            .expect("script shape");
        // No bare double quote can end the AppleScript string early.
        assert!(!literal.replace("\\\\", "").replace("\\\"", "").contains('"'));
        let shell = applescript_unescape(literal);
        assert!(shell.contains(&format!("cp {} ", sh_quote(hostile))));
        assert!(shell.contains(&format!("[ ! -f {} ] || [ -L {} ]", sh_quote(hostile), sh_quote(hostile))));
    }

    #[test]
    fn install_copies_config_only_when_absent() {
        let script = install_script("/h", "/c");
        assert!(script.contains("if [ ! -f '/Library/Application Support/RouteWise/routewise.db' ]"));
        assert!(script.contains("launchctl load '/Library/LaunchDaemons/com.routewise.helper.plist'"));
        assert!(script.ends_with("with administrator privileges"));
    }

    /// The shell text inside an install script, as AppleScript hands it over.
    fn shell_of(script: &str) -> String {
        let literal = script
            .strip_prefix("do shell script \"")
            .and_then(|s| s.strip_suffix("\" with administrator privileges"))
            .expect("script shape");
        applescript_unescape(literal)
    }

    #[test]
    fn install_refuses_symlinks_and_non_files_for_every_bundled_source() {
        let shell = shell_of(&install_script("/h", "/c"));
        for src in ["/h", "/c"] {
            assert!(shell.contains(&format!("if [ ! -f '{src}' ] || [ -L '{src}' ]; then echo")), "{src}");
        }
        assert!(shell.contains("is not a regular file"));
        // The checks run before anything is changed.
        assert!(shell.find("-L '/c'").unwrap() < shell.find("launchctl unload").unwrap());
    }

    #[test]
    fn install_stops_the_service_then_swaps_the_helper_in_by_rename() {
        let shell = shell_of(&install_script("/h", "/c"));
        let at = |needle: &str| shell.find(needle).unwrap_or_else(|| panic!("missing {needle}"));
        let unload = at("launchctl unload");
        let copy = at("cp '/h' '/Library/PrivilegedHelperTools/com.routewise.helper.new'");
        let swap = at("mv -f '/Library/PrivilegedHelperTools/com.routewise.helper.new' '/Library/PrivilegedHelperTools/com.routewise.helper'");
        let load = at("launchctl load");
        assert!(unload < copy && copy < swap && swap < load);
        assert!(!shell.contains("cp '/h' '/Library/PrivilegedHelperTools/com.routewise.helper'\n"));
    }

    #[test]
    fn the_plist_is_written_by_the_script_from_a_quoted_heredoc() {
        let shell = shell_of(&install_script("/h", "/c"));
        assert!(shell.contains("<<'ROUTEWISE_PLIST_END'\n<?xml"));
        assert!(shell.contains(&format!("\n</plist>\n{PLIST_DELIMITER}\n")));
        assert!(!shell.contains("cp '/p"));
        assert_eq!(shell.matches(PLIST_DELIMITER).count(), 2);
    }

    #[test]
    fn the_generated_plist_keeps_the_helper_running_from_its_installed_path() {
        let plist = launchd_plist();
        assert!(plist.contains(&format!("<key>Label</key>\n    <string>{HELPER_LABEL}</string>")));
        assert!(plist.contains(&format!("<string>{HELPER_PATH}</string>\n        <string>start</string>\n        <string>--foreground</string>")));
        assert!(plist.contains(&format!("<string>--config</string>\n        <string>{CONFIG_PATH}</string>")));
        assert!(plist.contains("<key>RunAtLoad</key>\n    <true/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
    }

    #[test]
    fn uninstall_removes_helper_and_plist() {
        let script = uninstall_script();
        assert!(script.contains("rm -f '/Library/PrivilegedHelperTools/com.routewise.helper'"));
        assert!(script.contains("# Managed by RouteWise"));
    }

    #[test]
    fn running_needs_a_numeric_pid() {
        assert!(is_running("system/com.routewise.helper = {\n\tstate = running\n\tpid = 412\n}"));
        assert!(is_running("pid=7"));
        assert!(!is_running("state = waiting\n\tlast exit code = 0"));
        assert!(!is_running("ppid = 1\n"));
        assert!(!is_running("pid = none"));
        assert!(!is_running(""));
    }

    #[test]
    fn cancelled_prompt_maps_to_cancelled() {
        assert_eq!(failure_message("execution error: User canceled. (-128)"), CANCELLED);
    }

    #[test]
    fn other_failures_keep_their_first_line_cut_short() {
        assert_eq!(failure_message("\n  cp: no such file\nmore"), "cp: no such file");
        assert_eq!(failure_message("  "), "osascript did not run");
        assert_eq!(failure_message(&"x".repeat(1000)).len(), MAX_MESSAGE_CHARS);
    }
}
