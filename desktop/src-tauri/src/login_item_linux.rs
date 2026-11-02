//! Launch at login on Linux through an XDG autostart entry,
//! `~/.config/autostart/routewise.desktop`: the desktop session starts every
//! entry in that folder. Compiled on every host under test so the entry text
//! and paths are covered wherever the tests run.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const ENTRY_NAME: &str = "routewise.desktop";

/// `$XDG_CONFIG_HOME/autostart`, else `~/.config/autostart`. A relative
/// `XDG_CONFIG_HOME` is not a location and is ignored, as the spec says.
fn autostart_dir(config_home: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let absolute = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
    absolute(config_home).or_else(|| absolute(home).map(|h| h.join(".config"))).map(|c| c.join("autostart"))
}

fn entry_path() -> Result<PathBuf, String> {
    autostart_dir(std::env::var_os("XDG_CONFIG_HOME"), std::env::var_os("HOME"))
        .map(|dir| dir.join(ENTRY_NAME))
        .ok_or_else(|| "The autostart folder is unknown.".to_string())
}

/// What to launch: the AppImage file itself, since the running binary sits in
/// a mount that is gone after exit; otherwise this executable.
fn launch_path(appimage: Option<OsString>, current_exe: io::Result<PathBuf>) -> Result<PathBuf, String> {
    match appimage.filter(|a| !a.is_empty()) {
        Some(path) => Ok(path.into()),
        None => current_exe.map_err(|e| format!("could not find the app's location: {e}")),
    }
}

/// Quotes a path as one `Exec` argument. The spec asks for double quotes
/// around a word with reserved characters, a backslash before the four that
/// stay special inside them, then a second backslash for the string layer; a
/// literal percent is `%%`.
fn exec_argument(path: &str) -> String {
    const RESERVED: &[char] = &[
        ' ', '\t', '\n', '"', '\'', '\\', '>', '<', '~', '|', '&', ';', '$', '*', '?', '#', '(', ')', '`',
    ];
    let path = path.replace('%', "%%");
    if !path.is_empty() && !path.contains(RESERVED) {
        return path;
    }
    let mut quoted = String::from('"');
    for c in path.chars() {
        match c {
            '\\' => quoted.push_str(r"\\\\"),
            '"' | '`' | '$' => {
                quoted.push_str(r"\\");
                quoted.push(c);
            }
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

fn desktop_entry(launch: &Path) -> Result<String, String> {
    let launch = launch.to_str().ok_or("The app's location has a name that cannot be used.")?;
    if launch.contains(['\n', '\r']) {
        return Err("The app's location has a name that cannot be used.".to_string());
    }
    Ok(format!(
        "[Desktop Entry]\nType=Application\nName=RouteWise\nComment=Route chosen domains through your VPN\n\
         Exec={} {}\nIcon=routewise-desktop\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
        exec_argument(launch),
        crate::login_item::AUTOSTART_ARG
    ))
}

pub fn is_enabled() -> Result<bool, String> {
    let path = entry_path()?;
    path.try_exists().map_err(|e| format!("could not read {}: {e}", path.display()))
}

pub fn set_enabled(enabled: bool) -> Result<(), String> {
    let path = entry_path()?;
    if !enabled {
        return match fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(format!("could not remove {}: {e}", path.display())),
            _ => Ok(()),
        };
    }
    let launch = launch_path(std::env::var_os("APPIMAGE"), std::env::current_exe())?;
    let text = desktop_entry(&launch)?;
    let dir = path.parent().ok_or("The autostart folder is unknown.")?;
    fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    fs::write(&path, text).map_err(|e| format!("could not write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> Option<OsString> {
        Some(s.into())
    }

    #[test]
    fn the_entry_lives_under_the_config_home_or_dot_config() {
        assert_eq!(autostart_dir(os("/cfg"), os("/home/u")), Some("/cfg/autostart".into()));
        assert_eq!(autostart_dir(None, os("/home/u")), Some("/home/u/.config/autostart".into()));
        assert_eq!(autostart_dir(os("rel"), os("/home/u")), Some("/home/u/.config/autostart".into()));
        assert_eq!(autostart_dir(None, None), None);
    }

    #[test]
    fn an_appimage_is_launched_by_its_own_path() {
        let exe = || Ok(PathBuf::from("/tmp/.mount_x/usr/bin/routewise-desktop"));
        assert_eq!(launch_path(os("/home/u/RouteWise.AppImage"), exe()).unwrap(), Path::new("/home/u/RouteWise.AppImage"));
        assert_eq!(launch_path(None, exe()).unwrap(), Path::new("/tmp/.mount_x/usr/bin/routewise-desktop"));
        assert_eq!(launch_path(os(""), exe()).unwrap(), Path::new("/tmp/.mount_x/usr/bin/routewise-desktop"));
        assert!(launch_path(None, Err(io::Error::other("gone"))).is_err());
    }

    #[test]
    fn exec_arguments_are_quoted_only_when_needed() {
        assert_eq!(exec_argument("/usr/bin/routewise-desktop"), "/usr/bin/routewise-desktop");
        assert_eq!(exec_argument("/opt/My App/rw"), "\"/opt/My App/rw\"");
        assert_eq!(exec_argument("/a/$b"), r#""/a/\\$b""#);
        assert_eq!(exec_argument(r"/a\b"), r#""/a\\\\b""#);
        assert_eq!(exec_argument("/a/100%"), "/a/100%%");
    }

    #[test]
    fn the_entry_launches_the_given_path() {
        let text = desktop_entry(Path::new("/usr/bin/routewise-desktop")).unwrap();
        assert!(text.starts_with("[Desktop Entry]\nType=Application\n"));
        assert!(text.contains("\nExec=/usr/bin/routewise-desktop --autostart\n"));
        assert!(text.contains("\nX-GNOME-Autostart-enabled=true\n"));
        assert!(desktop_entry(Path::new("/a\nExec=evil")).is_err());
    }
}
