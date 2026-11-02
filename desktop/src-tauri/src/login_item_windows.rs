//! Launch at login on Windows through the current user's Run key,
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`: Windows starts every
//! value there when the user signs in. Compiled on every host under test so the
//! value text is covered wherever the tests run.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::Path;

/// The value's name, which Task Manager's Startup tab shows.
const VALUE_NAME: &str = "RouteWise";

/// The command Windows runs: the executable's path in double quotes, so a
/// folder with spaces is one word, then the flag that marks a launch at login. A path cannot hold a double quote on
/// Windows, so one in the text is refused rather than escaped.
fn run_value(exe: &Path) -> Result<String, String> {
    const UNUSABLE: &str = "The app's location has a name that cannot be used.";
    let exe = exe.to_str().ok_or(UNUSABLE)?;
    if exe.is_empty() || exe.contains(['"', '\0', '\r', '\n']) {
        return Err(UNUSABLE.to_string());
    }
    Ok(format!("\"{exe}\" {}", crate::login_item::AUTOSTART_ARG))
}

pub fn is_enabled() -> Result<bool, String> {
    registry::value_exists(VALUE_NAME)
}

pub fn set_enabled(enabled: bool) -> Result<(), String> {
    if !enabled {
        return registry::delete_value(VALUE_NAME);
    }
    let exe = std::env::current_exe().map_err(|e| format!("could not find the app's location: {e}"))?;
    registry::set_value(VALUE_NAME, &run_value(&exe)?)
}

#[cfg(windows)]
mod registry {
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn describe(action: &str, code: u32) -> String {
        format!("could not {action} the launch-at-login entry (Windows error {code})")
    }

    /// An open registry key, closed on drop.
    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the key was opened by this module and is closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    /// Opens the Run key with `access`, or reports no key as `None`.
    fn open(access: u32) -> Result<Option<Key>, String> {
        let path = wide(RUN_KEY);
        let mut key: HKEY = ptr::null_mut();
        // SAFETY: `path` is nul-terminated and `key` receives the handle.
        let code = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, access, &mut key) };
        match code {
            ERROR_SUCCESS => Ok(Some(Key(key))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            code => Err(describe("open", code)),
        }
    }

    pub fn value_exists(name: &str) -> Result<bool, String> {
        let Some(key) = open(KEY_QUERY_VALUE)? else { return Ok(false) };
        let name = wide(name);
        // SAFETY: a null data buffer asks only whether the value exists.
        let code =
            unsafe { RegQueryValueExW(key.0, name.as_ptr(), ptr::null(), ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) };
        match code {
            ERROR_SUCCESS => Ok(true),
            ERROR_FILE_NOT_FOUND => Ok(false),
            code => Err(describe("read", code)),
        }
    }

    pub fn set_value(name: &str, data: &str) -> Result<(), String> {
        let path = wide(RUN_KEY);
        let mut key: HKEY = ptr::null_mut();
        // SAFETY: `path` is nul-terminated; the key is created when missing.
        let code = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                ptr::null(),
                &mut key,
                ptr::null_mut(),
            )
        };
        if code != ERROR_SUCCESS {
            return Err(describe("open", code));
        }
        let key = Key(key);
        let (name, data) = (wide(name), wide(data));
        // SAFETY: the buffer is `data.len() * 2` bytes of UTF-16 with its nul.
        let code = unsafe {
            RegSetValueExW(key.0, name.as_ptr(), 0, REG_SZ, data.as_ptr().cast(), (data.len() * 2) as u32)
        };
        if code == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(describe("write", code))
        }
    }

    /// Removes the value; a value or key that is already gone is fine.
    pub fn delete_value(name: &str) -> Result<(), String> {
        let Some(key) = open(KEY_SET_VALUE)? else { return Ok(()) };
        let name = wide(name);
        // SAFETY: `name` is nul-terminated.
        match unsafe { RegDeleteValueW(key.0, name.as_ptr()) } {
            ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
            code => Err(describe("remove", code)),
        }
    }
}

/// Without the Windows registry there is nothing to read or write.
#[cfg(not(windows))]
mod registry {
    pub fn value_exists(_: &str) -> Result<bool, String> {
        Err("Launch at login through the registry exists only on Windows.".into())
    }
    pub fn set_value(_: &str, _: &str) -> Result<(), String> {
        value_exists("").map(|_| ())
    }
    pub fn delete_value(_: &str) -> Result<(), String> {
        value_exists("").map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_run_value_quotes_the_executable_path() {
        assert_eq!(
            run_value(Path::new(r"C:\Program Files\RouteWise\routewise-desktop.exe")).unwrap(),
            r#""C:\Program Files\RouteWise\routewise-desktop.exe" --autostart"#
        );
        assert_eq!(run_value(Path::new(r"C:\a\rw.exe")).unwrap(), r#""C:\a\rw.exe" --autostart"#);
    }

    #[test]
    fn a_path_that_cannot_be_quoted_is_refused() {
        assert!(run_value(Path::new("")).is_err());
        assert!(run_value(Path::new("C:\\a\"b\\rw.exe")).is_err());
        assert!(run_value(Path::new("C:\\a\nb\\rw.exe")).is_err());
    }
}
