//! The "VPN Connected" notification. The tray's status polling feeds it, so it
//! works with the window closed. Only a tunnel seen down and then up notifies; the first status after the helper
//! was unreachable never does.

use tauri::{AppHandle, Runtime};
use tauri_plugin_notification::{NotificationExt, PermissionState};

#[derive(Debug, PartialEq, Eq)]
pub struct Notice {
    pub title: &'static str,
    pub body: String,
}

/// Remembers the last known tunnel state between polls.
#[derive(Debug, Default)]
pub struct ConnectionNotifier {
    /// `None` after the status was unavailable.
    previous: Option<bool>,
}

impl ConnectionNotifier {
    /// Feeds one poll: `None` when the status could not be read, otherwise
    /// whether a tunnel is up and on which interface.
    pub fn observe(&mut self, status: Option<(bool, Option<&str>)>) -> Option<Notice> {
        let Some((connected, interface)) = status else {
            self.previous = None;
            return None;
        };
        let came_up = self.previous == Some(false) && connected;
        self.previous = Some(connected);
        came_up.then(|| Notice {
            title: "VPN Connected",
            body: format!("RouteWise is active via {}.", interface.filter(|i| !i.is_empty()).unwrap_or("VPN")),
        })
    }
}

/// Posts a notice immediately.
pub fn send<R: Runtime>(app: &AppHandle<R>, notice: &Notice) {
    if let Err(e) = app.notification().builder().title(notice.title).body(&notice.body).show() {
        log::warn!("could not show a notification: {e}");
    }
}

/// Asks for notification permission once, at startup, when it is not granted.
pub fn request_permission_once<R: Runtime>(app: &AppHandle<R>) {
    let notification = app.notification();
    match notification.permission_state() {
        Ok(PermissionState::Granted) => {}
        Ok(_) => {
            if let Err(e) = notification.request_permission() {
                log::warn!("notification permission request failed: {e}");
            }
        }
        Err(e) => log::warn!("could not read the notification permission: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(i: &str) -> Option<(bool, Option<&str>)> {
        Some((true, Some(i)))
    }

    const DOWN: Option<(bool, Option<&str>)> = Some((false, None));

    #[test]
    fn notifies_when_a_tunnel_comes_up() {
        let mut n = ConnectionNotifier::default();
        assert_eq!(n.observe(DOWN), None);
        let notice = n.observe(up("utun4")).unwrap();
        assert_eq!(notice.title, "VPN Connected");
        assert_eq!(notice.body, "RouteWise is active via utun4.");
        assert_eq!(n.observe(up("utun4")), None, "still up: no repeat");
    }

    #[test]
    fn the_first_status_never_notifies() {
        let mut n = ConnectionNotifier::default();
        assert_eq!(n.observe(up("utun4")), None);
    }

    #[test]
    fn an_unreadable_status_resets_the_rule() {
        let mut n = ConnectionNotifier::default();
        n.observe(DOWN);
        n.observe(None);
        assert_eq!(n.observe(up("utun4")), None);
    }

    #[test]
    fn a_missing_interface_reads_vpn() {
        let mut n = ConnectionNotifier::default();
        n.observe(DOWN);
        assert_eq!(n.observe(Some((true, None))).unwrap().body, "RouteWise is active via VPN.");
    }

    #[test]
    fn reconnecting_notifies_again() {
        let mut n = ConnectionNotifier::default();
        n.observe(DOWN);
        n.observe(up("a"));
        n.observe(DOWN);
        assert!(n.observe(up("b")).is_some());
    }
}
