//! RouteWise desktop app: a Tauri shell whose Rust core proxies the webview to
//! the privileged helper over its local socket.

pub mod app_log;
mod app_log_files;
mod commands;
mod file_dialogs;
#[cfg(target_os = "macos")]
mod helper_script;
mod helper_service;
// Also built under test on unix hosts, so its pure parts run there.
#[cfg(any(target_os = "linux", all(test, unix)))]
mod helper_service_linux;
#[cfg(target_os = "macos")]
mod helper_service_macos;
#[cfg(any(windows, test))]
mod helper_service_windows;
mod log_folders;
mod login_item;
#[cfg(any(target_os = "linux", all(test, unix)))]
mod login_item_linux;
#[cfg(any(windows, test))]
mod login_item_windows;
mod native_prefs;
mod navigation;
mod notify;
mod profiles;
mod quit;
mod rpc;
mod telemetry;
mod tray;
mod update_release;
mod updates;
mod window;

use std::sync::Arc;

use tauri::{Manager, RunEvent, WindowEvent};

use commands::AppState;
use rpc::transport::Transport;

/// Where the helper listens: a unix socket, or the named pipe on Windows.
#[cfg(target_os = "macos")]
const HELPER_SOCKET: &str = "/var/run/routewise.sock";
#[cfg(target_os = "linux")]
const HELPER_SOCKET: &str = "/run/routewise.sock";
#[cfg(windows)]
const HELPER_SOCKET: &str = r"\\.\pipe\routewise";

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn helper_transport() -> Arc<dyn Transport> {
    Arc::new(rpc::transport::UnixTransport::new(HELPER_SOCKET))
}

#[cfg(windows)]
fn helper_transport() -> Arc<dyn Transport> {
    Arc::new(rpc::pipe_transport::PipeTransport::new(HELPER_SOCKET))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
compile_error!("no helper transport for this platform yet");

pub fn run() {
    // The app log (stderr and daily files) under error reporting, which
    // forwards warnings and errors when the user turned that on. Webview log
    // lines reach the file through this logger too, so no separate sink.
    let (app_logger, app_log_level) = app_log::init();
    telemetry::install_logger(app_logger, app_log_level);

    let transport = helper_transport();
    let tray_transport = transport.clone();
    let exit_transport = transport.clone();
    let telemetry_transport = transport.clone();
    let app = tauri::Builder::default()
        // Must be first: a second launch focuses the running instance.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| window::open_main_window(app)))
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::new(transport))
        .manage(navigation::PendingTab::default())
        .manage(updates::LastUpdateResult::default())
        .invoke_handler(tauri::generate_handler![
            commands::rpc,
            commands::stream_start,
            commands::stream_stop,
            helper_service::helper_service_status,
            helper_service::helper_install,
            helper_service::helper_uninstall,
            login_item::launch_at_login_get,
            login_item::launch_at_login_set,
            window::window_set_keep_on_top,
            log_folders::open_log_folder,
            file_dialogs::save_text_file,
            file_dialogs::open_text_file,
            file_dialogs::pick_vpn_program,
            updates::update_check,
            updates::update_last_result,
            updates::open_release_page,
            navigation::take_pending_tab,
            tray::system_stats::system_stats_history,
            telemetry::ui::report_ui_error,
            telemetry::ui::log_ui,
            telemetry::test_event::telemetry_send_test_event,
        ])
        .setup(|app| {
            telemetry::start(telemetry_transport, &app.package_info().version.to_string());
            window::set_dock_visible(app.handle(), false);
            notify::request_permission_once(app.handle());
            tray::build_tray(app.handle(), tray_transport)?;
            updates::start_background_checks(app.handle());
            // Without a menu bar, a first launch must show something: the tray
            // icon may sit in an overflow or have no host at all. A launch the
            // system made at login stays quiet.
            #[cfg(not(target_os = "macos"))]
            if !window::started_at_login(std::env::args_os()) {
                window::open_main_window(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // A destroyed window has no webview left to listen: stop polling and
            // drop back to menu-bar-only.
            if let (WindowEvent::Destroyed, window::MAIN_WINDOW) = (event, window.label()) {
                let app = window.app_handle();
                app.state::<AppState>().streams.stop_all();
                // A request nobody read must not steer the next window.
                app.state::<navigation::PendingTab>().take();
                window::set_dock_visible(app, false);
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building the RouteWise app");

    app.run(move |_app, event| match event {
        // Closing the last window must not quit a menu-bar app; only the tray's
        // Quit does, once the built-in VPNs are disconnected (it exits with an
        // explicit code).
        RunEvent::ExitRequested { api, code: None, .. } => api.prevent_exit(),
        // Cmd+Q, logout, and shutdown end the app without asking: disconnect
        // the built-in VPNs here, blocking the exit for a bounded time.
        RunEvent::Exit => {
            tauri::async_runtime::block_on(quit::disconnect_once(&exit_transport, quit::QUIT_TIMEOUT));
            telemetry::shutdown();
        }
        _ => {}
    });
}
