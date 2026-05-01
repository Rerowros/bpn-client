mod commands;
mod settings;

use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if std::env::var_os("BADVPN_OPEN_DEVTOOLS").is_some() {
                if let Some(window) = app.get_webview_window("main") {
                    window.open_devtools();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::start,
            commands::stop,
            commands::restart,
            commands::set_subscription,
            commands::refresh_subscription,
            commands::subscription_profiles,
            commands::add_subscription_profile,
            commands::select_subscription_profile,
            commands::remove_subscription_profile,
            commands::check_app_release_update,
            commands::check_component_updates,
            commands::get_settings,
            commands::save_settings,
            commands::reset_settings,
            commands::agent_service_status,
            commands::install_agent_service,
            commands::remove_agent_service,
            commands::zapret_profile_state,
            commands::zapret_service_status,
            commands::set_zapret_profile,
            commands::run_diagnostics,
            commands::update_runtime_components,
            commands::connections_snapshot,
            commands::close_connection,
            commands::close_all_connections,
            commands::clear_closed_connections,
            commands::proxy_catalog,
            commands::select_proxy
        ])
        .run(tauri::generate_context!())
        .expect("failed to run BadVpn Tauri application");
}
