pub mod cleaner;
pub mod security;

use tauri::Manager;

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            #[cfg(target_os = "windows")]
            {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window_vibrancy::apply_mica(&window, None)
                        .or_else(|_| window_vibrancy::apply_acrylic(&window, Some((15, 18, 25, 190))));
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            greet,
            cleaner::scan_all_caches,
            cleaner::clean_categories,
            cleaner::cancel_current_operation,
            cleaner::get_audit_logs,
            cleaner::is_elevated_admin,
            cleaner::request_admin_elevation,
            cleaner::open_brand_link,
            cleaner::scan_large_files,
            cleaner::reveal_in_explorer,
            cleaner::delete_large_files,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
