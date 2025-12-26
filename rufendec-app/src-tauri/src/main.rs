// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod rufendec;
mod encryption;

use encryption::{encrypt_directory, encrypt_file, scan_operational_info};
use tauri::{Manager, webview::WebviewWindowBuilder};
use tauri::WebviewUrl;
use url::Url;

#[tauri::command]
async fn open_github_window(app: tauri::AppHandle) -> Result<(), String> {
    // Check if window already exists
    if let Some(window) = app.get_webview_window("github") {
        let _ = window.set_focus();
        return Ok(());
    }

    // Parse the URL
    let url = Url::parse("https://github.com/omkarium/rufendec")
        .map_err(|e| format!("Invalid URL: {}", e))?;

    // Create new window using WebviewWindowBuilder
    let _window = WebviewWindowBuilder::new(&app, "github", WebviewUrl::External(url))
        .title("GitHub - Rufendec Source Code")
        .inner_size(1200.0, 800.0)
        .resizable(true)
        .center()
        .build()
        .map_err(|e| format!("Failed to create window: {}", e))?;

    Ok(())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![encrypt_directory, encrypt_file, scan_operational_info, open_github_window])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
