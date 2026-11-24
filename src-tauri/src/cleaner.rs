use crate::security::{self, CacheCategory};
use chrono::Local;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tauri::{AppHandle, Emitter};
use walkdir::WalkDir;

/// Global cancellation flag checked periodically during filesystem traversal and deletion.
static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Cancels any currently executing scan or clean operation.
#[tauri::command]
pub fn cancel_current_operation() {
    CANCEL_REQUESTED.store(true, Ordering::SeqCst);
}

/// Real-time progress payload emitted to the frontend during scans and cleaning sessions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OperationProgress {
    pub mode: String,          // "scanning" | "cleaning" | "idle"
    pub current_label: String, // e.g. "Social & Media • CapCut Media Cache"
    pub processed: u64,
    pub total: u64,
    pub percent: f64,
}

/// Represents an individual discovered subfolder/target within a category.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubTargetItem {
    pub id: String,
    pub name: String,
    pub display_path: String,
    pub size_bytes: u64,
    pub file_count: u64,
}

/// Represents the scan result for a cache or junk category with enriched sub-items.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CategoryScanResult {
    pub id: String,
    pub name: String,
    pub description: String,
    pub size_bytes: u64,
    pub file_count: u64,
    pub requires_admin: bool,
    pub is_installed: bool,
    pub target_paths: Vec<String>,
    pub sub_items: Vec<SubTargetItem>,
    pub scan_duration_ms: u64,
}

/// Represents the summary result of a cleaning operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CleanResult {
    pub freed_bytes: u64,
    pub deleted_files: u64,
    pub skipped_count: u64,
    pub duration_ms: u64,
    pub cleaned_categories: Vec<String>,
    pub errors: Vec<String>,
}

/// An entry in the persistent audit log.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: String,
    pub categories: Vec<String>,
    pub freed_bytes: u64,
    pub deleted_files: u64,
    pub skipped_count: u64,
    pub duration_ms: u64,
    pub use_recycle_bin: bool,
    pub success: bool,
}

/// Generates a human-friendly sub-item display name from a target path.
fn format_sub_item_name(path: &Path, category: CacheCategory) -> String {
    let path_str = path.to_string_lossy();
    let lower = path_str.to_lowercase();

    // Browser Caches
    if lower.contains("chrome") {
        let profile = extract_profile_name(&path_str);
        let sub = extract_cache_subdir(&path_str);
        return format!("Chrome • {} ({})", profile, sub);
    }
    if lower.contains("edge") {
        if lower.contains("component_crx_cache") {
            return "Edge • Component CRX Cache".to_string();
        }
        let profile = extract_profile_name(&path_str);
        let sub = extract_cache_subdir(&path_str);
        return format!("Edge • {} ({})", profile, sub);
    }
    if lower.contains("brave") {
        let profile = extract_profile_name(&path_str);
        let sub = extract_cache_subdir(&path_str);
        return format!("Brave • {} ({})", profile, sub);
    }
    if lower.contains("firefox") {
        return "Firefox • cache2".to_string();
    }
    if lower.contains("opera") {
        let sub = extract_cache_subdir(&path_str);
        return format!("Opera Stable • {}", sub);
    }

    // App & Dev Caches
    if lower.contains("npm-cache") {
        return "npm Cache".to_string();
    }
    if lower.contains("pip") && lower.contains("cache") {
        return "pip Cache".to_string();
    }
    if lower.contains("discord") {
        if lower.contains("code cache") {
            return "Discord • Code Cache".to_string();
        }
        return "Discord • Cache".to_string();
    }
    if lower.contains("adobe") {
        if lower.contains("media cache files") {
            return "Adobe • Media Cache Files".to_string();
        }
        return "Adobe • Media Cache".to_string();
    }

    // Social & Creative Media Caches
    if lower.contains("whatsapp") {
        if lower.contains("tempstate") {
            return "WhatsApp • Temp State".to_string();
        }
        return "WhatsApp • Local Cache".to_string();
    }
    if lower.contains("telegram") {
        if lower.contains("media_cache") {
            return "Telegram • Media Cache".to_string();
        }
        return "Telegram • Cache".to_string();
    }
    if lower.contains("capcut") {
        if lower.ends_with(r"\log") || lower.ends_with("/log") {
            return "CapCut • App Logs".to_string();
        }
        return "CapCut • Media Cache".to_string();
    }

    // GPU Shader Caches
    if lower.contains("d3dscache") {
        return "Direct3D Shader Cache".to_string();
    }
    if lower.contains("nvidia") {
        if lower.contains("glcache") {
            return "NVIDIA • OpenGL Cache".to_string();
        }
        return "NVIDIA • DirectX Cache".to_string();
    }
    if lower.contains("amd") {
        return "AMD • DirectX Cache".to_string();
    }
    if lower.contains("intel") {
        return "Intel • Shader Cache".to_string();
    }

    // Crash Dumps & Diagnostic Caches
    if lower.contains("crashdumps") {
        return "Crash Dumps (Minidumps)".to_string();
    }
    if lower.contains("wer") {
        return "Windows Error Reporting (WER)".to_string();
    }
    if lower.contains("inetcache") {
        return "Internet Temporary Files (INetCache)".to_string();
    }

    // System Temp & Update
    if lower.contains("softwaredistribution") {
        return "Windows Update Download Cache".to_string();
    }
    if lower.contains(r"windows\temp") {
        return "Windows System Temp".to_string();
    }

    // User Temp
    if category == CacheCategory::UserTemp {
        return "User Temp Files (%TEMP%)".to_string();
    }

    path.file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| path_str.to_string())
}

fn extract_profile_name(path_str: &str) -> String {
    let parts: Vec<&str> = path_str.split(['\\', '/']).collect();
    for i in 0..parts.len() {
        if parts[i].eq_ignore_ascii_case("User Data") && i + 1 < parts.len() {
            let next = parts[i + 1];
            if !next.eq_ignore_ascii_case("component_crx_cache") {
                return next.to_string();
            }
        }
    }
    "Default".to_string()
}

fn extract_cache_subdir(path_str: &str) -> String {
    let lower = path_str.to_lowercase();
    if lower.ends_with("code cache") {
        "Code Cache".to_string()
    } else if lower.ends_with("gpucache") {
        "GPUCache".to_string()
    } else {
        "Cache".to_string()
    }
}

/// Query Windows Recycle Bin for size and item count across all drives.
#[cfg(windows)]
pub fn query_recycle_bin() -> (u64, u64) {
    use windows::Win32::UI::Shell::{SHQueryRecycleBinW, SHQUERYRBINFO};

    unsafe {
        let mut info = SHQUERYRBINFO {
            cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
            i64Size: 0,
            i64NumItems: 0,
        };

        let hr = SHQueryRecycleBinW(None, &mut info);
        if hr.is_ok() {
            (info.i64Size.max(0) as u64, info.i64NumItems.max(0) as u64)
        } else {
            (0, 0)
        }
    }
}

#[cfg(not(windows))]
pub fn query_recycle_bin() -> (u64, u64) {
    (0, 0)
}

/// Empty Windows Recycle Bin across all drives without confirmation dialogs or sound.
#[cfg(windows)]
pub fn empty_recycle_bin() -> Result<(), String> {
    use windows::Win32::UI::Shell::SHEmptyRecycleBinW;

    unsafe {
        // SHERB_NOCONFIRMATION (0x01) | SHERB_NOPROGRESSUI (0x02) | SHERB_NOSOUND (0x04) = 7
        let hr = SHEmptyRecycleBinW(None, None, 7);
        if hr.is_ok() {
            Ok(())
        } else {
            Err(format!("Failed to empty Recycle Bin: {:?}", hr))
        }
    }
}

#[cfg(not(windows))]
pub fn empty_recycle_bin() -> Result<(), String> {
    Ok(())
}

/// Check if the application is running with elevated Administrator privileges.
#[tauri::command]
pub fn is_elevated_admin() -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION::default();
            let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
            let res = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                size,
                &mut size,
            );

            let _ = CloseHandle(token);
            res.is_ok() && elevation.TokenIsElevated != 0
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Relaunches the application with Windows Administrator privileges via UAC prompt ("runas").
/// If elevation succeeds, the current un-elevated process exits cleanly.
#[tauri::command]
pub fn request_admin_elevation() -> Result<(), String> {
    #[cfg(windows)]
    {
        use windows::core::{HSTRING, PCWSTR};
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Failed to get current executable path: {}", e))?;
        let exe_hstring = HSTRING::from(exe_path.as_os_str());
        let op_hstring = HSTRING::from("runas");

        unsafe {
            let res = ShellExecuteW(
                None,
                PCWSTR(op_hstring.as_ptr()),
                PCWSTR(exe_hstring.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            );

            let code = res.0 as isize;
            // ShellExecuteW returns HINSTANCE > 32 on success
            if code > 32 {
                std::process::exit(0);
            } else {
                Err(format!("UAC elevation failed or was cancelled by user (code: {})", code))
            }
        }
    }
    #[cfg(not(windows))]
    {
        Err("Admin elevation is only supported on Windows".to_string())
    }
}

/// Safely opens official Pixel Craft Studios brand links with strict allowlist validation.
/// Strictly rejects any target other than "website" or "whatsapp".
#[tauri::command]
pub fn open_brand_link(target: String) -> Result<(), String> {
    let url = match target.as_str() {
        "website" => "https://www.pixelcraftlk.com",
        "whatsapp" => "https://wa.me/94787676576",
        _ => return Err(format!("Unauthorized link target: {}", target)),
    };

    #[cfg(windows)]
    {
        use windows::core::{HSTRING, PCWSTR};
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let url_hstring = HSTRING::from(url);
        let op_hstring = HSTRING::from("open");

        unsafe {
            let res = ShellExecuteW(
                None,
                PCWSTR(op_hstring.as_ptr()),
                PCWSTR(url_hstring.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            );
            let code = res.0 as isize;
            if code > 32 {
                Ok(())
            } else {
                Err(format!("Failed to open link (code: {})", code))
            }
        }
    }
    #[cfg(not(windows))]
    {
        Err("Opening links is only supported on Windows".to_string())
    }
}

/// Helper to scan a directory recursively, summing up file size and file count while strictly
/// skipping reparse points / junctions / symlinks to prevent trap loops.
fn scan_directory_tree(root: &Path) -> (u64, u64) {
    let mut total_size = 0u64;
    let mut total_files = 0u64;

    for entry in WalkDir::new(root).follow_links(false).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();

        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                continue;
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & security::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    continue;
                }
            }

            if meta.is_file() {
                total_size += meta.len();
                total_files += 1;
            }
        }
    }

    (total_size, total_files)
}

/// Scans all universal junk categories and the Windows Recycle Bin in a background blocking task,
/// emitting real-time progress events to the UI and checking for cancellation.
#[tauri::command]
pub async fn scan_all_caches(app: AppHandle) -> Result<Vec<CategoryScanResult>, String> {
    CANCEL_REQUESTED.store(false, Ordering::SeqCst);

    tauri::async_runtime::spawn_blocking(move || {
        let categories = [
            CacheCategory::UserTemp,
            CacheCategory::SystemTemp,
            CacheCategory::BrowserCaches,
            CacheCategory::GpuShaderCache,
            CacheCategory::CrashDumps,
            CacheCategory::AppDevCaches,
            CacheCategory::SocialMedia,
        ];

        let total_steps = (categories.len() + 1) as u64; // 7 categories + Recycle Bin
        let mut results = Vec::new();

        for (i, &cat) in categories.iter().enumerate() {
            if CANCEL_REQUESTED.load(Ordering::SeqCst) {
                break;
            }

            let pct = ((i as f64) / (total_steps as f64) * 100.0).round();
            let _ = app.emit(
                "operation-progress",
                OperationProgress {
                    mode: "scanning".to_string(),
                    current_label: format!("Scanning {}...", cat.display_name()),
                    processed: i as u64,
                    total: total_steps,
                    percent: pct,
                },
            );

            let start = Instant::now();
            let base_paths = security::resolve_category_base_paths(cat);

            let mut total_bytes = 0u64;
            let mut total_files = 0u64;
            let mut target_paths_str = Vec::new();
            let mut sub_items = Vec::new();

            for path in &base_paths {
                if CANCEL_REQUESTED.load(Ordering::SeqCst) {
                    break;
                }

                let path_display = path.to_string_lossy().to_string();
                target_paths_str.push(path_display.clone());
                let (bytes, files) = scan_directory_tree(path);
                total_bytes += bytes;
                total_files += files;

                sub_items.push(SubTargetItem {
                    id: path_display.clone(),
                    name: format_sub_item_name(path, cat),
                    display_path: path_display,
                    size_bytes: bytes,
                    file_count: files,
                });
            }

            // Sort sub-items descending by size
            sub_items.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

            let is_installed = match cat {
                CacheCategory::AppDevCaches
                | CacheCategory::BrowserCaches
                | CacheCategory::GpuShaderCache
                | CacheCategory::CrashDumps
                | CacheCategory::SocialMedia => !base_paths.is_empty(),
                CacheCategory::UserTemp | CacheCategory::SystemTemp => true,
            };

            results.push(CategoryScanResult {
                id: cat.as_id().to_string(),
                name: cat.display_name().to_string(),
                description: cat.description().to_string(),
                size_bytes: total_bytes,
                file_count: total_files,
                requires_admin: cat.requires_admin(),
                is_installed,
                target_paths: target_paths_str,
                sub_items,
                scan_duration_ms: start.elapsed().as_millis() as u64,
            });
        }

        // Query Windows Recycle Bin if not cancelled
        if !CANCEL_REQUESTED.load(Ordering::SeqCst) {
            let _ = app.emit(
                "operation-progress",
                OperationProgress {
                    mode: "scanning".to_string(),
                    current_label: "Scanning Windows Recycle Bin...".to_string(),
                    processed: categories.len() as u64,
                    total: total_steps,
                    percent: 90.0,
                },
            );

            let rb_start = Instant::now();
            let (rb_size, rb_items) = query_recycle_bin();
            results.push(CategoryScanResult {
                id: "recycle_bin".to_string(),
                name: "Windows Recycle Bin".to_string(),
                description: "Deleted files and documents stored in the Windows Recycle Bin across all drives.".to_string(),
                size_bytes: rb_size,
                file_count: rb_items,
                requires_admin: false,
                is_installed: true,
                target_paths: vec!["RecycleBin".to_string()],
                sub_items: vec![SubTargetItem {
                    id: "recycle_bin".to_string(),
                    name: "Windows Recycle Bin (All Drives)".to_string(),
                    display_path: "RecycleBin".to_string(),
                    size_bytes: rb_size,
                    file_count: rb_items,
                }],
                scan_duration_ms: rb_start.elapsed().as_millis() as u64,
            });
        }

        let _ = app.emit(
            "operation-progress",
            OperationProgress {
                mode: "idle".to_string(),
                current_label: "Scan Complete".to_string(),
                processed: total_steps,
                total: total_steps,
                percent: 100.0,
            },
        );

        Ok(results)
    })
    .await
    .map_err(|e| format!("Scan task execution error: {}", e))?
}

/// Helper to get the audit log file path: `%LOCALAPPDATA%\SmartCacheCleaner\audit.log`
fn get_audit_log_path() -> Result<PathBuf, String> {
    let local = dirs::data_local_dir().ok_or_else(|| "Could not resolve LocalAppData".to_string())?;
    let app_dir = local.join("SmartCacheCleaner");
    if !app_dir.exists() {
        let _ = fs::create_dir_all(&app_dir);
    }
    Ok(app_dir.join("audit.log"))
}

/// Appends an audit log entry to the persistent JSON-lines log file.
fn append_audit_log(entry: &AuditLogEntry) {
    if let Ok(log_path) = get_audit_log_path() {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
            if let Ok(json) = serde_json::to_string(entry) {
                let _ = writeln!(file, "{}", json);
            }
        }
    }
}

/// Retrieves all historic cleaning audit logs.
#[tauri::command]
pub fn get_audit_logs() -> Result<Vec<AuditLogEntry>, String> {
    let log_path = get_audit_log_path()?;
    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(&log_path).map_err(|e| format!("Failed to open audit log: {}", e))?;
    let reader = BufReader::new(file);

    let mut logs = Vec::new();
    for line in reader.lines().flatten() {
        if let Ok(entry) = serde_json::from_str::<AuditLogEntry>(&line) {
            logs.push(entry);
        }
    }

    logs.reverse(); // Most recent entries first
    Ok(logs)
}

/// Cleans the selected categories and target paths with zero-trust safety:
/// - Runs inside a background blocking task so the main thread never freezes.
/// - Periodically checks `CANCEL_REQUESTED` and emits real-time progress events.
/// - Re-validates EVERY path and file target through `security::validate_safe_target` immediately before deletion.
/// - Empties Recycle Bin if selected.
/// - Uses batch `trash::delete_all` in chunks of 250 files (with per-file fallback) when `use_recycle_bin` is true.
/// - Skips locked/in-use files gracefully without crashing.
/// - Records and logs all actions to `%LOCALAPPDATA%\SmartCacheCleaner\audit.log`.
#[tauri::command]
pub async fn clean_categories(
    app: AppHandle,
    category_ids: Vec<String>,
    selected_target_paths: Vec<String>,
    use_recycle_bin: bool,
) -> Result<CleanResult, String> {
    CANCEL_REQUESTED.store(false, Ordering::SeqCst);

    tauri::async_runtime::spawn_blocking(move || {
        let start = Instant::now();
        let mut total_freed_bytes = 0u64;
        let mut total_deleted_files = 0u64;
        let mut total_skipped_count = 0u64;
        let mut errors = Vec::new();
        let mut cleaned_cats = Vec::new();

        // 1. Handle Windows Recycle Bin if requested
        if category_ids.iter().any(|id| id == "recycle_bin")
            || selected_target_paths.iter().any(|p| p == "RecycleBin" || p == "recycle_bin")
        {
            if !CANCEL_REQUESTED.load(Ordering::SeqCst) {
                let _ = app.emit(
                    "operation-progress",
                    OperationProgress {
                        mode: "cleaning".to_string(),
                        current_label: "Emptying Windows Recycle Bin...".to_string(),
                        processed: 0,
                        total: 100,
                        percent: 5.0,
                    },
                );

                let (rb_size, rb_items) = query_recycle_bin();
                match empty_recycle_bin() {
                    Ok(()) => {
                        total_freed_bytes += rb_size;
                        total_deleted_files += rb_items;
                        cleaned_cats.push("recycle_bin".to_string());
                    }
                    Err(e) => {
                        errors.push(format!("Recycle Bin empty failed: {}", e));
                    }
                }
            }
        }

        // 2. Determine base paths to clean
        let mut base_paths_to_clean: Vec<PathBuf> = Vec::new();

        if !selected_target_paths.is_empty() {
            for path_str in &selected_target_paths {
                if path_str == "RecycleBin" || path_str == "recycle_bin" {
                    continue;
                }
                let p = PathBuf::from(path_str);
                match security::validate_safe_target(&p) {
                    Ok(safe) => {
                        base_paths_to_clean.push(safe);
                    }
                    Err(err) => {
                        total_skipped_count += 1;
                        errors.push(format!("Zero-Trust rejected target path {:?}: {}", p, err));
                    }
                }
            }
        } else {
            for id in &category_ids {
                if id == "recycle_bin" {
                    continue;
                }

                let cat = match CacheCategory::from_id(id) {
                    Some(c) => c,
                    None => {
                        errors.push(format!("Unrecognized category ID: {}", id));
                        continue;
                    }
                };

                let paths = security::resolve_category_base_paths(cat);
                base_paths_to_clean.extend(paths);
            }
        }

        base_paths_to_clean.sort();
        base_paths_to_clean.dedup();

        for id in &category_ids {
            if !cleaned_cats.contains(id) {
                cleaned_cats.push(id.clone());
            }
        }

        // 3. Collect and validate every target file before deletion
        let mut all_files_to_delete: Vec<(PathBuf, u64)> = Vec::new();

        for base_path in &base_paths_to_clean {
            if CANCEL_REQUESTED.load(Ordering::SeqCst) {
                break;
            }

            for entry in WalkDir::new(base_path).follow_links(false).into_iter().filter_map(|e| e.ok()) {
                let p = entry.path();
                if p == base_path {
                    continue;
                }

                if let Ok(meta) = fs::symlink_metadata(p) {
                    if meta.file_type().is_symlink() {
                        total_skipped_count += 1;
                        continue;
                    }
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::MetadataExt;
                        if meta.file_attributes() & security::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                            total_skipped_count += 1;
                            continue;
                        }
                    }

                    if meta.is_file() {
                        match security::validate_safe_target(p) {
                            Ok(_) => {
                                all_files_to_delete.push((p.to_path_buf(), meta.len()));
                            }
                            Err(_) => {
                                total_skipped_count += 1;
                            }
                        }
                    }
                }
            }
        }

        let total_files = all_files_to_delete.len();
        let mut processed_files = 0usize;

        let _ = app.emit(
            "operation-progress",
            OperationProgress {
                mode: "cleaning".to_string(),
                current_label: format!("Prepared {} cache files for cleaning...", total_files),
                processed: 0,
                total: total_files as u64,
                percent: 0.0,
            },
        );

        // 4. Batch deletion in chunks of 250 files
        for chunk in all_files_to_delete.chunks(250) {
            if CANCEL_REQUESTED.load(Ordering::SeqCst) {
                break;
            }

            let first_name = chunk
                .first()
                .and_then(|(p, _)| p.file_name())
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "cache item".to_string());

            if use_recycle_bin {
                let path_bufs: Vec<PathBuf> = chunk.iter().map(|(p, _)| p.clone()).collect();
                if trash::delete_all(&path_bufs).is_ok() {
                    for (_, size) in chunk {
                        total_freed_bytes += size;
                        total_deleted_files += 1;
                    }
                } else {
                    // Fallback to per-file deletion if batch has locked/in-use items
                    for (file, size) in chunk {
                        if trash::delete(file).is_ok() {
                            total_freed_bytes += size;
                            total_deleted_files += 1;
                        } else {
                            total_skipped_count += 1;
                        }
                    }
                }
            } else {
                for (file, size) in chunk {
                    if fs::remove_file(file).is_ok() {
                        total_freed_bytes += size;
                        total_deleted_files += 1;
                    } else {
                        total_skipped_count += 1;
                    }
                }
            }

            processed_files += chunk.len();
            let pct = if total_files > 0 {
                ((processed_files as f64) / (total_files as f64) * 100.0).min(100.0)
            } else {
                100.0
            };

            let _ = app.emit(
                "operation-progress",
                OperationProgress {
                    mode: "cleaning".to_string(),
                    current_label: format!("Cleaning: {}", first_name),
                    processed: processed_files as u64,
                    total: total_files as u64,
                    percent: pct,
                },
            );
        }

        // Clean up empty subdirectories if permanent deletion and not cancelled
        if !use_recycle_bin && !CANCEL_REQUESTED.load(Ordering::SeqCst) {
            for base_path in &base_paths_to_clean {
                for entry in WalkDir::new(base_path)
                    .contents_first(true)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    let p = entry.path();
                    if p != base_path && p.is_dir() {
                        let _ = fs::remove_dir(p);
                    }
                }
            }
        }

        let _ = app.emit(
            "operation-progress",
            OperationProgress {
                mode: "idle".to_string(),
                current_label: "Cleanup Complete".to_string(),
                processed: processed_files as u64,
                total: total_files as u64,
                percent: 100.0,
            },
        );

        let duration_ms = start.elapsed().as_millis() as u64;
        let result = CleanResult {
            freed_bytes: total_freed_bytes,
            deleted_files: total_deleted_files,
            skipped_count: total_skipped_count,
            duration_ms,
            cleaned_categories: cleaned_cats.clone(),
            errors: errors.clone(),
        };

        // Log the clean event to the audit log
        let audit_entry = AuditLogEntry {
            timestamp: Local::now().to_rfc3339(),
            categories: cleaned_cats,
            freed_bytes: total_freed_bytes,
            deleted_files: total_deleted_files,
            skipped_count: total_skipped_count,
            duration_ms,
            use_recycle_bin,
            success: errors.is_empty(),
        };
        append_audit_log(&audit_entry);

        Ok(result)
    })
    .await
    .map_err(|e| format!("Clean task execution error: {}", e))?
}

/// Represents a discovered large file on the user's filesystem.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LargeFileItem {
    pub name: String,
    pub path: String,
    pub formatted_path: String,
    pub extension: String,
    pub size_bytes: u64,
    pub modified_days_ago: u64,
}

/// Helper function to check if a path is inside one of the user's allowed personal large file roots
/// (Downloads, Desktop, Documents, Videos).
fn get_user_large_file_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(p) = dirs::download_dir() {
        if p.exists() {
            roots.push(p);
        }
    }
    if let Some(p) = dirs::desktop_dir() {
        if p.exists() {
            roots.push(p);
        }
    }
    if let Some(p) = dirs::document_dir() {
        if p.exists() {
            roots.push(p);
        }
    }
    if let Some(p) = dirs::video_dir() {
        if p.exists() {
            roots.push(p);
        }
    }
    roots
}

fn is_within_user_large_file_roots(path: &Path) -> bool {
    let norm_path = security::normalize_for_comparison(path);
    for root in get_user_large_file_roots() {
        let norm_root = security::normalize_for_comparison(&root);
        if norm_path.starts_with(&norm_root) {
            return true;
        }
    }
    false
}

/// Validates that a large file target is safe to delete:
/// 1. Must reside strictly within user's Downloads, Desktop, Documents, or Videos.
/// 2. Must not be a directory (files only).
/// 3. Must not be a symlink or Windows junction (0x400).
/// 4. Must not be a critical system or credential file.
fn validate_safe_large_file_target(path: &Path) -> Result<PathBuf, String> {
    if !path.exists() {
        return Err(format!("File does not exist: {:?}", path));
    }

    // Inspect pre-canonicalized path and ancestors for symlinks/reparse points
    security::check_symlinks_and_reparse_points(path)?;

    let canonical = path
        .canonicalize()
        .map_err(|e| format!("Failed to canonicalize {:?}: {}", path, e))?;

    // Must be inside allowed personal user roots
    if !is_within_user_large_file_roots(&canonical) {
        return Err(format!(
            "Access denied: Path '{:?}' is outside allowed user profile roots (Downloads, Desktop, Documents, Videos)",
            canonical
        ));
    }

    // Must be a file, not a directory
    let meta = fs::symlink_metadata(&canonical)
        .map_err(|e| format!("Failed to read metadata for {:?}: {}", canonical, e))?;
    if !meta.is_file() {
        return Err(format!("Access denied: Target '{:?}' is not a regular file", canonical));
    }

    // Must not be a symlink or junction
    if meta.file_type().is_symlink() {
        return Err(format!("Access denied: Target '{:?}' is a symlink", canonical));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & security::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("Access denied: Target '{:?}' is a reparse point", canonical));
        }
    }

    // Block sensitive credential extensions or files
    let file_name = canonical
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if file_name.starts_with("id_rsa") || file_name.starts_with(".ssh") || file_name == "login data" {
        return Err(format!("Access denied: Target '{:?}' is a sensitive file", canonical));
    }

    Ok(canonical)
}

/// Safely walks the user's Downloads, Desktop, Documents, and Videos directories to find
/// files >= min_size_mb * 1024 * 1024 bytes, returning top 100 sorted descending by size.
/// Runs inside a background blocking task with cancellation and progress reporting.
#[tauri::command]
pub async fn scan_large_files(
    app: AppHandle,
    min_size_mb: u64,
) -> Result<Vec<LargeFileItem>, String> {
    CANCEL_REQUESTED.store(false, Ordering::SeqCst);

    tauri::async_runtime::spawn_blocking(move || {
        let min_bytes = min_size_mb.saturating_mul(1024 * 1024);
        let roots = get_user_large_file_roots();
        let total_roots = roots.len();

        let mut found_files: Vec<LargeFileItem> = Vec::new();

        for (idx, root) in roots.iter().enumerate() {
            if CANCEL_REQUESTED.load(Ordering::SeqCst) {
                break;
            }

            let root_name = root
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "User Folder".to_string());

            let pct = if total_roots > 0 {
                ((idx as f64) / (total_roots as f64) * 100.0).round()
            } else {
                0.0
            };

            let _ = app.emit(
                "operation-progress",
                OperationProgress {
                    mode: "scanning".to_string(),
                    current_label: format!("Searching {} for files > {} MB...", root_name, min_size_mb),
                    processed: idx as u64,
                    total: total_roots as u64,
                    percent: pct,
                },
            );

            for entry in WalkDir::new(root).follow_links(false).into_iter().filter_map(|e| e.ok()) {
                if CANCEL_REQUESTED.load(Ordering::SeqCst) {
                    break;
                }

                let p = entry.path();

                if let Ok(meta) = fs::symlink_metadata(p) {
                    // Skip symlinks
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::MetadataExt;
                        let attrs = meta.file_attributes();
                        // Skip junctions / reparse points (0x400)
                        if attrs & security::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                            continue;
                        }
                        // Skip hidden and system files (0x2 = hidden, 0x4 = system)
                        if attrs & 0x2 != 0 || attrs & 0x4 != 0 {
                            continue;
                        }
                    }

                    if meta.is_file() && meta.len() >= min_bytes {
                        let file_name = p
                            .file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_else(|| "Unknown".to_string());

                        // Skip hidden dotfiles
                        if file_name.starts_with('.') {
                            continue;
                        }

                        let extension = p
                            .extension()
                            .map(|ext| ext.to_string_lossy().to_uppercase())
                            .unwrap_or_default();

                        let modified_days_ago = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.elapsed().ok())
                            .map(|d| d.as_secs() / 86400)
                            .unwrap_or(0);

                        let formatted_path = security::strip_unc_prefix(p).to_string_lossy().to_string();

                        found_files.push(LargeFileItem {
                            name: file_name,
                            path: p.to_string_lossy().to_string(),
                            formatted_path,
                            extension,
                            size_bytes: meta.len(),
                            modified_days_ago,
                        });
                    }
                }
            }
        }

        let _ = app.emit(
            "operation-progress",
            OperationProgress {
                mode: "idle".to_string(),
                current_label: "Large Files Search Complete".to_string(),
                processed: total_roots as u64,
                total: total_roots as u64,
                percent: 100.0,
            },
        );

        // Sort descending by size
        found_files.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        found_files.truncate(100);

        Ok(found_files)
    })
    .await
    .map_err(|e| format!("Large file scan execution error: {}", e))?
}

/// Reveals a file in Windows File Explorer using `explorer.exe /select,<path>`.
#[tauri::command]
pub fn reveal_in_explorer(path: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::process::Command;

        let clean_path = security::strip_unc_prefix(Path::new(&path));
        if !clean_path.exists() {
            return Err("Target file does not exist".to_string());
        }

        // Validate that path lives inside user's home profile to prevent opening arbitrary system files
        if let Some(home) = dirs::home_dir() {
            let norm_home = security::normalize_for_comparison(&home);
            let norm_path = security::normalize_for_comparison(&clean_path);
            if !norm_path.starts_with(&norm_home) {
                return Err("Access denied: File is outside user profile".to_string());
            }
        }

        Command::new("explorer.exe")
            .arg(format!("/select,{}", clean_path.display()))
            .spawn()
            .map_err(|e| format!("Failed to spawn Explorer: {}", e))?;

        Ok(())
    }
    #[cfg(not(windows))]
    {
        Err("reveal_in_explorer is only supported on Windows".to_string())
    }
}

/// Deletes selected large files in chunks of 250, moving them to Recycle Bin by default
/// or permanently deleting them, and recording the event in the audit log.
#[tauri::command]
pub async fn delete_large_files(
    app: AppHandle,
    paths: Vec<String>,
    move_to_recycle_bin: bool,
) -> Result<CleanResult, String> {
    CANCEL_REQUESTED.store(false, Ordering::SeqCst);

    tauri::async_runtime::spawn_blocking(move || {
        let start = Instant::now();
        let mut total_freed_bytes = 0u64;
        let mut total_deleted_files = 0u64;
        let mut total_skipped_count = 0u64;
        let mut errors = Vec::new();

        let mut validated_files: Vec<(PathBuf, u64)> = Vec::new();

        for path_str in paths {
            let p = PathBuf::from(&path_str);
            match validate_safe_large_file_target(&p) {
                Ok(safe) => {
                    if let Ok(meta) = fs::metadata(&safe) {
                        validated_files.push((safe, meta.len()));
                    } else {
                        total_skipped_count += 1;
                    }
                }
                Err(err) => {
                    total_skipped_count += 1;
                    errors.push(format!("Zero-Trust rejected file {:?}: {}", p, err));
                }
            }
        }

        let total_files = validated_files.len();
        let mut processed_files = 0usize;

        // Batch deletion in chunks of 250 files
        for chunk in validated_files.chunks(250) {
            if CANCEL_REQUESTED.load(Ordering::SeqCst) {
                break;
            }

            let first_name = chunk
                .first()
                .and_then(|(p, _)| p.file_name())
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".to_string());

            if move_to_recycle_bin {
                let path_bufs: Vec<PathBuf> = chunk.iter().map(|(p, _)| p.clone()).collect();
                if trash::delete_all(&path_bufs).is_ok() {
                    for (_, size) in chunk {
                        total_freed_bytes += size;
                        total_deleted_files += 1;
                    }
                } else {
                    for (file, size) in chunk {
                        match trash::delete(file) {
                            Ok(()) => {
                                total_freed_bytes += size;
                                total_deleted_files += 1;
                            }
                            Err(e) => {
                                total_skipped_count += 1;
                                errors.push(format!("Failed to move {:?} to Recycle Bin: {}", file, e));
                            }
                        }
                    }
                }
            } else {
                for (file, size) in chunk {
                    match fs::remove_file(file) {
                        Ok(()) => {
                            total_freed_bytes += size;
                            total_deleted_files += 1;
                        }
                        Err(e) => {
                            total_skipped_count += 1;
                            errors.push(format!("Failed to remove {:?}: {}", file, e));
                        }
                    }
                }
            }

            processed_files += chunk.len();
            let pct = if total_files > 0 {
                ((processed_files as f64) / (total_files as f64) * 100.0).min(100.0)
            } else {
                100.0
            };

            let _ = app.emit(
                "operation-progress",
                OperationProgress {
                    mode: "cleaning".to_string(),
                    current_label: format!("Deleting: {}", first_name),
                    processed: processed_files as u64,
                    total: total_files as u64,
                    percent: pct,
                },
            );
        }

        let _ = app.emit(
            "operation-progress",
            OperationProgress {
                mode: "idle".to_string(),
                current_label: "File Deletion Complete".to_string(),
                processed: processed_files as u64,
                total: total_files as u64,
                percent: 100.0,
            },
        );

        let duration_ms = start.elapsed().as_millis() as u64;
        let result = CleanResult {
            freed_bytes: total_freed_bytes,
            deleted_files: total_deleted_files,
            skipped_count: total_skipped_count,
            duration_ms,
            cleaned_categories: vec!["large_files".to_string()],
            errors: errors.clone(),
        };

        let audit_entry = AuditLogEntry {
            timestamp: Local::now().to_rfc3339(),
            categories: vec!["large_files".to_string()],
            freed_bytes: total_freed_bytes,
            deleted_files: total_deleted_files,
            skipped_count: total_skipped_count,
            duration_ms,
            use_recycle_bin: move_to_recycle_bin,
            success: errors.is_empty(),
        };
        append_audit_log(&audit_entry);

        Ok(result)
    })
    .await
    .map_err(|e| format!("Large file deletion execution error: {}", e))?
}
