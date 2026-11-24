use std::path::{Path, PathBuf};

/// Reparse point / junction attribute mask on Windows (0x400)
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// Hardcoded blocklist of sensitive system, user personal, and browser credential targets.
pub const HARDCODED_BLOCKLIST: &[&str] = &[
    "System32",
    "SysWOW64",
    "WinSxS",
    "Boot",
    "Drivers",
    "Fonts",
    "Resources",
    "Program Files",
    "Documents",
    "Desktop",
    "Pictures",
    "Downloads",
    "Login Data",
    "Bookmarks",
    "Cookies",
    "Local State",
    ".ssh",
];

/// Universal Windows Junk & Cache Cleaner categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheCategory {
    UserTemp,
    SystemTemp,
    GpuShaderCache,
    CrashDumps,
    BrowserCaches,
    AppDevCaches,
    SocialMedia,
}

impl CacheCategory {
    pub fn as_id(&self) -> &'static str {
        match self {
            CacheCategory::UserTemp => "user_temp",
            CacheCategory::SystemTemp => "system_temp",
            CacheCategory::GpuShaderCache => "gpu_shader_cache",
            CacheCategory::CrashDumps => "crash_dumps",
            CacheCategory::BrowserCaches => "browser_caches",
            CacheCategory::AppDevCaches => "app_dev_caches",
            CacheCategory::SocialMedia => "social_media",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "user_temp" => Some(CacheCategory::UserTemp),
            "system_temp" => Some(CacheCategory::SystemTemp),
            "gpu_shader_cache" => Some(CacheCategory::GpuShaderCache),
            "crash_dumps" => Some(CacheCategory::CrashDumps),
            "browser_caches" => Some(CacheCategory::BrowserCaches),
            "app_dev_caches" => Some(CacheCategory::AppDevCaches),
            "social_media" => Some(CacheCategory::SocialMedia),
            _ => None,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            CacheCategory::UserTemp => "User Temporary Files",
            CacheCategory::SystemTemp => "System Temp & Windows Update Cache",
            CacheCategory::GpuShaderCache => "GPU Shader Cache",
            CacheCategory::CrashDumps => "Crash Dumps & Error Reports",
            CacheCategory::BrowserCaches => "Web Browser Caches",
            CacheCategory::AppDevCaches => "Application & Developer Caches",
            CacheCategory::SocialMedia => "Social & Creative Caches",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            CacheCategory::UserTemp => "Temporary application scratch files in %TEMP% (%LOCALAPPDATA%\\Temp).",
            CacheCategory::SystemTemp => "Windows system temp and downloaded update installer files (Requires Admin).",
            CacheCategory::GpuShaderCache => "Precompiled DirectX/Vulkan shader caches from DirectX, NVIDIA, AMD, and Intel.",
            CacheCategory::CrashDumps => "Application crash memory dumps and Windows Error Reporting (WER) queue files.",
            CacheCategory::BrowserCaches => "Web cache, code cache, and GPU cache from Chrome, Edge, Brave, Opera, and Firefox.",
            CacheCategory::AppDevCaches => "Package manager & app caches (npm, pip, Discord).",
            CacheCategory::SocialMedia => "Media & scratch caches from WhatsApp Desktop, Telegram media, CapCut, and Adobe Creative Cloud.",
        }
    }

    pub fn requires_admin(&self) -> bool {
        matches!(self, CacheCategory::SystemTemp)
    }
}

/// Helper to strip the Windows UNC / verbatim prefix (`\\?\` or `\\?\UNC\`) for uniform path operations.
pub fn strip_unc_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{}", stripped))
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

/// Normalizes a path for case-insensitive and prefix-independent path comparisons on Windows.
pub fn normalize_for_comparison(path: &Path) -> PathBuf {
    let stripped = strip_unc_prefix(path);
    PathBuf::from(stripped.to_string_lossy().to_lowercase())
}

/// Rule 4: Hardcoded Blocklist & Strict Windows Directory Containment.
/// Explicitly rejects:
/// - Any path containing `System32`, `SysWOW64`, `WinSxS`, `Boot`, `Drivers`, `Fonts`, `Resources`,
///   `Program Files`, `Documents`, `Desktop`, `Pictures`, `Downloads`, `Login Data`, `Bookmarks`,
///   `Cookies`, `Local State`, or `.ssh`.
/// - ANY path located inside `C:\Windows` that is NOT strictly inside `C:\Windows\Temp` or
///   `C:\Windows\SoftwareDistribution\Download`.
pub fn check_blocklist(path: &Path) -> Result<(), String> {
    let path_str = path.to_string_lossy();
    let lower_path = path_str.to_lowercase();

    // 1. Keyword containment check across the full path string
    for &blocked in HARDCODED_BLOCKLIST {
        let blocked_lower = blocked.to_lowercase();
        if lower_path.contains(&blocked_lower) {
            return Err(format!(
                "Access denied by blocklist: Path contains blocked pattern '{}' in '{:?}'",
                blocked, path
            ));
        }
    }

    // 2. Component-level check to catch exact folder name matches
    for component in path.components() {
        let comp_str = component.as_os_str().to_string_lossy().to_lowercase();
        for &blocked in HARDCODED_BLOCKLIST {
            let blocked_lower = blocked.to_lowercase();
            if comp_str == blocked_lower || comp_str.contains(&blocked_lower) {
                return Err(format!(
                    "Access denied by blocklist: Path component contains blocked pattern '{}' in '{:?}'",
                    blocked, path
                ));
            }
        }
    }

    // 3. Strict Windows directory containment guardrail:
    // If the path resides inside C:\Windows (%SystemRoot%), it MUST be inside Temp or SoftwareDistribution\Download
    let win_root_str = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let win_root = Path::new(&win_root_str);
    let norm_win_root = normalize_for_comparison(win_root);
    let norm_path = normalize_for_comparison(path);

    if norm_path.starts_with(&norm_win_root) {
        let norm_temp = normalize_for_comparison(&win_root.join("Temp"));
        let norm_soft_dist = normalize_for_comparison(&win_root.join("SoftwareDistribution").join("Download"));

        let inside_temp = norm_path.starts_with(&norm_temp);
        let inside_soft_dist = norm_path.starts_with(&norm_soft_dist);

        if !inside_temp && !inside_soft_dist {
            return Err(format!(
                "Access denied by Windows directory guardrail: Path '{:?}' is in Windows system root but not in Temp or SoftwareDistribution\\Download",
                path
            ));
        }
    }

    Ok(())
}

/// Rule 2: Symlink & Windows Junction Trap Protection.
/// Checks `std::os::windows::fs::MetadataExt::file_attributes()` and `is_symlink()`,
/// immediately rejecting any file or directory containing `FILE_ATTRIBUTE_REPARSE_POINT` (`0x400`)
/// or `is_symlink()`.
/// Inspects both the path itself and all existing ancestor directories.
pub fn check_symlinks_and_reparse_points(path: &Path) -> Result<(), String> {
    // 1. Inspect target path itself if it exists
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!("Access denied: Target path is a symlink: {:?}", path));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(format!(
                    "Access denied: Target path contains FILE_ATTRIBUTE_REPARSE_POINT (0x400 / junction): {:?}",
                    path
                ));
            }
        }
    }

    // 2. Inspect all existing ancestor directories up to filesystem root
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() || ancestor == Path::new("") {
            continue;
        }
        if let Ok(meta) = std::fs::symlink_metadata(ancestor) {
            if meta.file_type().is_symlink() {
                return Err(format!("Access denied: Ancestor path is a symlink: {:?}", ancestor));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(format!(
                        "Access denied: Ancestor path contains FILE_ATTRIBUTE_REPARSE_POINT (0x400 / junction): {:?}",
                        ancestor
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Rule 3: Universal Windows Allowlist Enforcement.
/// Verifies that the target path resides strictly inside one of these universal allowed roots:
/// - `user_temp`: `%TEMP%` (`%LOCALAPPDATA%\Temp`)
/// - `system_temp`: `C:\Windows\Temp` and `C:\Windows\SoftwareDistribution\Download`
/// - `gpu_shader_cache`: `%LOCALAPPDATA%\D3DSCache`, `%LOCALAPPDATA%\NVIDIA\DXCache`,
///   `%LOCALAPPDATA%\NVIDIA\GLCache`, `%LOCALAPPDATA%\AMD\DxCache`, `%LOCALAPPDATA%\Intel\ShaderCache`
/// - `crash_dumps`: `%LOCALAPPDATA%\CrashDumps`, `%LOCALAPPDATA%\Microsoft\Windows\WER`,
///   `%LOCALAPPDATA%\Microsoft\Windows\INetCache`
/// - `browser_caches`: Chrome, Edge, Brave, Opera (`%APPDATA%\Opera Software\Opera Stable`),
///   and Firefox (`%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2`) — cache folders ONLY.
/// - `app_dev_caches`: `%LOCALAPPDATA%\npm-cache`, `%LOCALAPPDATA%\pip\Cache`,
///   `%APPDATA%\discord\Cache`, `%APPDATA%\discord\Code Cache`, `%APPDATA%\Adobe\Common\Media Cache Files`.
pub fn verify_allowlist(target_path: &Path) -> Result<(), String> {
    let norm_target = normalize_for_comparison(target_path);

    // 1. Check %TEMP%
    let temp_root = std::env::temp_dir();
    let norm_temp = normalize_for_comparison(&temp_root);
    if norm_target.starts_with(&norm_temp) {
        return Ok(());
    }

    // 2. Check system_temp: C:\Windows\Temp & C:\Windows\SoftwareDistribution\Download
    let win_root_str = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let win_root = Path::new(&win_root_str);
    let norm_win_temp = normalize_for_comparison(&win_root.join("Temp"));
    let norm_soft_dist = normalize_for_comparison(&win_root.join("SoftwareDistribution").join("Download"));

    if norm_target.starts_with(&norm_win_temp) || norm_target.starts_with(&norm_soft_dist) {
        return Ok(());
    }

    // 3. Check %LOCALAPPDATA% roots
    if let Some(local_appdata) = dirs::data_local_dir() {
        let norm_local = normalize_for_comparison(&local_appdata);
        if let Ok(rel) = norm_target.strip_prefix(&norm_local) {
            let components: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect();

            if !components.is_empty() {
                // GPU Shader Caches
                // %LOCALAPPDATA%\D3DSCache
                if components[0] == "d3dscache" {
                    return Ok(());
                }
                // %LOCALAPPDATA%\NVIDIA\DXCache & GLCache
                if components.len() >= 2
                    && components[0] == "nvidia"
                    && (components[1] == "dxcache" || components[1] == "glcache")
                {
                    return Ok(());
                }
                // %LOCALAPPDATA%\AMD\DxCache
                if components.len() >= 2 && components[0] == "amd" && components[1] == "dxcache" {
                    return Ok(());
                }
                // %LOCALAPPDATA%\Intel\ShaderCache
                if components.len() >= 2 && components[0] == "intel" && components[1] == "shadercache" {
                    return Ok(());
                }

                // Crash Dumps & Diagnostic Caches
                // %LOCALAPPDATA%\CrashDumps
                if components[0] == "crashdumps" {
                    return Ok(());
                }
                // %LOCALAPPDATA%\Microsoft\Windows\WER & INetCache
                if components.len() >= 3
                    && components[0] == "microsoft"
                    && components[1] == "windows"
                    && (components[2] == "wer" || components[2] == "inetcache")
                {
                    return Ok(());
                }

                // App & Dev Caches
                // %LOCALAPPDATA%\npm-cache
                if components[0] == "npm-cache" {
                    return Ok(());
                }
                // %LOCALAPPDATA%\pip\Cache
                if components.len() >= 2 && components[0] == "pip" && components[1] == "cache" {
                    return Ok(());
                }

                // Social & Creative Media Caches under LocalAppData:
                // WhatsApp Desktop: %LOCALAPPDATA%\Packages\5319275A.WhatsAppDesktop_*\LocalCache or TempState
                if components.len() >= 3
                    && components[0] == "packages"
                    && components[1].starts_with("5319275a.whatsappdesktop")
                    && (components[2] == "localcache" || components[2] == "tempstate")
                {
                    return Ok(());
                }

                // CapCut: %LOCALAPPDATA%\CapCut\User Data\(Cache|log)
                if components.len() >= 3
                    && components[0] == "capcut"
                    && components[1] == "user data"
                    && (components[2] == "cache" || components[2] == "log")
                {
                    return Ok(());
                }

                // Browser Caches under LocalAppData:
                // Google Chrome: %LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\(Cache|Code Cache|GPUCache)
                if components.len() >= 5
                    && components[0] == "google"
                    && components[1] == "chrome"
                    && components[2] == "user data"
                {
                    let cache_type = &components[4];
                    if cache_type == "cache" || cache_type == "code cache" || cache_type == "gpucache" {
                        return Ok(());
                    }
                }

                // Microsoft Edge:
                // %LOCALAPPDATA%\Microsoft\Edge\User Data\<Profile>\(Cache|Code Cache|GPUCache|component_crx_cache)
                // or component_crx_cache directly under User Data
                if components.len() >= 4
                    && components[0] == "microsoft"
                    && components[1] == "edge"
                    && components[2] == "user data"
                {
                    if components[3] == "component_crx_cache" {
                        return Ok(());
                    }
                    if components.len() >= 5 {
                        let cache_type = &components[4];
                        if cache_type == "cache"
                            || cache_type == "code cache"
                            || cache_type == "gpucache"
                            || cache_type == "component_crx_cache"
                        {
                            return Ok(());
                        }
                    }
                }

                // Brave Browser:
                // %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\<Profile>\(Cache|Code Cache|GPUCache)
                if components.len() >= 5
                    && components[0] == "bravesoftware"
                    && components[1] == "brave-browser"
                    && components[2] == "user data"
                {
                    let cache_type = &components[4];
                    if cache_type == "cache" || cache_type == "code cache" || cache_type == "gpucache" {
                        return Ok(());
                    }
                }

                // Mozilla Firefox:
                // %LOCALAPPDATA%\Mozilla\Firefox\Profiles\<Profile>\cache2
                if components.len() >= 5
                    && components[0] == "mozilla"
                    && components[1] == "firefox"
                    && components[2] == "profiles"
                    && components[4] == "cache2"
                {
                    return Ok(());
                }

                // Opera Stable under LocalAppData (if present):
                if components.len() >= 3
                    && components[0] == "opera software"
                    && components[1] == "opera stable"
                {
                    let cache_type = &components[2];
                    if cache_type == "cache" || cache_type == "code cache" || cache_type == "gpucache" {
                        return Ok(());
                    }
                }
            }
        }
    }

    // 4. Check %APPDATA% (Roaming) roots
    if let Some(roaming_appdata) = dirs::config_dir() {
        let norm_roaming = normalize_for_comparison(&roaming_appdata);
        if let Ok(rel) = norm_target.strip_prefix(&norm_roaming) {
            let components: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect();

            if !components.is_empty() {
                // Opera Stable: %APPDATA%\Opera Software\Opera Stable\(Cache|Code Cache|GPUCache)
                if components.len() >= 3
                    && components[0] == "opera software"
                    && components[1] == "opera stable"
                {
                    let cache_type = &components[2];
                    if cache_type == "cache" || cache_type == "code cache" || cache_type == "gpucache" {
                        return Ok(());
                    }
                }

                // Discord Caches: %APPDATA%\discord\Cache & %APPDATA%\discord\Code Cache
                if components.len() >= 2
                    && components[0] == "discord"
                    && (components[1] == "cache" || components[1] == "code cache")
                {
                    return Ok(());
                }

                // Telegram Desktop Media Caches: %APPDATA%\Telegram Desktop\tdata\user_data\(cache|media_cache)
                // STRICTLY NEVER touch root tdata session/auth files
                if components.len() >= 4
                    && components[0] == "telegram desktop"
                    && components[1] == "tdata"
                    && components[2] == "user_data"
                    && (components[3] == "cache" || components[3] == "media_cache")
                {
                    return Ok(());
                }

                // Adobe Media Cache Files & Media Cache: %APPDATA%\Adobe\Common\(Media Cache Files|Media Cache)
                if components.len() >= 3
                    && components[0] == "adobe"
                    && components[1] == "common"
                    && (components[2] == "media cache files" || components[2] == "media cache")
                {
                    return Ok(());
                }
            }
        }
    }

    Err(format!(
        "Access denied: Target path '{:?}' does not match any universal allowed cache root",
        target_path
    ))
}

/// Rule 2 & Full Zero-Trust Pipeline:
/// Canonicalizes paths, validates symlinks / junction reparse points (`0x400`),
/// and strictly verifies against blocklist and universal allowlist.
pub fn validate_safe_target(path: &Path) -> Result<PathBuf, String> {
    // 1. Raw input blocklist check
    check_blocklist(path)?;

    // 2. Symlink & Windows Junction Trap Protection on pre-canonicalized path & ancestors
    check_symlinks_and_reparse_points(path)?;

    // 3. Canonicalize path
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("Failed to canonicalize path {:?}: {}", path, e))?;

    // 4. Blocklist check on canonicalized path (catches any resolved traversal)
    check_blocklist(&canonical)?;

    // 5. Reparse point and symlink check on canonicalized path
    check_symlinks_and_reparse_points(&canonical)?;

    // 6. Strict allowlist enforcement
    verify_allowlist(&canonical)?;

    Ok(canonical)
}

/// Discovers all existing safe target paths for a specific CacheCategory.
pub fn resolve_category_base_paths(category: CacheCategory) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    match category {
        CacheCategory::UserTemp => {
            let temp = std::env::temp_dir();
            if temp.exists() {
                if let Ok(safe) = validate_safe_target(&temp) {
                    paths.push(safe);
                }
            }
        }
        CacheCategory::SystemTemp => {
            let win_root_str = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
            let win_root = PathBuf::from(win_root_str);

            let win_temp = win_root.join("Temp");
            if win_temp.exists() {
                if let Ok(safe) = validate_safe_target(&win_temp) {
                    paths.push(safe);
                }
            }

            let soft_dist = win_root.join("SoftwareDistribution").join("Download");
            if soft_dist.exists() {
                if let Ok(safe) = validate_safe_target(&soft_dist) {
                    paths.push(safe);
                }
            }
        }
        CacheCategory::GpuShaderCache => {
            if let Some(local_appdata) = dirs::data_local_dir() {
                let candidates = [
                    local_appdata.join("D3DSCache"),
                    local_appdata.join("NVIDIA").join("DXCache"),
                    local_appdata.join("NVIDIA").join("GLCache"),
                    local_appdata.join("AMD").join("DxCache"),
                    local_appdata.join("Intel").join("ShaderCache"),
                ];
                for cand in candidates {
                    if cand.exists() {
                        if let Ok(safe) = validate_safe_target(&cand) {
                            paths.push(safe);
                        }
                    }
                }
            }
        }
        CacheCategory::CrashDumps => {
            if let Some(local_appdata) = dirs::data_local_dir() {
                let candidates = [
                    local_appdata.join("CrashDumps"),
                    local_appdata.join("Microsoft").join("Windows").join("WER"),
                    local_appdata.join("Microsoft").join("Windows").join("INetCache"),
                ];
                for cand in candidates {
                    if cand.exists() {
                        if let Ok(safe) = validate_safe_target(&cand) {
                            paths.push(safe);
                        }
                    }
                }
            }
        }
        CacheCategory::BrowserCaches => {
            if let Some(local_appdata) = dirs::data_local_dir() {
                // Chromium-based browsers: Chrome, Edge, Brave
                let browsers = [
                    local_appdata.join("Google").join("Chrome").join("User Data"),
                    local_appdata.join("Microsoft").join("Edge").join("User Data"),
                    local_appdata.join("BraveSoftware").join("Brave-Browser").join("User Data"),
                ];

                for user_data in browsers {
                    if !user_data.exists() {
                        continue;
                    }

                    // Check for Edge component_crx_cache directly under User Data
                    let crx_cache = user_data.join("component_crx_cache");
                    if crx_cache.exists() {
                        if let Ok(safe) = validate_safe_target(&crx_cache) {
                            paths.push(safe);
                        }
                    }

                    if let Ok(entries) = std::fs::read_dir(&user_data) {
                        for entry in entries.flatten() {
                            let p = entry.path();
                            if p.is_dir() {
                                for sub in ["Cache", "Code Cache", "GPUCache", "component_crx_cache"] {
                                    let cache_dir = p.join(sub);
                                    if cache_dir.exists() {
                                        if let Ok(safe) = validate_safe_target(&cache_dir) {
                                            paths.push(safe);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Firefox cache2
                let firefox_profiles = local_appdata.join("Mozilla").join("Firefox").join("Profiles");
                if firefox_profiles.exists() {
                    if let Ok(entries) = std::fs::read_dir(&firefox_profiles) {
                        for entry in entries.flatten() {
                            let cache2 = entry.path().join("cache2");
                            if cache2.exists() {
                                if let Ok(safe) = validate_safe_target(&cache2) {
                                    paths.push(safe);
                                }
                            }
                        }
                    }
                }
            }

            // Opera Stable in Roaming
            if let Some(roaming) = dirs::config_dir() {
                let opera_stable = roaming.join("Opera Software").join("Opera Stable");
                if opera_stable.exists() {
                    for sub in ["Cache", "Code Cache", "GPUCache"] {
                        let cache_dir = opera_stable.join(sub);
                        if cache_dir.exists() {
                            if let Ok(safe) = validate_safe_target(&cache_dir) {
                                paths.push(safe);
                            }
                        }
                    }
                }
            }
        }
        CacheCategory::AppDevCaches => {
            if let Some(local_appdata) = dirs::data_local_dir() {
                let npm_cache = local_appdata.join("npm-cache");
                if npm_cache.exists() {
                    if let Ok(safe) = validate_safe_target(&npm_cache) {
                        paths.push(safe);
                    }
                }

                let pip_cache = local_appdata.join("pip").join("Cache");
                if pip_cache.exists() {
                    if let Ok(safe) = validate_safe_target(&pip_cache) {
                        paths.push(safe);
                    }
                }
            }

            if let Some(roaming) = dirs::config_dir() {
                let discord_cache = roaming.join("discord").join("Cache");
                if discord_cache.exists() {
                    if let Ok(safe) = validate_safe_target(&discord_cache) {
                        paths.push(safe);
                    }
                }

                let discord_code_cache = roaming.join("discord").join("Code Cache");
                if discord_code_cache.exists() {
                    if let Ok(safe) = validate_safe_target(&discord_code_cache) {
                        paths.push(safe);
                    }
                }

                let adobe_media_cache = roaming
                    .join("Adobe")
                    .join("Common")
                    .join("Media Cache Files");
                if adobe_media_cache.exists() {
                    if let Ok(safe) = validate_safe_target(&adobe_media_cache) {
                        paths.push(safe);
                    }
                }
            }
        }
        CacheCategory::SocialMedia => {
            if let Some(local_appdata) = dirs::data_local_dir() {
                // WhatsApp Desktop
                let packages_dir = local_appdata.join("Packages");
                if packages_dir.exists() {
                    if let Ok(entries) = std::fs::read_dir(&packages_dir) {
                        for entry in entries.flatten() {
                            let name = entry.file_name().to_string_lossy().to_lowercase();
                            if name.starts_with("5319275a.whatsappdesktop") {
                                for sub in ["LocalCache", "TempState"] {
                                    let p = entry.path().join(sub);
                                    if p.exists() {
                                        if let Ok(safe) = validate_safe_target(&p) {
                                            paths.push(safe);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // CapCut Cache & Logs
                let capcut_user_data = local_appdata.join("CapCut").join("User Data");
                if capcut_user_data.exists() {
                    for sub in ["Cache", "log"] {
                        let p = capcut_user_data.join(sub);
                        if p.exists() {
                            if let Ok(safe) = validate_safe_target(&p) {
                                paths.push(safe);
                            }
                        }
                    }
                }
            }

            if let Some(roaming) = dirs::config_dir() {
                // Telegram Desktop media caches ONLY (STRICTLY user_data\cache and user_data\media_cache)
                let telegram_user_data = roaming.join("Telegram Desktop").join("tdata").join("user_data");
                if telegram_user_data.exists() {
                    for sub in ["cache", "media_cache"] {
                        let p = telegram_user_data.join(sub);
                        if p.exists() {
                            if let Ok(safe) = validate_safe_target(&p) {
                                paths.push(safe);
                            }
                        }
                    }
                }

                // Adobe Common Media Cache
                let adobe_common = roaming.join("Adobe").join("Common");
                if adobe_common.exists() {
                    for sub in ["Media Cache Files", "Media Cache"] {
                        let p = adobe_common.join(sub);
                        if p.exists() {
                            if let Ok(safe) = validate_safe_target(&p) {
                                paths.push(safe);
                            }
                        }
                    }
                }
            }
        }
    }

    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_universal_social_media_allowlist() {
        if let Some(local_appdata) = dirs::data_local_dir() {
            // WhatsApp Desktop
            let wa_cache = local_appdata
                .join("Packages")
                .join("5319275A.WhatsAppDesktop_cv1g1gvanyjgm")
                .join("LocalCache");
            assert!(verify_allowlist(&wa_cache).is_ok());

            let wa_temp = local_appdata
                .join("Packages")
                .join("5319275A.WhatsAppDesktop_cv1g1gvanyjgm")
                .join("TempState");
            assert!(verify_allowlist(&wa_temp).is_ok());

            // CapCut
            let capcut_cache = local_appdata.join("CapCut").join("User Data").join("Cache");
            assert!(verify_allowlist(&capcut_cache).is_ok());
            let capcut_log = local_appdata.join("CapCut").join("User Data").join("log");
            assert!(verify_allowlist(&capcut_log).is_ok());
        }

        if let Some(roaming) = dirs::config_dir() {
            // Telegram Desktop media caches ONLY
            let tg_cache = roaming
                .join("Telegram Desktop")
                .join("tdata")
                .join("user_data")
                .join("cache");
            assert!(verify_allowlist(&tg_cache).is_ok());

            let tg_media = roaming
                .join("Telegram Desktop")
                .join("tdata")
                .join("user_data")
                .join("media_cache");
            assert!(verify_allowlist(&tg_media).is_ok());

            // STRICT REJECTION: root tdata and auth files must be rejected
            let tg_root = roaming.join("Telegram Desktop").join("tdata");
            assert!(verify_allowlist(&tg_root).is_err());
            let tg_auth = roaming
                .join("Telegram Desktop")
                .join("tdata")
                .join("D877F783D5D3EF8C");
            assert!(verify_allowlist(&tg_auth).is_err());

            // Adobe Media Cache Files & Media Cache
            assert!(verify_allowlist(&roaming.join("Adobe").join("Common").join("Media Cache Files")).is_ok());
            assert!(verify_allowlist(&roaming.join("Adobe").join("Common").join("Media Cache")).is_ok());
        }
    }

    #[test]
    fn test_valid_user_temp_passes() {
        let temp_dir = std::env::temp_dir();
        let test_folder = temp_dir.join("pc_cleaner_security_unit_test_user_temp");
        fs::create_dir_all(&test_folder).expect("Failed to create test folder");

        let test_file = test_folder.join("test_file.tmp");
        fs::write(&test_file, b"temp data").expect("Failed to write test file");

        assert!(validate_safe_target(&test_folder).is_ok());
        assert!(validate_safe_target(&test_file).is_ok());

        let _ = fs::remove_file(&test_file);
        let _ = fs::remove_dir(&test_folder);
    }

    #[test]
    fn test_system_temp_allowed_and_other_windows_blocked() {
        let win_temp = Path::new(r"C:\Windows\Temp");
        // C:\Windows\Temp passes allowlist and blocklist
        assert!(
            verify_allowlist(win_temp).is_ok(),
            "C:\\Windows\\Temp should be allowed in universal allowlist"
        );
        assert!(
            check_blocklist(win_temp).is_ok(),
            "C:\\Windows\\Temp should pass blocklist check"
        );

        let soft_dist = Path::new(r"C:\Windows\SoftwareDistribution\Download");
        assert!(
            verify_allowlist(soft_dist).is_ok(),
            "SoftwareDistribution\\Download should be allowed"
        );
        assert!(
            check_blocklist(soft_dist).is_ok(),
            "SoftwareDistribution\\Download should pass blocklist check"
        );

        // Crucial: verify other paths in C:\Windows are strictly rejected
        let blocked_win_paths = [
            Path::new(r"C:\Windows\System32"),
            Path::new(r"C:\Windows\SysWOW64"),
            Path::new(r"C:\Windows\WinSxS"),
            Path::new(r"C:\Windows\Boot"),
            Path::new(r"C:\Windows\Fonts"),
            Path::new(r"C:\Windows\Resources"),
            Path::new(r"C:\Windows\explorer.exe"),
            Path::new(r"C:\Windows\notepad.exe"),
            Path::new(r"C:\Windows\Web"),
            Path::new(r"C:\Windows\INF"),
        ];

        for &path in &blocked_win_paths {
            assert!(
                check_blocklist(path).is_err(),
                "Path {:?} must be strictly blocked by Windows guardrail",
                path
            );
            assert!(
                verify_allowlist(path).is_err(),
                "Path {:?} must not be in universal allowlist",
                path
            );
        }
    }

    #[test]
    fn test_reject_user_personal_data_and_credentials() {
        let sensitive_paths = [
            Path::new(r"C:\Users\JohnDoe\Documents\TaxReport.pdf"),
            Path::new(r"C:\Users\JohnDoe\Desktop\Private.docx"),
            Path::new(r"C:\Users\JohnDoe\Pictures\Vacation.jpg"),
            Path::new(r"C:\Users\JohnDoe\Downloads\setup.exe"),
            Path::new(r"C:\Users\JohnDoe\.ssh\id_rsa"),
            Path::new(r"C:\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Login Data"),
            Path::new(r"C:\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"),
            Path::new(r"C:\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Cookies"),
            Path::new(r"C:\Users\JohnDoe\AppData\Local\Google\Chrome\User Data\Default\Local State"),
            Path::new(r"C:\Program Files\Common Files\Services.exe"),
            Path::new(r"C:\Program Files (x86)\App\Config.xml"),
        ];

        for &path in &sensitive_paths {
            assert!(
                check_blocklist(path).is_err(),
                "Path {:?} must be rejected by blocklist",
                path
            );
            assert!(
                validate_safe_target(path).is_err(),
                "Path {:?} must be rejected by validate_safe_target",
                path
            );
        }
    }

    #[test]
    fn test_universal_gpu_shader_cache_allowlist() {
        if let Some(local_appdata) = dirs::data_local_dir() {
            let paths = [
                local_appdata.join("D3DSCache"),
                local_appdata.join("NVIDIA").join("DXCache"),
                local_appdata.join("NVIDIA").join("GLCache"),
                local_appdata.join("AMD").join("DxCache"),
                local_appdata.join("Intel").join("ShaderCache"),
            ];
            for p in &paths {
                assert!(
                    verify_allowlist(p).is_ok(),
                    "GPU shader cache {:?} must pass allowlist",
                    p
                );
            }
        }
    }

    #[test]
    fn test_universal_crash_dumps_allowlist() {
        if let Some(local_appdata) = dirs::data_local_dir() {
            let paths = [
                local_appdata.join("CrashDumps"),
                local_appdata.join("Microsoft").join("Windows").join("WER"),
                local_appdata.join("Microsoft").join("Windows").join("INetCache"),
            ];
            for p in &paths {
                assert!(
                    verify_allowlist(p).is_ok(),
                    "Crash dump path {:?} must pass allowlist",
                    p
                );
            }
        }
    }

    #[test]
    fn test_universal_browser_caches_allowlist() {
        if let Some(local_appdata) = dirs::data_local_dir() {
            // Chrome
            assert!(verify_allowlist(&local_appdata.join("Google").join("Chrome").join("User Data").join("Default").join("Cache")).is_ok());
            assert!(verify_allowlist(&local_appdata.join("Google").join("Chrome").join("User Data").join("Profile 1").join("Code Cache")).is_ok());
            assert!(verify_allowlist(&local_appdata.join("Google").join("Chrome").join("User Data").join("Default").join("GPUCache")).is_ok());

            // Edge
            assert!(verify_allowlist(&local_appdata.join("Microsoft").join("Edge").join("User Data").join("Default").join("Cache")).is_ok());
            assert!(verify_allowlist(&local_appdata.join("Microsoft").join("Edge").join("User Data").join("component_crx_cache")).is_ok());

            // Brave
            assert!(verify_allowlist(&local_appdata.join("BraveSoftware").join("Brave-Browser").join("User Data").join("Default").join("Cache")).is_ok());

            // Firefox
            assert!(verify_allowlist(&local_appdata.join("Mozilla").join("Firefox").join("Profiles").join("xyz.default-release").join("cache2")).is_ok());

            // Rejection of browser root/profiles
            assert!(verify_allowlist(&local_appdata.join("Google").join("Chrome").join("User Data").join("Default")).is_err());
            assert!(verify_allowlist(&local_appdata.join("Mozilla").join("Firefox").join("Profiles").join("xyz.default-release")).is_err());
        }

        if let Some(roaming) = dirs::config_dir() {
            // Opera Stable
            assert!(verify_allowlist(&roaming.join("Opera Software").join("Opera Stable").join("Cache")).is_ok());
            assert!(verify_allowlist(&roaming.join("Opera Software").join("Opera Stable").join("Code Cache")).is_ok());
            assert!(verify_allowlist(&roaming.join("Opera Software").join("Opera Stable")).is_err());
        }
    }

    #[test]
    fn test_universal_app_dev_caches_allowlist() {
        if let Some(local_appdata) = dirs::data_local_dir() {
            assert!(verify_allowlist(&local_appdata.join("npm-cache")).is_ok());
            assert!(verify_allowlist(&local_appdata.join("pip").join("Cache")).is_ok());
        }

        if let Some(roaming) = dirs::config_dir() {
            assert!(verify_allowlist(&roaming.join("discord").join("Cache")).is_ok());
            assert!(verify_allowlist(&roaming.join("discord").join("Code Cache")).is_ok());
            assert!(verify_allowlist(&roaming.join("Adobe").join("Common").join("Media Cache Files")).is_ok());
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_reject_windows_junction_trap() {
        let temp_dir = std::env::temp_dir();
        let target_dir = temp_dir.join("pc_cleaner_security_test_junction_target");
        let junction_dir = temp_dir.join("pc_cleaner_security_test_junction_link");

        let _ = fs::remove_dir_all(&junction_dir);
        let _ = fs::remove_dir_all(&target_dir);

        fs::create_dir_all(&target_dir).expect("Failed to create target dir");

        let output = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                junction_dir.to_str().unwrap(),
                target_dir.to_str().unwrap(),
            ])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                let res = validate_safe_target(&junction_dir);
                assert!(
                    res.is_err(),
                    "Expected Windows Junction to be rejected, got {:?}",
                    res
                );

                let _ = std::process::Command::new("cmd")
                    .args(["/c", "rmdir", junction_dir.to_str().unwrap()])
                    .output();
            }
        }

        let _ = fs::remove_dir_all(&target_dir);
    }
}
