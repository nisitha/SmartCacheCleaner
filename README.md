# SmartCacheCleaner

> High-performance, Zero-Trust Windows cache cleaner and large file utility engineered with Tauri v2, Rust, and modern React.

Developed by **[Pixel Craft Studios](https://www.pixelcraftlk.com)**  
Direct Support (WhatsApp): **+94 78 767 6576**

---

## Overview

SmartCacheCleaner is a commercial-grade desktop utility designed for Windows 10 & 11. Unlike traditional cleaners that rely on risky scripts or black-box wipers, SmartCacheCleaner runs a kernel-aware, zero-trust filesystem engine written in Rust. It eliminates bloated application caches without endangering system stability, personal documents, or browser credentials.

---

## Core Capabilities

### 1. Zero-Trust Security Engine (Rust)
- **Strict Allowlist Verification:** Cleaning targets are validated against an immutable category allowlist. Critical operating system directories, desktop items, personal documents, and credential databases are hard-blocked at the kernel evaluation stage.
- **Symlink & Junction Defense:** Automatically detects and halts traversal across Windows NTFS Reparse Points (`FILE_ATTRIBUTE_REPARSE_POINT` / `0x400`), defending against directory traversal and junction attacks.
- **Recycle Bin Safe Mode:** By default, items are sent to the Windows Recycle Bin for safe recovery, with an optional permanent deletion mode for low-storage scenarios.
- **Tamper-Evident Audit Logging:** Cleaning sessions are logged locally to `%LOCALAPPDATA%\SmartCacheCleaner\audit.log`.

### 2. Comprehensive Cache Targets
- **System & Windows:** Windows Temp (`C:\Windows\Temp`), SoftwareDistribution download cache, and crash dump memory files.
- **User Environment:** `%LOCALAPPDATA%\Temp`, thumbnail caches, and error reporting logs.
- **Web Browsers:** Google Chrome, Microsoft Edge, Brave, and Mozilla Firefox (Code Cache, GPU Cache, Media Cache).
- **GPU & Gaming Shaders:** DirectX shader cache, NVIDIA DXCache/GLCache, and AMD D3DSCache.
- **Social & Creative Media:**
  - WhatsApp Desktop (`LocalCache`, `TempState`)
  - Telegram Desktop media cache (`tdata\user_data\cache` & `media_cache` strictly; root authentication sessions are never touched)
  - CapCut desktop caches & logs
  - Adobe Creative Cloud Common Media Cache files
- **Developer Caches:** npm, yarn, pip, Cargo target caches, Gradle, and Android build caches.

### 3. Large Files Finder
- Locates space-consuming files across user folders (`Downloads`, `Desktop`, `Documents`, `Videos`).
- Dynamic threshold filters: `> 100 MB`, `> 250 MB`, `> 500 MB`, and `> 1 GB`.
- Categorized extension badges (`.ISO`, `.ZIP`, `.MP4`, `.VHD`, etc.).
- Direct integration with Windows Explorer via one-click file reveal.
- Safe deletion with Recycle Bin fallback.

### 4. Commercial Dual-Theme Experience
- **Porcelain Light & Obsidian Dark:** High-contrast, clean UI inspired by Linear and Raycast design aesthetics.
- **Time-Based Automated Scheduling:** Automatically shifts themes based on daytime hours (6:00 AM – 6:00 PM) or locks to manual selection.
- **Native Frosted Transparency:** Utilizes Windows DWM glass effects and custom caption controls.

---

## Technology Architecture

- **Backend:** [Tauri v2](https://v2.tauri.app/), Rust 2021 Edition, Windows API crate (`windows-sys` / `windows`)
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, Lucide React
- **Typography:** Offline bundled `@fontsource/plus-jakarta-sans` and `@fontsource/jetbrains-mono`
- **Security:** Offline execution with zero external network tracking or telemetry

---

## Building from Source

### Prerequisites
1. **Node.js** (v18 or newer)
2. **Rust & Cargo** (stable toolchain with `x86_64-pc-windows-msvc` target)
3. **Microsoft C++ Build Tools** (Visual Studio 2022 with Desktop development with C++)

### Installation & Development Run
```powershell
# Clone the repository
git clone https://github.com/PixelCraftStudios/SmartCacheCleaner.git
cd SmartCacheCleaner

# Install frontend dependencies
npm install

# Launch development environment (hot-reload frontend + Rust debug backend)
npm run tauri dev
```

### Production Release Compilation
```powershell
# Run backend test suite
cargo test --manifest-path src-tauri/Cargo.toml

# Compile optimized Windows release binary and NSIS/MSI installers
npm run tauri build
```
Compiled artifacts are located in:
- Executable: `src-tauri/target/release/SmartCacheCleaner.exe`
- Installer: `src-tauri/target/release/bundle/nsis/SmartCacheCleaner_0.1.0_x64-setup.exe`

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Publisher

**Pixel Craft Studios**  
Website: [www.pixelcraftlk.com](https://www.pixelcraftlk.com)  
Contact: +94 78 767 6576  
Colombo, Sri Lanka
