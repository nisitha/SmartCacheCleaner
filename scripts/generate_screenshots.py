import os
import time
import threading
import http.server
import socketserver
from playwright.sync_api import sync_playwright

PORT = 41740
DIST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dist")
SCREENSHOTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "screenshots")

os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIST_DIR, **kwargs)
    def log_message(self, format, *args):
        pass

socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(("", PORT), Handler)
server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
server_thread.start()
time.sleep(0.5)

mock_js = """
window.__TAURI_INTERNALS__ = {
  invoke: async (cmd, args) => {
    if (cmd === 'is_elevated_admin') return false;
    if (cmd === 'scan_all_caches') {
      return [
        {
          id: 'user_temp',
          name: 'User Temp & App Data',
          description: 'Temporary files, application logs, and cache remnants in user local app data',
          size_bytes: 884736000,
          file_count: 14210,
          requires_admin: false,
          is_installed: true,
          target_paths: ['C:\\\\Users\\\\Nisitha\\\\AppData\\\\Local\\\\Temp'],
          sub_items: [
            { id: 'u1', name: 'Local AppData Temp', display_path: 'AppData\\\\Local\\\\Temp', size_bytes: 620000000, file_count: 10400 },
            { id: 'u2', name: 'Cryptnet URL Cache', display_path: 'AppData\\\\LocalLow\\\\Microsoft\\\\CryptnetUrlCache', size_bytes: 142000000, file_count: 2100 },
            { id: 'u3', name: 'Windows Error Reporting Queue', display_path: 'AppData\\\\Local\\\\Microsoft\\\\Windows\\\\WER', size_bytes: 122736000, file_count: 1710 }
          ],
          scan_duration_ms: 120
        },
        {
          id: 'system_temp',
          name: 'System Temp & Updates',
          description: 'Windows Update delivery caches and system-level temporary files',
          size_bytes: 1524629504,
          file_count: 8940,
          requires_admin: true,
          is_installed: true,
          target_paths: ['C:\\\\Windows\\\\Temp', 'C:\\\\Windows\\\\SoftwareDistribution\\\\Download'],
          sub_items: [
            { id: 's1', name: 'Windows Update Download Cache', display_path: 'Windows\\\\SoftwareDistribution\\\\Download', size_bytes: 1140000000, file_count: 5120 },
            { id: 's2', name: 'Windows System Temp', display_path: 'Windows\\\\Temp', size_bytes: 384629504, file_count: 3820 }
          ],
          scan_duration_ms: 180
        },
        {
          id: 'browser_caches',
          name: 'Web Browser Caches',
          description: 'GPU, Code Cache, and temporary web assets across Chrome, Edge, Brave, and Firefox',
          size_bytes: 1237327872,
          file_count: 12300,
          requires_admin: false,
          is_installed: true,
          target_paths: ['C:\\\\Users\\\\Nisitha\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Cache'],
          sub_items: [
            { id: 'b1', name: 'Google Chrome Web Cache', display_path: 'Google\\\\Chrome\\\\User Data\\\\Default\\\\Cache', size_bytes: 680000000, file_count: 6400 },
            { id: 'b2', name: 'Microsoft Edge Web Cache', display_path: 'Microsoft\\\\Edge\\\\User Data\\\\Default\\\\Cache', size_bytes: 410000000, file_count: 4200 },
            { id: 'b3', name: 'Brave Browser Cache', display_path: 'BraveSoftware\\\\Brave-Browser\\\\User Data\\\\Default\\\\Cache', size_bytes: 147327872, file_count: 1700 }
          ],
          scan_duration_ms: 210
        },
        {
          id: 'gpu_shader_cache',
          name: 'GPU & Shader Cache',
          description: 'DirectX, NVIDIA, AMD, and Vulkan precompiled graphics pipeline caches',
          size_bytes: 402653184,
          file_count: 1420,
          requires_admin: false,
          is_installed: true,
          target_paths: ['C:\\\\Users\\\\Nisitha\\\\AppData\\\\Local\\\\NVIDIA\\\\DXCache'],
          sub_items: [
            { id: 'g1', name: 'NVIDIA DirectX Shader Cache', display_path: 'NVIDIA\\\\DXCache', size_bytes: 260000000, file_count: 920 },
            { id: 'g2', name: 'DirectX Graphics Shader Cache', display_path: 'D3DSCache', size_bytes: 142653184, file_count: 500 }
          ],
          scan_duration_ms: 95
        },
        {
          id: 'social_media',
          name: 'Social & Creative Media',
          description: 'Media cache and temp state from WhatsApp Desktop, Telegram, CapCut, and Adobe CC',
          size_bytes: 817889280,
          file_count: 2840,
          requires_admin: false,
          is_installed: true,
          target_paths: ['C:\\\\Users\\\\Nisitha\\\\AppData\\\\Local\\\\CapCut\\\\User Data\\\\Cache'],
          sub_items: [
            { id: 'sm1', name: 'CapCut Video Cache & Logs', display_path: 'CapCut\\\\User Data\\\\Cache', size_bytes: 390000000, file_count: 1140 },
            { id: 'sm2', name: 'Telegram Desktop Media Cache', display_path: 'Telegram Desktop\\\\tdata\\\\user_data\\\\cache', size_bytes: 240000000, file_count: 980 },
            { id: 'sm3', name: 'WhatsApp Desktop LocalCache', display_path: 'Packages\\\\WhatsAppDesktop\\\\LocalCache', size_bytes: 187889280, file_count: 720 }
          ],
          scan_duration_ms: 110
        },
        {
          id: 'app_dev_caches',
          name: 'App & Dev Caches',
          description: 'Local package registries and build caches for Node/npm, Python pip, Rust Cargo, and Gradle',
          size_bytes: 515899392,
          file_count: 4120,
          requires_admin: false,
          is_installed: true,
          target_paths: ['C:\\\\Users\\\\Nisitha\\\\AppData\\\\Local\\\\npm-cache'],
          sub_items: [
            { id: 'd1', name: 'npm Global Cache', display_path: 'npm-cache', size_bytes: 310000000, file_count: 2800 },
            { id: 'd2', name: 'Python pip Cache', display_path: 'pip\\\\cache', size_bytes: 120000000, file_count: 820 },
            { id: 'd3', name: 'Rust Cargo Registry Cache', display_path: '.cargo\\\\registry\\\\cache', size_bytes: 85899392, file_count: 500 }
          ],
          scan_duration_ms: 130
        },
        {
          id: 'crash_dumps',
          name: 'Crash Dumps & Error Logs',
          description: 'Windows and application memory crash dumps (WER, Minidump)',
          size_bytes: 228589568,
          file_count: 84,
          requires_admin: false,
          is_installed: true,
          target_paths: ['C:\\\\Users\\\\Nisitha\\\\AppData\\\\Local\\\\CrashDumps'],
          sub_items: [
            { id: 'c1', name: 'User Crash Dumps', display_path: 'CrashDumps', size_bytes: 228589568, file_count: 84 }
          ],
          scan_duration_ms: 45
        }
      ];
    }
    if (cmd === 'scan_large_files') {
      return [
        {
          name: 'Windows11_InsiderPreview_Client_x64_en-us_26100.iso',
          path: 'C:\\\\Users\\\\Nisitha\\\\Downloads\\\\Windows11_InsiderPreview_Client_x64_en-us_26100.iso',
          formatted_path: 'Downloads\\\\Windows11_InsiderPreview_Client_x64_en-us_26100.iso',
          extension: '.iso',
          size_bytes: 5175705600,
          modified_days_ago: 14
        },
        {
          name: 'Davinci_Resolve_Studio_19.0_Windows.zip',
          path: 'C:\\\\Users\\\\Nisitha\\\\Downloads\\\\Davinci_Resolve_Studio_19.0_Windows.zip',
          formatted_path: 'Downloads\\\\Davinci_Resolve_Studio_19.0_Windows.zip',
          extension: '.zip',
          size_bytes: 2587852800,
          modified_days_ago: 3
        },
        {
          name: 'UnrealEngine_5.4_LinuxTarget.zip',
          path: 'C:\\\\Users\\\\Nisitha\\\\Documents\\\\UnrealEngine_5.4_LinuxTarget.zip',
          formatted_path: 'Documents\\\\UnrealEngine_5.4_LinuxTarget.zip',
          extension: '.zip',
          size_bytes: 1986422784,
          modified_days_ago: 28
        },
        {
          name: '4K_Cinematic_B-Roll_Master.mp4',
          path: 'C:\\\\Users\\\\Nisitha\\\\Videos\\\\4K_Cinematic_B-Roll_Master.mp4',
          formatted_path: 'Videos\\\\4K_Cinematic_B-Roll_Master.mp4',
          extension: '.mp4',
          size_bytes: 1524629504,
          modified_days_ago: 2
        },
        {
          name: 'Android_Studio_Ladybug_Patch2.exe',
          path: 'C:\\\\Users\\\\Nisitha\\\\Downloads\\\\Android_Studio_Ladybug_Patch2.exe',
          formatted_path: 'Downloads\\\\Android_Studio_Ladybug_Patch2.exe',
          extension: '.exe',
          size_bytes: 1202590720,
          modified_days_ago: 12
        },
        {
          name: 'Docker_Desktop_v4.35_Installer.exe',
          path: 'C:\\\\Users\\\\Nisitha\\\\Downloads\\\\Docker_Desktop_v4.35_Installer.exe',
          formatted_path: 'Downloads\\\\Docker_Desktop_v4.35_Installer.exe',
          extension: '.exe',
          size_bytes: 643825664,
          modified_days_ago: 45
        }
      ];
    }
    if (cmd === 'get_audit_logs') {
      return [];
    }
    return null;
  },
  metadata: {
    windows: [{ label: 'main' }],
    currentWindow: { label: 'main' }
  }
};
"""

with sync_playwright() as p:
    browser = p.chromium.launch(
        executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        args=['--disable-gpu', '--no-sandbox']
    )
    context = browser.new_context(viewport={'width': 1200, 'height': 780}, device_scale_factor=2)

    # 1. Dashboard Light
    page = context.new_page()
    page.add_init_script(mock_js)
    page.add_init_script("localStorage.setItem('smartcache_theme_mode', 'light');")
    page.goto(f'http://localhost:{PORT}/')
    page.wait_for_selector("text=Recoverable System Junk")
    time.sleep(1)
    page.screenshot(path=os.path.join(SCREENSHOTS_DIR, "dashboard-light.png"))
    print("Generated: dashboard-light.png")

    # 2. Dashboard Dark
    page.evaluate("() => { localStorage.setItem('smartcache_theme_mode', 'dark'); document.documentElement.setAttribute('data-theme', 'dark'); }")
    buttons = page.query_selector_all("button")
    for b in buttons:
        if b.inner_text().strip() == "Dark":
            b.click()
            break
    time.sleep(0.5)
    page.screenshot(path=os.path.join(SCREENSHOTS_DIR, "dashboard-dark.png"))
    print("Generated: dashboard-dark.png")

    # 3. Clean View (Porcelain Light Mode)
    page.locator("aside button:has-text('Light')").click()
    time.sleep(0.3)
    page.locator("aside button:has-text('Clean')").click()
    page.wait_for_selector("text=Categories (")
    time.sleep(1)
    page.screenshot(path=os.path.join(SCREENSHOTS_DIR, "clean-caches.png"))
    print("Generated: clean-caches.png")

    # 4. Large Files Finder (Porcelain Light Mode)
    page.locator("aside button:has-text('Large Files')").click()
    page.wait_for_selector("text=Large Files Finder")
    time.sleep(1)
    page.screenshot(path=os.path.join(SCREENSHOTS_DIR, "large-files.png"))
    print("Generated: large-files.png")

    browser.close()

httpd.shutdown()
print("All screenshots successfully generated!")
