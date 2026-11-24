import { useState, useEffect, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

interface OperationProgress {
  mode: "scanning" | "cleaning" | "idle";
  current_label: string;
  processed: number;
  total: number;
  percent: number;
}
import {
  LayoutDashboard,
  Sparkles,
  PieChart,
  History,
  Settings as SettingsIcon,
  ShieldCheck,
  RefreshCw,
  Folder,
  Trash2,
  Globe,
  Zap,
  AlertCircle,
  Terminal,
  Cpu,
  FileCode,
  ShieldAlert,
  CheckCircle2,
  X,
  Check,
  Minus,
  Square,
  ArrowUpRight,
  Sun,
  Moon,
  Clock,
  ChevronRight,
  Copy,
  FileSearch,
  FolderOpen,
  Film,
} from "lucide-react";

interface SubTargetItem {
  id: string;
  name: string;
  display_path: string;
  size_bytes: number;
  file_count: number;
}

interface LargeFileItem {
  name: string;
  path: string;
  formatted_path: string;
  extension: string;
  size_bytes: number;
  modified_days_ago: number;
}

interface CategoryScanResult {
  id: string;
  name: string;
  description: string;
  size_bytes: number;
  file_count: number;
  requires_admin: boolean;
  is_installed: boolean;
  target_paths: string[];
  sub_items: SubTargetItem[];
  scan_duration_ms: number;
}

interface CleanResult {
  freed_bytes: number;
  deleted_files: number;
  skipped_count: number;
  duration_ms: number;
  cleaned_categories: string[];
  errors: string[];
}

interface AuditLogEntry {
  timestamp: string;
  categories: string[];
  freed_bytes: number;
  deleted_files: number;
  skipped_count: number;
  duration_ms: number;
  use_recycle_bin: boolean;
  success: boolean;
}

type ViewType = "dashboard" | "clean" | "storage" | "large_files" | "audit" | "settings";
type ThemeMode = "auto" | "light" | "dark";
type ResolvedTheme = "light" | "dark";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const val = parseFloat((bytes / Math.pow(k, i)).toFixed(i >= 3 ? 2 : 1));
  return `${val} ${sizes[i]}`;
}

function splitBytes(bytes: number): { value: string; unit: string } {
  if (bytes === 0) return { value: "0", unit: "B" };
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const val = parseFloat((bytes / Math.pow(k, i)).toFixed(i >= 3 ? 2 : 1));
  return { value: val.toFixed(i >= 3 ? 2 : 1), unit: sizes[i] };
}

function formatDisplayPath(rawPath: string): string {
  return rawPath.replace(/^\\\\\?\\(UNC\\)?/, "");
}

function getAutoTheme(): ResolvedTheme {
  const hour = new Date().getHours();
  // 6:00 AM - 5:59 PM is light; 6:00 PM - 5:59 AM is dark
  return hour >= 6 && hour < 18 ? "light" : "dark";
}

function getCategoryShortName(catId: string, fallback: string): string {
  switch (catId) {
    case "user_temp":
      return "User Temp";
    case "system_temp":
      return "System & Updates";
    case "browser_caches":
      return "Browser Caches";
    case "gpu_shader_cache":
      return "GPU Shader Cache";
    case "crash_dumps":
      return "Crash Dumps";
    case "app_dev_caches":
      return "App & Dev Caches";
    case "social_media":
      return "Social & Media";
    case "recycle_bin":
      return "Recycle Bin";
    default:
      return fallback;
  }
}

interface CustomCheckboxProps {
  checked: boolean;
  indeterminate?: boolean;
  onChange?: () => void;
}

function CustomCheckbox({ checked, indeterminate, onChange }: CustomCheckboxProps) {
  const isCheckedOrIndeterminate = checked || indeterminate;
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={indeterminate ? "mixed" : checked}
      onClick={(e) => {
        e.stopPropagation();
        onChange?.();
      }}
      className={`w-[18px] h-[18px] rounded-[5px] shrink-0 flex items-center justify-center transition-all duration-150 cursor-pointer ${
        isCheckedOrIndeterminate
          ? "bg-[#0A84FF] text-white shadow-sm border border-[#0A84FF]"
          : "border-[1.5px] border-[var(--border-subtle)] bg-[var(--checkbox-bg)] hover:border-[var(--accent-primary)] hover:bg-[var(--accent-subtle)]"
      }`}
    >
      {checked ? (
        <Check size={12} strokeWidth={2.75} className="text-white" />
      ) : indeterminate ? (
        <Minus size={12} strokeWidth={2.75} className="text-white" />
      ) : null}
    </button>
  );
}

export default function App() {
  const [activeView, setActiveView] = useState<ViewType>("dashboard");
  const [categories, setCategories] = useState<CategoryScanResult[]>([]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanDurationMs, setScanDurationMs] = useState<number>(0);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedSubPaths, setSelectedSubPaths] = useState<Set<string>>(new Set());
  const [isCleaning, setIsCleaning] = useState<boolean>(false);
  const [cleanResult, setCleanResult] = useState<CleanResult | null>(null);
  const [showConfirmModal, setShowConfirmModal] = useState<boolean>(false);
  const [showCompleteModal, setShowCompleteModal] = useState<boolean>(false);
  const [isElevated, setIsElevated] = useState<boolean>(false);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [hoveredCategoryId, setHoveredCategoryId] = useState<string | null>(null);

  // User Settings
  const [useRecycleBin, setUseRecycleBin] = useState<boolean>(true);
  const [showEmptyCategories, setShowEmptyCategories] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Large Files Finder State
  const [largeFiles, setLargeFiles] = useState<LargeFileItem[]>([]);
  const [isScanningLargeFiles, setIsScanningLargeFiles] = useState<boolean>(false);
  const [largeFileSizeThresholdMb, setLargeFileSizeThresholdMb] = useState<number>(250);
  const [selectedLargeFiles, setSelectedLargeFiles] = useState<Set<string>>(new Set());
  const [isDeletingLargeFiles, setIsDeletingLargeFiles] = useState<boolean>(false);
  const [showLargeFilesConfirmModal, setShowLargeFilesConfirmModal] = useState<boolean>(false);
  const [largeFilesScanTimeMs, setLargeFilesScanTimeMs] = useState<number>(0);

  // Manual Scan & Real-Time Progress State
  const [hasScannedCaches, setHasScannedCaches] = useState<boolean>(false);
  const [hasScannedLargeFiles, setHasScannedLargeFiles] = useState<boolean>(false);
  const [progress, setProgress] = useState<OperationProgress | null>(null);

  const isOperating = isScanning || isCleaning || isScanningLargeFiles || isDeletingLargeFiles;

  function copyToClipboard(key: string, text: string) {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  }

  // Dual-Theme System (Default: Porcelain Light)
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem("smartcache_theme_mode");
    return saved === "dark" || saved === "auto" || saved === "light" ? saved : "light";
  });

  const [resolvedTheme, setResolvedTheme] = useState<ResolvedTheme>(() => {
    const initialMode = localStorage.getItem("smartcache_theme_mode") || "light";
    if (initialMode === "dark") return "dark";
    if (initialMode === "light") return "light";
    return getAutoTheme();
  });

  const appWindow = getCurrentWindow();

  // Theme Sync & Interval (30s)
  useEffect(() => {
    localStorage.setItem("smartcache_theme_mode", themeMode);

    function syncTheme() {
      const active: ResolvedTheme = themeMode === "auto" ? getAutoTheme() : themeMode;
      setResolvedTheme(active);
      document.documentElement.setAttribute("data-theme", active);
    }

    syncTheme();
    const timer = setInterval(syncTheme, 30_000);
    return () => clearInterval(timer);
  }, [themeMode]);

  // Real-Time Progress Listener
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listen<OperationProgress>("operation-progress", (event) => {
      setProgress(event.payload);
      if (event.payload.mode === "idle") {
        setTimeout(() => setProgress(null), 900);
      }
    }).then((fn) => {
      unlisten = fn;
    });

    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  // Initial Check (No Auto-Scan on Launch)
  useEffect(() => {
    checkElevation();
    loadAuditLogs();
  }, []);

  async function checkElevation() {
    try {
      const elevated = await invoke<boolean>("is_elevated_admin");
      setIsElevated(elevated);
    } catch {
      setIsElevated(false);
    }
  }

  async function handleElevate() {
    try {
      await invoke("request_admin_elevation");
    } catch (err) {
      console.error("Elevation failed or was cancelled:", err);
    }
  }

  async function loadAuditLogs() {
    try {
      const logs = await invoke<AuditLogEntry[]>("get_audit_logs");
      setAuditLogs(logs);
    } catch (err) {
      console.error("Failed to load audit logs:", err);
    }
  }

  async function handleCancelOperation() {
    try {
      await invoke("cancel_current_operation");
    } catch (err) {
      console.error("Failed to cancel operation:", err);
    }
  }

  async function handleScan() {
    setIsScanning(true);
    const start = performance.now();
    try {
      const results = await invoke<CategoryScanResult[]>("scan_all_caches");
      setCategories(results);
      setHasScannedCaches(true);
      setScanDurationMs(Math.round(performance.now() - start));

      // Auto-select all discovered sub-items by default
      const allPaths = new Set<string>();
      results.forEach((c) => {
        c.sub_items.forEach((s) => allPaths.add(s.id));
      });
      setSelectedSubPaths(allPaths);

      // Select first category with items, or first category
      const firstWithItems = results.find((c) => c.size_bytes > 0);
      if (firstWithItems) {
        setSelectedCategory(firstWithItems.id);
      } else if (results.length > 0) {
        setSelectedCategory(results[0].id);
      }
    } catch (err) {
      console.error("Scan error:", err);
    } finally {
      setIsScanning(false);
    }
  }

  async function handleClean() {
    setShowConfirmModal(false);
    setIsCleaning(true);

    try {
      const selectedCategoryIds: string[] = [];
      categories.forEach((cat) => {
        const hasSelected = cat.sub_items.some((sub) => selectedSubPaths.has(sub.id));
        if (hasSelected) {
          selectedCategoryIds.push(cat.id);
        }
      });

      const pathsArray = Array.from(selectedSubPaths);

      const result = await invoke<CleanResult>("clean_categories", {
        categoryIds: selectedCategoryIds,
        selectedTargetPaths: pathsArray,
        useRecycleBin,
      });

      setCleanResult(result);
      setShowCompleteModal(true);

      // Re-scan and refresh audit logs
      await handleScan();
      await loadAuditLogs();
    } catch (err) {
      console.error("Cleaning failed:", err);
    } finally {
      setIsCleaning(false);
    }
  }

  async function handleScanLargeFiles(thresholdMb: number = largeFileSizeThresholdMb) {
    setIsScanningLargeFiles(true);
    const start = performance.now();
    try {
      const results = await invoke<LargeFileItem[]>("scan_large_files", { minSizeMb: thresholdMb });
      setLargeFiles(results);
      setLargeFilesScanTimeMs(Math.round(performance.now() - start));
      setSelectedLargeFiles(new Set());
      setHasScannedLargeFiles(true);
    } catch (err) {
      console.error("Failed to scan large files:", err);
    } finally {
      setIsScanningLargeFiles(false);
    }
  }

  async function handleRevealInExplorer(path: string) {
    try {
      await invoke("reveal_in_explorer", { path });
    } catch (err) {
      console.error("Failed to reveal file in explorer:", err);
    }
  }

  function toggleLargeFile(path: string) {
    const next = new Set(selectedLargeFiles);
    if (next.has(path)) {
      next.delete(path);
    } else {
      next.add(path);
    }
    setSelectedLargeFiles(next);
  }

  function toggleAllLargeFiles() {
    if (selectedLargeFiles.size === largeFiles.length) {
      setSelectedLargeFiles(new Set());
    } else {
      setSelectedLargeFiles(new Set(largeFiles.map((f) => f.path)));
    }
  }

  const selectedLargeBytes = useMemo(() => {
    let bytes = 0;
    largeFiles.forEach((f) => {
      if (selectedLargeFiles.has(f.path)) {
        bytes += f.size_bytes;
      }
    });
    return bytes;
  }, [largeFiles, selectedLargeFiles]);

  async function handleDeleteLargeFiles() {
    setShowLargeFilesConfirmModal(false);
    setIsDeletingLargeFiles(true);
    try {
      const pathsArray = Array.from(selectedLargeFiles);
      const freedBytes = await invoke<number>("delete_large_files", {
        paths: pathsArray,
        moveToRecycleBin: useRecycleBin,
      });

      await handleScanLargeFiles(largeFileSizeThresholdMb);
      await loadAuditLogs();

      setCleanResult({
        freed_bytes: freedBytes,
        deleted_files: pathsArray.length,
        skipped_count: 0,
        duration_ms: 0,
        cleaned_categories: ["Large Files"],
        errors: [],
      });
      setShowCompleteModal(true);
    } catch (err) {
      console.error("Large files deletion failed:", err);
    } finally {
      setIsDeletingLargeFiles(false);
    }
  }


  function getExtensionBadgeColor(ext: string): { bg: string; text: string; border: string } {
    const e = ext.toLowerCase().replace(/^\./, "");
    if (["iso", "img", "vhd", "vhdx", "vmdk"].includes(e)) {
      return { bg: "bg-purple-500/10", text: "text-purple-500", border: "border-purple-500/25" };
    }
    if (["zip", "rar", "7z", "tar", "gz", "bz2"].includes(e)) {
      return { bg: "bg-amber-500/10", text: "text-amber-500", border: "border-amber-500/25" };
    }
    if (["mp4", "mkv", "mov", "avi", "wmv", "webm", "flv"].includes(e)) {
      return { bg: "bg-blue-500/10", text: "text-blue-500", border: "border-blue-500/25" };
    }
    if (["exe", "msi"].includes(e)) {
      return { bg: "bg-rose-500/10", text: "text-rose-500", border: "border-rose-500/25" };
    }
    if (["mp3", "wav", "flac", "aac", "m4a"].includes(e)) {
      return { bg: "bg-teal-500/10", text: "text-teal-500", border: "border-teal-500/25" };
    }
    return { bg: "bg-zinc-500/10", text: "text-zinc-400", border: "border-zinc-500/25" };
  }

  // Filter categories based on settings (hide 0B uninstalled apps unless enabled)
  const visibleCategories = useMemo(() => {
    return categories.filter((c) => {
      if (showEmptyCategories) return true;
      if (!c.is_installed && c.size_bytes === 0) return false;
      return true;
    });
  }, [categories, showEmptyCategories]);

  const focusedCat = useMemo(() => {
    return categories.find((c) => c.id === selectedCategory) || visibleCategories[0] || null;
  }, [categories, selectedCategory, visibleCategories]);

  // Aggregate selected bytes and files
  const { totalSelectedBytes, totalSelectedFiles, totalDiscoveredBytes, totalDiscoveredFiles } =
    useMemo(() => {
      let selBytes = 0;
      let selFiles = 0;
      let discBytes = 0;
      let discFiles = 0;

      categories.forEach((cat) => {
        discBytes += cat.size_bytes;
        discFiles += cat.file_count;
        cat.sub_items.forEach((sub) => {
          if (selectedSubPaths.has(sub.id)) {
            selBytes += sub.size_bytes;
            selFiles += sub.file_count;
          }
        });
      });

      return {
        totalSelectedBytes: selBytes,
        totalSelectedFiles: selFiles,
        totalDiscoveredBytes: discBytes,
        totalDiscoveredFiles: discFiles,
      };
    }, [categories, selectedSubPaths]);

  // Checkbox helpers
  function isCategoryChecked(cat: CategoryScanResult): boolean {
    if (cat.sub_items.length === 0) return false;
    return cat.sub_items.every((sub) => selectedSubPaths.has(sub.id));
  }

  function isCategoryIndeterminate(cat: CategoryScanResult): boolean {
    const checkedCount = cat.sub_items.filter((sub) => selectedSubPaths.has(sub.id)).length;
    return checkedCount > 0 && checkedCount < cat.sub_items.length;
  }

  function toggleCategory(cat: CategoryScanResult) {
    const next = new Set(selectedSubPaths);
    const allChecked = isCategoryChecked(cat);

    cat.sub_items.forEach((sub) => {
      if (allChecked) {
        next.delete(sub.id);
      } else {
        next.add(sub.id);
      }
    });

    setSelectedSubPaths(next);
  }

  function toggleSubItem(subId: string) {
    const next = new Set(selectedSubPaths);
    if (next.has(subId)) {
      next.delete(subId);
    } else {
      next.add(subId);
    }
    setSelectedSubPaths(next);
  }

  function handleSelectSafeAll() {
    const next = new Set<string>();
    categories.forEach((cat) => {
      if (!cat.requires_admin || isElevated) {
        cat.sub_items.forEach((sub) => next.add(sub.id));
      }
    });
    setSelectedSubPaths(next);
  }

  function cycleTheme() {
    if (themeMode === "light") setThemeMode("dark");
    else if (themeMode === "dark") setThemeMode("auto");
    else setThemeMode("light");
  }

  function handleHeaderMouseDown(e: React.MouseEvent) {
    if (e.button === 0 && !(e.target as HTMLElement).closest("button, a, input, [data-no-drag]")) {
      getCurrentWindow().startDragging();
    }
  }

  function handleHeaderDoubleClick(e: React.MouseEvent) {
    if (!(e.target as HTMLElement).closest("button, a, input, [data-no-drag]")) {
      getCurrentWindow().toggleMaximize();
    }
  }

  function getCategoryIcon(id: string) {
    switch (id) {
      case "user_temp":
        return <FileCode className="w-4 h-4 text-blue-500" strokeWidth={1.75} />;
      case "system_temp":
        return <Cpu className="w-4 h-4 text-amber-500" strokeWidth={1.75} />;
      case "browser_caches":
        return <Globe className="w-4 h-4 text-sky-500" strokeWidth={1.75} />;
      case "gpu_shader_cache":
        return <Zap className="w-4 h-4 text-purple-500" strokeWidth={1.75} />;
      case "crash_dumps":
        return <AlertCircle className="w-4 h-4 text-rose-500" strokeWidth={1.75} />;
      case "app_dev_caches":
        return <Terminal className="w-4 h-4 text-emerald-500" strokeWidth={1.75} />;
      case "social_media":
        return <Film className="w-4 h-4 text-indigo-500" strokeWidth={1.75} />;
      case "recycle_bin":
        return <Trash2 className="w-4 h-4 text-zinc-400" strokeWidth={1.75} />;
      default:
        return <Folder className="w-4 h-4 text-blue-500" strokeWidth={1.75} />;
    }
  }

  function getCategorySquircleBg(id: string) {
    switch (id) {
      case "user_temp":
        return "bg-[rgba(59,130,246,0.12)] border-[rgba(59,130,246,0.25)]";
      case "system_temp":
        return "bg-[rgba(245,158,11,0.12)] border-[rgba(245,158,11,0.25)]";
      case "browser_caches":
        return "bg-[rgba(56,189,248,0.12)] border-[rgba(56,189,248,0.25)]";
      case "gpu_shader_cache":
        return "bg-[rgba(168,85,247,0.12)] border-[rgba(168,85,247,0.25)]";
      case "crash_dumps":
        return "bg-[rgba(244,63,94,0.12)] border-[rgba(244,63,94,0.25)]";
      case "app_dev_caches":
        return "bg-[rgba(16,185,129,0.12)] border-[rgba(16,185,129,0.25)]";
      case "social_media":
        return "bg-[rgba(99,102,241,0.12)] border-[rgba(99,102,241,0.25)]";
      case "recycle_bin":
        return "bg-[rgba(161,161,170,0.12)] border-[rgba(161,161,170,0.25)]";
      default:
        return "bg-[rgba(56,189,248,0.12)] border-[rgba(56,189,248,0.25)]";
    }
  }

  function getCategoryColor(id: string, index: number): string {
    switch (id) {
      case "user_temp":
        return "bg-blue-500";
      case "system_temp":
        return "bg-amber-500";
      case "browser_caches":
        return "bg-sky-500";
      case "gpu_shader_cache":
        return "bg-purple-500";
      case "crash_dumps":
        return "bg-rose-500";
      case "app_dev_caches":
        return "bg-emerald-500";
      case "social_media":
        return "bg-indigo-500";
      case "recycle_bin":
        return "bg-zinc-400";
      default: {
        const fallback = ["bg-blue-500", "bg-emerald-500", "bg-purple-500", "bg-amber-500", "bg-sky-500"];
        return fallback[index % fallback.length];
      }
    }
  }

  const viewTitles: Record<ViewType, string> = {
    dashboard: "Dashboard",
    clean: "Clean Caches",
    storage: "Storage Breakdown",
    large_files: "Large Files Finder",
    audit: "Audit Log",
    settings: "Preferences",
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[var(--bg-canvas)] text-[var(--text-primary)] select-none font-sans">
      {/* 1. LEFT SIDEBAR: Full-Height Linear Shell (w-[224px]) */}
      <aside className="w-[224px] shrink-0 h-full flex flex-col bg-[var(--bg-sidebar)] border-r border-[var(--border-hairline)] z-20">
        {/* Top Drag Region with App Wordmark */}
        <div
          data-tauri-drag-region
          onMouseDown={handleHeaderMouseDown}
          onDoubleClick={handleHeaderDoubleClick}
          className="h-[46px] flex items-center justify-between px-4 shrink-0 border-b border-[var(--border-hairline)] select-none cursor-default"
        >
          <div className="flex items-center gap-2.5 pointer-events-none" data-tauri-drag-region>
            {/* Unified Lucide Shield Icon Container */}
            <div className="w-6 h-6 rounded-[8px] bg-gradient-to-br from-[#38BDF8] to-[#0284C7] flex items-center justify-center shadow-sm shrink-0">
              <ShieldCheck size={14} strokeWidth={2.2} className="text-white" />
            </div>
            <span className="text-[13px] font-bold tracking-tight text-[var(--text-primary)]">
              SmartCache
            </span>
          </div>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--border-hairline)] text-[var(--text-muted)] font-medium pointer-events-none">
            v1.0
          </span>
        </div>

        {/* Sidebar Nav Items */}
        <div className="flex-1 px-2.5 py-4 space-y-6 overflow-y-auto">
          <div>
            <span className="px-2 text-[10px] font-semibold tracking-wider text-[var(--text-muted)] uppercase">
              Workspace
            </span>
            <nav className="mt-2 space-y-1">
              {/* Dashboard */}
              <button
                onClick={() => setActiveView("dashboard")}
                className={`w-full flex items-center px-3 py-2 rounded-lg text-xs transition-all relative cursor-pointer ${
                  activeView === "dashboard"
                    ? "bg-[var(--accent-subtle)] text-[var(--text-primary)] font-semibold"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)] font-medium"
                }`}
              >
                {activeView === "dashboard" && (
                  <span className="w-[2.5px] h-[16px] rounded-r-full bg-[var(--accent-primary)] absolute left-0" />
                )}
                <LayoutDashboard
                  size={16}
                  strokeWidth={1.75}
                  className={activeView === "dashboard" ? "text-[var(--accent-primary)]" : "text-[var(--text-muted)]"}
                />
                <span className="ml-2.5">Dashboard</span>
              </button>

              {/* Clean */}
              <button
                onClick={() => setActiveView("clean")}
                className={`w-full flex items-center px-3 py-2 rounded-lg text-xs transition-all relative cursor-pointer ${
                  activeView === "clean"
                    ? "bg-[var(--accent-subtle)] text-[var(--text-primary)] font-semibold"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)] font-medium"
                }`}
              >
                {activeView === "clean" && (
                  <span className="w-[2.5px] h-[16px] rounded-r-full bg-[var(--accent-primary)] absolute left-0" />
                )}
                <Sparkles
                  size={16}
                  strokeWidth={1.75}
                  className={activeView === "clean" ? "text-[var(--accent-primary)]" : "text-[var(--text-muted)]"}
                />
                <span className="ml-2.5">Clean</span>
              </button>

              {/* Storage */}
              <button
                onClick={() => setActiveView("storage")}
                className={`w-full flex items-center px-3 py-2 rounded-lg text-xs transition-all relative cursor-pointer ${
                  activeView === "storage"
                    ? "bg-[var(--accent-subtle)] text-[var(--text-primary)] font-semibold"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)] font-medium"
                }`}
              >
                {activeView === "storage" && (
                  <span className="w-[2.5px] h-[16px] rounded-r-full bg-[var(--accent-primary)] absolute left-0" />
                )}
                <PieChart
                  size={16}
                  strokeWidth={1.75}
                  className={activeView === "storage" ? "text-[var(--accent-primary)]" : "text-[var(--text-muted)]"}
                />
                <span className="ml-2.5">Storage</span>
              </button>

              {/* Large Files */}
              <button
                onClick={() => setActiveView("large_files")}
                className={`w-full flex items-center px-3 py-2 rounded-lg text-xs transition-all relative cursor-pointer ${
                  activeView === "large_files"
                    ? "bg-[var(--accent-subtle)] text-[var(--text-primary)] font-semibold"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)] font-medium"
                }`}
              >
                {activeView === "large_files" && (
                  <span className="w-[2.5px] h-[16px] rounded-r-full bg-[var(--accent-primary)] absolute left-0" />
                )}
                <FileSearch
                  size={16}
                  strokeWidth={1.75}
                  className={activeView === "large_files" ? "text-[var(--accent-primary)]" : "text-[var(--text-muted)]"}
                />
                <span className="ml-2.5">Large Files</span>
              </button>
            </nav>
          </div>

          <div>
            <span className="px-2 text-[10px] font-semibold tracking-wider text-[var(--text-muted)] uppercase">
              System
            </span>
            <nav className="mt-2 space-y-1">
              {/* Audit Log */}
              <button
                onClick={() => setActiveView("audit")}
                className={`w-full flex items-center px-3 py-2 rounded-lg text-xs transition-all relative cursor-pointer ${
                  activeView === "audit"
                    ? "bg-[var(--accent-subtle)] text-[var(--text-primary)] font-semibold"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)] font-medium"
                }`}
              >
                {activeView === "audit" && (
                  <span className="w-[2.5px] h-[16px] rounded-r-full bg-[var(--accent-primary)] absolute left-0" />
                )}
                <History
                  size={16}
                  strokeWidth={1.75}
                  className={activeView === "audit" ? "text-[var(--accent-primary)]" : "text-[var(--text-muted)]"}
                />
                <span className="ml-2.5">Audit Log</span>
              </button>

              {/* Settings */}
              <button
                onClick={() => setActiveView("settings")}
                className={`w-full flex items-center px-3 py-2 rounded-lg text-xs transition-all relative cursor-pointer ${
                  activeView === "settings"
                    ? "bg-[var(--accent-subtle)] text-[var(--text-primary)] font-semibold"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)] font-medium"
                }`}
              >
                {activeView === "settings" && (
                  <span className="w-[2.5px] h-[16px] rounded-r-full bg-[var(--accent-primary)] absolute left-0" />
                )}
                <SettingsIcon
                  size={16}
                  strokeWidth={1.75}
                  className={activeView === "settings" ? "text-[var(--accent-primary)]" : "text-[var(--text-muted)]"}
                />
                <span className="ml-2.5">Preferences</span>
              </button>
            </nav>
          </div>
        </div>

        {/* Sidebar Footer: Theme Pill, Compact Offline Status & Attribution */}
        <div className="px-3 pb-3 pt-2 border-t border-[var(--border-hairline)] flex flex-col gap-2.5">
          {/* Sleek 28px-tall 3-Segment Theme Pill */}
          <div className="h-[28px] p-0.5 rounded-lg bg-[var(--border-hairline)] flex items-center gap-0.5">
            <button
              onClick={() => setThemeMode("light")}
              title="Porcelain Light"
              className={`flex-1 h-full rounded-md text-[11.5px] font-medium flex items-center justify-center gap-1 transition-all cursor-pointer ${
                themeMode === "light"
                  ? "bg-[var(--bg-card)] text-[var(--text-primary)] shadow-sm font-semibold"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}
            >
              <Sun size={12} strokeWidth={1.75} />
              <span>Light</span>
            </button>
            <button
              onClick={() => setThemeMode("dark")}
              title="Obsidian Dark"
              className={`flex-1 h-full rounded-md text-[11.5px] font-medium flex items-center justify-center gap-1 transition-all cursor-pointer ${
                themeMode === "dark"
                  ? "bg-[var(--bg-card)] text-[var(--text-primary)] shadow-sm font-semibold"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}
            >
              <Moon size={12} strokeWidth={1.75} />
              <span>Dark</span>
            </button>
            <button
              onClick={() => setThemeMode("auto")}
              title={`Auto: 6AM–6PM Light, 6PM–6AM Dark (${resolvedTheme === "light" ? "Day" : "Night"} active)`}
              className={`flex-1 h-full rounded-md text-[11.5px] font-medium flex items-center justify-center gap-1 transition-all cursor-pointer ${
                themeMode === "auto"
                  ? "bg-[var(--bg-card)] text-[var(--text-primary)] shadow-sm font-semibold"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}
            >
              <Clock size={12} strokeWidth={1.75} />
              <span>Auto</span>
            </button>
          </div>

          {/* Compact Inline Status Pill */}
          <div className="h-[28px] px-2.5 rounded-lg flex items-center justify-center gap-1.5 text-[11.5px] font-medium border border-[#10B981]/25 bg-[#10B981]/10 text-[#10B981]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] shrink-0 pulse-dot" />
            <span>Zero-Trust • Offline</span>
          </div>

          {/* Single Clean Footer Line */}
          <div className="text-[11px] text-center text-[var(--text-muted)] opacity-70">
            by Pixel Craft Studios
          </div>
        </div>
      </aside>

      {/* 2. RIGHT WORKSPACE (Header + Active View) */}
      <div className="flex-1 h-full flex flex-col bg-[var(--bg-canvas)] overflow-hidden">
        {/* Flush Top Header (h-[46px]) */}
        <header
          data-tauri-drag-region
          onMouseDown={handleHeaderMouseDown}
          onDoubleClick={handleHeaderDoubleClick}
          className="h-[46px] border-b border-[var(--border-hairline)] flex items-center justify-between pl-5 pr-0 shrink-0 select-none z-30 cursor-default"
        >
          {/* Left: Breadcrumbs in data-tauri-drag-region */}
          <div className="flex items-center gap-2 text-xs text-[var(--text-muted)] pointer-events-none" data-tauri-drag-region>
            <span className="font-medium text-[var(--text-secondary)]">SmartCache</span>
            <ChevronRight size={12} strokeWidth={1.5} />
            <span className="font-semibold text-[var(--text-primary)]">{viewTitles[activeView]}</span>
          </div>

          {/* Right: Actions + Windows 11 Flush Window Controls */}
          <div className="flex items-center h-full">
            {scanDurationMs > 0 && (
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full mr-2.5 border border-[#10B981]/25 bg-[#10B981]/10 pointer-events-none">
                <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] pulse-dot" />
                <span className="text-[11px] text-[#10B981] mono-num font-medium">
                  Scanned in {(scanDurationMs / 1000).toFixed(2)}s
                </span>
              </div>
            )}

            <button
              onClick={handleScan}
              disabled={isOperating}
              className="h-[28px] px-3 mr-2 rounded-md text-[12px] font-medium border border-[var(--border-hairline)] bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors disabled:opacity-50 flex items-center gap-1.5 cursor-pointer"
            >
              <RefreshCw
                size={13}
                strokeWidth={1.75}
                className={`text-[var(--accent-primary)] ${isScanning ? "animate-spin" : ""}`}
              />
              <span>{isScanning ? "Scanning..." : "Re-Scan"}</span>
            </button>

            {/* Quick Theme Cycle Icon Button */}
            <button
              onClick={cycleTheme}
              className="w-[28px] h-[28px] mr-3 rounded-md border border-[var(--border-hairline)] bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors flex items-center justify-center cursor-pointer"
              title={`Theme: ${themeMode} (click to cycle)`}
            >
              {themeMode === "auto" ? (
                <Clock size={14} strokeWidth={1.75} className="text-[var(--accent-primary)]" />
              ) : themeMode === "light" ? (
                <Sun size={14} strokeWidth={1.75} className="text-amber-500" />
              ) : (
                <Moon size={14} strokeWidth={1.75} className="text-sky-400" />
              )}
            </button>

            {/* Native Windows 11 Flush Caption Controls */}
            <div className="flex items-center h-full">
              <button
                onClick={() => appWindow.minimize()}
                className="win-ctrl-btn"
                title="Minimize"
              >
                <Minus size={14} strokeWidth={1.5} />
              </button>
              <button
                onClick={() => appWindow.toggleMaximize()}
                className="win-ctrl-btn"
                title="Maximize"
              >
                <Square size={12} strokeWidth={1.5} />
              </button>
              <button
                onClick={() => appWindow.close()}
                className="win-ctrl-btn win-ctrl-close"
                title="Close"
              >
                <X size={14} strokeWidth={1.5} />
              </button>
            </div>
          </div>
        </header>

        {/* 3. ACTIVE VIEW CONTAINER */}
        <main className="flex-1 overflow-hidden relative">
          {/* VIEW: DASHBOARD */}
          {activeView === "dashboard" && (
            <div className="h-full overflow-y-auto p-8 space-y-6">
              {/* Dense 2-Column Flagship Telemetry Hero Card */}
              <div className="p-6 rounded-2xl glass-hero flex items-center justify-between">
                {/* Left Side: Eyebrow, Split Size, Live Proportional Micro-bar, Subtitle */}
                <div className="space-y-2">
                  <span className="text-[11px] font-semibold tracking-wider text-[var(--accent-primary)] uppercase flex items-center gap-1.5">
                    <Sparkles size={14} strokeWidth={2} />
                    Recoverable System Junk
                  </span>

                  {(() => {
                    const { value, unit } = splitBytes(hasScannedCaches ? totalDiscoveredBytes : 0);
                    return (
                      <div className="flex items-baseline gap-2.5">
                        <span className="text-[48px] font-bold mono-num text-[var(--text-primary)] leading-none tracking-[-0.04em]">
                          {value}
                        </span>
                        <span className="text-[22px] font-medium text-[var(--text-muted)] leading-none">
                          {unit}
                        </span>
                      </div>
                    );
                  })()}

                  {/* Proportional Multi-Color Micro-Bar */}
                  <div className="h-[6px] w-full max-w-[340px] rounded-full flex gap-[2px] overflow-hidden bg-black/10 dark:bg-white/10 mt-3">
                    {hasScannedCaches ? (
                      categories.map((c, i) => {
                        const pct = totalDiscoveredBytes > 0 ? (c.size_bytes / totalDiscoveredBytes) * 100 : 0;
                        if (pct === 0) return null;
                        return (
                          <div
                            key={c.id}
                            style={{ width: `${pct}%` }}
                            className={`h-full ${getCategoryColor(c.id, i)} transition-all duration-300`}
                            title={`${c.name}: ${formatBytes(c.size_bytes)} (${pct.toFixed(1)}%)`}
                          />
                        );
                      })
                    ) : (
                      <div className="h-full w-full bg-transparent" />
                    )}
                  </div>

                  <p className="text-xs text-[var(--text-muted)] pt-1">
                    {hasScannedCaches
                      ? `Across ${categories.length} universal system targets • ${totalDiscoveredFiles.toLocaleString()} files detected`
                      : "No scan performed yet • Click 'Start Smart Scan' to analyze system junk"}
                  </p>
                </div>

                {/* Right Side: Circular Ring Gauge + Primary CTA */}
                <div className="flex items-center gap-6">
                  {/* Circular SVG Ring Gauge (76px x 76px) */}
                  <div className="relative w-[76px] h-[76px] flex items-center justify-center shrink-0">
                    <svg className="w-full h-full transform -rotate-90" viewBox="0 0 76 76">
                      <circle
                        cx="38"
                        cy="38"
                        r="30"
                        className="text-black/10 dark:text-white/10"
                        stroke="currentColor"
                        strokeWidth="6"
                        fill="transparent"
                      />
                      <circle
                        cx="38"
                        cy="38"
                        r="30"
                        stroke="#0EA5E9"
                        strokeWidth="6"
                        strokeDasharray={188.5}
                        strokeDashoffset={hasScannedCaches && totalDiscoveredBytes > 0 ? 30 : 188.5}
                        strokeLinecap="round"
                        fill="transparent"
                        className="transition-all duration-700 ease-apple"
                      />
                    </svg>
                    <div className="absolute flex flex-col items-center justify-center text-center">
                      <span className="text-xs font-bold mono-num text-[var(--text-primary)]">
                        {hasScannedCaches && totalDiscoveredBytes > 0 ? "100%" : "0%"}
                      </span>
                      <span className="text-[9px] text-[var(--text-muted)] font-medium">
                        {hasScannedCaches ? "Ready" : "Ready to Scan"}
                      </span>
                    </div>
                  </div>

                  {/* Primary CTA Button */}
                  <button
                    onClick={() => {
                      if (!hasScannedCaches) {
                        handleScan();
                      } else {
                        setActiveView("clean");
                      }
                    }}
                    disabled={isOperating}
                    className="px-6 py-3.5 rounded-xl font-semibold text-xs text-white btn-electric flex items-center gap-2 cursor-pointer shadow-lg select-none disabled:opacity-50"
                  >
                    <Sparkles size={15} strokeWidth={2} />
                    <span>
                      {isScanning
                        ? "Scanning..."
                        : hasScannedCaches
                        ? "Review & Clean Caches"
                        : "Start Smart Scan"}
                    </span>
                  </button>
                </div>
              </div>

              {/* 3-Column Stat Strip */}
              <div className="grid grid-cols-3 gap-4">
                {/* Last Cleanup */}
                <div className="p-4 rounded-xl glass-card flex flex-col justify-between">
                  <div>
                    <div className="text-xs font-medium text-[var(--text-muted)]">Last Cleanup Freed</div>
                    <div className="text-2xl font-bold text-[var(--text-primary)] mt-1 mono-num tabular-nums">
                      {auditLogs.length > 0 ? formatBytes(auditLogs[0].freed_bytes) : "0 B"}
                    </div>
                  </div>
                  <div className="text-[11px] text-[var(--text-secondary)] mt-2 mono-num">
                    {auditLogs.length > 0 ? auditLogs[0].timestamp.split("T")[0] : "No previous cleanups recorded"}
                  </div>
                </div>

                {/* Privilege Mode */}
                <div className="p-4 rounded-xl glass-card flex flex-col justify-between">
                  <div>
                    <div className="text-xs font-medium text-[var(--text-muted)]">Privilege Mode</div>
                    {isElevated ? (
                      <div className="text-xl font-bold text-[#10B981] mt-1 flex items-center gap-1.5">
                        <ShieldCheck size={18} strokeWidth={2} />
                        <span>Administrator</span>
                      </div>
                    ) : (
                      <div className="flex items-center justify-between mt-1">
                        <span className="text-xl font-bold text-amber-500">
                          Standard User
                        </span>
                        <button
                          onClick={handleElevate}
                          className="px-2.5 py-1 rounded-md text-[11px] font-semibold tracking-wide border border-amber-500/30 bg-amber-500/10 text-amber-500 hover:bg-amber-500/20 transition-all cursor-pointer flex items-center gap-1 select-none"
                          title="Relaunch SmartCacheCleaner with Windows Administrator privileges"
                        >
                          <span>Elevate</span>
                          <ArrowUpRight size={13} strokeWidth={2} />
                        </button>
                      </div>
                    )}
                  </div>
                  <div className="text-[11px] text-[var(--text-secondary)] mt-2">
                    {isElevated ? "Full System Access" : "System Temp requires Admin"}
                  </div>
                </div>

                {/* Security Guardrails */}
                <div className="p-4 rounded-xl glass-card flex flex-col justify-between">
                  <div>
                    <div className="text-xs font-medium text-[var(--text-muted)]">Security Guardrails</div>
                    <div className="text-xl font-bold text-[#10B981] mt-1 flex items-center gap-1.5">
                      <ShieldCheck size={18} strokeWidth={2} />
                      <span>Active</span>
                    </div>
                  </div>
                  <div className="text-[11px] text-[var(--text-secondary)] mt-2">
                    Zero-Trust Kernel & Junction Trap Protection
                  </div>
                </div>
              </div>

              {/* Top Cache Contributors Structured Table */}
              <div className="rounded-xl glass-card overflow-hidden">
                <div className="p-4 border-b border-[var(--border-hairline)] flex items-center justify-between">
                  <h3 className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                    Top Cache Contributors
                  </h3>
                  <span className="text-[11px] text-[var(--text-secondary)]">
                    Click row to inspect sub-items
                  </span>
                </div>

                {/* Table Column Headers */}
                <div className="grid grid-cols-12 px-4 py-2 border-b border-[var(--border-hairline)] bg-[var(--border-hairline)]/20 text-[10px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                  <div className="col-span-5">Category</div>
                  <div className="col-span-3">Detected Items</div>
                  <div className="col-span-2 text-right">Share</div>
                  <div className="col-span-2 text-right">Recoverable Size</div>
                </div>

                {/* Table Body */}
                <div className="divide-y divide-[var(--border-hairline)]">
                  {categories.filter((c) => c.size_bytes > 0).length === 0 ? (
                    <div className="py-12 flex flex-col items-center justify-center text-center">
                      <div className="w-10 h-10 rounded-xl bg-[var(--accent-subtle)] border border-[var(--accent-border)] flex items-center justify-center text-[var(--accent-primary)] mb-2.5">
                        <Sparkles size={20} strokeWidth={1.75} />
                      </div>
                      <span className="text-xs font-semibold text-[var(--text-primary)]">
                        {hasScannedCaches ? "System Clean • No Junk Detected" : "No Cache Data Available"}
                      </span>
                      <span className="text-[11px] text-[var(--text-muted)] mt-1 max-w-sm">
                        {hasScannedCaches
                          ? "All universal system targets are currently clean."
                          : "No Cache Data Available • Click Start Smart Scan to analyze system and application caches."}
                      </span>
                      {!hasScannedCaches && !isScanning && (
                        <button
                          onClick={handleScan}
                          disabled={isOperating}
                          className="mt-3.5 px-4 py-2 rounded-lg text-xs font-semibold btn-electric text-white cursor-pointer disabled:opacity-50"
                        >
                          Start Smart Scan
                        </button>
                      )}
                    </div>
                  ) : (
                    categories
                      .filter((c) => c.size_bytes > 0)
                      .sort((a, b) => b.size_bytes - a.size_bytes)
                      .slice(0, 6)
                      .map((cat) => {
                        const pct = totalDiscoveredBytes > 0 ? (cat.size_bytes / totalDiscoveredBytes) * 100 : 0;
                        return (
                          <div
                            key={cat.id}
                            onClick={() => {
                              setSelectedCategory(cat.id);
                              setActiveView("clean");
                            }}
                            className="grid grid-cols-12 items-center px-4 h-[48px] hover:bg-[var(--bg-card-hover)] cursor-pointer transition-colors group"
                          >
                            {/* Col 1: Icon + Name */}
                            <div className="col-span-5 flex items-center gap-3 min-w-0 pr-2">
                              <div
                                className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 border ${getCategorySquircleBg(
                                  cat.id
                                )}`}
                              >
                                {getCategoryIcon(cat.id)}
                              </div>
                              <span className="text-xs font-medium text-[var(--text-primary)] truncate">
                                {getCategoryShortName(cat.id, cat.name)}
                              </span>
                            </div>

                            {/* Col 2: Items count */}
                            <div className="col-span-3 text-xs text-[var(--text-secondary)] mono-num">
                              {cat.sub_items.length} {cat.sub_items.length === 1 ? "target" : "targets"} ({cat.file_count.toLocaleString()} files)
                            </div>

                            {/* Col 3: Progress Bar + Percent */}
                            <div className="col-span-2 flex items-center justify-end gap-2 pr-2">
                              <div className="w-[72px] h-[4px] bg-black/10 dark:bg-white/10 rounded-full overflow-hidden shrink-0">
                                <div
                                  className="h-full bg-[var(--accent-primary)] rounded-full transition-all duration-300"
                                  style={{ width: `${Math.min(pct, 100)}%` }}
                                />
                              </div>
                              <span className="text-[11px] text-[var(--text-muted)] mono-num w-8 text-right">
                                {pct.toFixed(0)}%
                              </span>
                            </div>

                            {/* Col 4: Recoverable Size + Arrow */}
                            <div className="col-span-2 flex items-center justify-end gap-2 text-right">
                              <span className="text-xs font-semibold text-[var(--text-primary)] mono-num tabular-nums">
                                {formatBytes(cat.size_bytes)}
                              </span>
                              <ChevronRight
                                size={14}
                                strokeWidth={1.75}
                                className="text-[var(--text-muted)] group-hover:translate-x-0.5 transition-transform"
                              />
                            </div>
                          </div>
                        );
                      })
                  )}
                </div>
              </div>
            </div>
          )}

          {/* VIEW: CLEAN (3-Column Layout: Middle Master + Right Detail) */}
          {activeView === "clean" && (
            categories.length === 0 && !isScanning ? (
              <div className="h-full flex-1 flex flex-col items-center justify-center p-8 text-center">
                <div className="w-16 h-16 rounded-2xl bg-[var(--accent-subtle)] border border-[var(--accent-border)] flex items-center justify-center text-[var(--accent-primary)] mb-4 shadow-sm">
                  <Sparkles size={32} strokeWidth={1.75} />
                </div>
                <h2 className="text-base font-bold text-[var(--text-primary)]">Ready to Scan Caches</h2>
                <p className="text-xs text-[var(--text-muted)] mt-1.5 max-w-md leading-relaxed">
                  Analyze system temporary files, browser caches, social & creative media caches, and crash dumps with zero-trust safety.
                </p>
                <button
                  onClick={handleScan}
                  disabled={isOperating}
                  className="mt-5 px-6 py-3 rounded-xl text-xs font-semibold btn-electric text-white shadow-lg cursor-pointer flex items-center gap-2 disabled:opacity-50"
                >
                  <Sparkles size={15} strokeWidth={2} />
                  <span>Scan Caches Now</span>
                </button>
              </div>
            ) : (
            <div className="h-full flex overflow-hidden">
              {/* MIDDLE MASTER PANE (315px) */}
              <div className="w-[315px] shrink-0 flex flex-col border-r border-[var(--border-hairline)] bg-[var(--bg-master)]">
                <div className="px-4 py-3 flex items-center justify-between border-b border-[var(--border-hairline)]">
                  <span className="text-[11px] font-semibold uppercase text-[var(--text-muted)] tracking-wider">
                    Categories ({visibleCategories.length})
                  </span>
                  <span className="text-xs font-semibold text-[var(--text-primary)] mono-num tabular-nums">
                    {formatBytes(totalDiscoveredBytes)}
                  </span>
                </div>

                <div className="flex-1 overflow-y-auto px-2 py-2 space-y-1">
                  {visibleCategories.map((cat) => {
                    const isFocused = selectedCategory === cat.id;
                    const isChecked = isCategoryChecked(cat);
                    const isIndeterminate = isCategoryIndeterminate(cat);
                    const displayName = getCategoryShortName(cat.id, cat.name);

                    return (
                      <div
                        key={cat.id}
                        onClick={() => setSelectedCategory(cat.id)}
                        className={`group relative flex items-center gap-2.5 px-3 py-2.5 rounded-xl cursor-pointer transition-all duration-150 border ${
                          isFocused
                            ? "bg-[var(--accent-subtle)] border-[var(--accent-border)] shadow-sm"
                            : "border-transparent hover:bg-[var(--bg-card-hover)]"
                        }`}
                      >
                        {/* Custom Linear-Style Checkbox */}
                        <CustomCheckbox
                          checked={isChecked}
                          indeterminate={isIndeterminate}
                          onChange={() => toggleCategory(cat)}
                        />

                        {/* Tinted Squircle Icon Container (36x36px) */}
                        <div
                          className={`w-9 h-9 rounded-[10px] flex items-center justify-center shrink-0 border ${getCategorySquircleBg(
                            cat.id
                          )}`}
                        >
                          {getCategoryIcon(cat.id)}
                        </div>

                        {/* Label & Item Count with inline Admin tag */}
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-semibold text-[var(--text-primary)] whitespace-nowrap">
                            {displayName}
                          </div>
                          <div className="text-[11px] text-[var(--text-muted)] flex items-center gap-1.5 mt-0.5">
                            <span>
                              {cat.sub_items.length} {cat.sub_items.length === 1 ? "item" : "items"}
                            </span>
                            {cat.requires_admin && !isElevated && (
                              <span className="text-amber-500 font-medium font-mono text-[10px]">• Admin</span>
                            )}
                          </div>
                        </div>

                        {/* Category Size */}
                        <div className="text-right shrink-0">
                          <span
                            className={`text-xs font-semibold mono-num tabular-nums ${
                              cat.size_bytes > 0 ? "text-[var(--text-primary)]" : "text-[var(--text-muted)]"
                            }`}
                          >
                            {formatBytes(cat.size_bytes)}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* RIGHT DETAIL PANE (flex-1) */}
              <div className="flex-1 flex flex-col bg-[var(--bg-canvas)] overflow-hidden">
                {focusedCat ? (
                  <>
                    {/* Detail Header / Category Summary Banner */}
                    <div className="p-5 border-b border-[var(--border-hairline)] bg-[var(--bg-card)]/50 backdrop-blur-md">
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-3 min-w-0">
                          <div
                            className={`w-9 h-9 rounded-xl flex items-center justify-center shrink-0 border ${getCategorySquircleBg(
                              focusedCat.id
                            )}`}
                          >
                            {getCategoryIcon(focusedCat.id)}
                          </div>
                          <h2 className="text-base font-bold text-[var(--text-primary)] tracking-tight truncate">
                            {focusedCat.id === "system_temp" ? "System Temp & Updates" : focusedCat.name}
                          </h2>
                          <span className="whitespace-nowrap shrink-0 px-2.5 py-1 rounded-md text-[12px] font-semibold mono-num bg-[var(--border-hairline)] text-[var(--text-primary)] tabular-nums">
                            {formatBytes(focusedCat.size_bytes)}
                          </span>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <div className="flex items-center gap-1.5 text-[11px] font-medium text-[#10B981] bg-[#10B981]/10 border border-[#10B981]/25 px-2.5 py-1 rounded-md whitespace-nowrap shrink-0">
                            <ShieldCheck size={13} strokeWidth={2} />
                            <span>Safe Cache • Personal Files Untouched</span>
                          </div>
                          {focusedCat.requires_admin && !isElevated && (
                            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-500/10 border border-amber-500/20 text-amber-500 text-[11px] font-medium whitespace-nowrap shrink-0">
                              <ShieldAlert size={13} strokeWidth={2} />
                              <span>Admin Required</span>
                            </div>
                          )}
                        </div>
                      </div>

                      <p className="mt-2 text-xs text-[var(--text-muted)] leading-relaxed pl-12">
                        {focusedCat.description}
                      </p>
                    </div>

                    {/* Sub-Items Scrollable List */}
                    <div className="flex-1 overflow-y-auto p-4 space-y-1.5">
                      {focusedCat.sub_items.length > 0 && (
                        <div className="flex items-center justify-between px-3 pb-2 text-[10.5px] font-semibold uppercase tracking-[0.06em] text-[var(--text-muted)] select-none">
                          <span>TARGET LOCATION</span>
                          <span>RECOVERABLE SIZE</span>
                        </div>
                      )}

                      {focusedCat.sub_items.length === 0 ? (
                        <div className="h-48 flex flex-col items-center justify-center text-center text-[var(--text-muted)]">
                          <CheckCircle2 size={32} strokeWidth={1.75} className="text-[#10B981] mb-2 opacity-80" />
                          <span className="text-sm font-medium text-[var(--text-primary)]">Clean</span>
                          <span className="text-xs mt-0.5 text-[var(--text-muted)]">No cache files detected in this category</span>
                        </div>
                      ) : (
                        focusedCat.sub_items.map((sub) => {
                          const isSubChecked = selectedSubPaths.has(sub.id);

                          return (
                            <div
                              key={sub.id}
                              onClick={() => toggleSubItem(sub.id)}
                              className={`flex items-center gap-3 px-3.5 py-2.5 rounded-xl border cursor-pointer transition-all duration-150 ${
                                isSubChecked
                                  ? "bg-[var(--bg-card)] border-[var(--border-subtle)] shadow-sm"
                                  : "bg-[var(--bg-card)]/40 border-[var(--border-hairline)] hover:bg-[var(--bg-card-hover)] text-[var(--text-secondary)]"
                              }`}
                            >
                              <CustomCheckbox
                                checked={isSubChecked}
                                onChange={() => toggleSubItem(sub.id)}
                              />

                              <Folder size={16} strokeWidth={1.75} className="text-[var(--accent-primary)] shrink-0" />

                              <div className="flex-1 min-w-0">
                                <div className="text-xs font-medium text-[var(--text-primary)] truncate">
                                  {sub.name}
                                </div>
                                <div className="text-[11.5px] text-[var(--text-muted)] mono-num truncate">
                                  {formatDisplayPath(sub.display_path)}
                                </div>
                              </div>

                              <div className="text-right shrink-0 pl-2">
                                <span className="text-xs font-semibold text-[var(--text-primary)] mono-num tabular-nums">
                                  {formatBytes(sub.size_bytes)}
                                </span>
                                <div className="text-[10px] text-[var(--text-muted)] mono-num tabular-nums">
                                  {sub.file_count.toLocaleString()} files
                                </div>
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>

                    {/* Floating Glass Bottom Action Bar */}
                    <div className="px-6 py-3.5 border-t border-[var(--border-hairline)] bg-[var(--bg-dock)] backdrop-blur-xl flex items-center justify-between gap-4 shrink-0 z-20">
                      {/* Left Summary: Stacked Selected Total + Files Count */}
                      <div className="flex flex-col shrink-0">
                        <div className="text-[13px] font-semibold text-[var(--text-primary)] mono-num">
                          Selected: {formatBytes(totalSelectedBytes)}
                        </div>
                        <div className="text-[11px] text-[var(--text-muted)] mono-num">
                          {totalSelectedFiles.toLocaleString()} files ready
                        </div>
                      </div>

                      {/* Right Action Group */}
                      <div className="flex items-center gap-2.5 shrink-0">
                        <button
                          onClick={() => setUseRecycleBin(!useRecycleBin)}
                          className={`h-[32px] px-3 rounded-lg border text-[11.5px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
                            useRecycleBin
                              ? "bg-[#10B981]/10 text-[#10B981] border-[#10B981]/25 hover:bg-[#10B981]/15"
                              : "bg-amber-500/10 text-amber-500 border-amber-500/25 hover:bg-amber-500/15"
                          }`}
                          title="Click to toggle deletion mode"
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${useRecycleBin ? "bg-[#10B981]" : "bg-amber-500"}`} />
                          <span>{useRecycleBin ? "Recycle Bin Safe" : "Permanent Delete"}</span>
                        </button>

                        <button
                          onClick={handleSelectSafeAll}
                          disabled={isOperating}
                          className="h-[34px] px-3.5 rounded-lg text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)] border border-[var(--border-hairline)] transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                        >
                          Select Safe All
                        </button>

                        <button
                          onClick={() => setShowConfirmModal(true)}
                          disabled={totalSelectedBytes === 0 || isOperating}
                          className="h-[34px] px-4 rounded-lg text-xs font-semibold btn-electric text-white shadow-sm transition-all duration-150 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          <Sparkles size={14} strokeWidth={2} />
                          <span>Clean Selected</span>
                        </button>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="flex-1 flex items-center justify-center text-[var(--text-muted)] text-xs">
                    Select a category from the master pane to inspect sub-items
                  </div>
                )}
              </div>
            </div>
            )
          )}

          {/* VIEW: STORAGE */}
          {activeView === "storage" && (
            <div className="h-full overflow-y-auto p-8 space-y-6">
              <div className="flex items-start justify-between">
                <div>
                  <h2 className="text-lg font-bold text-[var(--text-primary)] tracking-tight">Storage Breakdown</h2>
                  <p className="text-xs text-[var(--text-muted)] mt-0.5">
                    Distribution of recoverable cache and temporary files across categories
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-xs text-[var(--text-muted)]">Total Recoverable</span>
                  <div className="text-base font-bold text-[var(--text-primary)] mono-num tabular-nums">
                    {formatBytes(totalDiscoveredBytes)}
                  </div>
                </div>
              </div>

              {/* Segmented Bar Card */}
              <div className="p-6 rounded-2xl glass-card space-y-5">
                <div className="flex items-center justify-between text-xs text-[var(--text-muted)]">
                  <span className="font-semibold uppercase tracking-wider text-[11px] text-[var(--text-secondary)]">
                    Storage Distribution
                  </span>
                  <span className="text-[11px]">Hover legend or bar segments to highlight</span>
                </div>

                <div className="h-7 w-full rounded-lg overflow-hidden flex gap-[3px] bg-black/5 dark:bg-white/5 p-1 border border-[var(--border-hairline)]">
                  {categories.map((c, i) => {
                    const pct = totalDiscoveredBytes > 0 ? (c.size_bytes / totalDiscoveredBytes) * 100 : 0;
                    if (pct === 0) return null;
                    const isHovered = hoveredCategoryId === c.id;
                    const isAnyHovered = hoveredCategoryId !== null;
                    const opacity = isHovered ? 1 : isAnyHovered ? 0.3 : 1;
                    const transform = isHovered ? "scaleY(1.18)" : "scaleY(1)";
                    const filter = isHovered ? "brightness(1.2)" : "none";

                    return (
                      <div
                        key={c.id}
                        style={{
                          width: `${pct}%`,
                          opacity,
                          transform,
                          filter,
                        }}
                        onMouseEnter={() => setHoveredCategoryId(c.id)}
                        onMouseLeave={() => setHoveredCategoryId(null)}
                        className={`h-full rounded-[4px] ${getCategoryColor(
                          c.id,
                          i
                        )} transition-all duration-200 ease-apple cursor-pointer`}
                        title={`${c.name}: ${formatBytes(c.size_bytes)} (${pct.toFixed(1)}%)`}
                      />
                    );
                  })}
                </div>

                {/* Interactive Legend Cards */}
                <div className="grid grid-cols-2 gap-3 pt-2">
                  {categories.map((c, i) => {
                    const pct = totalDiscoveredBytes > 0 ? (c.size_bytes / totalDiscoveredBytes) * 100 : 0;
                    const isHovered = hoveredCategoryId === c.id;

                    return (
                      <div
                        key={c.id}
                        onMouseEnter={() => setHoveredCategoryId(c.id)}
                        onMouseLeave={() => setHoveredCategoryId(null)}
                        onClick={() => {
                          setSelectedCategory(c.id);
                          setActiveView("clean");
                        }}
                        className={`flex items-center justify-between p-3.5 rounded-xl border cursor-pointer transition-all duration-200 ${
                          isHovered
                            ? "bg-[var(--accent-subtle)] border-[var(--accent-border)] shadow-md"
                            : "glass-card hover:border-[var(--border-subtle)]"
                        }`}
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <div
                            className={`w-8 h-8 rounded-lg flex items-center justify-center border shrink-0 ${getCategorySquircleBg(
                              c.id
                            )}`}
                          >
                            {getCategoryIcon(c.id)}
                          </div>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span
                                className={`w-2 h-2 rounded-full shrink-0 ${getCategoryColor(
                                  c.id,
                                  i
                                )}`}
                              />
                              <span className="text-xs font-semibold text-[var(--text-primary)] truncate">
                                {getCategoryShortName(c.id, c.name)}
                              </span>
                            </div>
                            <div className="text-[11px] text-[var(--text-muted)] mt-0.5">
                              {c.sub_items.length} {c.sub_items.length === 1 ? "item" : "items"}
                            </div>
                          </div>
                        </div>

                        <div className="text-right shrink-0 pl-2">
                          <div className="text-xs font-bold text-[var(--text-primary)] mono-num tabular-nums">
                            {formatBytes(c.size_bytes)}
                          </div>
                          <div className="text-[11px] text-[var(--accent-primary)] mono-num tabular-nums font-medium">
                            {pct.toFixed(1)}%
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* VIEW: LARGE FILES FINDER */}
          {activeView === "large_files" && (
            <div className="h-full flex flex-col overflow-hidden relative">
              {/* Header Bar */}
              <div className="p-6 border-b border-[var(--border-hairline)] shrink-0 flex items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-lg font-bold text-[var(--text-primary)] tracking-tight">Large Files Finder</h2>
                    {largeFilesScanTimeMs > 0 && (
                      <span className="text-[10px] font-mono text-[var(--text-muted)] px-2 py-0.5 rounded-full bg-[var(--border-hairline)]">
                        Scanned in {(largeFilesScanTimeMs / 1000).toFixed(2)}s
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-[var(--text-muted)] mt-0.5">
                    Discovers space-hogging archives, disk images, and media across Downloads, Desktop, Documents, and Videos
                  </p>
                </div>

                {/* Threshold Pills & Refresh Button */}
                <div className="flex items-center gap-2 shrink-0">
                  <div className="flex items-center gap-1 bg-[var(--border-hairline)]/50 p-1 rounded-lg border border-[var(--border-hairline)]">
                    {[100, 250, 500, 1024].map((thresh) => {
                      const label = thresh >= 1024 ? "> 1 GB" : `> ${thresh} MB`;
                      const active = largeFileSizeThresholdMb === thresh;
                      return (
                        <button
                          key={thresh}
                          disabled={isOperating}
                          onClick={() => {
                            setLargeFileSizeThresholdMb(thresh);
                            handleScanLargeFiles(thresh);
                          }}
                          className={`px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all cursor-pointer disabled:opacity-50 ${
                            active
                              ? "bg-[var(--accent-primary)] text-white shadow-sm"
                              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)]"
                          }`}
                        >
                          {label}
                        </button>
                      );
                    })}
                  </div>

                  <button
                    onClick={() => handleScanLargeFiles(largeFileSizeThresholdMb)}
                    disabled={isOperating}
                    className="h-[30px] px-3 rounded-lg text-xs font-medium border border-[var(--border-hairline)] bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] text-[var(--text-primary)] transition-colors disabled:opacity-50 flex items-center gap-1.5 cursor-pointer"
                  >
                    <RefreshCw
                      size={13}
                      strokeWidth={1.75}
                      className={`text-[var(--accent-primary)] ${isScanningLargeFiles ? "animate-spin" : ""}`}
                    />
                    <span>{isScanningLargeFiles ? "Scanning..." : "Re-Scan"}</span>
                  </button>
                </div>
              </div>

              {/* Body: Table or Loading or Empty State */}
              <div className="flex-1 overflow-y-auto p-6 pb-24">
                {isScanningLargeFiles ? (
                  <div className="h-72 flex flex-col items-center justify-center text-center glass-card rounded-xl">
                    <RefreshCw size={28} className="animate-spin text-[var(--accent-primary)] mb-3" />
                    <span className="text-sm font-semibold text-[var(--text-primary)]">
                      Scanning User Folders...
                    </span>
                    <span className="text-xs text-[var(--text-muted)] mt-1">
                      Searching for files exceeding {largeFileSizeThresholdMb >= 1024 ? "1 GB" : `${largeFileSizeThresholdMb} MB`} in Downloads, Desktop, Documents, and Videos
                    </span>
                  </div>
                ) : !hasScannedLargeFiles ? (
                  <div className="h-72 flex flex-col items-center justify-center text-center glass-card rounded-xl">
                    <div className="w-12 h-12 rounded-xl bg-[var(--accent-subtle)] border border-[var(--accent-border)] flex items-center justify-center text-[var(--accent-primary)] mb-3">
                      <FileSearch size={24} strokeWidth={1.75} />
                    </div>
                    <span className="text-sm font-bold text-[var(--text-primary)]">Large Files Finder Ready</span>
                    <span className="text-xs text-[var(--text-muted)] mt-1 max-w-sm">
                      Scan your user folders (Downloads, Desktop, Documents, Videos) for files exceeding {largeFileSizeThresholdMb >= 1024 ? "1 GB" : `${largeFileSizeThresholdMb} MB`}.
                    </span>
                    <button
                      onClick={() => handleScanLargeFiles(largeFileSizeThresholdMb)}
                      disabled={isOperating}
                      className="mt-4 px-4 py-2 rounded-lg text-xs font-semibold btn-electric text-white cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
                    >
                      <FileSearch size={14} strokeWidth={2} />
                      <span>Scan Large Files</span>
                    </button>
                  </div>
                ) : largeFiles.length === 0 ? (
                  <div className="h-72 flex flex-col items-center justify-center text-center glass-card rounded-xl">
                    <div className="w-12 h-12 rounded-xl bg-[var(--accent-subtle)] border border-[var(--accent-border)] flex items-center justify-center text-[var(--accent-primary)] mb-3">
                      <FileSearch size={24} strokeWidth={1.75} />
                    </div>
                    <span className="text-sm font-bold text-[var(--text-primary)]">No Large Files Found</span>
                    <span className="text-xs text-[var(--text-muted)] mt-1 max-w-sm">
                      No files exceeding {largeFileSizeThresholdMb >= 1024 ? "1 GB" : `${largeFileSizeThresholdMb} MB`} were discovered. Try selecting a lower threshold above.
                    </span>
                  </div>
                ) : (
                  <div className="glass-card rounded-xl overflow-hidden border border-[var(--border-hairline)]">
                    {/* Table Header */}
                    <div className="px-4 py-3 border-b border-[var(--border-hairline)] bg-[var(--bg-card-hover)] flex items-center text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                      <div className="w-8 shrink-0 flex items-center">
                        <CustomCheckbox
                          checked={selectedLargeFiles.size === largeFiles.length && largeFiles.length > 0}
                          indeterminate={
                            selectedLargeFiles.size > 0 && selectedLargeFiles.size < largeFiles.length
                          }
                          onChange={toggleAllLargeFiles}
                        />
                      </div>
                      <div className="flex-1 min-w-0 pr-4">File Name & Path</div>
                      <div className="w-32 text-center shrink-0">Modified</div>
                      <div className="w-28 text-right shrink-0 pr-2">Size</div>
                      <div className="w-16 text-center shrink-0">Open</div>
                    </div>

                    {/* Table Body */}
                    <div className="divide-y divide-[var(--border-hairline)]">
                      {largeFiles.map((file) => {
                        const isSelected = selectedLargeFiles.has(file.path);
                        const badgeStyle = getExtensionBadgeColor(file.extension);
                        const displayExt = (file.extension || "FILE").toUpperCase().replace(/^\./, "");
                        const ageText =
                          file.modified_days_ago === 0
                            ? "Today"
                            : file.modified_days_ago === 1
                            ? "Yesterday"
                            : `${file.modified_days_ago}d ago`;

                        return (
                          <div
                            key={file.path}
                            onClick={() => toggleLargeFile(file.path)}
                            className={`px-4 py-2.5 flex items-center transition-colors cursor-pointer ${
                              isSelected
                                ? "bg-[var(--accent-subtle)]"
                                : "hover:bg-[var(--bg-card-hover)]"
                            }`}
                          >
                            {/* Checkbox */}
                            <div className="w-8 shrink-0 flex items-center" onClick={(e) => e.stopPropagation()}>
                              <CustomCheckbox
                                checked={isSelected}
                                onChange={() => toggleLargeFile(file.path)}
                              />
                            </div>

                            {/* Extension Badge + Name & Path */}
                            <div className="flex-1 min-w-0 flex items-center gap-3 pr-4">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wider shrink-0 border ${badgeStyle.bg} ${badgeStyle.text} ${badgeStyle.border}`}
                              >
                                {displayExt}
                              </span>
                              <div className="min-w-0">
                                <div className="text-xs font-semibold text-[var(--text-primary)] truncate">
                                  {file.name}
                                </div>
                                <div className="text-[11px] font-mono text-[var(--text-muted)] truncate mt-0.5">
                                  {formatDisplayPath(file.formatted_path)}
                                </div>
                              </div>
                            </div>

                            {/* Modified */}
                            <div className="w-32 text-center text-xs text-[var(--text-secondary)] shrink-0 mono-num">
                              {ageText}
                            </div>

                            {/* Size */}
                            <div className="w-28 text-right shrink-0 pr-2">
                              <span className="text-xs font-bold text-[var(--text-primary)] mono-num tabular-nums">
                                {formatBytes(file.size_bytes)}
                              </span>
                            </div>

                            {/* Reveal in Explorer */}
                            <div
                              className="w-16 text-center shrink-0 flex items-center justify-center"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <button
                                onClick={() => handleRevealInExplorer(file.path)}
                                title="Reveal in File Explorer"
                                className="p-1.5 rounded-md hover:bg-[var(--accent-subtle)] text-[var(--text-muted)] hover:text-[var(--accent-primary)] transition-colors cursor-pointer"
                              >
                                <FolderOpen size={15} strokeWidth={1.75} />
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>

              {/* Floating Bottom Action Dock */}
              {largeFiles.length > 0 && (
                <div className="absolute bottom-4 left-6 right-6 h-[54px] px-4 rounded-xl glass-card flex items-center justify-between border border-[var(--border-subtle)] shadow-xl z-20">
                  {/* Left: Summary */}
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-medium text-[var(--text-secondary)]">
                      <strong className="text-[var(--text-primary)] font-semibold">
                        {selectedLargeFiles.size.toLocaleString()}
                      </strong>{" "}
                      of {largeFiles.length.toLocaleString()} files selected
                    </span>
                    {selectedLargeFiles.size > 0 && (
                      <span className="text-xs font-bold text-[var(--accent-primary)] mono-num tabular-nums px-2 py-0.5 rounded-md bg-[var(--accent-subtle)] border border-[var(--accent-border)]">
                        {formatBytes(selectedLargeBytes)}
                      </span>
                    )}
                  </div>

                  {/* Right: Mode & Actions */}
                  <div className="flex items-center gap-2.5">
                    <span
                      className={`text-[10px] font-semibold px-2 py-1 rounded-md border ${
                        useRecycleBin
                          ? "bg-[#10B981]/10 text-[#10B981] border-[#10B981]/25"
                          : "bg-amber-500/10 text-amber-500 border-amber-500/25"
                      }`}
                    >
                      {useRecycleBin ? "Recycle Bin Safe" : "Permanent Deletion"}
                    </span>

                    <button
                      onClick={toggleAllLargeFiles}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium border border-[var(--border-hairline)] bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
                    >
                      {selectedLargeFiles.size === largeFiles.length ? "Deselect All" : "Select All"}
                    </button>

                    <button
                      onClick={() => setShowLargeFilesConfirmModal(true)}
                      disabled={selectedLargeFiles.size === 0 || isOperating}
                      className="px-4 py-1.5 rounded-lg text-xs font-semibold btn-electric text-white shadow-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5 cursor-pointer"
                    >
                      <Trash2 size={13} strokeWidth={2} />
                      <span>
                        {isDeletingLargeFiles
                          ? "Deleting..."
                          : useRecycleBin
                          ? "Move to Recycle Bin"
                          : "Delete Permanently"}
                      </span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* VIEW: AUDIT LOG */}
          {activeView === "audit" && (
            <div className="h-full overflow-y-auto p-8 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold text-[var(--text-primary)] tracking-tight">Audit Log</h2>
                  <p className="text-xs text-[var(--text-muted)] mt-0.5">
                    Immutable history of cache cleaning sessions recorded in %LOCALAPPDATA%\SmartCacheCleaner\audit.log
                  </p>
                </div>
                <button
                  onClick={loadAuditLogs}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] text-[var(--text-primary)] border border-[var(--border-hairline)] transition-colors cursor-pointer"
                >
                  Refresh
                </button>
              </div>

              {auditLogs.length === 0 ? (
                <div className="h-64 flex flex-col items-center justify-center text-center text-[var(--text-muted)] glass-card rounded-xl">
                  <History size={32} strokeWidth={1.5} className="opacity-40 mb-2" />
                  <span className="text-sm font-medium text-[var(--text-primary)]">No Cleaning Records Yet</span>
                  <span className="text-xs mt-1">Run a clean operation to view tamper-evident records</span>
                </div>
              ) : (
                <div className="space-y-2.5">
                  {auditLogs.map((log, i) => (
                    <div
                      key={i}
                      className="p-4 rounded-xl glass-card flex items-center justify-between"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-[var(--text-primary)] mono-num tabular-nums">
                            Freed {formatBytes(log.freed_bytes)}
                          </span>
                          <span
                            className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                              log.use_recycle_bin
                                ? "bg-[#10B981]/10 text-[#10B981] border border-[#10B981]/20"
                                : "bg-amber-500/10 text-amber-500 border border-amber-500/20"
                            }`}
                          >
                            {log.use_recycle_bin ? "Recycle Bin" : "Permanent"}
                          </span>
                        </div>
                        <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
                          {log.timestamp} • {log.deleted_files.toLocaleString()} files removed • {log.skipped_count.toLocaleString()} skipped
                        </div>
                        <div className="text-[11px] text-[var(--text-secondary)] mt-0.5">
                          Categories: {log.categories.join(", ")}
                        </div>
                      </div>

                      <div className="text-right">
                        <span className="text-xs text-[var(--text-muted)] tabular-nums font-mono">
                          {(log.duration_ms / 1000).toFixed(2)}s
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* VIEW: SETTINGS */}
          {activeView === "settings" && (
            <div className="h-full overflow-y-auto p-8 space-y-6">
              <div>
                <h2 className="text-lg font-bold text-[var(--text-primary)] tracking-tight">Preferences</h2>
                <p className="text-xs text-[var(--text-muted)] mt-0.5">
                  Configure appearance, deletion safety modes, and background discovery
                </p>
              </div>

              {/* Appearance & Theme Schedule */}
              <div className="p-5 rounded-xl glass-card space-y-3">
                <div className="flex items-center gap-2 text-xs font-semibold text-[var(--text-primary)]">
                  <Sun size={15} strokeWidth={2} className="text-[var(--accent-primary)]" />
                  <span>Appearance & Theme Schedule</span>
                </div>
                <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
                  SmartCache automatically transitions between Obsidian Dark and Porcelain Light based on local sunrise and sunset hours (6:00 AM – 6:00 PM), or you can lock your preferred theme.
                </p>

                <div className="grid grid-cols-3 gap-3 pt-2">
                  <button
                    onClick={() => setThemeMode("light")}
                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                      themeMode === "light"
                        ? "bg-[var(--accent-subtle)] border-[var(--accent-border)] shadow-sm"
                        : "border-[var(--border-hairline)] bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)]"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Sun size={16} strokeWidth={1.75} className="text-amber-500" />
                        <span className="text-xs font-semibold text-[var(--text-primary)]">Light Mode</span>
                      </div>
                      {themeMode === "light" && (
                        <Check size={14} strokeWidth={2.5} className="text-[var(--accent-primary)]" />
                      )}
                    </div>
                    <p className="text-[10px] text-[var(--text-muted)] mt-1.5 leading-normal">
                      Cool Porcelain workspace
                    </p>
                  </button>

                  <button
                    onClick={() => setThemeMode("dark")}
                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                      themeMode === "dark"
                        ? "bg-[var(--accent-subtle)] border-[var(--accent-border)] shadow-sm"
                        : "border-[var(--border-hairline)] bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)]"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Moon size={16} strokeWidth={1.75} className="text-sky-400" />
                        <span className="text-xs font-semibold text-[var(--text-primary)]">Dark Mode</span>
                      </div>
                      {themeMode === "dark" && (
                        <Check size={14} strokeWidth={2.5} className="text-[var(--accent-primary)]" />
                      )}
                    </div>
                    <p className="text-[10px] text-[var(--text-muted)] mt-1.5 leading-normal">
                      Deep Obsidian Slate
                    </p>
                  </button>

                  <button
                    onClick={() => setThemeMode("auto")}
                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                      themeMode === "auto"
                        ? "bg-[var(--accent-subtle)] border-[var(--accent-border)] shadow-sm"
                        : "border-[var(--border-hairline)] bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)]"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Clock size={16} strokeWidth={1.75} className="text-[var(--accent-primary)]" />
                        <span className="text-xs font-semibold text-[var(--text-primary)]">Auto Schedule</span>
                      </div>
                      {themeMode === "auto" && (
                        <Check size={14} strokeWidth={2.5} className="text-[var(--accent-primary)]" />
                      )}
                    </div>
                    <p className="text-[10px] text-[var(--text-muted)] mt-1.5 leading-normal">
                      6:00 AM Light • 6:00 PM Dark
                    </p>
                  </button>
                </div>
              </div>

              {/* Safety Preferences */}
              <div className="p-5 rounded-xl glass-card space-y-4">
                {/* Recycle Bin Toggle */}
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-xs font-semibold text-[var(--text-primary)]">
                      Move deleted files to Recycle Bin (Safer)
                    </div>
                    <div className="text-[11px] text-[var(--text-muted)] mt-0.5">
                      Sends cleaned cache files to Windows Recycle Bin with per-file fallback instead of immediate permanent deletion.
                    </div>
                  </div>
                  <button
                    onClick={() => setUseRecycleBin(!useRecycleBin)}
                    className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors duration-200 ease-apple cursor-pointer ${
                      useRecycleBin ? "bg-[#10B981]" : "bg-[var(--border-subtle)]"
                    }`}
                  >
                    <div
                      className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform duration-200 ease-apple ${
                        useRecycleBin ? "translate-x-5" : "translate-x-0"
                      }`}
                    />
                  </button>
                </div>

                <div className="border-t border-[var(--border-hairline)] pt-4 flex items-center justify-between">
                  <div>
                    <div className="text-xs font-semibold text-[var(--text-primary)]">
                      Show empty or uninstalled app categories
                    </div>
                    <div className="text-[11px] text-[var(--text-muted)] mt-0.5">
                      Display software categories (e.g. npm, pip, Adobe) even if not currently detected on this PC.
                    </div>
                  </div>
                  <button
                    onClick={() => setShowEmptyCategories(!showEmptyCategories)}
                    className={`w-11 h-6 flex items-center rounded-full p-1 transition-colors duration-200 ease-apple cursor-pointer ${
                      showEmptyCategories ? "bg-[var(--accent-primary)]" : "bg-[var(--border-subtle)]"
                    }`}
                  >
                    <div
                      className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform duration-200 ease-apple ${
                        showEmptyCategories ? "translate-x-5" : "translate-x-0"
                      }`}
                    />
                  </button>
                </div>
              </div>

              {/* Elevation Notice */}
              <div className="p-5 rounded-xl glass-card space-y-2">
                <div className="text-xs font-semibold text-[var(--text-primary)]">Windows Administrator Privileges</div>
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 text-xs font-semibold rounded-md border ${
                      isElevated
                        ? "bg-[#10B981]/10 text-[#10B981] border-[#10B981]/20"
                        : "bg-amber-500/10 text-amber-500 border-amber-500/20"
                    }`}
                  >
                    {isElevated ? "Administrator (Elevated)" : "Standard User"}
                  </span>
                  {!isElevated && (
                    <button
                      onClick={handleElevate}
                      className="px-2.5 py-1 rounded-md text-[11px] font-semibold border border-amber-500/30 bg-amber-500/10 text-amber-500 hover:bg-amber-500/20 transition-all flex items-center gap-1 cursor-pointer"
                    >
                      <span>Elevate</span>
                      <ArrowUpRight size={13} strokeWidth={2} />
                    </button>
                  )}
                </div>
                <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
                  {isElevated
                    ? "SmartCacheCleaner has full administrator permissions to clean system-level temporary files and Windows Update installer cache."
                    : "To clean Windows System Temp and SoftwareDistribution Update cache, elevate via the button above or launch the app by right-clicking and selecting 'Run as administrator'."}
                </p>
              </div>

              {/* Zero-Trust Specs */}
              <div className="p-5 rounded-xl glass-card space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-[var(--text-primary)]">
                  <ShieldCheck size={16} strokeWidth={2} className="text-[#10B981]" />
                  <span>Zero-Trust Security Guarantee</span>
                </div>
                <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
                  Every path is strictly canonicalized and checked for Windows junction traps (`FILE_ATTRIBUTE_REPARSE_POINT` 0x400) and symlinks. System32, Personal Documents, Desktop, Pictures, and Browser Credentials (Login Data, Cookies, Bookmarks) are hard-blocked at the kernel level.
                </p>
              </div>

              {/* About & Developer Support */}
              <div className="p-5 rounded-xl glass-card space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#38BDF8] to-[#0284C7] flex items-center justify-center text-white shadow-sm shrink-0">
                      <ShieldCheck size={20} strokeWidth={2} />
                    </div>
                    <div>
                      <div className="text-sm font-bold text-[var(--text-primary)]">
                        Pixel Craft Studios
                      </div>
                      <div className="text-[11px] text-[var(--text-muted)]">
                        Zero-Trust Windows Utility • v1.0.0
                      </div>
                    </div>
                  </div>
                  <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-[var(--border-hairline)] text-[var(--text-muted)]">
                    Commercial Edition
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 pt-1">
                  {/* Website Box */}
                  <div className="p-3 rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-card-hover)] flex items-center justify-between">
                    <div className="min-w-0 pr-2">
                      <div className="text-[10px] uppercase font-semibold text-[var(--text-muted)]">Official Website</div>
                      <div className="text-xs font-mono font-medium text-[var(--text-primary)] truncate mt-0.5">
                        www.pixelcraftlk.com
                      </div>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        onClick={() => invoke("open_brand_link", { target: "website" })}
                        className="p-1.5 rounded-md hover:bg-[var(--accent-subtle)] text-[var(--accent-primary)] transition-colors cursor-pointer"
                        title="Open Website in Browser"
                      >
                        <ArrowUpRight size={15} strokeWidth={1.75} />
                      </button>
                      <button
                        onClick={() => copyToClipboard("website", "https://www.pixelcraftlk.com")}
                        className="p-1.5 rounded-md hover:bg-[var(--bg-card)] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
                        title="Copy Website URL"
                      >
                        {copiedKey === "website" ? (
                          <Check size={14} strokeWidth={2.2} className="text-[#10B981]" />
                        ) : (
                          <Copy size={14} strokeWidth={1.75} />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* WhatsApp Box */}
                  <div className="p-3 rounded-lg border border-[var(--border-hairline)] bg-[var(--bg-card-hover)] flex items-center justify-between">
                    <div className="min-w-0 pr-2">
                      <div className="text-[10px] uppercase font-semibold text-[var(--text-muted)]">Direct WhatsApp Support</div>
                      <div className="text-xs font-mono font-medium text-[var(--text-primary)] truncate mt-0.5">
                        +94 78 767 6576
                      </div>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        onClick={() => invoke("open_brand_link", { target: "whatsapp" })}
                        className="p-1.5 rounded-md hover:bg-[var(--accent-subtle)] text-[var(--accent-primary)] transition-colors cursor-pointer"
                        title="Chat on WhatsApp"
                      >
                        <ArrowUpRight size={15} strokeWidth={1.75} />
                      </button>
                      <button
                        onClick={() => copyToClipboard("whatsapp", "+94787676576")}
                        className="p-1.5 rounded-md hover:bg-[var(--bg-card)] text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
                        title="Copy WhatsApp Number"
                      >
                        {copiedKey === "whatsapp" ? (
                          <Check size={14} strokeWidth={2.2} className="text-[#10B981]" />
                        ) : (
                          <Copy size={14} strokeWidth={1.75} />
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* 4. CONFIRMATION SHEET MODAL */}
      {showConfirmModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="w-[420px] rounded-2xl glass-card p-6 shadow-2xl animate-scale-in">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-[var(--accent-subtle)] border border-[var(--accent-border)] flex items-center justify-center">
                  <Sparkles size={16} strokeWidth={2} className="text-[var(--accent-primary)]" />
                </div>
                <h3 className="text-sm font-bold text-[var(--text-primary)]">Confirm Cache Cleanup</h3>
              </div>
              <button
                onClick={() => setShowConfirmModal(false)}
                className="p-1 rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
              >
                <X size={16} strokeWidth={2} />
              </button>
            </div>

            <p className="text-xs text-[var(--text-secondary)] leading-relaxed mb-4">
              You are about to remove{" "}
              <strong className="text-[var(--text-primary)] font-semibold mono-num tabular-nums">
                {formatBytes(totalSelectedBytes)}
              </strong>{" "}
              ({totalSelectedFiles.toLocaleString()} files) across selected categories.
            </p>

            <div className="p-3 rounded-xl bg-[var(--border-hairline)]/30 border border-[var(--border-hairline)] text-xs space-y-1.5 mb-5">
              <div className="flex justify-between">
                <span className="text-[var(--text-muted)]">Mode:</span>
                <span className="font-medium text-[var(--text-primary)]">
                  {useRecycleBin ? "Move to Recycle Bin (Safe)" : "Permanent Deletion"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-muted)]">Zero-Trust Re-Validation:</span>
                <span className="font-medium text-[#10B981]">Enforced</span>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2">
              <button
                onClick={() => setShowConfirmModal(false)}
                className="px-4 py-2 rounded-lg text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)] transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleClean}
                className="px-4 py-2 rounded-lg text-xs font-semibold btn-electric text-white shadow-sm transition-all cursor-pointer"
              >
                Clean Now
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 5. COMPLETION MODAL */}
      {showCompleteModal && cleanResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="w-[400px] rounded-2xl glass-card p-6 shadow-2xl animate-scale-in text-center">
            <div className="w-12 h-12 rounded-full bg-[#10B981]/15 border border-[#10B981]/25 flex items-center justify-center mx-auto mb-3">
              <Check size={24} strokeWidth={2.5} className="text-[#10B981]" />
            </div>

            <h3 className="text-base font-bold text-[var(--text-primary)]">Cleanup Complete</h3>
            <div className="text-2xl font-extrabold text-[#10B981] my-2 mono-num tabular-nums">
              Freed {formatBytes(cleanResult.freed_bytes)}
            </div>

            <p className="text-xs text-[var(--text-muted)] leading-relaxed mb-4">
              Removed {cleanResult.deleted_files.toLocaleString()} files in {(cleanResult.duration_ms / 1000).toFixed(2)} seconds.
              {cleanResult.skipped_count > 0 && ` (${cleanResult.skipped_count.toLocaleString()} in-use items skipped)`}
            </p>

            <button
              onClick={() => setShowCompleteModal(false)}
              className="w-full py-2.5 rounded-lg text-xs font-semibold btn-electric text-white shadow-sm transition-all cursor-pointer"
            >
              Done
            </button>
          </div>
        </div>
      )}

      {/* 6. CONFIRM LARGE FILES MODAL */}
      {showLargeFilesConfirmModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="w-[440px] rounded-2xl glass-card p-6 shadow-2xl animate-scale-in">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/25 flex items-center justify-center text-rose-500">
                  <AlertCircle size={16} strokeWidth={2} />
                </div>
                <h3 className="text-sm font-bold text-[var(--text-primary)]">Delete Large Files</h3>
              </div>
              <button
                onClick={() => setShowLargeFilesConfirmModal(false)}
                className="p-1 rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
              >
                <X size={16} strokeWidth={2} />
              </button>
            </div>

            <p className="text-xs text-[var(--text-secondary)] leading-relaxed mb-4">
              You are about to remove{" "}
              <strong className="text-[var(--text-primary)] font-semibold mono-num tabular-nums">
                {formatBytes(selectedLargeBytes)}
              </strong>{" "}
              across{" "}
              <strong className="text-[var(--text-primary)] font-semibold">
                {selectedLargeFiles.size}
              </strong>{" "}
              selected {selectedLargeFiles.size === 1 ? "file" : "files"} from your user directories (Downloads, Desktop, Documents, Videos).
            </p>

            <div className="p-3 rounded-xl bg-[var(--border-hairline)]/30 border border-[var(--border-hairline)] text-xs space-y-1.5 mb-5">
              <div className="flex justify-between">
                <span className="text-[var(--text-muted)]">Destination:</span>
                <span className="font-medium text-[var(--text-primary)]">
                  {useRecycleBin ? "Windows Recycle Bin (Restorable)" : "Permanent Deletion (Unrecoverable)"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-muted)]">Safety Check:</span>
                <span className="font-medium text-[#10B981]">User Roots & Non-Junction Verified</span>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2">
              <button
                onClick={() => setShowLargeFilesConfirmModal(false)}
                className="px-4 py-2 rounded-lg text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)] transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteLargeFiles}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white shadow-sm transition-all cursor-pointer"
              >
                {useRecycleBin ? "Move to Recycle Bin" : "Delete Permanently"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 7. LIVE OPERATION PROGRESS FLOATING CARD */}
      {isOperating && (
        <div className="fixed bottom-6 right-6 w-[400px] z-50 glass-card p-4 rounded-2xl shadow-2xl border border-[var(--border-subtle)] backdrop-blur-xl bg-[var(--bg-card)]/95">
          <div className="flex items-center justify-between mb-2.5">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-[var(--accent-subtle)] border border-[var(--accent-border)] flex items-center justify-center shrink-0">
                <RefreshCw size={15} className="animate-spin text-[var(--accent-primary)]" />
              </div>
              <div className="min-w-0">
                <span className="text-xs font-bold text-[var(--text-primary)] truncate block">
                  {isScanning
                    ? "Scanning System & App Caches..."
                    : isCleaning
                    ? "Cleaning Selected Caches..."
                    : isScanningLargeFiles
                    ? "Scanning Large Files..."
                    : "Deleting Large Files..."}
                </span>
                <span className="text-[11px] text-[var(--text-muted)] truncate block mono-num">
                  {progress?.current_label || "Running zero-trust operation..."}
                </span>
              </div>
            </div>
            <button
              onClick={handleCancelOperation}
              className="px-2.5 py-1 text-[11px] font-semibold rounded-md border border-rose-500/30 bg-rose-500/10 text-rose-500 hover:bg-rose-500/20 transition-all cursor-pointer shrink-0 ml-2"
            >
              Cancel
            </button>
          </div>

          {/* Smooth Animated Progress Bar */}
          <div className="w-full h-2 rounded-full bg-black/10 dark:bg-white/10 overflow-hidden mb-2">
            <div
              className="h-full bg-gradient-to-r from-[var(--accent-primary)] to-[#10B981] transition-all duration-300 ease-out"
              style={{
                width: `${Math.max(5, Math.min(progress?.percent ?? 5, 100))}%`,
              }}
            />
          </div>

          {/* Counter Metrics */}
          <div className="flex items-center justify-between text-[11px] mono-num tabular-nums text-[var(--text-muted)]">
            <span>
              {progress && progress.total > 0
                ? `${progress.processed.toLocaleString()} / ${progress.total.toLocaleString()} ${
                    isScanning ? "categories" : "files"
                  }`
                : isScanning
                ? "Analyzing system targets..."
                : isCleaning
                ? "Processing deletion batches..."
                : "Scanning directories..."}
            </span>
            <span className="font-semibold text-[var(--text-primary)]">
              {progress?.percent !== undefined ? `${progress.percent}%` : ""}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
