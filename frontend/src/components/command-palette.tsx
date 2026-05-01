"use client";

import { Command } from "cmdk";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { useEffect, useState, type ComponentType } from "react";
import {
  ArrowLeftRight,
  Clock,
  Copy,
  FileDiff,
  History as HistoryIcon,
  LayoutDashboard,
  Moon,
  Package,
  Play,
  ScanSearch,
  Search,
  Settings,
  Sun,
} from "lucide-react";
import { fetchScans, type Scan } from "@/lib/api";
import { RelativeTime } from "@/components/relative-time";

interface PageEntry {
  label: string;
  href: string;
  icon: ComponentType<{ size?: number; strokeWidth?: number }>;
  shortcut?: string;
}

const PAGES: PageEntry[] = [
  { label: "Overview", href: "/", icon: LayoutDashboard, shortcut: "G O" },
  { label: "New Scan", href: "/scan", icon: ScanSearch, shortcut: "G N" },
  { label: "History", href: "/history", icon: HistoryIcon, shortcut: "G H" },
  { label: "Compare", href: "/compare", icon: ArrowLeftRight, shortcut: "G C" },
  { label: "Diff", href: "/diff", icon: FileDiff },
  { label: "SBOM", href: "/sbom", icon: Package, shortcut: "G B" },
  { label: "Scanners", href: "/scanners", icon: Settings },
];

const GROUP_HEADING_CLASSES = `
  [&_[cmdk-group-heading]]:px-3
  [&_[cmdk-group-heading]]:pt-3
  [&_[cmdk-group-heading]]:pb-1
  [&_[cmdk-group-heading]]:text-[0.6875rem]
  [&_[cmdk-group-heading]]:uppercase
  [&_[cmdk-group-heading]]:tracking-wider
  [&_[cmdk-group-heading]]:text-muted
`;

const ITEM_CLASSES = `
  flex items-center gap-2.5 px-3 py-2 rounded-md
  text-sm text-foreground cursor-pointer select-none
  data-[selected=true]:bg-accent-soft
  data-[selected=true]:text-accent
`;

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [recent, setRecent] = useState<Scan[]>([]);
  const [recentLoaded, setRecentLoaded] = useState(false);
  const router = useRouter();
  const { resolvedTheme, setTheme } = useTheme();

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const isK = e.key.toLowerCase() === "k";
      if (isK && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((v) => !v);
        return;
      }
      if (e.key === "Escape") {
        setOpen(false);
      }
    }
    function onOpenEvent() {
      setOpen(true);
    }
    window.addEventListener("keydown", onKey);
    window.addEventListener(
      "securescan:command-palette:open",
      onOpenEvent as EventListener,
    );
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener(
        "securescan:command-palette:open",
        onOpenEvent as EventListener,
      );
    };
  }, []);

  useEffect(() => {
    if (!open || recentLoaded) return;
    let cancelled = false;
    fetchScans()
      .then((scans) => {
        if (cancelled) return;
        setRecent(scans.slice(0, 5));
        setRecentLoaded(true);
      })
      .catch(() => {
        if (!cancelled) setRecentLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [open, recentLoaded]);

  function go(href: string) {
    setOpen(false);
    router.push(href);
  }

  function copyUrl() {
    if (typeof window === "undefined") return;
    try {
      void navigator.clipboard?.writeText(window.location.href);
    } catch {
      // ignore — clipboard may be denied
    }
    setOpen(false);
  }

  function toggleTheme() {
    setTheme(resolvedTheme === "dark" ? "light" : "dark");
    setOpen(false);
  }

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[60] backdrop-blur-sm bg-black/30 flex items-start justify-center pt-[14vh] px-4"
      onClick={(e) => {
        if (e.target === e.currentTarget) setOpen(false);
      }}
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
    >
      <Command
        loop
        className="
          w-full max-w-[600px] max-h-[70vh] flex flex-col
          bg-card border border-border rounded-lg shadow-2xl
          overflow-hidden
        "
      >
        <div className="flex items-center gap-2 px-3 py-2.5 border-b border-border">
          <Search
            size={14}
            strokeWidth={1.5}
            className="text-muted shrink-0"
            aria-hidden
          />
          <Command.Input
            autoFocus
            placeholder="Search scans, scanners, pages…"
            className="
              flex-1 bg-transparent outline-none border-0
              text-sm text-foreground placeholder:text-muted
            "
          />
          <kbd
            className="
              inline-flex items-center rounded bg-surface-2
              px-1.5 py-0.5 text-[0.6875rem] font-mono text-muted
            "
          >
            Esc
          </kbd>
        </div>

        <Command.List className="flex-1 overflow-y-auto p-1">
          <Command.Empty className="px-3 py-6 text-center text-sm text-muted">
            No results.
          </Command.Empty>

          <Command.Group heading="Pages" className={GROUP_HEADING_CLASSES}>
            {PAGES.map((p) => (
              <Command.Item
                key={p.href}
                value={`page ${p.label}`}
                onSelect={() => go(p.href)}
                className={ITEM_CLASSES}
              >
                <p.icon size={14} strokeWidth={1.5} />
                <span className="flex-1">{p.label}</span>
                {p.shortcut && (
                  <span className="text-[0.6875rem] font-mono text-muted">
                    {p.shortcut}
                  </span>
                )}
              </Command.Item>
            ))}
          </Command.Group>

          {recent.length > 0 && (
            <Command.Group
              heading="Recent scans"
              className={GROUP_HEADING_CLASSES}
            >
              {recent.map((scan) => (
                <Command.Item
                  key={scan.id}
                  value={`scan ${scan.id} ${scan.target_path}`}
                  onSelect={() => go(`/scan/${scan.id}`)}
                  className={ITEM_CLASSES}
                >
                  <Clock size={14} strokeWidth={1.5} />
                  <span className="flex-1 truncate font-mono text-xs">
                    {scan.target_path}
                  </span>
                  <RelativeTime
                    iso={scan.started_at ?? scan.completed_at}
                    className="text-[0.6875rem] text-muted shrink-0"
                  />
                </Command.Item>
              ))}
            </Command.Group>
          )}

          <Command.Group heading="Actions" className={GROUP_HEADING_CLASSES}>
            <Command.Item
              value="action toggle theme"
              onSelect={toggleTheme}
              className={ITEM_CLASSES}
            >
              {resolvedTheme === "dark" ? (
                <Sun size={14} strokeWidth={1.5} />
              ) : (
                <Moon size={14} strokeWidth={1.5} />
              )}
              <span className="flex-1">Toggle theme</span>
            </Command.Item>
            <Command.Item
              value="action copy current url"
              onSelect={copyUrl}
              className={ITEM_CLASSES}
            >
              <Copy size={14} strokeWidth={1.5} />
              <span className="flex-1">Copy current URL</span>
            </Command.Item>
            <Command.Item
              value="action run new scan"
              onSelect={() => go("/scan")}
              className={ITEM_CLASSES}
            >
              <Play size={14} strokeWidth={1.5} />
              <span className="flex-1">Run new scan</span>
            </Command.Item>
          </Command.Group>
        </Command.List>
      </Command>
    </div>
  );
}
