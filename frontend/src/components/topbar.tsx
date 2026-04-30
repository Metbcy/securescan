"use client";

import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Search } from "lucide-react";
import { ApiStatus } from "@/components/api-status";
import { NotificationBell } from "@/components/notification-bell";
import { ThemeToggle } from "@/components/theme-toggle";
import { fetchScan } from "@/lib/api";

const PAGE_LABELS: Record<string, string> = {
  "/": "Overview",
  "/scan": "New Scan",
  "/history": "History",
  "/compare": "Compare",
  "/diff": "Diff",
  "/sbom": "SBOM",
  "/scanners": "Scanners",
  "/notifications": "Notifications",
};

function deriveLabel(pathname: string): string {
  if (PAGE_LABELS[pathname]) return PAGE_LABELS[pathname];
  if (pathname.startsWith("/scan/")) return "Scan";
  return pathname;
}

export function Topbar() {
  const pathname = usePathname();
  const [scanTarget, setScanTarget] = useState<{
    path: string;
    target: string;
  } | null>(null);

  useEffect(() => {
    const m = pathname.match(/^\/scan\/([^/]+)/);
    if (!m) return;
    let cancelled = false;
    fetchScan(m[1])
      .then((scan) => {
        if (!cancelled) {
          setScanTarget({ path: pathname, target: scan.target_path });
        }
      })
      .catch(() => {
        // best-effort; topbar still works without target context
      });
    return () => {
      cancelled = true;
    };
  }, [pathname]);

  function openPalette() {
    window.dispatchEvent(new CustomEvent("securescan:command-palette:open"));
  }

  const primary = deriveLabel(pathname);
  const showScanTarget =
    pathname.startsWith("/scan/") && scanTarget?.path === pathname;

  return (
    <header className="sticky top-0 z-30 h-14 bg-background border-b border-border">
      <div className="h-full flex items-center gap-3 sm:gap-4 px-4 md:px-6">
        {/* Left: breadcrumb-ish title. pl-14 on mobile clears the hamburger. */}
        <div className="flex items-center gap-2 min-w-0 pl-14 md:pl-0 shrink-0 md:shrink">
          <span className="text-sm font-medium text-foreground-strong truncate">
            {primary}
          </span>
          {showScanTarget && (
            <>
              <span aria-hidden className="text-muted text-sm">
                ·
              </span>
              <span
                className="text-sm font-mono text-muted truncate max-w-[28ch]"
                title={scanTarget!.target}
              >
                {scanTarget!.target}
              </span>
            </>
          )}
        </div>

        {/* Center: command palette trigger styled like a search input. */}
        <div className="flex-1 flex justify-center min-w-0">
          <button
            type="button"
            onClick={openPalette}
            className="
              w-full max-w-md inline-flex items-center gap-2
              bg-surface-2 border border-border rounded-md
              text-muted text-sm pl-3 pr-2 py-1.5
              hover:text-foreground hover:border-border-strong
              transition-colors
            "
            aria-label="Open command palette"
          >
            <Search size={14} strokeWidth={1.5} aria-hidden />
            <span className="flex-1 text-left truncate">
              Search scans, scanners, pages…
            </span>
            <kbd
              className="
                inline-flex items-center rounded bg-card border border-border
                px-1.5 py-0.5 text-[0.6875rem] font-mono text-muted
              "
            >
              ⌘K
            </kbd>
          </button>
        </div>

        {/* Right: status, theme, avatar. */}
        <div className="flex items-center gap-2 shrink-0">
          <ApiStatus />
          <NotificationBell />
          <ThemeToggle />
          <div
            aria-label="Account"
            title="Account"
            className="
              h-8 w-8 inline-flex items-center justify-center
              rounded-full border border-border bg-surface-2
              text-xs font-medium text-muted
            "
          >
            S
          </div>
        </div>
      </div>
    </header>
  );
}
