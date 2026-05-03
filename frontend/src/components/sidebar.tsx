"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useMemo, useSyncExternalStore } from "react";
import {
  Bell,
  GitCompare,
  History,
  KeyRound,
  LayoutDashboard,
  Menu,
  Package,
  ScanSearch,
  Settings,
  Shield,
  Webhook,
  X,
} from "lucide-react";
import { useState } from "react";

const APP_VERSION = "0.11.10";
const RECENTS_STORAGE_KEY = "securescan:recent-scans";

type NavGroup = "main" | "settings";

interface NavItem {
  label: string;
  href: string;
  icon: typeof LayoutDashboard;
  group?: NavGroup;
}

const navItems: NavItem[] = [
  { label: "Overview", href: "/", icon: LayoutDashboard },
  { label: "New Scan", href: "/scan", icon: ScanSearch },
  { label: "Diff", href: "/diff", icon: GitCompare },
  { label: "History", href: "/history", icon: History },
  { label: "Notifications", href: "/notifications", icon: Bell },
  { label: "SBOM", href: "/sbom", icon: Package },
  { label: "Scanners", href: "/scanners", icon: Settings },
  { label: "API keys", href: "/settings/keys", icon: KeyRound, group: "settings" },
  { label: "Webhooks", href: "/settings/webhooks", icon: Webhook, group: "settings" },
];

interface RecentScan {
  id: string;
  target_path: string;
}

function truncatePath(p: string, max: number) {
  if (p.length <= max) return p;
  return "…" + p.slice(p.length - (max - 1));
}

function parseRecents(raw: string | null): RecentScan[] {
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(
        (s): s is RecentScan =>
          !!s &&
          typeof (s as RecentScan).id === "string" &&
          typeof (s as RecentScan).target_path === "string",
      )
      .slice(0, 5);
  } catch {
    return [];
  }
}

function subscribeStorage(callback: () => void) {
  if (typeof window === "undefined") return () => {};
  window.addEventListener("storage", callback);
  return () => window.removeEventListener("storage", callback);
}

function getRecentsRaw(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(RECENTS_STORAGE_KEY);
}

function getServerRecentsRaw(): string | null {
  return null;
}

export function Sidebar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  const raw = useSyncExternalStore(
    subscribeStorage,
    getRecentsRaw,
    getServerRecentsRaw,
  );
  const recents = useMemo(() => parseRecents(raw), [raw]);

  const isActive = (href: string) => {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  };

  return (
    <>
      {/* Mobile hamburger — sits above topbar on small viewports only. */}
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="fixed top-3 left-3 z-50 md:hidden p-2 rounded-md bg-card border border-border text-foreground hover:bg-surface-2"
        aria-label="Open menu"
      >
        <Menu size={18} strokeWidth={1.5} />
      </button>

      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/60 md:hidden"
          onClick={() => setOpen(false)}
          aria-hidden
        />
      )}

      <aside
        className={`
          fixed top-0 left-0 z-50 h-full
          w-[220px] md:w-14 lg:w-[220px]
          bg-card border-r border-border
          flex flex-col transition-transform duration-200
          md:translate-x-0
          ${open ? "translate-x-0" : "-translate-x-full"}
        `}
      >
        {/* Logo */}
        <div className="flex items-center justify-between h-14 px-5 md:px-3 lg:px-5 border-b border-border">
          <Link
            href="/"
            className="flex items-center gap-2.5 min-w-0"
            onClick={() => setOpen(false)}
          >
            <Shield
              size={18}
              strokeWidth={1.5}
              className="text-accent shrink-0"
              aria-hidden
            />
            <span className="text-base font-semibold tracking-tight text-foreground-strong md:hidden lg:inline">
              SecureScan
            </span>
          </Link>
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="md:hidden p-1 text-muted hover:text-foreground"
            aria-label="Close menu"
          >
            <X size={18} strokeWidth={1.5} />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 md:px-2 lg:px-3 py-4 overflow-y-auto">
          <ul className="space-y-0.5">
            {navItems.map((item, idx) => {
              const active = isActive(item.href);
              const prev = idx > 0 ? navItems[idx - 1] : null;
              const startsSettings =
                item.group === "settings" && prev?.group !== "settings";
              return (
                <li key={item.href}>
                  {startsSettings && (
                    <>
                      <div
                        aria-hidden
                        className="mt-4 mb-2 border-t border-border md:mx-1 lg:mx-0"
                      />
                      <p className="px-3 mb-1.5 text-[0.6875rem] uppercase tracking-wider text-muted md:hidden lg:block">
                        Settings
                      </p>
                    </>
                  )}
                  <Link
                    href={item.href}
                    onClick={() => setOpen(false)}
                    title={item.label}
                    aria-current={active ? "page" : undefined}
                    className={`
                      group relative flex items-center gap-3 rounded-md
                      px-3 md:px-2.5 lg:px-3 py-2
                      text-sm font-medium transition-colors
                      ${
                        active
                          ? "bg-accent-soft text-accent"
                          : "text-muted hover:text-foreground hover:bg-surface-2"
                      }
                    `}
                  >
                    {active && (
                      <span
                        aria-hidden
                        className="absolute left-0 top-1.5 bottom-1.5 w-px bg-accent rounded-full"
                      />
                    )}
                    <item.icon
                      size={18}
                      strokeWidth={1.5}
                      className="shrink-0"
                      aria-hidden
                    />
                    <span className="md:hidden lg:inline">{item.label}</span>
                  </Link>
                </li>
              );
            })}
          </ul>

          {recents.length > 0 && (
            <div className="md:hidden lg:block">
              <div className="mt-5 mb-3 border-t border-border" />
              <p className="px-3 mb-1.5 text-[0.6875rem] uppercase tracking-wider text-muted">
                Recent
              </p>
              <ul className="space-y-0.5">
                {recents.map((scan) => {
                  const href = `/scan/${scan.id}`;
                  const active = pathname === href;
                  return (
                    <li key={scan.id}>
                      <Link
                        href={href}
                        onClick={() => setOpen(false)}
                        title={scan.target_path}
                        className={`
                          flex items-center rounded-md px-3 py-1.5
                          font-mono text-xs truncate transition-colors
                          ${
                            active
                              ? "bg-accent-soft text-accent"
                              : "text-muted hover:text-foreground hover:bg-surface-2"
                          }
                        `}
                      >
                        {truncatePath(scan.target_path, 26)}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </nav>

        {/* Footer */}
        <div className="px-5 md:px-3 lg:px-5 py-4 border-t border-border md:hidden lg:block">
          <p className="text-xs text-muted">SecureScan v{APP_VERSION}</p>
        </div>
      </aside>
    </>
  );
}
