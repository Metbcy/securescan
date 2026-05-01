"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";
import { Bell, BellOff } from "lucide-react";
import {
  getUnreadNotificationCount,
  listNotifications,
  markAllNotificationsRead,
  markNotificationRead,
  type Notification,
  type NotificationSeverity,
} from "@/lib/api";
import { RelativeTime } from "./relative-time";

const POLL_MS = 30_000;
const POPOVER_LIMIT = 10;

const SEVERITY_DOT: Record<NotificationSeverity, string> = {
  info: "bg-muted",
  warning: "bg-sev-medium",
  error: "bg-sev-critical",
};

function fullTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString();
}

export function NotificationBell() {
  const router = useRouter();
  const labelId = useId();

  const [unreadCount, setUnreadCount] = useState(0);
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<Notification[]>([]);
  const [listLoading, setListLoading] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [markAllBusy, setMarkAllBusy] = useState(false);

  const wrapperRef = useRef<HTMLDivElement | null>(null);
  const buttonRef = useRef<HTMLButtonElement | null>(null);

  // Poll the unread count every POLL_MS. Always cleared on unmount so we
  // don't leak intervals across page navigations (the topbar is rendered in
  // the root layout, which keeps the bell mounted, but if a future refactor
  // unmounts it the cleanup is correct).
  useEffect(() => {
    let cancelled = false;
    async function tick() {
      try {
        const n = await getUnreadNotificationCount();
        if (!cancelled) setUnreadCount(n);
      } catch {
        // Best-effort: keep the previous count rather than flicker to 0.
      }
    }
    void tick();
    const id = setInterval(tick, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const refreshList = useCallback(async () => {
    setListLoading(true);
    setListError(null);
    try {
      const data = await listNotifications({ limit: POPOVER_LIMIT });
      setItems(data);
      // Reconcile the badge with whatever the list endpoint reported, in
      // case the dedicated count endpoint is lagging.
      setUnreadCount(data.filter((n) => n.read_at == null).length);
    } catch (err) {
      setListError(
        err instanceof Error ? err.message : "Failed to load notifications.",
      );
    } finally {
      setListLoading(false);
    }
  }, []);

  // Open: load the most recent batch.
  useEffect(() => {
    if (!open) return;
    void refreshList();
  }, [open, refreshList]);

  // Close on outside click or Escape.
  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (!wrapperRef.current) return;
      if (!wrapperRef.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setOpen(false);
        buttonRef.current?.focus();
      }
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const optimisticallyMarkRead = useCallback(
    async (n: Notification) => {
      if (n.read_at) return;
      const now = new Date().toISOString();
      const previous = items;
      const previousCount = unreadCount;
      // Optimistic local update.
      setItems((prev) =>
        prev.map((row) =>
          row.id === n.id ? { ...row, read_at: now } : row,
        ),
      );
      setUnreadCount((c) => Math.max(0, c - 1));
      try {
        await markNotificationRead(n.id);
      } catch {
        // Roll back on failure.
        setItems(previous);
        setUnreadCount(previousCount);
      }
    },
    [items, unreadCount],
  );

  async function handleMarkAll() {
    if (markAllBusy || unreadCount === 0) return;
    setMarkAllBusy(true);
    const previous = items;
    const previousCount = unreadCount;
    const now = new Date().toISOString();
    setItems((prev) =>
      prev.map((row) => (row.read_at ? row : { ...row, read_at: now })),
    );
    setUnreadCount(0);
    try {
      await markAllNotificationsRead();
    } catch {
      setItems(previous);
      setUnreadCount(previousCount);
    } finally {
      setMarkAllBusy(false);
    }
  }

  function handleRowActivate(n: Notification) {
    void optimisticallyMarkRead(n);
    if (n.link) {
      setOpen(false);
      router.push(n.link);
    }
  }

  const badgeLabel = unreadCount > 9 ? "9+" : String(unreadCount);
  const ariaLabel =
    unreadCount > 0
      ? `Notifications, ${unreadCount} unread`
      : "Notifications";

  return (
    <div className="relative" ref={wrapperRef}>
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-label={ariaLabel}
        aria-haspopup="dialog"
        aria-expanded={open}
        title={ariaLabel}
        className="relative inline-flex h-8 w-8 items-center justify-center rounded-md border border-border bg-surface text-muted transition-colors hover:bg-surface-2 hover:text-foreground focus-visible:text-foreground"
      >
        <Bell size={16} strokeWidth={1.5} aria-hidden />
        {unreadCount > 0 && (
          <span
            aria-hidden
            className="absolute -top-1 -right-1 inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-accent px-1 text-[0.625rem] font-semibold leading-none text-accent-foreground tabular-nums shadow-sm"
          >
            {badgeLabel}
          </span>
        )}
      </button>

      {open && (
        <div
          role="dialog"
          aria-labelledby={labelId}
          className="absolute right-0 top-10 z-40 w-[360px] max-w-[calc(100vw-1rem)] overflow-hidden rounded-md border border-border-strong bg-card shadow-xl"
        >
          <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
            <h2
              id={labelId}
              className="text-sm font-medium text-foreground-strong"
            >
              Notifications
            </h2>
            <button
              type="button"
              onClick={() => void handleMarkAll()}
              disabled={markAllBusy || unreadCount === 0}
              className="text-xs text-accent hover:underline disabled:cursor-not-allowed disabled:text-muted disabled:no-underline"
            >
              Mark all read
            </button>
          </div>

          <div className="max-h-[420px] overflow-y-auto">
            {listLoading && items.length === 0 ? (
              <div className="px-4 py-6 text-center text-xs text-muted">
                Loading…
              </div>
            ) : listError ? (
              <div className="px-4 py-6 text-center text-xs text-sev-critical">
                {listError}
                <div className="mt-2">
                  <button
                    type="button"
                    onClick={() => void refreshList()}
                    className="text-xs text-accent underline hover:no-underline"
                  >
                    Retry
                  </button>
                </div>
              </div>
            ) : items.length === 0 ? (
              <div className="flex flex-col items-center justify-center px-4 py-10 text-center">
                <BellOff
                  size={20}
                  strokeWidth={1.5}
                  className="mb-2 text-muted"
                  aria-hidden
                />
                <p className="text-sm text-foreground">No notifications</p>
                <p className="mt-1 text-xs text-muted">
                  We&apos;ll let you know when scans complete or scanners
                  fail.
                </p>
              </div>
            ) : (
              <ul className="divide-y divide-border">
                {items.map((n) => {
                  const unread = n.read_at == null;
                  const dotCls = SEVERITY_DOT[n.severity];
                  const rowCls = `relative flex w-full items-start gap-2.5 px-4 py-3 text-left transition-colors hover:bg-surface-2 ${
                    unread
                      ? "bg-accent-soft/20 border-l-2 border-l-accent pl-[14px]"
                      : ""
                  }`;
                  const content = (
                    <>
                      <span
                        aria-hidden
                        className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${dotCls}`}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-baseline gap-2">
                          <p
                            className={`min-w-0 flex-1 truncate text-sm ${
                              unread
                                ? "font-semibold text-foreground-strong"
                                : "font-medium text-foreground"
                            }`}
                            title={n.title}
                          >
                            {n.title}
                          </p>
                          <RelativeTime
                            iso={n.created_at}
                            title={fullTime(n.created_at)}
                            className="shrink-0 text-[0.6875rem] text-muted tabular-nums"
                          />
                        </div>
                        {n.body && (
                          <p
                            className="mt-0.5 truncate text-xs text-muted"
                            title={n.body}
                          >
                            {n.body}
                          </p>
                        )}
                      </div>
                    </>
                  );

                  return (
                    <li key={n.id}>
                      {n.link ? (
                        <button
                          type="button"
                          onClick={() => handleRowActivate(n)}
                          className={`${rowCls} w-full`}
                        >
                          {content}
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => void optimisticallyMarkRead(n)}
                          className={`${rowCls} w-full`}
                        >
                          {content}
                        </button>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          <div className="border-t border-border px-4 py-2.5 text-center">
            <Link
              href="/notifications"
              onClick={() => setOpen(false)}
              className="text-xs text-accent hover:underline"
            >
              View all notifications
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
