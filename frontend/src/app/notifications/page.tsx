"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Bell, BellOff, CheckCheck, Loader2 } from "lucide-react";
import { PageHeader } from "@/components/page-header";
import {
  listNotifications,
  markAllNotificationsRead,
  markNotificationRead,
  type Notification,
  type NotificationSeverity,
} from "@/lib/api";

const PAGE_SIZE = 25;

const SEVERITY_DOT: Record<NotificationSeverity, string> = {
  info: "bg-muted",
  warning: "bg-sev-medium",
  error: "bg-sev-critical",
};

const SEVERITY_LABEL: Record<NotificationSeverity, string> = {
  info: "Info",
  warning: "Warning",
  error: "Error",
};

type Filter = "all" | "unread" | "read";

const FILTER_CHIPS: { id: Filter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "unread", label: "Unread" },
  { id: "read", label: "Read" },
];

function formatRelative(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const diff = Date.now() - t;
  const sec = Math.max(0, Math.round(diff / 1000));
  if (sec < 5) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.round(hr / 24);
  if (day < 30) return `${day}d ago`;
  const mo = Math.round(day / 30);
  if (mo < 12) return `${mo}mo ago`;
  const yr = Math.round(mo / 12);
  return `${yr}y ago`;
}

function fullTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString();
}

export default function NotificationsPage() {
  const [items, setItems] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const [markAllBusy, setMarkAllBusy] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      // Pull a generous slice — backend caps at 200 — and let the client
      // page through it. The volumes here are tiny in practice.
      const data = await listNotifications({ limit: 200 });
      setItems(data);
    } catch (err) {
      setLoadError(
        err instanceof Error ? err.message : "Failed to load notifications.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Reset paging when the filter changes so users always see the top of
  // the new slice.
  useEffect(() => {
    setVisibleCount(PAGE_SIZE);
  }, [filter]);

  const filtered = useMemo(() => {
    if (filter === "unread") return items.filter((n) => n.read_at == null);
    if (filter === "read") return items.filter((n) => n.read_at != null);
    return items;
  }, [items, filter]);

  const totalUnread = useMemo(
    () => items.filter((n) => n.read_at == null).length,
    [items],
  );

  const visible = filtered.slice(0, visibleCount);
  const hasMore = visibleCount < filtered.length;

  const counts = useMemo(
    () => ({
      all: items.length,
      unread: totalUnread,
      read: items.length - totalUnread,
    }),
    [items.length, totalUnread],
  );

  async function activateRow(n: Notification) {
    if (n.read_at) return;
    const now = new Date().toISOString();
    const previous = items;
    setItems((prev) =>
      prev.map((row) => (row.id === n.id ? { ...row, read_at: now } : row)),
    );
    try {
      await markNotificationRead(n.id);
    } catch {
      setItems(previous);
    }
  }

  async function handleMarkAll() {
    if (markAllBusy || totalUnread === 0) return;
    setMarkAllBusy(true);
    const previous = items;
    const now = new Date().toISOString();
    setItems((prev) =>
      prev.map((row) => (row.read_at ? row : { ...row, read_at: now })),
    );
    try {
      await markAllNotificationsRead();
    } catch (err) {
      setItems(previous);
      setLoadError(
        err instanceof Error ? err.message : "Failed to mark all read.",
      );
    } finally {
      setMarkAllBusy(false);
    }
  }

  const headerActions = (
    <button
      type="button"
      onClick={() => void handleMarkAll()}
      disabled={markAllBusy || totalUnread === 0}
      className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-foreground hover:border-border-strong disabled:cursor-not-allowed disabled:opacity-50"
    >
      {markAllBusy ? (
        <Loader2 size={14} className="animate-spin" aria-hidden="true" />
      ) : (
        <CheckCheck size={14} aria-hidden="true" />
      )}
      Mark all read
      {totalUnread > 0 && (
        <span className="font-mono text-[0.6875rem] text-muted tabular-nums">
          ({totalUnread})
        </span>
      )}
    </button>
  );

  return (
    <div className="space-y-4">
      <PageHeader
        title="Notifications"
        meta="Recent activity from your scans."
        actions={headerActions}
      />

      <div
        role="group"
        aria-label="Filter notifications"
        className="flex items-center gap-1"
      >
        {FILTER_CHIPS.map((chip) => {
          const active = filter === chip.id;
          const count = counts[chip.id];
          return (
            <button
              key={chip.id}
              type="button"
              onClick={() => setFilter(chip.id)}
              aria-pressed={active}
              className={`inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-xs transition-colors ${
                active
                  ? "border-accent/60 bg-accent-soft text-foreground"
                  : "border-border bg-surface-2 text-muted hover:text-foreground hover:border-border-strong"
              }`}
            >
              <span>{chip.label}</span>
              <span className="font-mono tabular-nums opacity-70">
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {loadError && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
        >
          <span className="flex-1">{loadError}</span>
          <button
            type="button"
            onClick={() => void refresh()}
            className="text-xs underline hover:no-underline"
          >
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div className="rounded-md border border-border bg-card">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-16 border-b border-border last:border-b-0 animate-pulse"
              style={{ opacity: 1 - i * 0.12 }}
            />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-md border border-border bg-card py-20 text-center">
          <div className="mb-4 inline-flex h-10 w-10 items-center justify-center rounded-full bg-surface-2 text-muted">
            {filter === "unread" ? (
              <BellOff size={20} aria-hidden="true" />
            ) : (
              <Bell size={20} aria-hidden="true" />
            )}
          </div>
          <h2 className="text-base font-medium text-foreground-strong">
            {filter === "unread"
              ? "No unread notifications"
              : filter === "read"
                ? "No read notifications"
                : "No notifications"}
          </h2>
          <p className="mt-1 max-w-sm text-sm text-muted">
            {filter === "all"
              ? "We'll let you know when scans complete or scanners fail."
              : "Try a different filter to see other notifications."}
          </p>
        </div>
      ) : (
        <>
          <ul className="overflow-hidden rounded-md border border-border bg-card">
            {visible.map((n, idx) => {
              const unread = n.read_at == null;
              const last = idx === visible.length - 1;
              const rowBase = `relative flex items-start gap-3 px-4 py-3 transition-colors ${
                last ? "" : "border-b border-border"
              } ${unread ? "bg-accent-soft/20" : ""} ${
                n.link ? "hover:bg-surface-2 cursor-pointer" : ""
              }`;
              const indicator = (
                <span
                  aria-hidden
                  className={`absolute left-0 top-0 bottom-0 w-0.5 ${
                    unread ? "bg-accent" : "bg-transparent"
                  }`}
                />
              );

              const inner = (
                <>
                  {indicator}
                  <span
                    aria-label={SEVERITY_LABEL[n.severity]}
                    title={SEVERITY_LABEL[n.severity]}
                    className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${SEVERITY_DOT[n.severity]}`}
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
                      <span className="shrink-0 font-mono text-[0.6875rem] uppercase tracking-wider text-muted">
                        {n.type}
                      </span>
                      <time
                        className="shrink-0 text-[0.6875rem] text-muted tabular-nums"
                        dateTime={n.created_at}
                        title={fullTime(n.created_at)}
                      >
                        {formatRelative(n.created_at)}
                      </time>
                    </div>
                    {n.body && (
                      <p
                        className="mt-0.5 text-xs text-muted line-clamp-2"
                        title={n.body}
                      >
                        {n.body}
                      </p>
                    )}
                    {!unread && (
                      <p className="mt-1 text-[0.6875rem] text-muted">
                        Read{" "}
                        <time
                          dateTime={n.read_at ?? undefined}
                          title={n.read_at ? fullTime(n.read_at) : ""}
                        >
                          {n.read_at ? formatRelative(n.read_at) : ""}
                        </time>
                      </p>
                    )}
                  </div>
                </>
              );

              return (
                <li key={n.id} className="relative list-none">
                  {n.link ? (
                    <Link
                      href={n.link}
                      onClick={() => void activateRow(n)}
                      className={rowBase}
                    >
                      {inner}
                    </Link>
                  ) : (
                    <button
                      type="button"
                      onClick={() => void activateRow(n)}
                      className={`${rowBase} w-full text-left`}
                    >
                      {inner}
                    </button>
                  )}
                </li>
              );
            })}
          </ul>

          <div className="flex items-center justify-between text-xs text-muted">
            <span>
              Showing{" "}
              <span className="font-mono tabular-nums text-foreground">
                {visible.length}
              </span>{" "}
              of{" "}
              <span className="font-mono tabular-nums text-foreground">
                {filtered.length}
              </span>
            </span>
            {hasMore && (
              <button
                type="button"
                onClick={() => setVisibleCount((c) => c + PAGE_SIZE)}
                className="inline-flex items-center rounded-md border border-border bg-surface-2 px-3 py-1.5 text-xs text-foreground hover:border-border-strong"
              >
                Load more
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}
