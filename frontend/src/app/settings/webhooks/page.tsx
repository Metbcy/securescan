"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Eye,
  Globe,
  Info,
  Loader2,
  MoreHorizontal,
  Pencil,
  Play,
  Plus,
  Power,
  PowerOff,
  Trash2,
  Webhook as WebhookIcon,
  X,
} from "lucide-react";
import {
  deleteWebhook,
  getApiKeyMe,
  listWebhooks,
  patchWebhook,
  testWebhook,
} from "@/lib/api";
import type {
  ApiKeyView,
  Webhook,
  WebhookCreated,
  WebhookDelivery,
  WebhookEventType,
} from "@/lib/api";
import { PageHeader } from "@/components/page-header";
import { DataTable, type Column } from "@/components/data-table";
import { WebhookCreateModal } from "@/components/webhook-create-modal";
import { WebhookDeliveryLog } from "@/components/webhook-delivery-log";

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

const URL_TRUNCATE_AT = 60;

function relativeTime(iso?: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const diff = Date.now() - then;
  const sec = Math.round(diff / 1000);
  if (sec < 5) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.round(hr / 24);
  return `${day}d ago`;
}

function fullTime(iso?: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString();
}

function truncateUrl(url: string, max: number = URL_TRUNCATE_AT): string {
  if (url.length <= max) return url;
  return url.slice(0, max - 1) + "…";
}

/**
 * URL-host detection. Pure client-side: uses URL parsing where possible and
 * falls back to substring tests so a malformed URL still renders something
 * sensible. Brand glyphs are out of scope (we don't ship a brand-icon
 * library) — Slack/Discord get tinted text labels instead, generic URLs get
 * the lucide Globe.
 */
type WebhookKind = "slack" | "discord" | "generic";

function detectWebhookKind(url: string): WebhookKind {
  let host = "";
  try {
    host = new URL(url).host.toLowerCase();
  } catch {
    host = url.toLowerCase();
  }
  if (host.includes("hooks.slack.com")) return "slack";
  if (host.includes("discord.com") || host.includes("discordapp.com")) {
    return "discord";
  }
  return "generic";
}

function WebhookKindIcon({ url }: { url: string }) {
  const kind = detectWebhookKind(url);
  if (kind === "slack") {
    return (
      <span
        aria-label="Slack webhook"
        title="Slack webhook"
        className="inline-flex h-5 w-12 items-center justify-center rounded-sm border border-border bg-surface-2 text-[0.625rem] font-semibold uppercase tracking-wider text-foreground-strong"
      >
        Slack
      </span>
    );
  }
  if (kind === "discord") {
    return (
      <span
        aria-label="Discord webhook"
        title="Discord webhook"
        className="inline-flex h-5 w-14 items-center justify-center rounded-sm border border-border bg-surface-2 text-[0.625rem] font-semibold uppercase tracking-wider text-foreground-strong"
      >
        Discord
      </span>
    );
  }
  return (
    <span
      aria-label="Generic HTTP webhook"
      title="Generic HTTP webhook"
      className="inline-flex h-5 w-5 items-center justify-center text-muted"
    >
      <Globe size={14} aria-hidden="true" />
    </span>
  );
}

const EVENT_LABEL: Record<WebhookEventType, string> = {
  "scan.complete": "complete",
  "scan.failed": "failed",
  "scanner.failed": "scanner failed",
};

function EventPills({ events }: { events: WebhookEventType[] }) {
  if (!events.length) {
    return <span className="text-xs text-muted">—</span>;
  }
  return (
    <div className="inline-flex flex-wrap items-center gap-1">
      {events.map((ev) => (
        <span
          key={ev}
          title={ev}
          className="inline-flex items-center rounded-full border border-border bg-surface-2 px-2 py-0.5 font-mono text-[0.6875rem] text-foreground"
        >
          {EVENT_LABEL[ev] ?? ev}
        </span>
      ))}
    </div>
  );
}

function StatusPill({ enabled }: { enabled: boolean }) {
  if (enabled) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent-soft px-2 py-0.5 text-[0.6875rem] text-accent">
        <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-accent" />
        Enabled
      </span>
    );
  }
  return (
    <span className="inline-flex items-center rounded-full border border-border bg-surface-2 px-2 py-0.5 text-[0.6875rem] text-muted">
      Disabled
    </span>
  );
}

interface LastDeliveryCellProps {
  delivery: WebhookDelivery | null | undefined;
  onClick: () => void;
}

function LastDeliveryCell({ delivery, onClick }: LastDeliveryCellProps) {
  if (!delivery) {
    return (
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          onClick();
        }}
        className="text-[0.6875rem] text-muted underline-offset-2 hover:text-foreground hover:underline"
      >
        No deliveries yet
      </button>
    );
  }
  const dotCls =
    delivery.status === "succeeded"
      ? "bg-accent"
      : delivery.status === "failed"
        ? "bg-sev-critical"
        : delivery.status === "delivering"
          ? "bg-sev-medium animate-pulse"
          : "bg-muted";
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      title={`${delivery.status} · ${fullTime(delivery.updated_at) || fullTime(delivery.created_at)}`}
      className="inline-flex items-center gap-1.5 rounded-md text-[0.6875rem] text-muted hover:text-foreground"
    >
      <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${dotCls}`} />
      <time dateTime={delivery.updated_at || delivery.created_at}>
        {relativeTime(delivery.updated_at || delivery.created_at)}
      </time>
    </button>
  );
}

/* ------------------------------------------------------------------ */
/* Row action menu                                                     */
/* ------------------------------------------------------------------ */

interface RowMenuProps {
  webhook: Webhook;
  busy: boolean;
  onTest: (w: Webhook) => void;
  onEdit: (w: Webhook) => void;
  onToggle: (w: Webhook) => void;
  onDelete: (w: Webhook) => void;
}

function RowMenu({
  webhook,
  busy,
  onTest,
  onEdit,
  onToggle,
  onDelete,
}: RowMenuProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (!ref.current) return;
      if (!ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="relative inline-block" ref={ref}>
      <button
        type="button"
        aria-label="Row actions"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-foreground focus-visible:bg-surface-2"
      >
        <MoreHorizontal size={16} aria-hidden="true" />
      </button>
      {open && (
        <div
          role="menu"
          onClick={(e) => e.stopPropagation()}
          className="absolute right-0 top-8 z-20 w-48 overflow-hidden rounded-md border border-border-strong bg-card shadow-lg"
        >
          <button
            type="button"
            role="menuitem"
            disabled={busy}
            onClick={() => {
              setOpen(false);
              onTest(webhook);
            }}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-surface-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Play size={14} aria-hidden="true" />
            Test
          </button>
          <button
            type="button"
            role="menuitem"
            disabled={busy}
            onClick={() => {
              setOpen(false);
              onEdit(webhook);
            }}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-surface-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Pencil size={14} aria-hidden="true" />
            Edit
          </button>
          <button
            type="button"
            role="menuitem"
            disabled={busy}
            onClick={() => {
              setOpen(false);
              onToggle(webhook);
            }}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-foreground hover:bg-surface-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {webhook.enabled ? (
              <>
                <PowerOff size={14} aria-hidden="true" />
                Disable
              </>
            ) : (
              <>
                <Power size={14} aria-hidden="true" />
                Enable
              </>
            )}
          </button>
          <div aria-hidden className="border-t border-border" />
          <button
            type="button"
            role="menuitem"
            disabled={busy}
            onClick={() => {
              setOpen(false);
              onDelete(webhook);
            }}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-sev-critical hover:bg-surface-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Trash2 size={14} aria-hidden="true" />
            Delete
          </button>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Edit modal                                                          */
/* ------------------------------------------------------------------ */

interface EditWebhookProps {
  webhook: Webhook;
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onSave: (patch: {
    name: string;
    url: string;
    event_filter: WebhookEventType[];
  }) => void;
}

const ALL_EVENTS: WebhookEventType[] = [
  "scan.complete",
  "scan.failed",
  "scanner.failed",
];

function EditWebhook({ webhook, busy, error, onCancel, onSave }: EditWebhookProps) {
  const [name, setName] = useState(webhook.name);
  const [url, setUrl] = useState(webhook.url);
  const [filter, setFilter] = useState<WebhookEventType[]>(webhook.event_filter);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape" && !busy) onCancel();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onCancel, busy]);

  const trimmedName = name.trim();
  const trimmedUrl = url.trim();
  const urlValid = /^https?:\/\/[^\s]+$/i.test(trimmedUrl);
  const canSave =
    trimmedName.length > 0 && urlValid && filter.length > 0 && !busy;

  function toggleEvent(ev: WebhookEventType) {
    setFilter((prev) =>
      prev.includes(ev) ? prev.filter((e) => e !== ev) : [...prev, ev],
    );
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="edit-webhook-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4"
      onClick={() => {
        if (!busy) onCancel();
      }}
    >
      <div
        className="w-full max-w-lg rounded-md border border-border-strong bg-card shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2
            id="edit-webhook-title"
            className="text-sm font-medium text-foreground-strong"
          >
            Edit webhook
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onCancel}
            disabled={busy}
            className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-foreground disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <div className="space-y-4 px-4 py-4">
          <div>
            <label
              htmlFor="edit-webhook-name"
              className="block text-xs font-medium uppercase tracking-wider text-muted"
            >
              Name
            </label>
            <input
              id="edit-webhook-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value.slice(0, 80))}
              maxLength={80}
              className="mt-1.5 h-9 w-full rounded-md border border-border bg-surface-2 px-2.5 text-sm focus:outline-none focus:ring-1 focus:ring-[var(--ring)]"
            />
          </div>
          <div>
            <label
              htmlFor="edit-webhook-url"
              className="block text-xs font-medium uppercase tracking-wider text-muted"
            >
              Receiver URL
            </label>
            <input
              id="edit-webhook-url"
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              className={`mt-1.5 h-9 w-full rounded-md border bg-surface-2 px-2.5 font-mono text-xs focus:outline-none focus:ring-1 focus:ring-[var(--ring)] ${
                trimmedUrl.length > 0 && !urlValid
                  ? "border-sev-critical/50"
                  : "border-border"
              }`}
            />
            {trimmedUrl.length > 0 && !urlValid && (
              <p className="mt-1 text-xs text-sev-critical">
                URL must start with{" "}
                <code className="font-mono">http://</code> or{" "}
                <code className="font-mono">https://</code>.
              </p>
            )}
          </div>
          <fieldset>
            <legend className="block text-xs font-medium uppercase tracking-wider text-muted">
              Events
            </legend>
            <ul className="mt-1.5 space-y-1.5">
              {ALL_EVENTS.map((ev) => {
                const checked = filter.includes(ev);
                return (
                  <li key={ev}>
                    <label
                      className={`flex cursor-pointer items-center gap-3 rounded-md border border-border bg-surface-2 px-3 py-1.5 hover:border-border-strong ${
                        checked ? "ring-1 ring-[var(--ring)]" : ""
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleEvent(ev)}
                        className="accent-[var(--accent)]"
                      />
                      <span className="font-mono text-xs">{ev}</span>
                    </label>
                  </li>
                );
              })}
            </ul>
            {filter.length === 0 && (
              <p className="mt-1.5 text-xs text-sev-critical">
                Pick at least one event.
              </p>
            )}
          </fieldset>
          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
            >
              <AlertTriangle
                size={14}
                className="mt-0.5 shrink-0"
                aria-hidden="true"
              />
              <span>{error}</span>
            </div>
          )}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm hover:border-border-strong disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() =>
              onSave({
                name: trimmedName,
                url: trimmedUrl,
                event_filter: filter,
              })
            }
            disabled={!canSave}
            className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {busy && (
              <Loader2 size={14} className="animate-spin" aria-hidden="true" />
            )}
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Confirm-delete                                                      */
/* ------------------------------------------------------------------ */

interface ConfirmDeleteProps {
  webhook: Webhook;
  busy: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}

function ConfirmDelete({
  webhook,
  busy,
  error,
  onCancel,
  onConfirm,
}: ConfirmDeleteProps) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape" && !busy) onCancel();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onCancel, busy]);

  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="confirm-delete-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4"
      onClick={() => {
        if (!busy) onCancel();
      }}
    >
      <div
        className="w-full max-w-sm rounded-md border border-border-strong bg-card shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2
            id="confirm-delete-title"
            className="text-sm font-medium text-foreground-strong"
          >
            Delete this webhook?
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onCancel}
            disabled={busy}
            className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-foreground disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <div className="space-y-3 px-4 py-4">
          <p className="text-sm text-muted">
            This will stop sending events to{" "}
            <span className="font-medium text-foreground">{webhook.name}</span>{" "}
            immediately. The action can&apos;t be undone.
          </p>
          <div
            className="truncate rounded-md border border-border bg-surface-2 px-3 py-2 font-mono text-xs text-muted"
            title={webhook.url}
          >
            {webhook.url}
          </div>
          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
            >
              <AlertTriangle
                size={14}
                className="mt-0.5 shrink-0"
                aria-hidden="true"
              />
              <span>{error}</span>
            </div>
          )}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm hover:border-border-strong disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-md bg-sev-critical px-3 py-1.5 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {busy && (
              <Loader2 size={14} className="animate-spin" aria-hidden="true" />
            )}
            {busy ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Toast                                                                */
/* ------------------------------------------------------------------ */

interface Toast {
  id: number;
  tone: "success" | "error" | "info";
  message: string;
}

function ToastStack({
  toasts,
  onDismiss,
}: {
  toasts: Toast[];
  onDismiss: (id: number) => void;
}) {
  if (toasts.length === 0) return null;
  return (
    <div className="fixed bottom-4 right-4 z-[60] flex flex-col gap-2">
      {toasts.map((t) => {
        const tone =
          t.tone === "success"
            ? "border-accent/40 bg-accent-soft text-foreground"
            : t.tone === "info"
              ? "border-border bg-card text-foreground"
              : "border-sev-critical/30 bg-sev-critical-bg text-sev-critical";
        return (
          <div
            key={t.id}
            role="status"
            className={`flex max-w-sm items-start gap-2 rounded-md border px-3 py-2 text-sm shadow-lg ${tone}`}
          >
            <span className="flex-1">{t.message}</span>
            <button
              type="button"
              aria-label="Dismiss"
              onClick={() => onDismiss(t.id)}
              className="text-muted hover:text-foreground"
            >
              <X size={12} aria-hidden="true" />
            </button>
          </div>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Page                                                                 */
/* ------------------------------------------------------------------ */

interface LastDeliveryMap {
  [webhookId: string]: WebhookDelivery | null;
}

function WebhooksPageInner() {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [lastDelivery, setLastDelivery] = useState<LastDeliveryMap>({});
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [me, setMe] = useState<ApiKeyView | null>(null);
  const [usingMock, setUsingMock] = useState(false);

  const [creating, setCreating] = useState(false);
  const [editTarget, setEditTarget] = useState<Webhook | null>(null);
  const [editBusy, setEditBusy] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Webhook | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [highlightId, setHighlightId] = useState<string | null>(null);
  const [busyRowId, setBusyRowId] = useState<string | null>(null);

  const [drawerWebhook, setDrawerWebhook] = useState<Webhook | null>(null);
  const [highlightDeliveryId, setHighlightDeliveryId] = useState<string | null>(
    null,
  );
  const drawerOpen = drawerWebhook !== null;

  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastIdRef = useRef(1);

  const pushToast = useCallback((tone: Toast["tone"], message: string) => {
    const id = toastIdRef.current++;
    setToasts((prev) => [...prev, { id, tone, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3500);
    return id;
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      // Don't gate the table on /keys/me — that endpoint can be slow or
      // unauthenticated and we'd rather show the table now than wait.
      const list = await listWebhooks();
      setWebhooks(list);
      // Probe to detect whether we're talking to the local mock fallback.
      try {
        const probe = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}${
            process.env.NEXT_PUBLIC_API_PREFIX || "/api/v1"
          }/webhooks`,
          { method: "HEAD", signal: AbortSignal.timeout(2500) },
        );
        setUsingMock(probe.status === 404);
      } catch {
        // Connection refused or timed out — treat as "BE not mounted",
        // which is exactly when the mock kicks in.
        setUsingMock(true);
      }
    } catch (err) {
      setLoadError(
        err instanceof Error ? err.message : "Failed to load webhooks.",
      );
    } finally {
      setLoading(false);
    }
    // Fetch /keys/me in the background; don't block the table on it.
    getApiKeyMe()
      .then((mine) => setMe(mine))
      .catch(() => setMe(null));
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Pull a "last delivery" preview for each webhook so the column has
  // something to show. Best-effort — failures fall through silently.
  useEffect(() => {
    let cancelled = false;
    if (webhooks.length === 0) {
      setLastDelivery({});
      return;
    }
    (async () => {
      const { listWebhookDeliveries } = await import("@/lib/api");
      const next: LastDeliveryMap = {};
      await Promise.all(
        webhooks.map(async (w) => {
          try {
            const list = await listWebhookDeliveries(w.id);
            next[w.id] = list[0] ?? null;
          } catch {
            next[w.id] = null;
          }
        }),
      );
      if (!cancelled) setLastDelivery(next);
    })();
    return () => {
      cancelled = true;
    };
  }, [webhooks]);

  // Refresh the last-delivery cache while the drawer is open so the row
  // dot/timestamp keeps up with retries firing in the background.
  useEffect(() => {
    if (!drawerOpen || !drawerWebhook) return;
    const interval = setInterval(async () => {
      try {
        const { listWebhookDeliveries } = await import("@/lib/api");
        const list = await listWebhookDeliveries(drawerWebhook.id);
        setLastDelivery((prev) => ({ ...prev, [drawerWebhook.id]: list[0] ?? null }));
      } catch {
        /* swallow */
      }
    }, 5_000);
    return () => clearInterval(interval);
  }, [drawerOpen, drawerWebhook]);

  /* --- handlers --- */

  const handleCreated = useCallback(
    (created: WebhookCreated) => {
      const view: Webhook = {
        id: created.id,
        name: created.name,
        url: created.url,
        event_filter: created.event_filter,
        enabled: created.enabled,
        created_at: created.created_at,
      };
      setWebhooks((prev) => [view, ...prev.filter((w) => w.id !== view.id)]);
      setHighlightId(view.id);
      setTimeout(
        () => setHighlightId((id) => (id === view.id ? null : id)),
        3000,
      );
      pushToast("success", `Webhook '${created.name}' created.`);
    },
    [pushToast],
  );

  const handleTest = useCallback(
    async (w: Webhook) => {
      setBusyRowId(w.id);
      try {
        const { delivery_id } = await testWebhook(w.id);
        setDrawerWebhook(w);
        setHighlightDeliveryId(delivery_id);
        pushToast("info", `Test webhook fired to '${w.name}'.`);
      } catch (err) {
        pushToast(
          "error",
          err instanceof Error ? err.message : "Failed to fire test webhook.",
        );
      } finally {
        setBusyRowId(null);
      }
    },
    [pushToast],
  );

  const handleToggle = useCallback(
    async (w: Webhook) => {
      setBusyRowId(w.id);
      try {
        const updated = await patchWebhook(w.id, { enabled: !w.enabled });
        setWebhooks((prev) =>
          prev.map((row) => (row.id === w.id ? { ...row, ...updated } : row)),
        );
        pushToast(
          "success",
          updated.enabled
            ? `Enabled '${updated.name}'.`
            : `Disabled '${updated.name}'.`,
        );
      } catch (err) {
        pushToast(
          "error",
          err instanceof Error ? err.message : "Failed to toggle webhook.",
        );
      } finally {
        setBusyRowId(null);
      }
    },
    [pushToast],
  );

  const handleEditSave = useCallback(
    async (patch: {
      name: string;
      url: string;
      event_filter: WebhookEventType[];
    }) => {
      if (!editTarget) return;
      setEditBusy(true);
      setEditError(null);
      try {
        const updated = await patchWebhook(editTarget.id, patch);
        setWebhooks((prev) =>
          prev.map((row) =>
            row.id === editTarget.id ? { ...row, ...updated } : row,
          ),
        );
        setEditTarget(null);
        pushToast("success", `Updated '${updated.name}'.`);
      } catch (err) {
        setEditError(
          err instanceof Error ? err.message : "Failed to update webhook.",
        );
      } finally {
        setEditBusy(false);
      }
    },
    [editTarget, pushToast],
  );

  const handleDeleteConfirm = useCallback(async () => {
    if (!deleteTarget) return;
    setDeleteBusy(true);
    setDeleteError(null);
    try {
      await deleteWebhook(deleteTarget.id);
      setWebhooks((prev) => prev.filter((w) => w.id !== deleteTarget.id));
      setLastDelivery((prev) => {
        const next = { ...prev };
        delete next[deleteTarget.id];
        return next;
      });
      pushToast("success", `Deleted '${deleteTarget.name}'.`);
      setDeleteTarget(null);
    } catch (err) {
      setDeleteError(
        err instanceof Error ? err.message : "Failed to delete webhook.",
      );
    } finally {
      setDeleteBusy(false);
    }
  }, [deleteTarget, pushToast]);

  const sortedWebhooks = useMemo(() => {
    return [...webhooks].sort((a, b) => {
      // Disabled rows sink below enabled ones, then most-recent first.
      const aOff = a.enabled ? 0 : 1;
      const bOff = b.enabled ? 0 : 1;
      if (aOff !== bOff) return aOff - bOff;
      return (
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      );
    });
  }, [webhooks]);

  const columns: Column<Webhook>[] = [
    {
      key: "name",
      header: "Name",
      cell: (w) => (
        <div className="min-w-0">
          <div className="font-medium text-foreground-strong" title={w.name}>
            {w.name}
          </div>
        </div>
      ),
    },
    {
      key: "url",
      header: "URL",
      cell: (w) => (
        <div className="flex min-w-0 items-center gap-2">
          <WebhookKindIcon url={w.url} />
          <span
            className="truncate font-mono text-xs text-muted"
            title={w.url}
          >
            {truncateUrl(w.url)}
          </span>
        </div>
      ),
    },
    {
      key: "events",
      header: "Events",
      width: "w-[200px]",
      cell: (w) => <EventPills events={w.event_filter} />,
    },
    {
      key: "status",
      header: "Status",
      width: "w-[110px]",
      cell: (w) => <StatusPill enabled={w.enabled} />,
    },
    {
      key: "last_delivery",
      header: "Last delivery",
      width: "w-[140px]",
      cell: (w) => (
        <LastDeliveryCell
          delivery={lastDelivery[w.id]}
          onClick={() => {
            setDrawerWebhook(w);
            setHighlightDeliveryId(null);
          }}
        />
      ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "w-[56px]",
      align: "right",
      cell: (w) => (
        <div onClick={(e) => e.stopPropagation()}>
          <RowMenu
            webhook={w}
            busy={busyRowId === w.id}
            onTest={(target) => void handleTest(target)}
            onEdit={(target) => {
              setEditError(null);
              setEditTarget(target);
            }}
            onToggle={(target) => void handleToggle(target)}
            onDelete={(target) => {
              setDeleteError(null);
              setDeleteTarget(target);
            }}
          />
        </div>
      ),
    },
  ];

  const headerActions = (
    <button
      type="button"
      onClick={() => setCreating(true)}
      className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground hover:opacity-90"
    >
      <Plus size={14} aria-hidden="true" />
      New webhook
    </button>
  );

  return (
    <div className="space-y-4">
      <PageHeader
        title="Webhooks"
        meta="Send scan events to Slack, Discord, or any HTTP receiver."
        actions={headerActions}
      />

      {usingMock && (
        <div
          role="status"
          className="flex items-start gap-2 rounded-md border border-sev-medium/30 bg-sev-medium-bg px-3 py-2 text-xs text-sev-medium"
        >
          <Info size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>
            Backend <code className="font-mono">/api/v1/webhooks</code>{" "}
            isn&apos;t mounted yet — using a browser-local mock so the page is
            exercisable. Webhooks and deliveries live in{" "}
            <code className="font-mono">localStorage</code> and disappear when
            you clear site data.
          </span>
        </div>
      )}

      {me && !usingMock && (
        <div
          role="status"
          className="flex items-start gap-2 rounded-md border border-accent/30 bg-accent-soft px-3 py-2 text-xs text-foreground"
        >
          <Eye
            size={14}
            className="mt-0.5 shrink-0 text-accent"
            aria-hidden="true"
          />
          <span>
            You&apos;re authenticated as{" "}
            <span className="font-medium">{me.name}</span>{" "}
            <span className="font-mono text-muted">({me.prefix})</span>.
            Webhook management requires the{" "}
            <span className="font-mono">admin</span> scope.
          </span>
        </div>
      )}

      {loadError && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
        >
          <AlertTriangle
            size={14}
            className="mt-0.5 shrink-0"
            aria-hidden="true"
          />
          <span>{loadError}</span>
          <button
            type="button"
            onClick={() => void refresh()}
            className="ml-auto text-xs underline hover:no-underline"
          >
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div className="rounded-md border border-border bg-card">
          <div className="h-10 border-b border-border bg-surface-2/40" />
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-12 border-b border-border last:border-b-0 animate-pulse"
              style={{ opacity: 1 - i * 0.12 }}
            />
          ))}
        </div>
      ) : sortedWebhooks.length === 0 && !loadError ? (
        <div className="flex flex-col items-center justify-center rounded-md border border-border bg-card py-20 text-center">
          <div className="mb-4 inline-flex h-10 w-10 items-center justify-center rounded-full bg-surface-2 text-muted">
            <WebhookIcon size={20} aria-hidden="true" />
          </div>
          <h2 className="text-base font-medium text-foreground-strong">
            No webhooks yet
          </h2>
          <p className="mt-1 max-w-sm text-sm text-muted">
            Send scan completions, failures, and scanner crashes to Slack,
            Discord, or any HTTPS endpoint. Each webhook is signed with an
            HMAC-SHA256 secret you save once.
          </p>
          <button
            type="button"
            onClick={() => setCreating(true)}
            className="mt-5 inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground hover:opacity-90"
          >
            <Plus size={14} aria-hidden="true" />
            Create your first webhook
          </button>
        </div>
      ) : (
        <DataTable
          data={sortedWebhooks}
          columns={columns}
          getRowKey={(w) => w.id}
          density="compact"
          rowClassName={(w) => {
            const dim = w.enabled ? "" : "opacity-70";
            const ring =
              highlightId === w.id ? "ring-1 ring-accent bg-accent-soft/30" : "";
            return `${dim} ${ring}`.trim();
          }}
        />
      )}

      <WebhookCreateModal
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={handleCreated}
      />

      {editTarget && (
        <EditWebhook
          webhook={editTarget}
          busy={editBusy}
          error={editError}
          onCancel={() => {
            if (!editBusy) {
              setEditTarget(null);
              setEditError(null);
            }
          }}
          onSave={(patch) => void handleEditSave(patch)}
        />
      )}

      {deleteTarget && (
        <ConfirmDelete
          webhook={deleteTarget}
          busy={deleteBusy}
          error={deleteError}
          onCancel={() => {
            if (!deleteBusy) {
              setDeleteTarget(null);
              setDeleteError(null);
            }
          }}
          onConfirm={() => void handleDeleteConfirm()}
        />
      )}

      <WebhookDeliveryLog
        webhook={drawerWebhook}
        open={drawerOpen}
        onClose={() => {
          setDrawerWebhook(null);
          setHighlightDeliveryId(null);
        }}
        highlightDeliveryId={highlightDeliveryId}
        onHighlightedSettled={(delivery) => {
          // Update the row's "last delivery" preview now that it's terminal,
          // and surface the outcome via a toast so the user notices even if
          // they switched tabs.
          if (drawerWebhook) {
            setLastDelivery((prev) => ({
              ...prev,
              [drawerWebhook.id]: delivery,
            }));
          }
          if (delivery.status === "succeeded") {
            pushToast("success", "Test delivered");
          } else if (delivery.status === "failed") {
            const codeBit =
              delivery.response_code && delivery.response_code !== 0
                ? ` (HTTP ${delivery.response_code})`
                : "";
            pushToast("error", `Test failed${codeBit}`);
          }
        }}
      />

      <ToastStack
        toasts={toasts}
        onDismiss={(id) => setToasts((prev) => prev.filter((t) => t.id !== id))}
      />
    </div>
  );
}

export default function WebhooksPage() {
  return (
    <Suspense fallback={null}>
      <WebhooksPageInner />
    </Suspense>
  );
}
