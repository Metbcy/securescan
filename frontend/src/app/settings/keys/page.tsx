"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  AlertTriangle,
  Eye,
  Info,
  KeyRound,
  Loader2,
  MoreHorizontal,
  Plus,
  ShieldAlert,
  Trash2,
  X,
} from "lucide-react";
import {
  getApiKeyMe,
  listApiKeys,
  revokeApiKey,
} from "@/lib/api";
import type { ApiKeyScope, ApiKeyView } from "@/lib/api";
import { PageHeader } from "@/components/page-header";
import { DataTable, type Column } from "@/components/data-table";
import { KeyCreateModal } from "@/components/key-create-modal";

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

function relativeTime(iso?: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const diff = Date.now() - then;
  const sec = Math.round(diff / 1000);
  if (sec < 5) return "just now";
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} minute${min === 1 ? "" : "s"} ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr} hour${hr === 1 ? "" : "s"} ago`;
  const day = Math.round(hr / 24);
  if (day < 30) return `${day} day${day === 1 ? "" : "s"} ago`;
  const mo = Math.round(day / 30);
  if (mo < 12) return `${mo} month${mo === 1 ? "" : "s"} ago`;
  const yr = Math.round(mo / 12);
  return `${yr} year${yr === 1 ? "" : "s"} ago`;
}

function fullTime(iso?: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString();
}

const SCOPE_PILL_CLS: Record<ApiKeyScope, string> = {
  read: "bg-surface-2 text-foreground border border-border",
  write: "bg-sev-medium-bg text-sev-medium border border-sev-medium/30",
  admin:
    "bg-sev-critical-bg text-sev-critical border border-sev-critical/30",
};

function ScopePills({ scopes }: { scopes: ApiKeyScope[] }) {
  if (!scopes.length) {
    return <span className="text-xs text-muted">—</span>;
  }
  return (
    <div className="inline-flex flex-wrap items-center gap-1">
      {scopes.map((s) => (
        <span
          key={s}
          className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[0.6875rem] ${SCOPE_PILL_CLS[s]}`}
        >
          {s === "admin" && <ShieldAlert size={10} aria-hidden="true" />}
          {s}
        </span>
      ))}
    </div>
  );
}

function StatusPill({ keyRow }: { keyRow: ApiKeyView }) {
  if (keyRow.revoked_at) {
    return (
      <span
        className="inline-flex items-center rounded-full border border-border bg-surface-2 px-2 py-0.5 text-[0.6875rem] text-muted"
        title={`Revoked ${fullTime(keyRow.revoked_at)}`}
      >
        Revoked
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent-soft px-2 py-0.5 text-[0.6875rem] text-accent">
      <span
        aria-hidden
        className="h-1.5 w-1.5 rounded-full bg-accent"
      />
      Active
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Row action menu                                                     */
/* ------------------------------------------------------------------ */

interface RowMenuProps {
  keyRow: ApiKeyView;
  busy: boolean;
  onRevoke: (k: ApiKeyView) => void;
}

function RowMenu({ keyRow, busy, onRevoke }: RowMenuProps) {
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

  const revoked = !!keyRow.revoked_at;

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
          className="absolute right-0 top-8 z-20 w-44 overflow-hidden rounded-md border border-border-strong bg-card shadow-lg"
        >
          {revoked ? (
            <div className="px-3 py-2 text-xs text-muted">No actions available.</div>
          ) : (
            <button
              type="button"
              role="menuitem"
              disabled={busy}
              onClick={() => {
                setOpen(false);
                onRevoke(keyRow);
              }}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-sev-critical hover:bg-surface-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Trash2 size={14} aria-hidden="true" />
              Revoke
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Confirm-revoke modal                                                */
/* ------------------------------------------------------------------ */

interface ConfirmRevokeProps {
  keyRow: ApiKeyView;
  onCancel: () => void;
  onConfirm: () => void;
  busy: boolean;
  error: string | null;
}

function ConfirmRevoke({ keyRow, onCancel, onConfirm, busy, error }: ConfirmRevokeProps) {
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
      aria-labelledby="confirm-revoke-title"
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
            id="confirm-revoke-title"
            className="text-sm font-medium text-foreground-strong"
          >
            Revoke this key?
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
            Once revoked, the key{" "}
            <span className="font-medium text-foreground">{keyRow.name}</span>{" "}
            will stop authenticating immediately. This action can&apos;t be
            undone.
          </p>
          <div className="rounded-md border border-border bg-surface-2 px-3 py-2 font-mono text-xs text-muted">
            {keyRow.prefix}…
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
            {busy ? "Revoking…" : "Revoke"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Toast (lightweight, page-local)                                     */
/* ------------------------------------------------------------------ */

interface Toast {
  id: number;
  tone: "success" | "error";
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
    <div className="fixed bottom-4 right-4 z-40 flex flex-col gap-2">
      {toasts.map((t) => {
        const tone =
          t.tone === "success"
            ? "border-accent/40 bg-accent-soft text-foreground"
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
/* Page                                                                */
/* ------------------------------------------------------------------ */

function KeysPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [keys, setKeys] = useState<ApiKeyView[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [me, setMe] = useState<ApiKeyView | null>(null);
  const [creating, setCreating] = useState(false);
  const [confirmTarget, setConfirmTarget] = useState<ApiKeyView | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [highlightId, setHighlightId] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastIdRef = useRef(1);
  const [usingMock, setUsingMock] = useState(false);

  const pushToast = useCallback(
    (tone: Toast["tone"], message: string) => {
      const id = toastIdRef.current++;
      setToasts((prev) => [...prev, { id, tone, message }]);
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 3500);
    },
    [],
  );

  // Initial load.
  const refresh = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const [list, mine] = await Promise.all([
        listApiKeys(),
        getApiKeyMe().catch(() => null),
      ]);
      setKeys(list);
      setMe(mine);
      // Best-effort detection: if the helper hit the localStorage fallback
      // there's no way to distinguish a real-but-empty list from a mocked
      // one. We probe the API directly to surface the mock banner.
      try {
        const probe = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}${process.env.NEXT_PUBLIC_API_PREFIX || "/api/v1"}/keys`,
          { method: "HEAD" },
        );
        setUsingMock(probe.status === 404);
      } catch {
        setUsingMock(false);
      }
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Failed to load API keys.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Highlight the freshly-created row briefly when ?created=<id> is present.
  useEffect(() => {
    const created = searchParams.get("created");
    if (!created) return;
    setHighlightId(created);
    const t = setTimeout(() => {
      setHighlightId(null);
      const params = new URLSearchParams(searchParams.toString());
      params.delete("created");
      const qs = params.toString();
      router.replace(qs ? `?${qs}` : "/settings/keys");
    }, 3000);
    return () => clearTimeout(t);
  }, [searchParams, router]);

  function openConfirmRevoke(k: ApiKeyView) {
    setConfirmTarget(k);
    setConfirmError(null);
  }

  async function handleConfirmRevoke() {
    if (!confirmTarget) return;
    setConfirmBusy(true);
    setConfirmError(null);
    try {
      await revokeApiKey(confirmTarget.id);
      const revokedAt = new Date().toISOString();
      setKeys((prev) =>
        prev.map((k) =>
          k.id === confirmTarget.id
            ? { ...k, revoked_at: k.revoked_at ?? revokedAt }
            : k,
        ),
      );
      pushToast("success", `Key '${confirmTarget.name}' revoked.`);
      setConfirmTarget(null);
    } catch (err) {
      setConfirmError(
        err instanceof Error ? err.message : "Failed to revoke key.",
      );
    } finally {
      setConfirmBusy(false);
    }
  }

  const sortedKeys = useMemo(() => {
    return [...keys].sort((a, b) => {
      // Active keys above revoked, then most-recent first.
      const aRev = a.revoked_at ? 1 : 0;
      const bRev = b.revoked_at ? 1 : 0;
      if (aRev !== bRev) return aRev - bRev;
      return (
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      );
    });
  }, [keys]);

  const columns: Column<ApiKeyView>[] = [
    {
      key: "name",
      header: "Name",
      cell: (k) => (
        <div className="min-w-0">
          <div className="font-medium text-foreground-strong" title={k.name}>
            {k.name}
          </div>
          {me?.id === k.id && (
            <div className="text-[0.6875rem] text-accent">
              you&apos;re using this key
            </div>
          )}
        </div>
      ),
    },
    {
      key: "prefix",
      header: "Prefix",
      width: "w-[220px]",
      cell: (k) => (
        <span
          className="font-mono text-xs text-muted"
          title={`${k.prefix}…`}
        >
          {k.prefix}
        </span>
      ),
    },
    {
      key: "scopes",
      header: "Scopes",
      width: "w-[180px]",
      cell: (k) => <ScopePills scopes={k.scopes} />,
    },
    {
      key: "created",
      header: "Created",
      width: "w-[140px]",
      cell: (k) => (
        <time
          className="text-sm text-foreground/90"
          title={fullTime(k.created_at)}
          dateTime={k.created_at}
        >
          {relativeTime(k.created_at)}
        </time>
      ),
    },
    {
      key: "last_used",
      header: "Last used",
      width: "w-[140px]",
      cell: (k) => (
        <span
          className="text-sm text-foreground/90"
          title={k.last_used_at ? fullTime(k.last_used_at) : "Never used"}
        >
          {k.last_used_at ? relativeTime(k.last_used_at) : "Never"}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      width: "w-[110px]",
      cell: (k) => <StatusPill keyRow={k} />,
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "w-[56px]",
      align: "right",
      cell: (k) => (
        <div onClick={(e) => e.stopPropagation()}>
          <RowMenu keyRow={k} busy={false} onRevoke={openConfirmRevoke} />
        </div>
      ),
    },
  ];

  /* ---- render ---- */

  const headerActions = (
    <button
      type="button"
      onClick={() => setCreating(true)}
      className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground hover:opacity-90"
    >
      <Plus size={14} aria-hidden="true" />
      New key
    </button>
  );

  return (
    <div className="space-y-4">
      <PageHeader
        title="API keys"
        meta="Manage authentication keys for the API."
        actions={headerActions}
      />

      {usingMock && (
        <div
          role="status"
          className="flex items-start gap-2 rounded-md border border-sev-medium/30 bg-sev-medium-bg px-3 py-2 text-xs text-sev-medium"
        >
          <Info size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>
            Backend <code className="font-mono">/api/v1/keys</code> isn&apos;t
            mounted yet — using a browser-local mock so the page is exercisable.
            Created keys live in <code className="font-mono">localStorage</code>{" "}
            and disappear when you clear site data.
          </span>
        </div>
      )}

      {me && !usingMock && (
        <div
          role="status"
          className="flex items-start gap-2 rounded-md border border-accent/30 bg-accent-soft px-3 py-2 text-xs text-foreground"
        >
          <Eye size={14} className="mt-0.5 shrink-0 text-accent" aria-hidden="true" />
          <span>
            You&apos;re authenticated as{" "}
            <span className="font-medium">{me.name}</span>{" "}
            <span className="font-mono text-muted">({me.prefix})</span>.
            Revoking this key will lock you out — keep at least one admin key
            with you.
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
      ) : sortedKeys.length === 0 && !loadError ? (
        <div className="flex flex-col items-center justify-center rounded-md border border-border bg-card py-20 text-center">
          <div className="mb-4 inline-flex h-10 w-10 items-center justify-center rounded-full bg-surface-2 text-muted">
            <KeyRound size={20} aria-hidden="true" />
          </div>
          <h2 className="text-base font-medium text-foreground-strong">
            No API keys yet
          </h2>
          <p className="mt-1 max-w-sm text-sm text-muted">
            Create your first key to authenticate API requests. Give it a name,
            pick the scopes it should have, and copy the secret — it&apos;s
            only shown once.
          </p>
          <button
            type="button"
            onClick={() => setCreating(true)}
            className="mt-5 inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground hover:opacity-90"
          >
            <Plus size={14} aria-hidden="true" />
            Create your first key
          </button>
        </div>
      ) : (
        <DataTable
          data={sortedKeys}
          columns={columns}
          getRowKey={(k) => k.id}
          density="compact"
          rowClassName={(k) => {
            const dim = k.revoked_at ? "opacity-60" : "";
            const ring =
              highlightId === k.id
                ? "ring-1 ring-accent bg-accent-soft/30"
                : "";
            return `${dim} ${ring}`.trim();
          }}
        />
      )}

      <KeyCreateModal
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={(created) => {
          // Optimistically prepend the new row; the next refresh will
          // reconcile with the backend ordering.
          setKeys((prev) => {
            const view = {
              id: created.id,
              name: created.name,
              prefix: created.prefix,
              scopes: created.scopes,
              created_at: created.created_at,
              last_used_at: created.last_used_at,
              revoked_at: created.revoked_at,
            };
            const without = prev.filter((k) => k.id !== created.id);
            return [view, ...without];
          });
          // Highlight the new row and remember which one for the URL.
          setHighlightId(created.id);
          setTimeout(() => setHighlightId((id) => (id === created.id ? null : id)), 3000);
          pushToast("success", `Key '${created.name}' created.`);
        }}
      />

      {confirmTarget && (
        <ConfirmRevoke
          keyRow={confirmTarget}
          onCancel={() => {
            if (!confirmBusy) {
              setConfirmTarget(null);
              setConfirmError(null);
            }
          }}
          onConfirm={() => void handleConfirmRevoke()}
          busy={confirmBusy}
          error={confirmError}
        />
      )}

      <ToastStack
        toasts={toasts}
        onDismiss={(id) => setToasts((prev) => prev.filter((t) => t.id !== id))}
      />
    </div>
  );
}

export default function KeysPage() {
  return (
    <Suspense fallback={null}>
      <KeysPageInner />
    </Suspense>
  );
}
