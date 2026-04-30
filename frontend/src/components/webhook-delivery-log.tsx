"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Loader2,
  RefreshCw,
  X,
} from "lucide-react";
import { listWebhookDeliveries } from "@/lib/api";
import type { Webhook, WebhookDelivery, WebhookDeliveryStatus } from "@/lib/api";

interface WebhookDeliveryLogProps {
  webhook: Webhook | null;
  open: boolean;
  onClose: () => void;
  // Optional id to highlight (e.g. a freshly-fired test delivery).
  highlightDeliveryId?: string | null;
  // Notified when the highlighted delivery transitions to a terminal state.
  onHighlightedSettled?: (delivery: WebhookDelivery) => void;
}

const POLL_MS = 5_000;
const RESPONSE_BODY_TRUNCATE = 500;

const STATUS_PILL_CLS: Record<WebhookDeliveryStatus, string> = {
  pending:
    "bg-surface-2 text-muted border border-border",
  delivering:
    "bg-sev-medium-bg text-sev-medium border border-sev-medium/30",
  succeeded:
    "bg-accent-soft text-accent border border-accent/40",
  failed:
    "bg-sev-critical-bg text-sev-critical border border-sev-critical/30",
};

const STATUS_LABEL: Record<WebhookDeliveryStatus, string> = {
  pending: "Pending",
  delivering: "Delivering",
  succeeded: "Succeeded",
  failed: "Failed",
};

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

function StatusPill({ status }: { status: WebhookDeliveryStatus }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[0.6875rem] font-medium ${STATUS_PILL_CLS[status]}`}
    >
      <span
        aria-hidden
        className={`h-1.5 w-1.5 rounded-full ${
          status === "succeeded"
            ? "bg-accent"
            : status === "failed"
              ? "bg-sev-critical"
              : status === "delivering"
                ? "bg-sev-medium animate-pulse"
                : "bg-muted"
        }`}
      />
      {STATUS_LABEL[status]}
    </span>
  );
}

interface ResponseBodyProps {
  body: string | null;
}

function ResponseBody({ body }: ResponseBodyProps) {
  const [showFull, setShowFull] = useState(false);
  if (!body) {
    return (
      <p className="text-xs italic text-muted">
        No response body recorded.
      </p>
    );
  }
  const long = body.length > RESPONSE_BODY_TRUNCATE;
  const visible = !long || showFull ? body : body.slice(0, RESPONSE_BODY_TRUNCATE);
  return (
    <div className="space-y-1.5">
      <pre className="max-h-64 overflow-auto rounded-md border border-border bg-surface-2 px-3 py-2 font-mono text-[0.6875rem] leading-relaxed text-foreground whitespace-pre-wrap break-all">
        {visible}
        {long && !showFull && "…"}
      </pre>
      {long && (
        <button
          type="button"
          onClick={() => setShowFull((v) => !v)}
          className="text-[0.6875rem] text-muted underline hover:text-foreground"
        >
          {showFull
            ? "Show less"
            : `Show full response (${body.length} bytes)`}
        </button>
      )}
    </div>
  );
}

export function WebhookDeliveryLog({
  webhook,
  open,
  onClose,
  highlightDeliveryId,
  onHighlightedSettled,
}: WebhookDeliveryLogProps) {
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  // Re-render once a second so the relative timestamps stay fresh while the
  // drawer is open.
  const [, setTick] = useState(0);

  const settledNotifiedRef = useRef<Set<string>>(new Set());
  const onSettledRef = useRef(onHighlightedSettled);
  onSettledRef.current = onHighlightedSettled;

  const webhookId = webhook?.id ?? null;

  const refresh = useCallback(
    async (mode: "loading" | "background") => {
      if (!webhookId) return;
      if (mode === "loading") {
        setLoading(true);
      } else {
        setRefreshing(true);
      }
      try {
        const list = await listWebhookDeliveries(webhookId);
        setDeliveries(list);
        setError(null);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to load deliveries.",
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [webhookId],
  );

  // Initial load whenever the drawer opens or switches to a new webhook.
  useEffect(() => {
    if (!open || !webhookId) return;
    setExpanded(new Set());
    settledNotifiedRef.current = new Set();
    void refresh("loading");
  }, [open, webhookId, refresh]);

  // Auto-refresh every POLL_MS while open. The dispatcher works in the
  // background, so users want to see retries land without manual refresh.
  useEffect(() => {
    if (!open || !webhookId) return;
    const interval = setInterval(() => {
      void refresh("background");
    }, POLL_MS);
    return () => clearInterval(interval);
  }, [open, webhookId, refresh]);

  // Keep the relative timestamps fresh.
  useEffect(() => {
    if (!open) return;
    const tick = setInterval(() => setTick((n) => n + 1), 1000);
    return () => clearInterval(tick);
  }, [open]);

  // Tighter poll cycle while the highlighted delivery hasn't settled yet —
  // the dispatcher mock flips status after ~1s, so 5s feels laggy on the
  // very first frame. We layer this on top of the regular auto-refresh.
  useEffect(() => {
    if (!open || !webhookId || !highlightDeliveryId) return;
    const target = deliveries.find((d) => d.id === highlightDeliveryId);
    if (target && (target.status === "succeeded" || target.status === "failed")) {
      return;
    }
    const t = setTimeout(() => {
      void refresh("background");
    }, 1200);
    return () => clearTimeout(t);
  }, [open, webhookId, highlightDeliveryId, deliveries, refresh]);

  // Notify the parent the moment the highlighted delivery becomes terminal.
  useEffect(() => {
    if (!highlightDeliveryId) return;
    if (settledNotifiedRef.current.has(highlightDeliveryId)) return;
    const target = deliveries.find((d) => d.id === highlightDeliveryId);
    if (!target) return;
    if (target.status !== "succeeded" && target.status !== "failed") return;
    settledNotifiedRef.current.add(highlightDeliveryId);
    onSettledRef.current?.(target);
  }, [deliveries, highlightDeliveryId]);

  // Esc closes.
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  function toggleExpanded(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const sortedDeliveries = useMemo(() => {
    // Backend already returns newest-first, but we sort defensively in case
    // the mock ever shuffles them.
    return [...deliveries].sort(
      (a, b) =>
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
    );
  }, [deliveries]);

  if (!open || !webhook) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="webhook-deliveries-title"
      className="fixed inset-0 z-50 flex"
      onClick={onClose}
    >
      <div
        aria-hidden
        className="absolute inset-0 bg-black/55"
      />
      <div
        className="relative ml-auto flex h-full w-full max-w-xl flex-col border-l border-border-strong bg-card shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
          <div className="min-w-0">
            <p className="text-[0.6875rem] uppercase tracking-wider text-muted">
              Delivery log
            </p>
            <h2
              id="webhook-deliveries-title"
              className="truncate text-sm font-medium text-foreground-strong"
              title={webhook.name}
            >
              {webhook.name}
            </h2>
            <p
              className="truncate font-mono text-[0.6875rem] text-muted"
              title={webhook.url}
            >
              {webhook.url}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-1">
            <button
              type="button"
              onClick={() => void refresh("background")}
              disabled={loading || refreshing}
              aria-label="Refresh deliveries"
              className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-foreground disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <RefreshCw
                size={14}
                aria-hidden="true"
                className={refreshing ? "animate-spin" : ""}
              />
            </button>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-foreground"
            >
              <X size={16} aria-hidden="true" />
            </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto">
          {error && (
            <div
              role="alert"
              className="m-4 flex items-start gap-2 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
            >
              <AlertTriangle
                size={14}
                className="mt-0.5 shrink-0"
                aria-hidden="true"
              />
              <span className="flex-1">{error}</span>
              <button
                type="button"
                onClick={() => void refresh("loading")}
                className="text-xs underline hover:no-underline"
              >
                Retry
              </button>
            </div>
          )}

          {loading && deliveries.length === 0 ? (
            <div className="flex items-center justify-center py-16 text-sm text-muted">
              <Loader2 size={16} className="mr-2 animate-spin" aria-hidden="true" />
              Loading deliveries…
            </div>
          ) : sortedDeliveries.length === 0 ? (
            <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
              <p className="text-sm font-medium text-foreground-strong">
                No deliveries yet
              </p>
              <p className="mt-1 max-w-xs text-xs text-muted">
                Once a matching event fires (or you click <em>Test</em>), the
                attempt history will show up here.
              </p>
            </div>
          ) : (
            <ul className="divide-y divide-border">
              {sortedDeliveries.map((d) => {
                const isOpen = expanded.has(d.id);
                const isHighlighted = highlightDeliveryId === d.id;
                const inFlight = d.status === "pending" || d.status === "delivering";
                return (
                  <li
                    key={d.id}
                    className={
                      isHighlighted
                        ? "ring-1 ring-inset ring-accent bg-accent-soft/20"
                        : ""
                    }
                  >
                    <button
                      type="button"
                      onClick={() => toggleExpanded(d.id)}
                      aria-expanded={isOpen}
                      className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-surface-2 focus-visible:bg-surface-2"
                    >
                      <span
                        aria-hidden
                        className="text-muted shrink-0"
                      >
                        {isOpen ? (
                          <ChevronDown size={14} />
                        ) : (
                          <ChevronRight size={14} />
                        )}
                      </span>
                      <div className="flex min-w-0 flex-1 flex-col gap-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <StatusPill status={d.status} />
                          <span className="font-mono text-xs text-foreground">
                            {d.event}
                          </span>
                          {isHighlighted && inFlight && (
                            <span className="inline-flex items-center gap-1 text-[0.6875rem] text-accent">
                              <Loader2
                                size={10}
                                className="animate-spin"
                                aria-hidden="true"
                              />
                              live
                            </span>
                          )}
                        </div>
                        <div className="flex flex-wrap items-center gap-3 text-[0.6875rem] text-muted">
                          <span>
                            attempt{" "}
                            <span className="font-mono text-foreground">
                              #{d.attempt}
                            </span>
                          </span>
                          <span>
                            {d.response_code !== null ? (
                              <>
                                HTTP{" "}
                                <span
                                  className={`font-mono ${
                                    d.response_code >= 200 && d.response_code < 300
                                      ? "text-accent"
                                      : d.response_code === 0
                                        ? "text-sev-critical"
                                        : "text-sev-critical"
                                  }`}
                                >
                                  {d.response_code === 0 ? "—" : d.response_code}
                                </span>
                              </>
                            ) : (
                              <span className="font-mono">—</span>
                            )}
                          </span>
                          <time
                            dateTime={d.created_at}
                            title={fullTime(d.created_at)}
                          >
                            {relativeTime(d.created_at)}
                          </time>
                        </div>
                      </div>
                    </button>
                    {isOpen && (
                      <div className="space-y-3 border-t border-border bg-surface-2/40 px-4 py-3">
                        <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-[0.6875rem]">
                          <dt className="text-muted">Delivery ID</dt>
                          <dd className="font-mono text-foreground break-all">
                            {d.id}
                          </dd>
                          <dt className="text-muted">Created</dt>
                          <dd className="text-foreground" title={fullTime(d.created_at)}>
                            {fullTime(d.created_at) || d.created_at}
                          </dd>
                          <dt className="text-muted">Updated</dt>
                          <dd className="text-foreground" title={fullTime(d.updated_at)}>
                            {fullTime(d.updated_at) || d.updated_at}
                          </dd>
                          {(d.status === "pending" || d.status === "delivering") && (
                            <>
                              <dt className="text-muted">Next attempt</dt>
                              <dd
                                className="text-foreground"
                                title={fullTime(d.next_attempt_at)}
                              >
                                {relativeTime(d.next_attempt_at)}
                              </dd>
                            </>
                          )}
                        </dl>
                        <div>
                          <p className="mb-1 text-[0.6875rem] uppercase tracking-wider text-muted">
                            Response body
                          </p>
                          <ResponseBody body={d.response_body} />
                        </div>
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        <footer className="border-t border-border bg-surface-2/40 px-4 py-2 text-[0.6875rem] text-muted">
          {sortedDeliveries.length > 0 && (
            <span>
              Showing {sortedDeliveries.length} most-recent
              {sortedDeliveries.length === 1 ? " delivery" : " deliveries"} ·
              auto-refreshing every {POLL_MS / 1000}s.
            </span>
          )}
        </footer>
      </div>
    </div>
  );
}
