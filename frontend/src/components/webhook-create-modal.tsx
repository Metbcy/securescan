"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  Check,
  Copy,
  Info,
  Loader2,
  ShieldAlert,
  X,
} from "lucide-react";
import { createWebhook } from "@/lib/api";
import type { WebhookCreated, WebhookEventType } from "@/lib/api";

interface WebhookCreateModalProps {
  open: boolean;
  onClose: () => void;
  onCreated: (created: WebhookCreated) => void;
}

const NAME_MAX = 80;
const REVEAL_GRACE_MS = 1000;
const URL_PATTERN = /^https?:\/\/[^\s]+$/i;

interface EventOption {
  id: WebhookEventType;
  label: string;
  blurb: string;
}

const EVENT_OPTIONS: EventOption[] = [
  {
    id: "scan.complete",
    label: "scan.complete",
    blurb: "Fires after a scan finishes successfully.",
  },
  {
    id: "scan.failed",
    label: "scan.failed",
    blurb: "Fires when a scan exits with an error.",
  },
  {
    id: "scanner.failed",
    label: "scanner.failed",
    blurb: "One scanner crashed (the scan itself may still complete).",
  },
];

function defaultEvents(): Record<WebhookEventType, boolean> {
  return {
    "scan.complete": true,
    "scan.failed": false,
    "scanner.failed": false,
  };
}

export function WebhookCreateModal({
  open,
  onClose,
  onCreated,
}: WebhookCreateModalProps) {
  const [step, setStep] = useState<"form" | "reveal">("form");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [urlTouched, setUrlTouched] = useState(false);
  const [events, setEvents] = useState<Record<WebhookEventType, boolean>>(
    defaultEvents,
  );
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<WebhookCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const [closeArmed, setCloseArmed] = useState(true);

  const nameInputRef = useRef<HTMLInputElement | null>(null);
  const secretInputRef = useRef<HTMLInputElement | null>(null);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Reset internal state every time the modal is (re)opened.
  useEffect(() => {
    if (!open) return;
    setStep("form");
    setName("");
    setUrl("");
    setUrlTouched(false);
    setEvents(defaultEvents());
    setSubmitting(false);
    setError(null);
    setCreated(null);
    setCopied(false);
    setConfirmDiscard(false);
    setCloseArmed(true);
    const t = setTimeout(() => {
      nameInputRef.current?.focus();
    }, 50);
    return () => clearTimeout(t);
  }, [open]);

  // After the secret-reveal step opens, briefly disable the close button so a
  // fat-fingered Esc / X tap doesn't blow away an unsaved secret.
  useEffect(() => {
    if (step !== "reveal") return;
    setCloseArmed(false);
    const t = setTimeout(() => setCloseArmed(true), REVEAL_GRACE_MS);
    return () => clearTimeout(t);
  }, [step]);

  // Auto-select the secret on focus for one-shot copy.
  useEffect(() => {
    if (step !== "reveal") return;
    const el = secretInputRef.current;
    if (!el) return;
    el.focus();
    el.select();
  }, [step]);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
    };
  }, []);

  const handleClose = useCallback(() => {
    if (!closeArmed) return;
    if (step === "reveal") {
      setConfirmDiscard(true);
      return;
    }
    onClose();
  }, [closeArmed, onClose, step]);

  // Esc closes (with the same guard semantics as the X button).
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key !== "Escape") return;
      if (confirmDiscard) {
        setConfirmDiscard(false);
        return;
      }
      handleClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, handleClose, confirmDiscard]);

  const trimmedName = name.trim();
  const trimmedUrl = url.trim();
  const urlValid = URL_PATTERN.test(trimmedUrl);
  const selectedEvents = EVENT_OPTIONS.filter((opt) => events[opt.id]).map(
    (opt) => opt.id,
  );
  const anyEvent = selectedEvents.length > 0;
  const canSubmit =
    trimmedName.length > 0 && urlValid && anyEvent && !submitting;

  function toggleEvent(id: WebhookEventType) {
    setEvents((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const result = await createWebhook({
        name: trimmedName.slice(0, NAME_MAX),
        url: trimmedUrl,
        event_filter: selectedEvents,
      });
      setCreated(result);
      setStep("reveal");
      onCreated(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create webhook.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleCopy() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.secret);
      setCopied(true);
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
      copyTimerRef.current = setTimeout(() => setCopied(false), 1600);
    } catch {
      setError(
        "Couldn't access the clipboard. Select the secret and copy manually.",
      );
    }
  }

  if (!open) return null;

  const showUrlError = urlTouched && trimmedUrl.length > 0 && !urlValid;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="webhook-create-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4"
      onClick={handleClose}
    >
      <div
        className="w-full max-w-lg rounded-md border border-border-strong bg-card shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2
            id="webhook-create-title"
            className="text-sm font-medium text-foreground-strong"
          >
            {step === "form"
              ? "Create a webhook"
              : "Save your webhook signing secret"}
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={handleClose}
            disabled={!closeArmed}
            className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-foreground disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <X size={16} aria-hidden="true" />
          </button>
        </div>

        {step === "form" ? (
          <form onSubmit={handleSubmit}>
            <div className="space-y-5 px-4 py-4">
              <div>
                <label
                  htmlFor="webhook-name"
                  className="block text-xs font-medium uppercase tracking-wider text-muted"
                >
                  Name
                </label>
                <input
                  ref={nameInputRef}
                  id="webhook-name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value.slice(0, NAME_MAX))}
                  placeholder="e.g. slack-#sec-alerts"
                  maxLength={NAME_MAX}
                  required
                  className="mt-1.5 h-9 w-full rounded-md border border-border bg-surface-2 px-2.5 text-sm placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-[var(--ring)]"
                />
                <p className="mt-1 text-xs text-muted">
                  Used to identify this webhook in the dashboard. Up to{" "}
                  {NAME_MAX} characters.
                </p>
              </div>

              <div>
                <label
                  htmlFor="webhook-url"
                  className="block text-xs font-medium uppercase tracking-wider text-muted"
                >
                  Receiver URL
                </label>
                <input
                  id="webhook-url"
                  type="url"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onBlur={() => setUrlTouched(true)}
                  placeholder="https://hooks.slack.com/services/…"
                  required
                  spellCheck={false}
                  autoCapitalize="off"
                  autoCorrect="off"
                  className={`mt-1.5 h-9 w-full rounded-md border bg-surface-2 px-2.5 font-mono text-xs placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-[var(--ring)] ${
                    showUrlError ? "border-sev-critical/50" : "border-border"
                  }`}
                />
                {showUrlError ? (
                  <p className="mt-1 text-xs text-sev-critical">
                    URL must start with <code className="font-mono">http://</code>{" "}
                    or <code className="font-mono">https://</code>.
                  </p>
                ) : (
                  <p className="mt-1 text-xs text-muted">
                    Slack, Discord, or any HTTPS endpoint that accepts a JSON
                    POST.
                  </p>
                )}
              </div>

              <fieldset>
                <legend className="block text-xs font-medium uppercase tracking-wider text-muted">
                  Events
                </legend>
                <ul className="mt-1.5 space-y-1.5">
                  {EVENT_OPTIONS.map((opt) => {
                    const checked = events[opt.id];
                    return (
                      <li key={opt.id}>
                        <label
                          className={`flex cursor-pointer items-start gap-3 rounded-md border border-border bg-surface-2 px-3 py-2 transition-colors hover:border-border-strong ${
                            checked ? "ring-1 ring-[var(--ring)]" : ""
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => toggleEvent(opt.id)}
                            className="mt-1 accent-[var(--accent)]"
                          />
                          <div className="min-w-0 flex-1">
                            <span className="inline-flex items-center rounded-full border border-border bg-surface-2 px-2 py-0.5 font-mono text-[0.6875rem] text-foreground">
                              {opt.label}
                            </span>
                            <p className="mt-0.5 text-xs text-muted">
                              {opt.blurb}
                            </p>
                          </div>
                        </label>
                      </li>
                    );
                  })}
                </ul>
                {!anyEvent && (
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
                onClick={handleClose}
                disabled={submitting}
                className="rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm hover:border-border-strong disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={!canSubmit}
                className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting && (
                  <Loader2
                    size={14}
                    className="animate-spin"
                    aria-hidden="true"
                  />
                )}
                {submitting ? "Creating…" : "Create"}
              </button>
            </div>
          </form>
        ) : (
          created && (
            <div>
              <div className="space-y-4 px-4 py-4">
                <div
                  role="alert"
                  className="flex items-start gap-2 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
                >
                  <ShieldAlert
                    size={16}
                    className="mt-0.5 shrink-0"
                    aria-hidden="true"
                  />
                  <div>
                    <p className="font-medium">Save this secret now.</p>
                    <p className="text-sev-critical/90">
                      It signs every webhook payload. SecureScan won&apos;t
                      show it again.
                    </p>
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="webhook-secret"
                    className="block text-xs font-medium uppercase tracking-wider text-muted"
                  >
                    Signing secret
                  </label>
                  <div className="mt-1.5 flex items-stretch gap-2">
                    <input
                      ref={secretInputRef}
                      id="webhook-secret"
                      type="text"
                      readOnly
                      value={created.secret}
                      onFocus={(e) => e.currentTarget.select()}
                      className="h-9 flex-1 rounded-md border border-border bg-surface-2 px-2.5 font-mono text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-[var(--ring)]"
                    />
                    <button
                      type="button"
                      onClick={handleCopy}
                      aria-label="Copy secret"
                      className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-2 px-2.5 text-xs font-medium text-foreground hover:border-border-strong"
                    >
                      {copied ? (
                        <>
                          <Check size={12} aria-hidden="true" />
                          Copied!
                        </>
                      ) : (
                        <>
                          <Copy size={12} aria-hidden="true" />
                          Copy
                        </>
                      )}
                    </button>
                  </div>
                </div>

                <p className="text-xs text-muted">
                  Use this secret with HMAC-SHA256 over{" "}
                  <code className="font-mono text-foreground">
                    {"{timestamp}.{raw-body}"}
                  </code>{" "}
                  to verify the{" "}
                  <code className="font-mono text-foreground">
                    X-SecureScan-Signature
                  </code>{" "}
                  header.
                </p>

                <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-xs">
                  <dt className="text-muted">Name</dt>
                  <dd className="text-foreground">{created.name}</dd>
                  <dt className="text-muted">URL</dt>
                  <dd
                    className="truncate font-mono text-foreground"
                    title={created.url}
                  >
                    {created.url}
                  </dd>
                  <dt className="text-muted">Events</dt>
                  <dd className="flex flex-wrap gap-1">
                    {created.event_filter.map((ev) => (
                      <span
                        key={ev}
                        className="inline-flex items-center rounded-full border border-border bg-surface-2 px-2 py-0.5 font-mono text-[0.6875rem]"
                      >
                        {ev}
                      </span>
                    ))}
                  </dd>
                </dl>

                {error && (
                  <div
                    role="alert"
                    className="flex items-start gap-2 rounded-md border border-sev-medium/30 bg-sev-medium-bg px-3 py-2 text-xs text-sev-medium"
                  >
                    <Info
                      size={12}
                      className="mt-0.5 shrink-0"
                      aria-hidden="true"
                    />
                    <span>{error}</span>
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between gap-2 border-t border-border px-4 py-3">
                <p className="text-xs text-muted">
                  {closeArmed
                    ? "Once closed, the secret is gone for good."
                    : "Take a second to save it…"}
                </p>
                <button
                  type="button"
                  onClick={() => {
                    if (!closeArmed) return;
                    onClose();
                  }}
                  disabled={!closeArmed}
                  className="inline-flex items-center rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  I&apos;ve saved it
                </button>
              </div>
            </div>
          )
        )}
      </div>

      {confirmDiscard && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4"
          onClick={(e) => {
            e.stopPropagation();
            setConfirmDiscard(false);
          }}
        >
          <div
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="confirm-discard-title"
            className="w-full max-w-sm rounded-md border border-border-strong bg-card shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="border-b border-border px-4 py-3">
              <h3
                id="confirm-discard-title"
                className="text-sm font-medium text-foreground-strong"
              >
                Close without saving the secret?
              </h3>
            </div>
            <p className="px-4 py-4 text-sm text-muted">
              You won&apos;t be able to see it again. The webhook is still
              registered — you can delete it from the table if you don&apos;t
              need it.
            </p>
            <div className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
              <button
                type="button"
                onClick={() => setConfirmDiscard(false)}
                className="rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm hover:border-border-strong"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  setConfirmDiscard(false);
                  onClose();
                }}
                className="rounded-md bg-sev-critical px-3 py-1.5 text-sm font-medium text-white hover:opacity-90"
              >
                Discard
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
