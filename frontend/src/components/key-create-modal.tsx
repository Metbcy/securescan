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
import { createApiKey } from "@/lib/api";
import type { ApiKeyCreated, ApiKeyScope } from "@/lib/api";

interface KeyCreateModalProps {
  open: boolean;
  onClose: () => void;
  onCreated: (created: ApiKeyCreated) => void;
}

const NAME_MAX = 80;
const REVEAL_GRACE_MS = 1000;

interface ScopeOption {
  id: ApiKeyScope;
  label: string;
  blurb: string;
  tone: "neutral" | "warn" | "danger";
  defaultChecked: boolean;
}

const SCOPE_OPTIONS: ScopeOption[] = [
  {
    id: "read",
    label: "read",
    blurb: "View scans, findings, SBOMs and dashboards.",
    tone: "neutral",
    defaultChecked: true,
  },
  {
    id: "write",
    label: "write",
    blurb: "Start, cancel, delete scans and edit triage state.",
    tone: "warn",
    defaultChecked: true,
  },
  {
    id: "admin",
    label: "admin",
    blurb: "Required to manage other API keys. Treat with care.",
    tone: "danger",
    defaultChecked: false,
  },
];

const SCOPE_TONE_CLS: Record<ScopeOption["tone"], string> = {
  neutral: "border-border",
  warn: "border-sev-medium/40",
  danger: "border-sev-critical/40",
};

const SCOPE_PILL_CLS: Record<ScopeOption["tone"], string> = {
  neutral:
    "bg-surface-2 text-foreground border border-border",
  warn: "bg-sev-medium-bg text-sev-medium border border-sev-medium/30",
  danger:
    "bg-sev-critical-bg text-sev-critical border border-sev-critical/30",
};

function defaultScopes(): Record<ApiKeyScope, boolean> {
  return SCOPE_OPTIONS.reduce<Record<ApiKeyScope, boolean>>(
    (acc, opt) => {
      acc[opt.id] = opt.defaultChecked;
      return acc;
    },
    { read: false, write: false, admin: false },
  );
}

export function KeyCreateModal({ open, onClose, onCreated }: KeyCreateModalProps) {
  const [step, setStep] = useState<"form" | "reveal">("form");
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<Record<ApiKeyScope, boolean>>(defaultScopes);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const [confirmDiscard, setConfirmDiscard] = useState(false);
  const [closeArmed, setCloseArmed] = useState(true);

  const nameInputRef = useRef<HTMLInputElement | null>(null);
  const keyInputRef = useRef<HTMLInputElement | null>(null);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Reset internal state every time the modal is (re)opened.
  useEffect(() => {
    if (!open) return;
    setStep("form");
    setName("");
    setScopes(defaultScopes());
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
    const el = keyInputRef.current;
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
  const anyScope = SCOPE_OPTIONS.some((opt) => scopes[opt.id]);
  const canSubmit = trimmedName.length > 0 && anyScope && !submitting;

  function toggleScope(id: ApiKeyScope) {
    setScopes((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const selected: ApiKeyScope[] = SCOPE_OPTIONS.filter(
        (opt) => scopes[opt.id],
      ).map((opt) => opt.id);
      const result = await createApiKey({
        name: trimmedName.slice(0, NAME_MAX),
        scopes: selected,
      });
      setCreated(result);
      setStep("reveal");
      onCreated(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create API key.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleCopy() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.key);
      setCopied(true);
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
      copyTimerRef.current = setTimeout(() => setCopied(false), 1600);
    } catch {
      // clipboard unavailable — surface a hint instead of swallowing silently
      setError("Couldn't access the clipboard. Select the key and copy manually.");
    }
  }

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="key-create-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4"
      onClick={handleClose}
    >
      <div
        ref={dialogRef}
        className="w-full max-w-lg rounded-md border border-border-strong bg-card shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2
            id="key-create-title"
            className="text-sm font-medium text-foreground-strong"
          >
            {step === "form" ? "Create an API key" : "Save your new API key"}
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
                  htmlFor="key-name"
                  className="block text-xs font-medium uppercase tracking-wider text-muted"
                >
                  Name
                </label>
                <input
                  ref={nameInputRef}
                  id="key-name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value.slice(0, NAME_MAX))}
                  placeholder="e.g. ci-bot"
                  maxLength={NAME_MAX}
                  required
                  className="mt-1.5 h-9 w-full rounded-md border border-border bg-surface-2 px-2.5 text-sm placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-[var(--ring)]"
                />
                <p className="mt-1 text-xs text-muted">
                  Used to identify this key in the dashboard. Up to {NAME_MAX}{" "}
                  characters.
                </p>
              </div>

              <fieldset>
                <legend className="block text-xs font-medium uppercase tracking-wider text-muted">
                  Scopes
                </legend>
                <ul className="mt-1.5 space-y-1.5">
                  {SCOPE_OPTIONS.map((opt) => {
                    const checked = scopes[opt.id];
                    return (
                      <li key={opt.id}>
                        <label
                          className={`flex cursor-pointer items-start gap-3 rounded-md border bg-surface-2 px-3 py-2 transition-colors hover:border-border-strong ${
                            checked ? "ring-1 ring-[var(--ring)]" : ""
                          } ${SCOPE_TONE_CLS[opt.tone]}`}
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => toggleScope(opt.id)}
                            className="mt-1 accent-[var(--accent)]"
                          />
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <span
                                className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[0.6875rem] ${SCOPE_PILL_CLS[opt.tone]}`}
                              >
                                {opt.tone === "danger" && (
                                  <ShieldAlert size={10} aria-hidden="true" />
                                )}
                                {opt.label}
                              </span>
                              {opt.tone === "danger" && (
                                <span
                                  className="inline-flex items-center gap-1 text-[0.6875rem] text-sev-critical"
                                  title="Required to manage other API keys. Treat with care."
                                >
                                  <Info size={10} aria-hidden="true" />
                                  dangerous
                                </span>
                              )}
                            </div>
                            <p className="mt-0.5 text-xs text-muted">{opt.blurb}</p>
                          </div>
                        </label>
                      </li>
                    );
                  })}
                </ul>
                {!anyScope && (
                  <p className="mt-1.5 text-xs text-sev-critical">
                    Pick at least one scope.
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
                    <p className="font-medium">Save this key now.</p>
                    <p className="text-sev-critical/90">
                      SecureScan won&apos;t show it again — there&apos;s no way
                      to recover the full key after you close this dialog.
                    </p>
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="key-secret"
                    className="block text-xs font-medium uppercase tracking-wider text-muted"
                  >
                    Secret
                  </label>
                  <div className="mt-1.5 flex items-stretch gap-2">
                    <input
                      ref={keyInputRef}
                      id="key-secret"
                      type="text"
                      readOnly
                      value={created.key}
                      onFocus={(e) => e.currentTarget.select()}
                      className="h-9 flex-1 rounded-md border border-border bg-surface-2 px-2.5 font-mono text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-[var(--ring)]"
                    />
                    <button
                      type="button"
                      onClick={handleCopy}
                      aria-label="Copy key"
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

                <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-xs">
                  <dt className="text-muted">Name</dt>
                  <dd className="text-foreground">{created.name}</dd>
                  <dt className="text-muted">Prefix</dt>
                  <dd className="font-mono text-foreground">{created.prefix}</dd>
                  <dt className="text-muted">Scopes</dt>
                  <dd className="flex flex-wrap gap-1">
                    {created.scopes.map((s) => {
                      const tone =
                        s === "admin"
                          ? "danger"
                          : s === "write"
                            ? "warn"
                            : "neutral";
                      return (
                        <span
                          key={s}
                          className={`inline-flex items-center rounded-full px-2 py-0.5 font-mono text-[0.6875rem] ${SCOPE_PILL_CLS[tone]}`}
                        >
                          {s}
                        </span>
                      );
                    })}
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
                Close without saving the key?
              </h3>
            </div>
            <p className="px-4 py-4 text-sm text-muted">
              You won&apos;t be able to see it again. The key is still active —
              you can revoke it from the table if you don&apos;t need it.
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
