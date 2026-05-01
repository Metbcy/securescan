"use client";

import { useEffect, useRef, useState } from "react";
import { ChevronRight, ChevronDown, Slash, X } from "lucide-react";
import {
  addFindingComment,
  deleteFindingComment,
  listFindingComments,
  TRIAGE_STATUSES,
  type Finding,
  type FindingComment,
  type FindingState,
  type TriageStatus,
} from "@/lib/api";
import { severityEdgeClass, type Severity } from "@/components/severity-edge";
import { RelativeTime } from "@/components/relative-time";

export type SuppressionReason = "inline" | "config" | "baseline";

const SUPPRESSION_REASONS: readonly SuppressionReason[] = ["inline", "config", "baseline"];

const SEV_BADGE: Record<Severity, string> = {
  critical: "bg-sev-critical-bg text-sev-critical",
  high: "bg-sev-high-bg text-sev-high",
  medium: "bg-sev-medium-bg text-sev-medium",
  low: "bg-sev-low-bg text-sev-low",
  info: "bg-sev-info-bg text-sev-info",
};

const SEV_DOT: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

/**
 * Pill colors per triage status. `new` is intentionally omitted — rows in
 * the default state render an empty cell rather than a pill, per spec.
 *
 *   - triaged       → neutral muted (acknowledged but no decision yet)
 *   - false_positive→ sev-info blue tint (informational, not a real issue)
 *   - accepted_risk → sev-medium amber (we know; it's accepted)
 *   - fixed         → accent green (also strikes through the title; a "fixed"
 *                     finding reappearing in a later scan is a regression
 *                     signal we want to be visually loud)
 *   - wont_fix      → neutral with slash icon (decision is "no")
 */
export const STATUS_PILL: Record<Exclude<TriageStatus, "new">, string> = {
  triaged: "bg-surface-2 text-muted border-border",
  false_positive: "bg-sev-info-bg text-sev-info border-sev-info/40",
  accepted_risk: "bg-sev-medium-bg text-sev-medium border-sev-medium/40",
  fixed: "bg-accent-soft text-accent border-accent/40",
  wont_fix: "bg-surface-2 text-muted border-border",
};

export const STATUS_LABEL: Record<TriageStatus, string> = {
  new: "New",
  triaged: "Triaged",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
  fixed: "Fixed",
  wont_fix: "Won't fix",
};

function normalize(severity: string): Severity {
  const s = severity?.toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") {
    return s;
  }
  return "info";
}

export function getSuppressedBy(metadata: Record<string, unknown> | undefined | null): SuppressionReason | null {
  if (!metadata) return null;
  const raw = metadata["suppressed_by"];
  if (typeof raw !== "string") return null;
  return (SUPPRESSION_REASONS as readonly string[]).includes(raw) ? (raw as SuppressionReason) : null;
}

export function getOriginalSeverity(metadata: Record<string, unknown> | undefined | null): string | null {
  if (!metadata) return null;
  const raw = metadata["original_severity"];
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

export function getOverrideSource(metadata: Record<string, unknown> | undefined | null): string {
  if (!metadata) return "config";
  const raw = metadata["severity_override_source"];
  return typeof raw === "string" && raw.length > 0 ? raw : "config";
}

export function getCodeSnippet(metadata: Record<string, unknown> | undefined | null): string | null {
  if (!metadata) return null;
  const raw = metadata["code_snippet"] ?? metadata["snippet"];
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

export function getSuppressionNote(metadata: Record<string, unknown> | undefined | null): string | null {
  if (!metadata) return null;
  const raw = metadata["suppression_note"] ?? metadata["suppressed_reason"];
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

/**
 * Render the triage status pill used both in the table's Status column
 * and inline in the expanded triage panel.
 */
export function StatusPill({ status }: { status: TriageStatus }) {
  if (status === "new") return null;
  const label = STATUS_LABEL[status];
  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[0.6875rem] font-medium border ${STATUS_PILL[status]}`}
      title={`Triage status: ${label}`}
    >
      {status === "wont_fix" && <Slash size={10} strokeWidth={1.5} aria-hidden />}
      {label}
    </span>
  );
}

interface FindingRowProps {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
  colSpan: number;
  /** Current triage state (after optimistic overrides applied by the parent). */
  state: FindingState | null;
  /** Apply a status PATCH. Parent handles optimistic-update + rollback. */
  onPatchState: (
    fingerprint: string,
    body: { status: TriageStatus; note?: string | null },
  ) => Promise<FindingState>;
}

export function FindingRow({
  finding,
  expanded,
  onToggle,
  colSpan,
  state,
  onPatchState,
}: FindingRowProps) {
  const sev = normalize(finding.severity);
  const suppressedBy = getSuppressedBy(finding.metadata);
  const originalSeverity = getOriginalSeverity(finding.metadata);
  const overrideSource = getOverrideSource(finding.metadata);
  const severityChanged =
    originalSeverity !== null && originalSeverity.toLowerCase() !== finding.severity.toLowerCase();
  const severityPinned =
    originalSeverity !== null && originalSeverity.toLowerCase() === finding.severity.toLowerCase();
  const codeSnippet = getCodeSnippet(finding.metadata);
  const suppressionNote = getSuppressionNote(finding.metadata);

  const status: TriageStatus = state?.status ?? "new";
  const isFixed = status === "fixed";
  const fingerprint = finding.fingerprint ?? "";

  const fileLine =
    finding.file_path != null
      ? finding.line_start != null
        ? `${finding.file_path}:${finding.line_start}`
        : finding.file_path
      : "—";

  return (
    <>
      <tr
        onClick={onToggle}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onToggle();
          }
        }}
        tabIndex={0}
        aria-expanded={expanded}
        className={`group cursor-pointer border-b border-border transition-colors hover:bg-surface-2 focus-visible:bg-surface-2 ${
          suppressedBy ? "opacity-60" : ""
        }`}
      >
        <td className={`${severityEdgeClass(finding.severity)} px-3 py-3 align-top w-8 text-muted`}>
          {expanded ? (
            <ChevronDown size={14} strokeWidth={1.5} />
          ) : (
            <ChevronRight size={14} strokeWidth={1.5} />
          )}
        </td>
        <td className="px-2 py-3 align-top whitespace-nowrap w-[80px]">
          {status === "new" ? (
            <span aria-hidden className="text-muted/50">—</span>
          ) : (
            <StatusPill status={status} />
          )}
        </td>
        <td className="px-3 py-3 align-top whitespace-nowrap">
          <span
            className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium ${SEV_BADGE[sev]}`}
          >
            <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${SEV_DOT[sev]}`} />
            {finding.severity}
          </span>
          {severityChanged && originalSeverity && (
            <span
              className="ml-1.5 inline-flex items-center px-1.5 py-0.5 rounded text-[0.6875rem] font-mono text-muted bg-surface-2 border border-border"
              title={`Severity overridden by ${overrideSource}`}
            >
              was: {originalSeverity.toLowerCase()} → {finding.severity.toLowerCase()} ({overrideSource})
            </span>
          )}
          {severityPinned && (
            <span
              className="ml-1.5 inline-flex items-center px-1.5 py-0.5 rounded text-[0.6875rem] font-mono text-muted bg-surface-2 border border-border"
              title="Severity pinned in config"
            >
              pinned
            </span>
          )}
        </td>
        <td className="px-3 py-3 align-top font-mono text-xs text-muted max-w-[28ch]">
          <span className="block truncate" title={fileLine}>
            {fileLine}
          </span>
        </td>
        <td className="px-3 py-3 align-top">
          <div className="flex items-start gap-2 min-w-0">
            <span
              className={`text-sm leading-snug min-w-0 ${
                expanded ? "" : "line-clamp-1 group-hover:line-clamp-2"
              } ${suppressedBy || isFixed ? "line-through" : ""}`}
              title={finding.title}
            >
              {finding.title}
            </span>
            {suppressedBy && (
              <span
                className="inline-flex items-center shrink-0 px-1.5 py-0.5 rounded text-[0.6875rem] font-mono font-medium bg-surface-2 text-muted border border-border"
                title={suppressionNote ?? `Suppressed by ${suppressedBy}`}
              >
                Suppressed · {suppressedBy}
              </span>
            )}
          </div>
        </td>
        <td className="px-3 py-3 align-top text-xs text-muted font-mono whitespace-nowrap">
          {finding.scanner}
        </td>
        <td className="px-3 py-3 align-top text-right">
          {finding.rule_id && (
            <span className="text-[0.6875rem] font-mono text-muted" title={`Rule ${finding.rule_id}`}>
              {finding.rule_id}
            </span>
          )}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-surface-2/40">
          <td className={`${severityEdgeClass(finding.severity)}`} aria-hidden />
          <td colSpan={colSpan - 1} className="px-3 pt-2 pb-5">
            <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_22rem] gap-4">
              <div className="space-y-4 text-sm max-w-[80ch] min-w-0">
                {finding.description && (
                  <div>
                    <p className="text-[0.6875rem] uppercase tracking-wider text-muted mb-1">
                      Message
                    </p>
                    <p className="text-foreground leading-relaxed whitespace-pre-wrap">
                      {finding.description}
                    </p>
                  </div>
                )}
                {codeSnippet && (
                  <div>
                    <p className="text-[0.6875rem] uppercase tracking-wider text-muted mb-1">
                      Code
                    </p>
                    <pre className="rounded-md border border-border bg-card px-3 py-2 text-xs font-mono text-foreground overflow-x-auto">
                      {codeSnippet}
                    </pre>
                  </div>
                )}
                {finding.remediation && (
                  <div>
                    <p className="text-[0.6875rem] uppercase tracking-wider text-muted mb-1">
                      Suggestion
                    </p>
                    <p className="text-foreground leading-relaxed whitespace-pre-wrap">
                      {finding.remediation}
                    </p>
                  </div>
                )}
                {suppressedBy && (
                  <div>
                    <p className="text-[0.6875rem] uppercase tracking-wider text-muted mb-1">
                      Suppression
                    </p>
                    <p className="text-muted leading-relaxed">
                      Suppressed by <span className="font-mono text-foreground">{suppressedBy}</span>
                      {suppressionNote ? <> — {suppressionNote}</> : null}
                    </p>
                  </div>
                )}
                <div className="flex flex-wrap gap-x-6 gap-y-1 text-[0.6875rem] text-muted">
                  {finding.cwe && (
                    <span>
                      CWE: <span className="font-mono text-foreground">{finding.cwe}</span>
                    </span>
                  )}
                  {finding.rule_id && (
                    <span>
                      Rule: <span className="font-mono text-foreground">{finding.rule_id}</span>
                    </span>
                  )}
                  {finding.compliance_tags && finding.compliance_tags.length > 0 && (
                    <span className="flex flex-wrap items-center gap-1">
                      Compliance:
                      {finding.compliance_tags.map((tag) => (
                        <span
                          key={tag}
                          className="inline-block px-1.5 py-0.5 rounded text-[0.6875rem] font-mono bg-accent-soft text-accent"
                        >
                          {tag}
                        </span>
                      ))}
                    </span>
                  )}
                </div>
              </div>

              {/* Right column: triage + comments. Compact, doesn't push the
                  message/code/CWE/etc content far down on wide viewports. */}
              <div className="space-y-3 min-w-0">
                {fingerprint ? (
                  <>
                    <TriagePanel
                      fingerprint={fingerprint}
                      state={state}
                      onPatchState={onPatchState}
                    />
                    <CommentsPanel fingerprint={fingerprint} />
                  </>
                ) : (
                  <p className="rounded-md border border-border bg-card px-3 py-2 text-xs text-muted">
                    Triage unavailable: this finding has no fingerprint.
                  </p>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

/* ---------- Triage panel ---------- */

interface TriagePanelProps {
  fingerprint: string;
  state: FindingState | null;
  onPatchState: (
    fingerprint: string,
    body: { status: TriageStatus; note?: string | null },
  ) => Promise<FindingState>;
}

function TriagePanel({ fingerprint, state, onPatchState }: TriagePanelProps) {
  const status: TriageStatus = state?.status ?? "new";
  const [noteValue, setNoteValue] = useState<string>(state?.note ?? "");
  const [noteFocused, setNoteFocused] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  // Re-sync the note input when the state object identity changes (e.g. after
  // a successful PATCH replaces the parent's override). Don't clobber the
  // user's typing while focused.
  const lastSyncedNote = useRef<string>(state?.note ?? "");
  useEffect(() => {
    const next = state?.note ?? "";
    if (!noteFocused && next !== lastSyncedNote.current) {
      setNoteValue(next);
      lastSyncedNote.current = next;
    }
  }, [state, noteFocused]);

  const submit = async (nextStatus: TriageStatus, note: string | null) => {
    setError(null);
    setPending(true);
    try {
      await onPatchState(fingerprint, { status: nextStatus, note });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setPending(false);
    }
  };

  const onStatusChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const next = e.target.value as TriageStatus;
    void submit(next, noteValue.length > 0 ? noteValue : null);
  };

  const onNoteCommit = () => {
    setNoteFocused(false);
    const trimmed = noteValue;
    if (trimmed === (state?.note ?? "")) return;
    void submit(status, trimmed.length > 0 ? trimmed : null);
  };

  return (
    <div className="rounded-md border border-border bg-card p-3 space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-[0.6875rem] uppercase tracking-wider text-muted">Triage</p>
        {pending && <span className="text-[0.6875rem] text-muted">saving…</span>}
      </div>

      <label className="block">
        <span className="sr-only">Status</span>
        <select
          value={status}
          onChange={onStatusChange}
          onClick={(e) => e.stopPropagation()}
          disabled={pending}
          className="w-full bg-surface-2 border border-border rounded-md px-2 py-1.5 text-xs text-foreground hover:border-border-strong focus:outline-none focus:ring-2 focus:ring-ring/50 disabled:opacity-60"
        >
          {TRIAGE_STATUSES.map((s) => (
            <option key={s} value={s}>
              {STATUS_LABEL[s]}
            </option>
          ))}
        </select>
      </label>

      <label className="block">
        <span className="sr-only">Note</span>
        <textarea
          value={noteValue}
          onChange={(e) => setNoteValue(e.target.value)}
          onFocus={() => setNoteFocused(true)}
          onBlur={onNoteCommit}
          onClick={(e) => e.stopPropagation()}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              (e.currentTarget as HTMLTextAreaElement).blur();
            }
          }}
          rows={noteFocused ? 3 : 1}
          placeholder="Add a triage note (optional)"
          className="w-full resize-none bg-surface-2 border border-border rounded-md px-2 py-1.5 text-xs text-foreground placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-ring/50 transition-[height]"
        />
      </label>

      {error && (
        <p className="text-[0.6875rem] text-sev-critical" role="alert">
          {error}
        </p>
      )}

      {state && (
        <p className="text-[0.6875rem] text-muted">
          Updated by{" "}
          <span className="text-foreground">{state.updated_by ?? "anonymous"}</span>{" "}
          <RelativeTime
            iso={state.updated_at}
            title={new Date(state.updated_at).toLocaleString()}
          />
        </p>
      )}
    </div>
  );
}

/* ---------- Comments panel ---------- */

interface CommentsPanelProps {
  fingerprint: string;
}

function CommentsPanel({ fingerprint }: CommentsPanelProps) {
  const [comments, setComments] = useState<FindingComment[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Lazy-load on first mount of the expanded panel — the parent re-mounts
  // this component when the row is collapsed and re-expanded, so this
  // doubles as the "re-fetch on next expand" hook.
  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      try {
        const list = await listFindingComments(fingerprint);
        if (alive) setComments(list);
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : "Failed to load comments");
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [fingerprint]);

  const onSend = async () => {
    const text = draft.trim();
    if (!text || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const created = await addFindingComment(fingerprint, { text });
      setComments((prev) => [...(prev ?? []), created]);
      setDraft("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to add comment");
    } finally {
      setSubmitting(false);
    }
  };

  const onDelete = async (id: string) => {
    setError(null);
    const prev = comments;
    setComments((cur) => (cur ?? []).filter((c) => c.id !== id));
    try {
      await deleteFindingComment(fingerprint, id);
    } catch (e) {
      setComments(prev);
      setError(e instanceof Error ? e.message : "Failed to delete comment");
    }
  };

  return (
    <div className="rounded-md border border-border bg-card p-3 space-y-2">
      <p className="text-[0.6875rem] uppercase tracking-wider text-muted">
        Comments
        {comments && comments.length > 0 && (
          <span className="ml-1.5 text-muted/70 tabular-nums">({comments.length})</span>
        )}
      </p>

      {loading && (
        <p className="text-[0.6875rem] text-muted">Loading…</p>
      )}

      {!loading && comments && comments.length === 0 && (
        <p className="text-[0.6875rem] text-muted italic">
          No comments yet — add the first.
        </p>
      )}

      {!loading && comments && comments.length > 0 && (
        <ul className="space-y-1.5">
          {comments.map((c) => (
            <li
              key={c.id}
              className="group/c relative rounded-md border border-border bg-surface-2 px-2 py-1.5"
            >
              <div className="flex items-center justify-between gap-2 mb-0.5">
                <p className="text-[0.6875rem] text-muted truncate">
                  <span className="text-foreground">{c.author ?? "anonymous"}</span>
                  <span className="mx-1">·</span>
                  <RelativeTime
                    iso={c.created_at}
                    title={new Date(c.created_at).toLocaleString()}
                  />
                </p>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    void onDelete(c.id);
                  }}
                  className="opacity-0 group-hover/c:opacity-100 focus-visible:opacity-100 text-muted hover:text-sev-critical transition-opacity"
                  aria-label="Delete comment"
                  title="Delete comment"
                >
                  <X size={12} strokeWidth={1.5} />
                </button>
              </div>
              <p className="text-xs text-foreground leading-snug whitespace-pre-wrap break-words">
                {c.text}
              </p>
            </li>
          ))}
        </ul>
      )}

      <div className="space-y-1.5">
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onClick={(e) => e.stopPropagation()}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
              e.preventDefault();
              void onSend();
            }
          }}
          rows={2}
          placeholder="Add comment…"
          className="w-full resize-none bg-surface-2 border border-border rounded-md px-2 py-1.5 text-xs text-foreground placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-ring/50"
          disabled={submitting}
        />
        <div className="flex items-center justify-between gap-2">
          {error ? (
            <p className="text-[0.6875rem] text-sev-critical truncate" role="alert">
              {error}
            </p>
          ) : (
            <span />
          )}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              void onSend();
            }}
            disabled={submitting || draft.trim().length === 0}
            className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium border border-border bg-surface-2 text-foreground hover:border-border-strong disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {submitting ? "Sending…" : "Send"}
          </button>
        </div>
      </div>
    </div>
  );
}
