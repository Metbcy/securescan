"use client";

import { ChevronRight, ChevronDown } from "lucide-react";
import type { Finding } from "@/lib/api";
import { severityEdgeClass, type Severity } from "@/components/severity-edge";

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

interface FindingRowProps {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
  colSpan: number;
}

export function FindingRow({ finding, expanded, onToggle, colSpan }: FindingRowProps) {
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
              } ${suppressedBy ? "line-through" : ""}`}
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
            <div className="space-y-4 text-sm max-w-[80ch]">
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
          </td>
        </tr>
      )}
    </>
  );
}
