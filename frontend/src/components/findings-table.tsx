"use client";

import { Fragment, useState } from "react";
import { ChevronDown, ChevronRight, FileCode } from "lucide-react";
import type { Finding } from "@/lib/api";

interface FindingsTableProps {
  findings: Finding[];
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/20",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/20",
  info: "bg-zinc-500/15 text-zinc-400 border-zinc-500/20",
};

type SuppressionReason = "inline" | "config" | "baseline";

const SUPPRESSION_REASONS: readonly SuppressionReason[] = ["inline", "config", "baseline"];

const SUPPRESSION_COLORS: Record<SuppressionReason, string> = {
  inline: "bg-cyan-500/15 text-cyan-400 border-cyan-500/20",
  config: "bg-violet-500/15 text-violet-400 border-violet-500/20",
  baseline: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

function getSuppressedBy(metadata: Record<string, unknown> | undefined | null): SuppressionReason | null {
  if (!metadata) return null;
  const raw = metadata["suppressed_by"];
  if (typeof raw !== "string") return null;
  return (SUPPRESSION_REASONS as readonly string[]).includes(raw) ? (raw as SuppressionReason) : null;
}

function getOriginalSeverity(metadata: Record<string, unknown> | undefined | null): string | null {
  if (!metadata) return null;
  const raw = metadata["original_severity"];
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

export function FindingsTable({ findings }: FindingsTableProps) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [showSuppressed, setShowSuppressed] = useState(false);

  const suppressedCount = findings.reduce(
    (n, f) => (getSuppressedBy(f.metadata) ? n + 1 : n),
    0
  );

  const visible = showSuppressed
    ? findings
    : findings.filter((f) => getSuppressedBy(f.metadata) === null);

  const sorted = [...visible].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
  );

  const toggle = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-[#52525b]">
        <FileCode size={40} className="mb-3" />
        <p className="text-sm">No findings to display</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {suppressedCount > 0 && (
        <label className="flex items-center gap-2 text-xs text-[#a1a1aa] select-none cursor-pointer w-fit">
          <input
            type="checkbox"
            checked={showSuppressed}
            onChange={(e) => setShowSuppressed(e.target.checked)}
            className="h-3.5 w-3.5 rounded border-[#404040] bg-[#0e0e0e] accent-cyan-500"
          />
          <span>
            Show suppressed findings{" "}
            <span className="text-[#52525b]">
              ({suppressedCount} hidden by default)
            </span>
          </span>
        </label>
      )}
      <div className="overflow-x-auto rounded-lg border border-[#262626]">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[#262626] text-left text-xs text-[#a1a1aa] uppercase tracking-wider">
              <th className="px-4 py-3 w-8" />
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Scanner</th>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3">File</th>
              <th className="px-4 py-3">Line</th>
              <th className="px-4 py-3">Compliance</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f) => {
              const expanded = expandedIds.has(f.id);
              const suppressedBy = getSuppressedBy(f.metadata);
              const originalSeverity = getOriginalSeverity(f.metadata);
              const severityChanged =
                originalSeverity !== null &&
                originalSeverity.toLowerCase() !== f.severity.toLowerCase();
              const severityPinned =
                originalSeverity !== null &&
                originalSeverity.toLowerCase() === f.severity.toLowerCase();
              return (
                <Fragment key={f.id}>
                  <tr
                    onClick={() => toggle(f.id)}
                    className={`border-b border-[#1a1a1a] cursor-pointer hover:bg-[#141414] transition-colors ${
                      suppressedBy ? "opacity-60" : ""
                    }`}
                  >
                    <td className="px-4 py-3 text-[#52525b]">
                      {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </td>
                    <td className="px-4 py-3 align-top">
                      <span
                        className={`inline-block px-2.5 py-0.5 rounded-full text-xs font-medium border ${
                          SEVERITY_COLORS[f.severity] ?? ""
                        }`}
                      >
                        {f.severity}
                      </span>
                      {severityChanged && (
                        <div className="mt-1 text-[10px] text-[#52525b] font-mono">
                          (was: {originalSeverity})
                        </div>
                      )}
                      {severityPinned && (
                        <div className="mt-1 text-[10px] text-[#52525b] font-mono">
                          (pinned)
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 text-[#a1a1aa] align-top">{f.scanner}</td>
                    <td className="px-4 py-3 font-medium max-w-xs align-top">
                      <div className="flex items-start gap-2">
                        <span className="truncate">{f.title}</span>
                        {suppressedBy && (
                          <span
                            className={`inline-block shrink-0 px-1.5 py-0.5 rounded text-[10px] font-mono font-medium border ${SUPPRESSION_COLORS[suppressedBy]}`}
                            title={`Suppressed by ${suppressedBy}`}
                          >
                            [SUPPRESSED:{suppressedBy}]
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-[#a1a1aa] font-mono text-xs max-w-[200px] truncate align-top">
                      {f.file_path ?? "—"}
                    </td>
                    <td className="px-4 py-3 text-[#a1a1aa] font-mono text-xs align-top">
                      {f.line_start != null ? f.line_start : "—"}
                    </td>
                    <td className="px-4 py-3 align-top">
                      <div className="flex flex-wrap gap-1">
                        {f.compliance_tags?.map((tag) => (
                          <span
                            key={tag}
                            className="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-500/15 text-blue-400 border border-blue-500/20"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                  {expanded && (
                    <tr className="bg-[#0e0e0e]">
                      <td colSpan={7} className="px-6 py-4">
                        <div className="space-y-3 text-sm">
                          {f.description && (
                            <div>
                              <p className="text-xs text-[#52525b] uppercase tracking-wider mb-1">
                                Description
                              </p>
                              <p className="text-[#a1a1aa] leading-relaxed">{f.description}</p>
                            </div>
                          )}
                          {f.remediation && (
                            <div>
                              <p className="text-xs text-[#52525b] uppercase tracking-wider mb-1">
                                Remediation
                              </p>
                              <p className="text-[#a1a1aa] leading-relaxed">{f.remediation}</p>
                            </div>
                          )}
                          {f.cwe && (
                            <p className="text-xs text-[#52525b]">
                              CWE: <span className="text-[#a1a1aa]">{f.cwe}</span>
                            </p>
                          )}
                          {f.rule_id && (
                            <p className="text-xs text-[#52525b]">
                              Rule: <span className="text-[#a1a1aa]">{f.rule_id}</span>
                            </p>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
