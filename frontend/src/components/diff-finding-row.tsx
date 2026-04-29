import Link from "next/link";
import { ChevronRight } from "lucide-react";
import type { Finding } from "@/lib/api";

export type DiffKind = "new" | "resolved" | "unchanged";

interface DiffFindingRowProps {
  finding: Finding;
  kind: DiffKind;
  /** Scan id to deep-link the finding into. For `resolved` rows
   * (no longer present in head) this falls back to the base scan. */
  linkScanId: string;
}

const SYMBOL: Record<DiffKind, string> = {
  new: "+",
  resolved: "−",
  unchanged: "=",
};

const SYMBOL_CLASS: Record<DiffKind, string> = {
  new: "text-sev-critical",
  resolved: "text-accent",
  unchanged: "text-muted",
};

const EDGE_CLASS: Record<DiffKind, string> = {
  new: "bg-sev-critical",
  resolved: "bg-accent",
  unchanged: "bg-border",
};

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const SEVERITY_TEXT: Record<string, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  info: "text-sev-info",
};

function fileLabel(f: Finding): string {
  if (!f.file_path) return "—";
  const path = f.file_path;
  const line = f.line_start ? `:${f.line_start}` : "";
  return `${path}${line}`;
}

export function DiffFindingRow({ finding, kind, linkScanId }: DiffFindingRowProps) {
  const fp = finding.fingerprint || finding.id;
  const href = `/scan/${linkScanId}?finding=${encodeURIComponent(fp)}`;
  const sev = finding.severity;

  return (
    <tr className="group border-b border-border last:border-b-0 hover:bg-surface-2 transition-colors">
      {/* Severity-tinted left edge — 2px column rendered as a styled cell */}
      <td className="p-0 w-1 align-stretch">
        <span
          aria-hidden
          className={`block w-[2px] h-full ${EDGE_CLASS[kind]}`}
        />
      </td>

      {/* +/-/= symbol */}
      <td className="px-3 py-2 w-6 text-center font-mono text-sm font-semibold">
        <span className={SYMBOL_CLASS[kind]} aria-label={kind}>
          {SYMBOL[kind]}
        </span>
      </td>

      {/* Severity */}
      <td className="px-3 py-2 w-28">
        <span className="inline-flex items-center gap-1.5">
          <span
            aria-hidden
            className={`inline-block h-1.5 w-1.5 rounded-full ${SEVERITY_DOT[sev] ?? "bg-muted"}`}
          />
          <span className={`text-2xs uppercase tracking-wider font-medium ${SEVERITY_TEXT[sev] ?? "text-muted"}`}>
            {sev}
          </span>
        </span>
      </td>

      {/* File:line */}
      <td className="px-3 py-2 font-mono text-xs text-muted whitespace-nowrap max-w-[20ch] truncate">
        {fileLabel(finding)}
      </td>

      {/* Message — title + secondary description, truncated */}
      <td className="px-3 py-2 min-w-0">
        <div className="flex flex-col min-w-0">
          <span className="text-sm text-foreground-strong truncate">
            {finding.title}
          </span>
          {finding.rule_id ? (
            <span className="text-2xs text-muted font-mono truncate">
              {finding.rule_id}
            </span>
          ) : null}
        </div>
      </td>

      {/* Scanner */}
      <td className="px-3 py-2 w-28 text-xs text-muted whitespace-nowrap">
        {finding.scanner}
      </td>

      {/* Action — view in head */}
      <td className="px-3 py-2 w-[7.5rem] text-right whitespace-nowrap">
        <Link
          href={href}
          className="inline-flex items-center gap-1 text-xs text-muted hover:text-accent transition-colors"
        >
          View
          <ChevronRight size={14} strokeWidth={1.5} />
        </Link>
      </td>
    </tr>
  );
}
