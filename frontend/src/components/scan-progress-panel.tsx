import { CheckCircle2, MinusCircle, XCircle } from "lucide-react";
import { SeverityPillStrip } from "./severity-pill-strip";
import type { ScanSummary } from "@/lib/api";

export type ScannerProgressState =
  | "queued"
  | "running"
  | "complete"
  | "failed"
  | "skipped";

export interface ScannerProgress {
  state: ScannerProgressState;
  duration_s?: number;
  findings_count?: number;
  reason?: string;
  error?: string;
}

interface ScanProgressPanelProps {
  scanners: Record<string, ScannerProgress>;
  totalScanners?: number;
  /** Wall-clock duration string ("0:42") rendered in the panel header. */
  duration?: string;
  /** Pre-derived severity counts; rendered as a pill strip in the
   * footer when ``findings > 0``. */
  partialSummary?: ScanSummary | null;
  /** Total partial findings count. */
  partialFindings?: number;
}

function StateDot({ state }: { state: ScannerProgressState }) {
  switch (state) {
    case "running":
      return (
        <span
          aria-label="running"
          className="relative inline-flex h-2.5 w-2.5 shrink-0"
        >
          <span className="absolute inset-0 rounded-full bg-accent animate-ping opacity-60" />
          <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-accent" />
        </span>
      );
    case "complete":
      return (
        <CheckCircle2
          size={12}
          strokeWidth={1.75}
          className="text-accent shrink-0"
          aria-label="complete"
        />
      );
    case "failed":
      return (
        <XCircle
          size={12}
          strokeWidth={1.75}
          className="text-sev-critical shrink-0"
          aria-label="failed"
        />
      );
    case "skipped":
      return (
        <MinusCircle
          size={12}
          strokeWidth={1.75}
          className="text-muted shrink-0"
          aria-label="skipped"
        />
      );
    case "queued":
    default:
      return (
        <span
          aria-label="queued"
          className="inline-block h-2.5 w-2.5 shrink-0 rounded-full border border-border-strong"
        />
      );
  }
}

export function ScanProgressPanel({
  scanners,
  totalScanners,
  duration,
  partialSummary,
  partialFindings,
}: ScanProgressPanelProps) {
  const entries = Object.entries(scanners);
  const completed = entries.filter(
    ([, s]) =>
      s.state === "complete" || s.state === "skipped" || s.state === "failed",
  ).length;
  const total = totalScanners ?? entries.length;
  const showFindings = (partialFindings ?? 0) > 0;

  return (
    <div className="rounded-md border border-border bg-card p-3 mb-4">
      <div className="flex items-center justify-between mb-2 gap-2 flex-wrap">
        <span className="text-sm font-medium">
          Live progress · <span className="tabular-nums">{completed}</span>/
          <span className="tabular-nums">{total}</span> scanners
        </span>
        <span className="inline-flex items-center gap-3 text-xs text-muted">
          {duration && (
            <span className="tabular-nums">{duration} elapsed</span>
          )}
          <span className="inline-flex items-center gap-1.5">
            <span
              aria-hidden
              className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse"
            />
            streaming events
          </span>
        </span>
      </div>
      {entries.length === 0 ? (
        <p className="text-xs text-muted">Waiting for first scanner…</p>
      ) : (
        <ul className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-x-3 gap-y-1.5">
          {entries.map(([name, prog]) => (
            <li
              key={name}
              className="flex items-center gap-2 text-xs"
              title={
                prog.state === "failed" && prog.error
                  ? prog.error
                  : prog.state === "skipped" && prog.reason
                    ? prog.reason
                    : undefined
              }
            >
              <StateDot state={prog.state} />
              <span className="font-mono truncate">{name}</span>
              {prog.findings_count !== undefined && (
                <span className="text-muted tabular-nums">
                  · {prog.findings_count}
                </span>
              )}
              {prog.duration_s !== undefined && (
                <span className="text-muted ml-auto tabular-nums">
                  {prog.duration_s.toFixed(1)}s
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      {showFindings && partialSummary && (
        <div className="mt-3 pt-3 border-t border-border flex items-center justify-between gap-3 flex-wrap">
          <span className="text-xs text-muted">
            <span className="tabular-nums text-foreground">{partialFindings}</span> partial finding{partialFindings === 1 ? "" : "s"} so far
          </span>
          <SeverityPillStrip counts={partialSummary} size="xs" />
        </div>
      )}
    </div>
  );
}
