import { CheckCircle2, MinusCircle, XCircle } from "lucide-react";

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
}: ScanProgressPanelProps) {
  const entries = Object.entries(scanners);
  const completed = entries.filter(
    ([, s]) =>
      s.state === "complete" || s.state === "skipped" || s.state === "failed",
  ).length;
  const total = totalScanners ?? entries.length;

  return (
    <div className="rounded-md border border-border bg-card p-3 mb-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium">
          Live progress · <span className="tabular-nums">{completed}</span>/
          <span className="tabular-nums">{total}</span> scanners
        </span>
        <span className="inline-flex items-center gap-1.5 text-xs text-muted">
          <span
            aria-hidden
            className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse"
          />
          streaming events
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
    </div>
  );
}
