import { CheckCircle, Loader2, MinusCircle } from "lucide-react";

export interface ScannerSkipChip {
  name: string;
  reason: string;
  install_hint?: string | null;
}

interface ScannerChipStripProps {
  ran: string[];
  skipped?: ScannerSkipChip[];
  /** Names of scanners currently running (rendered with a spinner instead of a check). */
  running?: string[];
}

export function ScannerChipStrip({ ran, skipped, running }: ScannerChipStripProps) {
  const runningSet = new Set(running ?? []);

  if (ran.length === 0 && (!skipped || skipped.length === 0) && runningSet.size === 0) {
    return null;
  }

  return (
    <div className="flex flex-wrap gap-1.5">
      {ran.map((s) => {
        const isRunning = runningSet.has(s);
        return (
          <span
            key={`ran-${s}`}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-accent-soft text-accent text-xs font-medium"
            title={isRunning ? `${s} — running` : `${s} — completed`}
          >
            {isRunning ? (
              <Loader2 size={12} strokeWidth={1.5} className="animate-spin" />
            ) : (
              <CheckCircle size={12} strokeWidth={1.5} />
            )}
            <span className="font-mono">{s}</span>
          </span>
        );
      })}
      {/* Scanners that are running but not yet in `ran` (still emitting partial findings). */}
      {Array.from(runningSet)
        .filter((s) => !ran.includes(s))
        .map((s) => (
          <span
            key={`running-${s}`}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-accent-soft text-accent text-xs font-medium"
            title={`${s} — running`}
          >
            <Loader2 size={12} strokeWidth={1.5} className="animate-spin" />
            <span className="font-mono">{s}</span>
          </span>
        ))}
      {(skipped ?? []).map((s) => (
        <span
          key={`skipped-${s.name}`}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-surface-2 text-muted text-xs font-medium border border-border"
          title={s.install_hint ? `${s.reason} — ${s.install_hint}` : s.reason}
        >
          <MinusCircle size={12} strokeWidth={1.5} />
          <span className="font-mono">{s.name}</span>
          <span className="text-[0.6875rem] text-muted/70">· {s.reason}</span>
        </span>
      ))}
    </div>
  );
}
