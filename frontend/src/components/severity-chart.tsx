interface SeverityChartProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

type Key = keyof SeverityChartProps;

const ORDER: Key[] = ["critical", "high", "medium", "low", "info"];

const SEG_BG: Record<Key, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const PILL_BG: Record<Key, string> = {
  critical: "bg-sev-critical-bg text-sev-critical",
  high: "bg-sev-high-bg text-sev-high",
  medium: "bg-sev-medium-bg text-sev-medium",
  low: "bg-sev-low-bg text-sev-low",
  info: "bg-sev-info-bg text-sev-info",
};

const DOT_BG: Record<Key, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const LABELS: Record<Key, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export function SeverityChart(props: SeverityChartProps) {
  const total = ORDER.reduce((sum, k) => sum + props[k], 0);

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-medium text-muted">Findings by severity</h3>

      {total === 0 ? (
        <p className="text-sm text-muted">No findings.</p>
      ) : (
        <>
          <div
            className="flex h-2 w-full overflow-hidden rounded-full bg-surface-2"
            role="img"
            aria-label={`${total} findings by severity`}
          >
            {ORDER.map((k) => {
              const v = props[k];
              if (v === 0) return null;
              const pct = (v / total) * 100;
              return (
                <div
                  key={k}
                  className={`${SEG_BG[k]} h-full`}
                  style={{ width: `${pct}%` }}
                  title={`${LABELS[k]}: ${v}`}
                />
              );
            })}
          </div>

          <div className="flex flex-wrap gap-1.5">
            {ORDER.map((k) => {
              const v = props[k];
              if (v === 0) return null;
              return (
                <span
                  key={k}
                  className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium tabular-nums ${PILL_BG[k]}`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${DOT_BG[k]}`}
                    aria-hidden
                  />
                  {v}
                  <span className="font-normal opacity-80">{LABELS[k]}</span>
                </span>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
