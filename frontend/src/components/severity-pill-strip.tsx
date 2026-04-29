type Counts = {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
};

const ORDER: (keyof Counts)[] = ["critical", "high", "medium", "low", "info"];

const PILL_BG: Record<keyof Counts, string> = {
  critical: "bg-sev-critical-bg text-sev-critical",
  high: "bg-sev-high-bg text-sev-high",
  medium: "bg-sev-medium-bg text-sev-medium",
  low: "bg-sev-low-bg text-sev-low",
  info: "bg-sev-info-bg text-sev-info",
};

const DOT_BG: Record<keyof Counts, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

interface SeverityPillStripProps {
  counts: Counts;
  size?: "xs" | "sm";
  showZero?: boolean;
  showLabels?: boolean;
}

export function SeverityPillStrip({
  counts,
  size = "sm",
  showZero = false,
  showLabels = false,
}: SeverityPillStripProps) {
  const cls =
    size === "xs"
      ? "text-[0.6875rem] px-1.5 py-0.5"
      : "text-xs px-2 py-0.5";
  const dotSize = size === "xs" ? "w-1 h-1" : "w-1.5 h-1.5";

  const visible = ORDER.filter((k) => (counts[k] ?? 0) > 0 || showZero);

  if (visible.length === 0) {
    return (
      <span className="text-xs text-muted tabular-nums">No findings</span>
    );
  }

  return (
    <div className="inline-flex flex-wrap items-center gap-1">
      {visible.map((k) => {
        const v = counts[k] ?? 0;
        return (
          <span
            key={k}
            className={`inline-flex items-center gap-1 rounded-md font-medium tabular-nums ${PILL_BG[k]} ${cls}`}
          >
            <span
              className={`${dotSize} rounded-full ${DOT_BG[k]}`}
              aria-hidden
            />
            {v}
            {showLabels && <span className="font-normal opacity-80">{k}</span>}
          </span>
        );
      })}
    </div>
  );
}
