/*
 * SeverityEdge — 1px left edge accent for table rows.
 *
 * DESIGN.md bans side-stripe accents > 1px. This component honors that
 * default, allowing a momentary `border-l-2` only on hover/focus when the
 * row is being actively interacted with.
 *
 * Use the `severityEdgeClass` helper directly on a <td> for the simplest
 * integration with table layout. The <SeverityEdge /> JSX form is provided
 * for non-table contexts (e.g. card rows) where an absolutely-positioned
 * span is preferred.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

const EDGE_BORDER: Record<Severity, string> = {
  critical: "border-l border-l-sev-critical",
  high: "border-l border-l-sev-high",
  medium: "border-l border-l-sev-medium",
  low: "border-l border-l-sev-low",
  info: "border-l border-l-sev-info",
};

const EDGE_BG: Record<Severity, string> = {
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

export function severityEdgeClass(severity: string): string {
  return EDGE_BORDER[normalize(severity)];
}

export function severityEdgeBg(severity: string): string {
  return EDGE_BG[normalize(severity)];
}

export function SeverityEdge({ severity }: { severity: string }) {
  return (
    <span
      aria-hidden
      className={`pointer-events-none absolute inset-y-0 left-0 w-px ${severityEdgeBg(severity)} group-hover:w-0.5 group-focus-within:w-0.5 transition-[width] duration-150`}
    />
  );
}
