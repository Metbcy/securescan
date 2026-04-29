"use client";

import {
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  AlertTriangle,
  ArrowLeftRight,
  Calendar,
  Equal,
  FileText,
  Hash,
  Loader2,
  Minus,
  Plus,
  ShieldCheck,
} from "lucide-react";
import type { CompareResult, Finding, Scan } from "@/lib/api";
import { compareScans, fetchScans } from "@/lib/api";

// ──────────────────────────────────────────────────────────────────────────────
// Inline page header (DSH3 primitive not yet on origin/main).
// ──────────────────────────────────────────────────────────────────────────────

function PageHeader({
  title,
  meta,
  actions,
}: {
  title: string;
  meta: string;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between md:gap-6">
      <div className="space-y-1.5 min-w-0">
        <h1 className="text-3xl font-semibold tracking-tight text-foreground-strong leading-tight">
          {title}
        </h1>
        <p className="text-sm text-muted max-w-prose leading-relaxed">{meta}</p>
      </div>
      {actions ? (
        <div className="flex shrink-0 items-center gap-2">{actions}</div>
      ) : null}
    </header>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Severity tokens.
// ──────────────────────────────────────────────────────────────────────────────

const SEV_PILL: Record<Finding["severity"], string> = {
  critical: "bg-sev-critical-bg text-sev-critical",
  high: "bg-sev-high-bg text-sev-high",
  medium: "bg-sev-medium-bg text-sev-medium",
  low: "bg-sev-low-bg text-sev-low",
  info: "bg-sev-info-bg text-sev-info",
};

const SEV_ORDER: Record<Finding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function SeverityPill({ severity }: { severity: Finding["severity"] }) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[0.6875rem] font-medium leading-none capitalize ${SEV_PILL[severity]}`}
    >
      <span aria-hidden>●</span>
      {severity}
    </span>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Scan picker card.
// ──────────────────────────────────────────────────────────────────────────────

function statusToken(status: Scan["status"]): string {
  switch (status) {
    case "completed":
      return "bg-accent-soft text-accent";
    case "running":
    case "pending":
      return "bg-surface-2 text-muted";
    case "failed":
      return "bg-sev-critical-bg text-sev-critical";
    case "cancelled":
      return "bg-surface-2 text-muted";
    default:
      return "bg-surface-2 text-muted";
  }
}

function formatDate(scan: Scan): string {
  const ts = scan.completed_at ?? scan.started_at;
  if (!ts) return "—";
  return new Date(ts).toLocaleString();
}

function ScanPickerCard({
  label,
  value,
  onChange,
  scans,
  loading,
  otherValue,
}: {
  label: string;
  value: string;
  onChange: (id: string) => void;
  scans: Scan[];
  loading: boolean;
  otherValue: string;
}) {
  const selected = scans.find((s) => s.id === value);

  return (
    <div className="rounded-md border border-border bg-card p-5 space-y-4 min-w-0">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-medium text-muted uppercase tracking-wider">
          {label}
        </span>
        {selected && (
          <span
            className={`inline-flex items-center px-1.5 py-0.5 rounded text-[0.6875rem] font-medium uppercase tracking-wider ${statusToken(selected.status)}`}
          >
            {selected.status}
          </span>
        )}
      </div>

      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={loading}
        className="w-full h-9 px-3 rounded-md border border-border bg-surface-2 text-sm text-foreground focus:outline-none focus:border-border-strong focus:ring-2 focus:ring-ring transition-colors disabled:opacity-60"
      >
        <option value="">
          {loading ? "Loading scans…" : "Select a scan…"}
        </option>
        {scans.map((s) => {
          const ts = s.completed_at ?? s.started_at;
          const date = ts ? new Date(ts).toLocaleDateString() : "pending";
          const tail = s.target_path.split("/").slice(-2).join("/") ||
            s.target_path;
          const disabled = s.id === otherValue;
          return (
            <option key={s.id} value={s.id} disabled={disabled}>
              {date} — {tail} ({s.findings_count})
              {disabled ? " · already chosen" : ""}
            </option>
          );
        })}
      </select>

      {selected ? (
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-2 text-xs">
          <dt className="flex items-center gap-1.5 text-muted">
            <FileText size={12} />
            Target
          </dt>
          <dd
            className="font-mono text-foreground-strong truncate"
            title={selected.target_path}
          >
            {selected.target_path}
          </dd>

          <dt className="flex items-center gap-1.5 text-muted">
            <Calendar size={12} />
            Date
          </dt>
          <dd className="text-foreground-strong">{formatDate(selected)}</dd>

          <dt className="flex items-center gap-1.5 text-muted">
            <Hash size={12} />
            Findings
          </dt>
          <dd className="text-foreground-strong tabular-nums">
            {selected.findings_count}
          </dd>

          <dt className="flex items-center gap-1.5 text-muted">
            <ShieldCheck size={12} />
            Scan ID
          </dt>
          <dd
            className="font-mono text-muted truncate text-[0.6875rem]"
            title={selected.id}
          >
            {selected.id}
          </dd>
        </dl>
      ) : (
        <p className="text-xs text-muted">
          Choose a completed scan to populate target, date, and finding count.
        </p>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Diff summary chip strip.
// ──────────────────────────────────────────────────────────────────────────────

function SummaryChips({ summary }: { summary: CompareResult["summary"] }) {
  const items: {
    key: string;
    icon: ReactNode;
    label: string;
    count: number;
    className: string;
  }[] = [
    {
      key: "added",
      icon: <Plus size={12} strokeWidth={2.5} />,
      label: "added",
      count: summary.new_count,
      className: "bg-sev-critical-bg text-sev-critical",
    },
    {
      key: "removed",
      icon: <Minus size={12} strokeWidth={2.5} />,
      label: "removed",
      count: summary.fixed_count,
      className: "bg-accent-soft text-accent",
    },
    {
      key: "unchanged",
      icon: <Equal size={12} strokeWidth={2.5} />,
      label: "unchanged",
      count: summary.unchanged_count,
      className: "bg-surface-2 text-muted",
    },
  ];

  return (
    <div className="flex flex-wrap items-center gap-2">
      {items.map((it) => (
        <span
          key={it.key}
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium ${it.className}`}
        >
          {it.icon}
          <span className="tabular-nums font-semibold">{it.count}</span>
          <span className="text-muted/0">·</span>
          <span>{it.label}</span>
        </span>
      ))}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Diff findings table — shared shape between tabs, but the leftmost column
// changes meaning per row's diff state.
// ──────────────────────────────────────────────────────────────────────────────

type DiffState = "added" | "removed" | "unchanged";

interface DiffRow {
  finding: Finding;
  state: DiffState;
}

function DiffMarker({ state }: { state: DiffState }) {
  if (state === "added") {
    return (
      <span
        aria-label="new"
        className="inline-flex items-center justify-center w-5 h-5 rounded bg-sev-critical-bg text-sev-critical"
      >
        <Plus size={12} strokeWidth={2.5} />
      </span>
    );
  }
  if (state === "removed") {
    return (
      <span
        aria-label="resolved"
        className="inline-flex items-center justify-center w-5 h-5 rounded bg-accent-soft text-accent"
      >
        <Minus size={12} strokeWidth={2.5} />
      </span>
    );
  }
  return (
    <span
      aria-label="unchanged"
      className="inline-flex items-center justify-center w-5 h-5 rounded bg-surface-2 text-muted"
    >
      <Equal size={12} strokeWidth={2} />
    </span>
  );
}

function DiffTable({
  rows,
  emptyTitle,
  emptyHint,
}: {
  rows: DiffRow[];
  emptyTitle: string;
  emptyHint: string;
}) {
  const sorted = useMemo(() => {
    const copy = [...rows];
    copy.sort((a, b) => {
      const sa = SEV_ORDER[a.finding.severity] ?? 99;
      const sb = SEV_ORDER[b.finding.severity] ?? 99;
      if (sa !== sb) return sa - sb;
      return (a.finding.title ?? "").localeCompare(b.finding.title ?? "");
    });
    return copy;
  }, [rows]);

  if (sorted.length === 0) {
    return (
      <div className="rounded-md border border-border bg-card px-4 py-12 text-center">
        <p className="text-sm font-medium text-foreground-strong">
          {emptyTitle}
        </p>
        <p className="text-xs text-muted mt-1">{emptyHint}</p>
      </div>
    );
  }

  return (
    <div className="rounded-md border border-border bg-card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-surface-2 border-b border-border">
            <tr>
              <th className="px-4 py-2.5 w-10" aria-label="diff status" />
              <th className="px-4 py-2.5 text-left text-xs font-medium text-muted uppercase tracking-wider w-[110px]">
                Severity
              </th>
              <th className="px-4 py-2.5 text-left text-xs font-medium text-muted uppercase tracking-wider w-[140px]">
                Scanner
              </th>
              <th className="px-4 py-2.5 text-left text-xs font-medium text-muted uppercase tracking-wider">
                Title
              </th>
              <th className="px-4 py-2.5 text-left text-xs font-medium text-muted uppercase tracking-wider w-[36ch]">
                File
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.map(({ finding, state }) => (
              <tr
                key={`${state}-${finding.id}`}
                className={`border-b border-border/60 last:border-0 transition-colors ${
                  state === "added"
                    ? "hover:bg-sev-critical-bg/40"
                    : state === "removed"
                    ? "hover:bg-accent-soft/40"
                    : "hover:bg-surface-2/50"
                }`}
              >
                <td className="px-4 py-2 align-top">
                  <DiffMarker state={state} />
                </td>
                <td className="px-4 py-2 align-top">
                  <SeverityPill severity={finding.severity} />
                </td>
                <td className="px-4 py-2 font-mono text-xs text-muted align-top">
                  {finding.scanner}
                </td>
                <td className="px-4 py-2 align-top">
                  <div
                    className={`text-sm leading-snug ${
                      state === "removed"
                        ? "text-muted line-through decoration-muted/60"
                        : "text-foreground-strong"
                    }`}
                  >
                    {finding.title}
                  </div>
                  {finding.rule_id && (
                    <div className="text-[0.6875rem] font-mono text-muted mt-0.5">
                      {finding.rule_id}
                    </div>
                  )}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-muted align-top">
                  {finding.file_path ? (
                    <span className="truncate inline-block max-w-[36ch] align-bottom" title={`${finding.file_path}${finding.line_start ? `:${finding.line_start}` : ""}`}>
                      {finding.file_path}
                      {finding.line_start ? (
                        <span className="text-muted">:{finding.line_start}</span>
                      ) : null}
                    </span>
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Page.
// ──────────────────────────────────────────────────────────────────────────────

type DiffTab = "all" | "new" | "resolved" | "unchanged";

export default function ComparePage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [scansLoading, setScansLoading] = useState(true);
  const [scansError, setScansError] = useState<string | null>(null);

  const [scanAId, setScanAId] = useState("");
  const [scanBId, setScanBId] = useState("");

  const [result, setResult] = useState<CompareResult | null>(null);
  const [comparing, setComparing] = useState(false);
  const [compareError, setCompareError] = useState<string | null>(null);

  const [tab, setTab] = useState<DiffTab>("all");

  useEffect(() => {
    let cancelled = false;
    fetchScans()
      .then((data) => {
        if (cancelled) return;
        setScans(data.filter((s) => s.status === "completed"));
      })
      .catch(() => {
        if (cancelled) return;
        setScansError(
          "Failed to load scans. Is the backend running on /api/v1?",
        );
      })
      .finally(() => {
        if (cancelled) return;
        setScansLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const canCompare =
    !!scanAId && !!scanBId && scanAId !== scanBId && !comparing;

  async function handleCompare() {
    if (!canCompare) return;
    setComparing(true);
    setCompareError(null);
    setResult(null);
    try {
      const data = await compareScans(scanAId, scanBId);
      setResult(data);
      setTab("all");
    } catch {
      setCompareError(
        "Failed to compare scans. Make sure both are completed scans on the same target.",
      );
    } finally {
      setComparing(false);
    }
  }

  function handleSwap() {
    setScanAId(scanBId);
    setScanBId(scanAId);
    setResult(null);
  }

  // Build the unified diff row list for whichever tab is active.
  const allRows: DiffRow[] = useMemo(() => {
    if (!result) return [];
    return [
      ...result.new_findings.map<DiffRow>((f) => ({
        finding: f,
        state: "added",
      })),
      ...result.fixed_findings.map<DiffRow>((f) => ({
        finding: f,
        state: "removed",
      })),
      ...result.unchanged_findings.map<DiffRow>((f) => ({
        finding: f,
        state: "unchanged",
      })),
    ];
  }, [result]);

  const visibleRows = useMemo(() => {
    if (!result) return [];
    if (tab === "all") return allRows;
    if (tab === "new") return allRows.filter((r) => r.state === "added");
    if (tab === "resolved") return allRows.filter((r) => r.state === "removed");
    return allRows.filter((r) => r.state === "unchanged");
  }, [tab, allRows, result]);

  const emptyCopy: Record<DiffTab, { title: string; hint: string }> = {
    all: {
      title: "No findings on either side",
      hint: "Both scans came back clean — nothing to diff.",
    },
    new: {
      title: "No new findings",
      hint: "Nothing regressed between the baseline and the latest scan.",
    },
    resolved: {
      title: "Nothing resolved",
      hint: "No prior findings dropped off in the latest scan.",
    },
    unchanged: {
      title: "Nothing unchanged",
      hint: "Every finding on either side either appeared or disappeared.",
    },
  };

  const tabs: { key: DiffTab; label: string; count: number | null }[] = result
    ? [
        { key: "all", label: "All", count: allRows.length },
        { key: "new", label: "New findings", count: result.summary.new_count },
        {
          key: "resolved",
          label: "Resolved",
          count: result.summary.fixed_count,
        },
        {
          key: "unchanged",
          label: "Unchanged",
          count: result.summary.unchanged_count,
        },
      ]
    : [];

  return (
    <div className="space-y-6 max-w-6xl">
      <PageHeader
        title="Compare scans"
        meta="Side-by-side diff of two scans on the same target. Useful before merging a PR."
      />

      {/* Selectors */}
      <section className="space-y-4">
        {scansError && (
          <div
            role="alert"
            className="flex items-start gap-2 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
          >
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>{scansError}</span>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr] gap-4 md:items-stretch">
          <ScanPickerCard
            label="Baseline scan"
            value={scanAId}
            onChange={setScanAId}
            scans={scans}
            loading={scansLoading}
            otherValue={scanBId}
          />
          <div className="flex md:flex-col items-center justify-center gap-2">
            <button
              type="button"
              onClick={handleSwap}
              disabled={!scanAId && !scanBId}
              className="inline-flex items-center gap-1.5 h-9 px-3 rounded-md border border-border bg-surface-2 text-foreground-strong text-xs font-medium hover:bg-border transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              title="Swap baseline and latest"
            >
              <ArrowLeftRight size={14} />
              Swap
            </button>
          </div>
          <ScanPickerCard
            label="Latest scan"
            value={scanBId}
            onChange={setScanBId}
            scans={scans}
            loading={scansLoading}
            otherValue={scanAId}
          />
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleCompare}
            disabled={!canCompare}
            className="inline-flex items-center gap-2 h-9 px-4 rounded-md bg-accent text-accent-foreground text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {comparing ? (
              <>
                <Loader2 size={14} className="animate-spin" />
                Comparing…
              </>
            ) : (
              <>
                <ArrowLeftRight size={14} />
                Compare
              </>
            )}
          </button>
          {scanAId && scanBId && scanAId === scanBId && (
            <span className="text-xs text-muted">
              Pick two different scans to compare.
            </span>
          )}
        </div>

        {compareError && (
          <div
            role="alert"
            className="flex items-start gap-2 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
          >
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>{compareError}</span>
          </div>
        )}
      </section>

      {/* Result */}
      {result && (
        <section className="space-y-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <SummaryChips summary={result.summary} />
            <p className="text-xs text-muted">
              Risk delta:{" "}
              <span
                className={`tabular-nums font-semibold ${
                  result.summary.risk_delta > 0
                    ? "text-sev-critical"
                    : result.summary.risk_delta < 0
                    ? "text-accent"
                    : "text-foreground-strong"
                }`}
              >
                {result.summary.risk_delta > 0 ? "+" : ""}
                {result.summary.risk_delta}
              </span>
            </p>
          </div>

          {/* Tabs */}
          <div className="border-b border-border">
            <div
              role="tablist"
              aria-label="Diff filter"
              className="flex gap-1 -mb-px"
            >
              {tabs.map((t) => (
                <button
                  key={t.key}
                  role="tab"
                  aria-selected={tab === t.key}
                  onClick={() => setTab(t.key)}
                  className={`inline-flex items-center gap-2 px-3 h-9 text-xs font-medium border-b-2 transition-colors ${
                    tab === t.key
                      ? "border-accent text-foreground-strong"
                      : "border-transparent text-muted hover:text-foreground-strong"
                  }`}
                >
                  {t.label}
                  {t.count != null && (
                    <span
                      className={`tabular-nums px-1.5 py-0.5 rounded text-[0.6875rem] font-medium ${
                        tab === t.key
                          ? "bg-accent-soft text-accent"
                          : "bg-surface-2 text-muted"
                      }`}
                    >
                      {t.count}
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>

          <DiffTable
            rows={visibleRows}
            emptyTitle={emptyCopy[tab].title}
            emptyHint={emptyCopy[tab].hint}
          />
        </section>
      )}
    </div>
  );
}
