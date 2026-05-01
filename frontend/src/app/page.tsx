"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ScanSearch,
  Plus,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  Clock,
  StopCircle,
} from "lucide-react";
import { PageHeader, StatLine } from "@/components/page-header";
import { SeverityPillStrip } from "@/components/severity-pill-strip";
import { RiskScore } from "@/components/risk-score";
import { SeverityChart } from "@/components/severity-chart";
import { TrendChart } from "@/components/trend-chart";
import { FindingsTable } from "@/components/findings-table";
import type {
  DashboardStats,
  Scan,
  ScanSummary,
  Finding,
  TrendPoint,
  ComplianceCoverage,
} from "@/lib/api";
import {
  fetchDashboardStats,
  fetchScans,
  fetchScanSummary,
  fetchFindings,
  fetchTrends,
  fetchComplianceCoverage,
} from "@/lib/api";

// ---------- helpers ----------

function relativeTime(iso?: string): string {
  if (!iso) return "never";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "never";
  const diff = Date.now() - t;
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  const mo = Math.floor(day / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(mo / 12)}y ago`;
}

function shortDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

const STATUS_TONE: Record<
  Scan["status"],
  { dot: string; text: string; bg: string; Icon: React.ElementType; spin?: boolean }
> = {
  completed: {
    dot: "bg-accent",
    text: "text-accent",
    bg: "bg-accent-soft",
    Icon: CheckCircle2,
  },
  running: {
    dot: "bg-sev-low",
    text: "text-sev-low",
    bg: "bg-sev-low-bg",
    Icon: Loader2,
    spin: true,
  },
  pending: {
    dot: "bg-sev-info",
    text: "text-sev-info",
    bg: "bg-sev-info-bg",
    Icon: Clock,
  },
  failed: {
    dot: "bg-sev-critical",
    text: "text-sev-critical",
    bg: "bg-sev-critical-bg",
    Icon: XCircle,
  },
  cancelled: {
    dot: "bg-sev-medium",
    text: "text-sev-medium",
    bg: "bg-sev-medium-bg",
    Icon: StopCircle,
  },
};

function StatusBadge({ status }: { status: Scan["status"] }) {
  const tone = STATUS_TONE[status] ?? STATUS_TONE.pending;
  const Icon = tone.Icon;
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-medium ${tone.bg} ${tone.text}`}
    >
      <Icon size={12} className={tone.spin ? "animate-spin" : ""} strokeWidth={1.75} />
      {status}
    </span>
  );
}

function Sparkline({
  values,
  height = 28,
  width = 96,
}: {
  values: number[];
  height?: number;
  width?: number;
}) {
  if (values.length < 2) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const stepX = width / (values.length - 1);
  const path = values
    .map((v, i) => {
      const x = i * stepX;
      const y = height - ((v - min) / span) * (height - 2) - 1;
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="inline-block align-middle"
      aria-hidden
    >
      <path
        d={path}
        fill="none"
        stroke="var(--accent)"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// ---------- skeletons ----------

function HeaderSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-6 pb-4 border-b border-border">
        <div className="space-y-2">
          <div className="h-8 w-40 rounded bg-surface-2 animate-pulse" />
          <div className="h-4 w-64 rounded bg-surface-2 animate-pulse" />
        </div>
        <div className="flex gap-2">
          <div className="h-9 w-28 rounded-md bg-surface-2 animate-pulse" />
          <div className="h-9 w-24 rounded-md bg-surface-2 animate-pulse" />
        </div>
      </div>
      <div className="flex items-stretch divide-x divide-border border-b border-border">
        {[0, 1, 2].map((i) => (
          <div key={i} className="flex-1 px-5 py-4 first:pl-0 last:pr-0 space-y-2">
            <div className="h-3 w-20 rounded bg-surface-2 animate-pulse" />
            <div className="h-7 w-24 rounded bg-surface-2 animate-pulse" />
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 md:grid-cols-[2fr_3fr] gap-6">
        <div className="h-64 rounded-md border border-border bg-surface animate-pulse" />
        <div className="h-64 rounded-md border border-border bg-surface animate-pulse" />
      </div>
      <div className="space-y-2">
        {[0, 1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className="h-10 rounded-md border border-border bg-surface animate-pulse"
          />
        ))}
      </div>
    </div>
  );
}

// ---------- page ----------

export default function Home() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [latestSummary, setLatestSummary] = useState<ScanSummary | null>(null);
  const [latestFindings, setLatestFindings] = useState<Finding[]>([]);
  const [recentSummaries, setRecentSummaries] = useState<
    Record<string, ScanSummary>
  >({});
  const [trends, setTrends] = useState<TrendPoint[]>([]);
  const [compliance, setCompliance] = useState<ComplianceCoverage[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadTick, setReloadTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [statsData, scansData] = await Promise.all([
          fetchDashboardStats(),
          fetchScans(),
        ]);
        if (cancelled) return;
        setStats(statsData);
        setScans(scansData);

        fetchTrends(30)
          .then((t) => {
            if (!cancelled) setTrends(t);
          })
          .catch(() => {});

        const latest = scansData[0];
        if (latest && latest.status === "completed") {
          const [sum, fin] = await Promise.all([
            fetchScanSummary(latest.id),
            // Overview only renders top 5 findings ("Top findings"
            // panel). Pass limit=5 so we don't ship a multi-MB payload
            // for a 5-row preview — backend returns findings sorted
            // by severity desc, so this is the 5 most-severe.
            fetchFindings(latest.id, { limit: 5 }),
          ]);
          if (cancelled) return;
          setLatestSummary(sum);
          setLatestFindings(fin);
          fetchComplianceCoverage(latest.id)
            .then((c) => {
              if (!cancelled) setCompliance(c);
            })
            .catch(() => {});
        }

        const recent = scansData.slice(0, 5);
        const summaryEntries = await Promise.all(
          recent.map(async (s) => {
            if (s.status !== "completed") return [s.id, null] as const;
            try {
              const sum = await fetchScanSummary(s.id);
              return [s.id, sum] as const;
            } catch {
              return [s.id, null] as const;
            }
          }),
        );
        if (cancelled) return;
        const sumMap: Record<string, ScanSummary> = {};
        for (const [id, sum] of summaryEntries) if (sum) sumMap[id] = sum;
        setRecentSummaries(sumMap);
      } catch {
        if (!cancelled)
          setError(
            "Backend not connected. Make sure the API server is running on port 8000.",
          );
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [reloadTick]);

  const lastScanned = scans[0]?.completed_at ?? scans[0]?.started_at;
  const latestScan = scans[0];

  const totalCounts = useMemo(() => {
    if (!latestSummary) return null;
    return {
      critical: latestSummary.critical,
      high: latestSummary.high,
      medium: latestSummary.medium,
      low: latestSummary.low,
      info: latestSummary.info,
    };
  }, [latestSummary]);

  const sparkValues = useMemo(
    () => trends.map((t) => t.risk_score).filter((n) => Number.isFinite(n)),
    [trends],
  );

  // --- loading ---
  if (loading) return <HeaderSkeleton />;

  // --- error ---
  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Overview" />
        <div className="flex items-center justify-between gap-4 rounded-md border border-sev-critical/40 bg-sev-critical-bg text-sev-critical px-4 py-3 text-sm">
          <span className="flex items-center gap-2">
            <AlertTriangle size={16} strokeWidth={1.75} />
            {error}
          </span>
          <button
            type="button"
            onClick={() => setReloadTick((n) => n + 1)}
            className="px-2.5 py-1 rounded-md border border-sev-critical/40 text-xs font-medium hover:bg-sev-critical/10 transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  // --- empty ---
  if (!stats || stats.total_scans === 0) {
    return (
      <div className="space-y-8">
        <PageHeader title="Overview" />
        <div className="flex flex-col items-center justify-center py-20 text-center max-w-md mx-auto">
          <ScanSearch
            size={24}
            strokeWidth={1.5}
            className="text-muted mb-4"
          />
          <h2 className="text-base font-medium text-foreground-strong mb-2">
            No scans yet
          </h2>
          <p className="text-sm text-muted leading-relaxed mb-6">
            Run your first scan to surface findings from Semgrep, Bandit, Trivy,
            Checkov, and more. SecureScan stores results locally and never
            phones home.
          </p>
          <div className="flex items-center gap-3">
            <Link
              href="/scan"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md bg-accent text-accent-foreground text-sm font-medium hover:opacity-90 transition-opacity"
            >
              <Plus size={14} strokeWidth={1.75} />
              New scan
            </Link>
            <Link
              href="/scanners"
              className="text-sm text-muted hover:text-foreground transition-colors"
            >
              View installed scanners →
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // --- main ---
  return (
    <div className="space-y-8">
      <PageHeader
        title="Overview"
        meta={
          <>
            {stats.total_scans.toLocaleString()} scan
            {stats.total_scans === 1 ? "" : "s"} ·{" "}
            {stats.total_findings.toLocaleString()} finding
            {stats.total_findings === 1 ? "" : "s"} · last scanned{" "}
            {relativeTime(lastScanned)}
          </>
        }
        actions={
          <>
            <Link
              href="/history"
              className="inline-flex items-center px-3 py-2 rounded-md text-sm font-medium text-muted hover:text-foreground hover:bg-surface-2 transition-colors"
            >
              View history
            </Link>
            <Link
              href="/scan"
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-accent text-accent-foreground text-sm font-medium hover:opacity-90 transition-opacity"
            >
              <Plus size={14} strokeWidth={1.75} />
              New scan
            </Link>
          </>
        }
      />

      <StatLine
        items={[
          {
            label: "Total scans",
            value: stats.total_scans.toLocaleString(),
          },
          {
            label: "Total findings",
            value: stats.total_findings.toLocaleString(),
            trail:
              totalCounts &&
              (totalCounts.critical || totalCounts.high) ? (
                <SeverityPillStrip counts={totalCounts} size="xs" />
              ) : null,
          },
          {
            label: "Avg risk score",
            value: Math.round(stats.average_risk_score),
            trail:
              sparkValues.length > 1 ? (
                <Sparkline values={sparkValues} />
              ) : null,
          },
        ]}
      />

      {/* Latest scan */}
      {latestScan && (
        <section className="space-y-3">
          <div className="flex items-end justify-between gap-4">
            <h2 className="text-lg font-semibold text-foreground-strong">
              Latest scan
            </h2>
            <span
              className="text-xs font-mono text-muted truncate max-w-[60%]"
              title={latestScan.target_path}
            >
              {latestScan.target_path}
            </span>
          </div>

          <div className="rounded-md border border-border bg-surface">
            {latestSummary ? (
              <div className="grid grid-cols-1 md:grid-cols-[2fr_3fr] divide-y md:divide-y-0 md:divide-x divide-border">
                {/* Left: 40% */}
                <div className="p-5 space-y-5">
                  <div className="flex items-center gap-5">
                    <RiskScore score={latestSummary.risk_score} size="lg" />
                    <div className="space-y-2 min-w-0">
                      <StatusBadge status={latestScan.status} />
                      <p className="text-xs text-muted">
                        {relativeTime(
                          latestScan.completed_at ?? latestScan.started_at,
                        )}
                      </p>
                    </div>
                  </div>

                  {(latestScan.scanners_run?.length ||
                    latestScan.scanners_skipped?.length) && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium text-muted uppercase tracking-wider">
                        Scanners
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {latestScan.scanners_run?.map((s) => (
                          <span
                            key={s}
                            className="inline-flex items-center gap-1 rounded-md bg-accent-soft text-accent px-1.5 py-0.5 text-[0.6875rem] font-medium"
                          >
                            <CheckCircle2 size={10} strokeWidth={2} />
                            {s}
                          </span>
                        ))}
                        {latestScan.scanners_skipped?.map((s) => (
                          <span
                            key={s.name}
                            className="inline-flex items-center gap-1 rounded-md bg-surface-2 text-muted px-1.5 py-0.5 text-[0.6875rem] font-medium"
                            title={s.reason}
                          >
                            <XCircle size={10} strokeWidth={2} />
                            {s.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div>
                    <SeverityChart
                      critical={latestSummary.critical}
                      high={latestSummary.high}
                      medium={latestSummary.medium}
                      low={latestSummary.low}
                      info={latestSummary.info}
                    />
                  </div>
                </div>

                {/* Right: 60% — top 5 findings */}
                <div className="p-5 space-y-3 min-w-0">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-medium text-muted">
                      Top findings
                    </h3>
                    <span className="text-xs text-muted tabular-nums">
                      {latestSummary.total_findings} total
                    </span>
                  </div>
                  {latestFindings.length === 0 ? (
                    <p className="text-sm text-muted py-6 text-center">
                      No findings — clean scan.
                    </p>
                  ) : (
                    <FindingsTable findings={latestFindings.slice(0, 5)} />
                  )}
                  {latestFindings.length > 5 && (
                    <Link
                      href={`/scan/${latestScan.id}`}
                      className="inline-flex items-center gap-1 text-sm text-accent hover:underline"
                    >
                      View all {latestSummary.total_findings} findings
                      <ArrowRight size={14} strokeWidth={1.75} />
                    </Link>
                  )}
                </div>
              </div>
            ) : (
              <div className="p-5 flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <StatusBadge status={latestScan.status} />
                  <p className="text-sm text-muted">
                    {latestScan.target_path}
                  </p>
                </div>
                <Link
                  href={`/scan/${latestScan.id}`}
                  className="text-sm text-accent hover:underline"
                >
                  Open →
                </Link>
              </div>
            )}
          </div>
        </section>
      )}

      {/* Recent scans */}
      {scans.length > 0 && (
        <section className="space-y-3">
          <div className="flex items-end justify-between gap-4">
            <h2 className="text-lg font-semibold text-foreground-strong">
              Recent scans
            </h2>
            <Link
              href="/history"
              className="text-sm text-muted hover:text-foreground transition-colors"
            >
              History →
            </Link>
          </div>
          <div className="overflow-hidden rounded-md border border-border bg-surface">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs font-medium text-muted uppercase tracking-wider">
                  <th className="px-4 py-2.5 font-medium">Target</th>
                  <th className="px-4 py-2.5 font-medium">Date</th>
                  <th className="px-4 py-2.5 font-medium">Status</th>
                  <th className="px-4 py-2.5 font-medium">Findings</th>
                  <th className="px-4 py-2.5 font-medium">Risk</th>
                  <th className="px-4 py-2.5 w-8" />
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 5).map((s) => {
                  const sum = recentSummaries[s.id];
                  return (
                    <tr
                      key={s.id}
                      className="border-b border-border last:border-0 hover:bg-surface-2 transition-colors"
                    >
                      <td className="px-4 py-2.5 font-mono text-xs text-foreground max-w-[280px]">
                        <Link
                          href={`/scan/${s.id}`}
                          className="block truncate hover:underline"
                          title={s.target_path}
                        >
                          {s.target_path}
                        </Link>
                      </td>
                      <td className="px-4 py-2.5 text-muted whitespace-nowrap">
                        {shortDate(s.completed_at ?? s.started_at)}
                      </td>
                      <td className="px-4 py-2.5">
                        <StatusBadge status={s.status} />
                      </td>
                      <td className="px-4 py-2.5">
                        {sum ? (
                          <SeverityPillStrip
                            counts={{
                              critical: sum.critical,
                              high: sum.high,
                              medium: sum.medium,
                              low: sum.low,
                              info: sum.info,
                            }}
                            size="xs"
                          />
                        ) : (
                          <span className="text-xs text-muted tabular-nums">
                            {s.findings_count ?? 0}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2.5">
                        {s.risk_score != null ? (
                          <RiskScore score={s.risk_score} size="sm" />
                        ) : (
                          <span className="text-xs text-muted">—</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <Link
                          href={`/scan/${s.id}`}
                          className="text-muted hover:text-foreground transition-colors"
                          aria-label={`View scan ${s.id}`}
                        >
                          <ArrowRight size={14} strokeWidth={1.75} />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Compliance coverage */}
      {compliance.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground-strong">
            Compliance coverage
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {compliance.map((c) => {
              const violatedRatio =
                c.total_controls > 0
                  ? c.controls_violated.length / c.total_controls
                  : 0;
              const danger = violatedRatio > 0.5;
              return (
                <div
                  key={c.framework_id}
                  className="rounded-md border border-border bg-surface p-5 space-y-3"
                >
                  <div>
                    <h3 className="text-sm font-medium text-foreground-strong">
                      {c.framework}
                    </h3>
                    <p className="text-xs text-muted">v{c.version}</p>
                  </div>
                  <div className="flex items-baseline gap-1.5">
                    <span
                      className={`text-2xl font-semibold tabular-nums ${
                        danger ? "text-sev-critical" : "text-foreground-strong"
                      }`}
                    >
                      {c.controls_violated.length}
                    </span>
                    <span className="text-xs text-muted">
                      / {c.total_controls} controls violated
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-surface-2 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        danger ? "bg-sev-critical" : "bg-accent"
                      }`}
                      style={{
                        width: `${Math.min(100, Math.max(0, violatedRatio * 100))}%`,
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* Trends */}
      {trends.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground-strong">
            Risk trend
            <span className="ml-2 text-sm font-normal text-muted">
              30 days
            </span>
          </h2>
          <div className="rounded-md border border-border bg-surface p-5">
            <TrendChart data={trends} />
          </div>
        </section>
      )}
    </div>
  );
}
