"use client";

import { useMemo, useState } from "react";
import {
  ChevronDown,
  Search,
  ShieldCheck,
  ShieldAlert,
  Filter as FilterIcon,
} from "lucide-react";
import Link from "next/link";
import type { Finding } from "@/lib/api";
import { FindingRow, getSuppressedBy } from "@/components/finding-row";

interface FindingsTableProps {
  findings: Finding[];
  /** Total number of scanners that ran for this scan — used by the empty-state copy. */
  scannersRanCount?: number;
  /** Sticky offset for the filter bar. Defaults to top-14 (matches the topbar). */
  stickyTop?: string;
}

type Severity = "critical" | "high" | "medium" | "low" | "info";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEV_CHIP_ACTIVE: Record<Severity, string> = {
  critical: "bg-sev-critical-bg text-sev-critical border-sev-critical/40",
  high: "bg-sev-high-bg text-sev-high border-sev-high/40",
  medium: "bg-sev-medium-bg text-sev-medium border-sev-medium/40",
  low: "bg-sev-low-bg text-sev-low border-sev-low/40",
  info: "bg-sev-info-bg text-sev-info border-sev-info/40",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

function normalize(severity: string): Severity {
  const s = severity?.toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") {
    return s;
  }
  return "info";
}

const PAGE_SIZES = [10, 25, 50, 100] as const;
type PageSize = (typeof PAGE_SIZES)[number];

export function FindingsTable({
  findings,
  scannersRanCount,
  stickyTop = "top-14",
}: FindingsTableProps) {
  const [query, setQuery] = useState("");
  const [activeSeverities, setActiveSeverities] = useState<Set<Severity>>(new Set());
  const [activeScanner, setActiveScanner] = useState<string>("__all__");
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState<PageSize>(25);

  const totalAll = findings.length;
  const suppressedCount = useMemo(
    () => findings.reduce((n, f) => (getSuppressedBy(f.metadata) ? n + 1 : n), 0),
    [findings],
  );

  const scannerOptions = useMemo(() => {
    const set = new Set<string>();
    for (const f of findings) {
      if (f.scanner) set.add(f.scanner);
    }
    return Array.from(set).sort();
  }, [findings]);

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      if (!showSuppressed && getSuppressedBy(f.metadata)) continue;
      counts[normalize(f.severity)] += 1;
    }
    return counts;
  }, [findings, showSuppressed]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((f) => {
      if (!showSuppressed && getSuppressedBy(f.metadata)) return false;
      if (activeSeverities.size > 0 && !activeSeverities.has(normalize(f.severity))) return false;
      if (activeScanner !== "__all__" && f.scanner !== activeScanner) return false;
      if (q.length > 0) {
        const hay = `${f.title} ${f.description ?? ""} ${f.file_path ?? ""} ${f.scanner}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [findings, query, activeSeverities, activeScanner, showSuppressed]);

  const sorted = useMemo(
    () =>
      [...filtered].sort(
        (a, b) => SEVERITY_RANK[normalize(a.severity)] - SEVERITY_RANK[normalize(b.severity)],
      ),
    [filtered],
  );

  const paginate = sorted.length >= 25;
  const totalPages = paginate ? Math.max(1, Math.ceil(sorted.length / pageSize)) : 1;
  const safePage = Math.min(page, totalPages - 1);
  const visible = paginate
    ? sorted.slice(safePage * pageSize, safePage * pageSize + pageSize)
    : sorted;

  const toggleSeverity = (s: Severity) => {
    setPage(0);
    setActiveSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const clearSeverity = () => {
    setPage(0);
    setActiveSeverities(new Set());
  };

  const toggleExpanded = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Empty state: 0 total findings — distinguished by whether any scanner ran.
  if (totalAll === 0) {
    const noScanners = scannersRanCount === 0;
    return (
      <div className="rounded-md border border-border bg-card">
        <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
          {noScanners ? (
            <ShieldAlert size={32} strokeWidth={1.5} className="text-sev-medium mb-3" />
          ) : (
            <ShieldCheck size={32} strokeWidth={1.5} className="text-accent mb-3" />
          )}
          <h3 className="text-base font-medium text-foreground-strong">
            {noScanners ? "No scanners ran" : "No findings"}
          </h3>
          <p className="mt-1 max-w-md text-sm text-muted leading-relaxed">
            {noScanners ? (
              <>
                This scan didn&apos;t execute any scanners. Check that at least one scanner is
                installed and enabled.{" "}
                <Link href="/scanners" className="text-accent hover:underline">
                  Open scanner config
                </Link>
                .
              </>
            ) : (
              <>
                {scannersRanCount ?? "Several"} scanner{scannersRanCount === 1 ? "" : "s"}{" "}
                ran. SecureScan didn&apos;t find anything matching your enabled rules.{" "}
                <Link href="/scanners" className="text-accent hover:underline">
                  Open scanner config
                </Link>
                .
              </>
            )}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Sticky filter bar */}
      <div
        className={`sticky ${stickyTop} z-20 -mx-1 px-1 pt-1 pb-1 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/75`}
      >
        <div className="flex flex-wrap items-center gap-2 h-auto md:h-10 rounded-md border border-border bg-card px-2.5 py-1.5">
          {/* Search */}
          <label className="flex items-center gap-1.5 flex-1 min-w-[180px] max-w-md">
            <Search
              size={14}
              strokeWidth={1.5}
              aria-hidden
              className="text-muted shrink-0"
            />
            <input
              type="text"
              value={query}
              onChange={(e) => {
                setPage(0);
                setQuery(e.target.value);
              }}
              placeholder="Filter by message, file, or scanner"
              className="w-full bg-transparent text-sm placeholder:text-muted focus:outline-none"
              aria-label="Filter findings"
            />
          </label>

          <span aria-hidden className="hidden md:block h-5 w-px bg-border" />

          {/* Severity chip group */}
          <div
            role="group"
            aria-label="Severity filter"
            className="flex flex-wrap items-center gap-1"
          >
            <button
              type="button"
              onClick={clearSeverity}
              aria-pressed={activeSeverities.size === 0}
              className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border transition-colors ${
                activeSeverities.size === 0
                  ? "bg-accent-soft text-accent border-accent/40"
                  : "bg-surface-2 text-muted border-border hover:text-foreground"
              }`}
            >
              All
            </button>
            {SEVERITY_ORDER.map((s) => {
              const count = severityCounts[s];
              if (count === 0) return null;
              const active = activeSeverities.has(s);
              return (
                <button
                  key={s}
                  type="button"
                  onClick={() => toggleSeverity(s)}
                  aria-pressed={active}
                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium border transition-colors ${
                    active
                      ? SEV_CHIP_ACTIVE[s]
                      : "bg-surface-2 text-muted border-border hover:text-foreground"
                  }`}
                >
                  {SEVERITY_LABEL[s]}
                  <span className="tabular-nums opacity-80">{count}</span>
                </button>
              );
            })}
          </div>

          <span aria-hidden className="hidden md:block h-5 w-px bg-border" />

          {/* Scanner dropdown */}
          {scannerOptions.length > 0 && (
            <label className="inline-flex items-center gap-1.5 text-xs text-muted">
              <FilterIcon size={12} strokeWidth={1.5} aria-hidden />
              <span className="sr-only">Scanner</span>
              <div className="relative">
                <select
                  value={activeScanner}
                  onChange={(e) => {
                    setPage(0);
                    setActiveScanner(e.target.value);
                  }}
                  className="appearance-none bg-surface-2 border border-border rounded-md pl-2 pr-6 py-1 text-xs text-foreground hover:border-border-strong focus:outline-none focus:ring-2 focus:ring-ring/50"
                >
                  <option value="__all__">All scanners</option>
                  {scannerOptions.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
                <ChevronDown
                  size={12}
                  strokeWidth={1.5}
                  aria-hidden
                  className="pointer-events-none absolute right-1.5 top-1/2 -translate-y-1/2 text-muted"
                />
              </div>
            </label>
          )}

          {/* Show suppressed toggle */}
          {suppressedCount > 0 && (
            <label className="inline-flex items-center gap-1.5 text-xs text-muted select-none cursor-pointer">
              <input
                type="checkbox"
                checked={showSuppressed}
                onChange={(e) => {
                  setPage(0);
                  setShowSuppressed(e.target.checked);
                }}
                className="h-3.5 w-3.5 rounded border-border bg-surface-2 accent-accent"
              />
              <span>
                Show suppressed{" "}
                <span className="text-muted/70 tabular-nums">({suppressedCount})</span>
              </span>
            </label>
          )}

          {/* Right: count */}
          <div className="ml-auto text-xs text-muted tabular-nums whitespace-nowrap">
            {sorted.length === totalAll ? (
              <>
                <span className="font-medium text-foreground">{totalAll}</span>{" "}
                {totalAll === 1 ? "finding" : "findings"}
              </>
            ) : (
              <>
                <span className="font-medium text-foreground">{sorted.length}</span> of {totalAll}{" "}
                shown
              </>
            )}
          </div>
        </div>
      </div>

      {/* Findings table */}
      {sorted.length === 0 ? (
        <div className="rounded-md border border-border bg-card px-6 py-12 text-center">
          <p className="text-sm text-muted">
            No findings match the current filters.{" "}
            <button
              type="button"
              onClick={() => {
                setQuery("");
                setActiveSeverities(new Set());
                setActiveScanner("__all__");
              }}
              className="text-accent hover:underline"
            >
              Reset filters
            </button>
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-md border border-border bg-card">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-b border-border text-left text-[0.6875rem] uppercase tracking-wider text-muted">
                <th className="px-3 py-2 w-8 font-medium" />
                <th className="px-3 py-2 font-medium">Severity</th>
                <th className="px-3 py-2 font-medium">File:line</th>
                <th className="px-3 py-2 font-medium">Message</th>
                <th className="px-3 py-2 font-medium">Scanner</th>
                <th className="px-3 py-2 font-medium text-right">Rule</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((f) => (
                <FindingRow
                  key={f.id}
                  finding={f}
                  expanded={expandedIds.has(f.id)}
                  onToggle={() => toggleExpanded(f.id)}
                  colSpan={6}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination footer */}
      {paginate && (
        <div className="flex flex-wrap items-center justify-between gap-2 px-1 text-xs text-muted">
          <div className="tabular-nums">
            <span className="font-medium text-foreground">{sorted.length}</span> total
          </div>
          <div className="flex items-center gap-3">
            <label className="inline-flex items-center gap-1.5">
              Rows
              <select
                value={pageSize}
                onChange={(e) => {
                  setPage(0);
                  setPageSize(Number(e.target.value) as PageSize);
                }}
                className="bg-surface-2 border border-border rounded-md px-2 py-1 text-xs text-foreground hover:border-border-strong focus:outline-none focus:ring-2 focus:ring-ring/50"
              >
                {PAGE_SIZES.map((sz) => (
                  <option key={sz} value={sz}>
                    {sz}
                  </option>
                ))}
              </select>
            </label>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={safePage === 0}
                className="px-2 py-1 rounded-md border border-border bg-surface-2 hover:text-foreground disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Prev
              </button>
              <span className="tabular-nums px-1">
                {safePage + 1} / {totalPages}
              </span>
              <button
                type="button"
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={safePage >= totalPages - 1}
                className="px-2 py-1 rounded-md border border-border bg-surface-2 hover:text-foreground disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
