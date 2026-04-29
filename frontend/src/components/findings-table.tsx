"use client";

import { useCallback, useDeferredValue, useMemo, useState } from "react";
import {
  ChevronDown,
  Search,
  ShieldCheck,
  ShieldAlert,
  Filter as FilterIcon,
} from "lucide-react";
import Link from "next/link";
import {
  getCachedFindingState,
  patchFindingState,
  TRIAGE_STATUSES,
  type Finding,
  type FindingState,
  type TriageStatus,
} from "@/lib/api";
import {
  FindingRow,
  STATUS_LABEL,
  STATUS_PILL,
  getSuppressedBy,
} from "@/components/finding-row";

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

/**
 * Statuses that the triage filter hides by default. `fixed` is intentionally
 * NOT in this set: a "fixed" finding reappearing in a later scan is a
 * regression signal we want to remain visible without flipping a toggle.
 */
const DEFAULT_HIDDEN_STATUSES: ReadonlySet<TriageStatus> = new Set<TriageStatus>([
  "false_positive",
  "accepted_risk",
  "wont_fix",
]);

/** Active-chip styling for status filter buttons; `new` has no pill colors. */
const STATUS_CHIP_ACTIVE: Record<TriageStatus, string> = {
  new: "bg-accent-soft text-accent border-accent/40",
  triaged: STATUS_PILL.triaged,
  false_positive: STATUS_PILL.false_positive,
  accepted_risk: STATUS_PILL.accepted_risk,
  fixed: STATUS_PILL.fixed,
  wont_fix: STATUS_PILL.wont_fix,
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
  const [activeStatuses, setActiveStatuses] = useState<Set<TriageStatus>>(new Set());
  const [activeScanner, setActiveScanner] = useState<string>("__all__");
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [showTriaged, setShowTriaged] = useState(false);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState<PageSize>(25);

  // Local optimistic-update map for triage state. The single source of truth
  // for any finding's triage state is:
  //   stateOverrides.get(fp) ?? finding.state ?? getCachedFindingState(fp)
  // The cached fallback handles the case where the backend's triage tables
  // aren't deployed yet (state always comes back null) but the user has
  // already triaged from the same browser. See lib/api.ts.
  const [stateOverrides, setStateOverrides] = useState<Map<string, FindingState | null>>(
    () => new Map(),
  );

  // Reset overrides when the underlying findings list identity changes (e.g.
  // user navigates to a different scan). Uses the "store previous prop and
  // reset during render" pattern recommended by React docs to avoid an
  // effect-driven cascading render.
  const [prevFindings, setPrevFindings] = useState(findings);
  if (prevFindings !== findings) {
    setPrevFindings(findings);
    setStateOverrides(new Map());
  }

  // Defer the search query so typing remains responsive on very large scans.
  const deferredQuery = useDeferredValue(query);

  /**
   * Resolve the *current* triage state for a finding. Order:
   *   1. Optimistic override applied locally in this session
   *   2. State that came down with the finding from the backend
   *   3. Cached state from a prior local triage (fallback when backend
   *      doesn't yet persist triage)
   */
  const resolveState = useCallback(
    (f: Finding): FindingState | null => {
      const fp = f.fingerprint;
      if (fp && stateOverrides.has(fp)) return stateOverrides.get(fp) ?? null;
      if (f.state) return f.state;
      if (fp) return getCachedFindingState(fp);
      return null;
    },
    [stateOverrides],
  );

  // Pre-normalize the findings list once per `findings` change. All downstream
  // filters/counts/sort operate on this projection so we don't re-lowercase
  // severity strings or rebuild the search haystack on every keystroke.
  const projected = useMemo(
    () =>
      findings.map((f) => {
        const currentState = resolveState(f);
        const statusKey: TriageStatus = currentState?.status ?? "new";
        return {
          finding: f,
          currentState,
          severityNorm: normalize(f.severity),
          suppressed: getSuppressedBy(f.metadata),
          statusKey,
          isTriageHidden: DEFAULT_HIDDEN_STATUSES.has(statusKey),
          haystack:
            `${f.title} ${f.description ?? ""} ${f.file_path ?? ""} ${f.scanner}`.toLowerCase(),
        };
      }),
    [findings, resolveState],
  );

  const totalAll = findings.length;
  const suppressedCount = useMemo(
    () => projected.reduce((n, p) => (p.suppressed ? n + 1 : n), 0),
    [projected],
  );
  const triagedHiddenCount = useMemo(
    () => projected.reduce((n, p) => (p.isTriageHidden ? n + 1 : n), 0),
    [projected],
  );

  const scannerOptions = useMemo(() => {
    const set = new Set<string>();
    for (const p of projected) {
      if (p.finding.scanner) set.add(p.finding.scanner);
    }
    return Array.from(set).sort();
  }, [projected]);

  // Severity counts honor the suppression + triage toggles so the chip-strip
  // counts match what the user can actually see.
  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const p of projected) {
      if (!showSuppressed && p.suppressed) continue;
      if (!showTriaged && p.isTriageHidden) continue;
      counts[p.severityNorm] += 1;
    }
    return counts;
  }, [projected, showSuppressed, showTriaged]);

  // Status counts honor the suppression toggle but NOT the triage toggle —
  // otherwise the hidden-status chips would always read 0 and you'd never
  // know there were 47 false positives ready to surface.
  const statusCounts = useMemo(() => {
    const counts: Record<TriageStatus, number> = {
      new: 0,
      triaged: 0,
      false_positive: 0,
      accepted_risk: 0,
      fixed: 0,
      wont_fix: 0,
    };
    for (const p of projected) {
      if (!showSuppressed && p.suppressed) continue;
      counts[p.statusKey] += 1;
    }
    return counts;
  }, [projected, showSuppressed]);

  const filtered = useMemo(() => {
    const q = deferredQuery.trim().toLowerCase();
    return projected.filter((p) => {
      if (!showSuppressed && p.suppressed) return false;
      if (!showTriaged && p.isTriageHidden) return false;
      if (activeSeverities.size > 0 && !activeSeverities.has(p.severityNorm)) return false;
      if (activeStatuses.size > 0 && !activeStatuses.has(p.statusKey)) return false;
      if (activeScanner !== "__all__" && p.finding.scanner !== activeScanner) return false;
      if (q.length > 0 && !p.haystack.includes(q)) return false;
      return true;
    });
  }, [
    projected,
    deferredQuery,
    activeSeverities,
    activeStatuses,
    activeScanner,
    showSuppressed,
    showTriaged,
  ]);

  const sorted = useMemo(
    () =>
      [...filtered].sort((a, b) => SEVERITY_RANK[a.severityNorm] - SEVERITY_RANK[b.severityNorm]),
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

  const toggleStatus = (s: TriageStatus) => {
    setPage(0);
    setActiveStatuses((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const clearStatus = () => {
    setPage(0);
    setActiveStatuses(new Set());
  };

  const toggleExpanded = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Optimistic update: write the override locally first (next render flips
  // the badge), then fire the PATCH. On error roll back to the previous
  // override value so the row snaps back. The caller-facing error state is
  // owned by the row's <TriagePanel>, which receives the rejection.
  const handlePatchState = useCallback(
    async (
      fingerprint: string,
      body: { status: TriageStatus; note?: string | null },
    ): Promise<FindingState> => {
      const finding = findings.find((f) => f.fingerprint === fingerprint);
      const previous: FindingState | null =
        stateOverrides.has(fingerprint)
          ? stateOverrides.get(fingerprint) ?? null
          : finding?.state ?? (fingerprint ? getCachedFindingState(fingerprint) : null);

      const optimistic: FindingState = {
        fingerprint,
        status: body.status,
        note: body.note ?? previous?.note ?? null,
        updated_at: new Date().toISOString(),
        updated_by: previous?.updated_by ?? null,
      };
      setStateOverrides((prev) => {
        const next = new Map(prev);
        next.set(fingerprint, optimistic);
        return next;
      });

      try {
        const confirmed = await patchFindingState(fingerprint, body);
        setStateOverrides((prev) => {
          const next = new Map(prev);
          next.set(fingerprint, confirmed);
          return next;
        });
        return confirmed;
      } catch (e) {
        setStateOverrides((prev) => {
          const next = new Map(prev);
          next.set(fingerprint, previous);
          return next;
        });
        throw e;
      }
    },
    [findings, stateOverrides],
  );

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
        <div className="flex flex-wrap items-center gap-2 h-auto md:min-h-10 rounded-md border border-border bg-card px-2.5 py-1.5">
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

          {/* Status chip group — only render statuses that have ≥1 finding */}
          <div
            role="group"
            aria-label="Triage status filter"
            className="flex flex-wrap items-center gap-1"
          >
            <button
              type="button"
              onClick={clearStatus}
              aria-pressed={activeStatuses.size === 0}
              className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border transition-colors ${
                activeStatuses.size === 0
                  ? "bg-accent-soft text-accent border-accent/40"
                  : "bg-surface-2 text-muted border-border hover:text-foreground"
              }`}
              title="Show all triage statuses"
            >
              Any status
            </button>
            {TRIAGE_STATUSES.map((s) => {
              const count = statusCounts[s];
              if (count === 0) return null;
              const active = activeStatuses.has(s);
              return (
                <button
                  key={s}
                  type="button"
                  onClick={() => toggleStatus(s)}
                  aria-pressed={active}
                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium border transition-colors ${
                    active
                      ? STATUS_CHIP_ACTIVE[s]
                      : "bg-surface-2 text-muted border-border hover:text-foreground"
                  }`}
                >
                  {STATUS_LABEL[s]}
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

          {/* Show triaged toggle — independent of suppression toggle.
              Triage filter and suppression filter are AND-combined: a finding
              that is BOTH suppressed AND false-positive needs both toggles ON
              to appear. */}
          {triagedHiddenCount > 0 && (
            <label className="inline-flex items-center gap-1.5 text-xs text-muted select-none cursor-pointer">
              <input
                type="checkbox"
                checked={showTriaged}
                onChange={(e) => {
                  setPage(0);
                  setShowTriaged(e.target.checked);
                }}
                className="h-3.5 w-3.5 rounded border-border bg-surface-2 accent-accent"
              />
              <span>
                Show triaged{" "}
                <span className="text-muted/70 tabular-nums">({triagedHiddenCount})</span>
              </span>
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

          {/* Right: counts. Show triage-hidden + suppressed-hidden when any. */}
          <div className="ml-auto text-xs text-muted tabular-nums whitespace-nowrap flex items-center gap-1.5">
            <span>
              <span className="font-medium text-foreground">{totalAll}</span> total
            </span>
            {!showTriaged && triagedHiddenCount > 0 && (
              <>
                <span aria-hidden>·</span>
                <span>
                  <span className="font-medium text-foreground">{triagedHiddenCount}</span>{" "}
                  triaged hidden
                </span>
              </>
            )}
            {!showSuppressed && suppressedCount > 0 && (
              <>
                <span aria-hidden>·</span>
                <span>
                  <span className="font-medium text-foreground">{suppressedCount}</span>{" "}
                  suppressed hidden
                </span>
              </>
            )}
            {sorted.length !== totalAll && (
              <>
                <span aria-hidden>·</span>
                <span>
                  <span className="font-medium text-foreground">{sorted.length}</span> shown
                </span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Findings table */}
      {sorted.length === 0 ? (
        <div className="rounded-md border border-border bg-card px-6 py-12 text-center">
          <p className="text-sm text-muted leading-relaxed">
            All <span className="font-medium text-foreground">{totalAll}</span>{" "}
            {totalAll === 1 ? "finding is" : "findings are"} hidden by current filters.
            {(triagedHiddenCount > 0 && !showTriaged) || (suppressedCount > 0 && !showSuppressed) ? (
              <>
                {" "}
                <span className="block mt-1 text-[0.6875rem]">
                  {triagedHiddenCount > 0 && !showTriaged && (
                    <>
                      Toggle <span className="font-medium text-foreground">Show triaged</span> to
                      reveal {triagedHiddenCount}.
                    </>
                  )}
                  {triagedHiddenCount > 0 && !showTriaged && suppressedCount > 0 && !showSuppressed && (
                    <> </>
                  )}
                  {suppressedCount > 0 && !showSuppressed && (
                    <>
                      Toggle <span className="font-medium text-foreground">Show suppressed</span>{" "}
                      to reveal {suppressedCount}.
                    </>
                  )}
                </span>
              </>
            ) : null}
            <button
              type="button"
              onClick={() => {
                setQuery("");
                setActiveSeverities(new Set());
                setActiveStatuses(new Set());
                setActiveScanner("__all__");
              }}
              className="ml-1 text-accent hover:underline"
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
                <th className="px-2 py-2 w-[80px] font-medium">Status</th>
                <th className="px-3 py-2 font-medium">Severity</th>
                <th className="px-3 py-2 font-medium">File:line</th>
                <th className="px-3 py-2 font-medium">Message</th>
                <th className="px-3 py-2 font-medium">Scanner</th>
                <th className="px-3 py-2 font-medium text-right">Rule</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((p) => (
                <FindingRow
                  key={p.finding.id}
                  finding={p.finding}
                  expanded={expandedIds.has(p.finding.id)}
                  onToggle={() => toggleExpanded(p.finding.id)}
                  colSpan={7}
                  state={p.currentState}
                  onPatchState={handlePatchState}
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
