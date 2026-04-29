"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, ChevronDown, History, Search } from "lucide-react";
import { fetchScans } from "@/lib/api";
import type { Scan } from "@/lib/api";
import { HistoryTable } from "@/components/history-table";
import { StatusIcon } from "@/components/status-icon";
import type { SortDirection, SortState } from "@/components/data-table";

/* ------------------------------------------------------------------ */
/* Local fallback for DSH3's PageHeader. Merge reconciles when DSH3    */
/* lands `frontend/src/components/page-header.tsx`.                    */
/* ------------------------------------------------------------------ */

function LocalPageHeader({
  title,
  meta,
  actions,
}: {
  title: string;
  meta?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-baseline justify-between gap-3 pb-1">
      <div className="flex items-baseline gap-3">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">{title}</h1>
        {meta != null && <span className="text-sm text-muted">{meta}</span>}
      </div>
      {actions != null && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}

/* ------------------------------------------------------------------ */

type StatusFilter = "all" | "completed" | "running" | "failed" | "cancelled";
type DateRange = "7d" | "30d" | "90d" | "all";
type PageSize = 10 | 25 | 50 | 100;

const VALID_PAGE_SIZES: PageSize[] = [10, 25, 50, 100];

const STATUS_CHIPS: { id: StatusFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "completed", label: "Completed" },
  { id: "running", label: "Running" },
  { id: "failed", label: "Failed" },
  { id: "cancelled", label: "Cancelled" },
];

const DATE_OPTIONS: { id: DateRange; label: string }[] = [
  { id: "7d", label: "Last 7 days" },
  { id: "30d", label: "Last 30 days" },
  { id: "90d", label: "Last 90 days" },
  { id: "all", label: "All time" },
];

function parseSort(raw: string | null): SortState {
  const fallback: SortState = { key: "date", direction: "desc" };
  if (!raw) return fallback;
  const idx = raw.lastIndexOf("-");
  if (idx <= 0) return fallback;
  const key = raw.slice(0, idx);
  const direction = raw.slice(idx + 1) as SortDirection;
  if (!["date", "risk", "findings"].includes(key)) return fallback;
  if (direction !== "asc" && direction !== "desc") return fallback;
  return { key, direction };
}

function sortToParam(s: SortState): string {
  return `${s.key}-${s.direction}`;
}

function dateLowerBound(range: DateRange): number {
  if (range === "all") return 0;
  const days = range === "7d" ? 7 : range === "30d" ? 30 : 90;
  return Date.now() - days * 24 * 60 * 60 * 1000;
}

function HistoryPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // Filter state — local; not persisted in URL by spec (URL persists sort + page-size).
  const [searchInput, setSearchInput] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [dateRange, setDateRange] = useState<DateRange>("all");
  const [dateOpen, setDateOpen] = useState(false);
  const dateRef = useRef<HTMLDivElement | null>(null);

  // URL-persisted state.
  const sort = useMemo<SortState>(() => parseSort(searchParams.get("sort")), [searchParams]);
  const pageSize = useMemo<PageSize>(() => {
    const raw = Number(searchParams.get("size"));
    return (VALID_PAGE_SIZES as number[]).includes(raw) ? (raw as PageSize) : 25;
  }, [searchParams]);
  const page = useMemo(() => {
    const raw = Number(searchParams.get("page"));
    return Number.isFinite(raw) && raw >= 1 ? Math.floor(raw) : 1;
  }, [searchParams]);

  /* Load scans. */
  useEffect(() => {
    let alive = true;
    fetchScans()
      .then((data) => {
        if (alive) setScans(data);
      })
      .catch(() => {
        if (alive) setLoadError("Failed to load scan history");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  /* Debounce the search input. */
  useEffect(() => {
    const t = setTimeout(() => setSearchQuery(searchInput.trim().toLowerCase()), 200);
    return () => clearTimeout(t);
  }, [searchInput]);

  /* Close date dropdown on outside click / ESC. */
  useEffect(() => {
    if (!dateOpen) return;
    function onDoc(e: MouseEvent) {
      if (!dateRef.current) return;
      if (!dateRef.current.contains(e.target as Node)) setDateOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setDateOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [dateOpen]);

  /* Per-status counts (across all scans, not the filtered subset). */
  const statusCounts = useMemo(() => {
    const c = { all: scans.length, completed: 0, running: 0, failed: 0, cancelled: 0 };
    for (const s of scans) {
      if (s.status === "completed") c.completed += 1;
      else if (s.status === "running" || s.status === "pending") c.running += 1;
      else if (s.status === "failed") c.failed += 1;
      else if (s.status === "cancelled") c.cancelled += 1;
    }
    return c;
  }, [scans]);

  const filtered = useMemo(() => {
    const lowerBound = dateLowerBound(dateRange);
    const q = searchQuery;
    return scans.filter((s) => {
      if (statusFilter !== "all") {
        if (statusFilter === "running") {
          if (s.status !== "running" && s.status !== "pending") return false;
        } else if (s.status !== statusFilter) {
          return false;
        }
      }
      if (lowerBound > 0) {
        const iso = s.completed_at ?? s.started_at;
        if (!iso) return false;
        const t = new Date(iso).getTime();
        if (Number.isNaN(t) || t < lowerBound) return false;
      }
      if (q) {
        const inTarget = s.target_path.toLowerCase().includes(q);
        const inId = s.id.toLowerCase().includes(q);
        if (!inTarget && !inId) return false;
      }
      return true;
    });
  }, [scans, statusFilter, dateRange, searchQuery]);

  const sorted = useMemo(() => {
    const copy = [...filtered];
    const dir = sort.direction === "asc" ? 1 : -1;
    copy.sort((a, b) => {
      let cmp = 0;
      if (sort.key === "date") {
        const ta = new Date(a.completed_at ?? a.started_at ?? 0).getTime() || 0;
        const tb = new Date(b.completed_at ?? b.started_at ?? 0).getTime() || 0;
        cmp = ta - tb;
      } else if (sort.key === "risk") {
        cmp = (a.risk_score ?? -1) - (b.risk_score ?? -1);
      } else if (sort.key === "findings") {
        cmp = a.findings_count - b.findings_count;
      }
      if (cmp === 0) {
        const ta = new Date(a.completed_at ?? a.started_at ?? 0).getTime() || 0;
        const tb = new Date(b.completed_at ?? b.started_at ?? 0).getTime() || 0;
        cmp = ta - tb;
      }
      return cmp * dir;
    });
    return copy;
  }, [filtered, sort]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const sliceStart = (safePage - 1) * pageSize;
  const pageRows = sorted.slice(sliceStart, sliceStart + pageSize);

  /* If page drifted past the new totalPages (filter change), reset URL to page 1. */
  useEffect(() => {
    if (page > totalPages) {
      const params = new URLSearchParams(searchParams.toString());
      params.set("page", "1");
      router.replace(`?${params.toString()}`);
    }
  }, [page, totalPages, router, searchParams]);

  const updateParams = useCallback(
    (mut: (params: URLSearchParams) => void) => {
      const params = new URLSearchParams(searchParams.toString());
      mut(params);
      const qs = params.toString();
      router.replace(qs ? `?${qs}` : "?");
    },
    [router, searchParams],
  );

  const onSortChange = useCallback(
    (next: SortState) => {
      updateParams((p) => {
        p.set("sort", sortToParam(next));
        p.set("page", "1");
      });
    },
    [updateParams],
  );

  const onPageSizeChange = useCallback(
    (n: PageSize) => {
      updateParams((p) => {
        p.set("size", String(n));
        p.set("page", "1");
      });
    },
    [updateParams],
  );

  const onPageChange = useCallback(
    (n: number) => {
      updateParams((p) => p.set("page", String(n)));
    },
    [updateParams],
  );

  const resetFilters = useCallback(() => {
    setSearchInput("");
    setSearchQuery("");
    setStatusFilter("all");
    setDateRange("all");
  }, []);

  const filtersActive =
    searchQuery !== "" || statusFilter !== "all" || dateRange !== "all";

  /* ------------------------------------------------------------------ */
  /* Render                                                              */
  /* ------------------------------------------------------------------ */

  if (loading) {
    return (
      <div className="space-y-6">
        <LocalPageHeader title="Scan history" meta="Loading…" />
        <div className="rounded-md border border-border bg-card">
          <div className="h-10 border-b border-border bg-surface-2/40" />
          {Array.from({ length: 8 }).map((_, i) => (
            <div
              key={i}
              className="h-12 border-b border-border last:border-b-0 animate-pulse"
              style={{ opacity: 1 - i * 0.08 }}
            />
          ))}
        </div>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="space-y-6">
        <LocalPageHeader title="Scan history" />
        <div className="rounded-md border border-sev-critical/30 bg-sev-critical-bg p-6 text-center">
          <AlertTriangle size={28} className="mx-auto mb-3 text-sev-critical" aria-hidden="true" />
          <p className="text-sm font-medium text-sev-critical">{loadError}</p>
        </div>
      </div>
    );
  }

  /* True empty state — no scans at all. */
  if (scans.length === 0) {
    return (
      <div className="space-y-6">
        <LocalPageHeader title="Scan history" meta="0 total scans" />
        <div className="flex flex-col items-center justify-center rounded-md border border-border bg-card py-20 text-center">
          <History size={32} className="mb-4 text-muted" aria-hidden="true" />
          <h2 className="text-base font-medium text-foreground">No scans yet</h2>
          <p className="mt-1 max-w-sm text-sm text-muted">
            Once you&apos;ve run scans, they&apos;ll appear here. SecureScan keeps the full
            history locally and never syncs anywhere.
          </p>
          <Link
            href="/scan"
            className="mt-5 inline-flex items-center rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground hover:opacity-90"
          >
            New scan
          </Link>
        </div>
      </div>
    );
  }

  const dateLabel = DATE_OPTIONS.find((o) => o.id === dateRange)?.label ?? "All time";

  return (
    <div className="space-y-4">
      <LocalPageHeader
        title="Scan history"
        meta={`${scans.length} total scan${scans.length === 1 ? "" : "s"}`}
        actions={
          <Link
            href="/scan"
            className="inline-flex items-center rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground hover:opacity-90"
          >
            New scan
          </Link>
        }
      />

      {actionError && (
        <div
          role="alert"
          className="flex items-center gap-3 rounded-md border border-sev-critical/30 bg-sev-critical-bg p-3"
        >
          <AlertTriangle size={16} className="shrink-0 text-sev-critical" aria-hidden="true" />
          <p className="text-sm text-sev-critical">{actionError}</p>
          <button
            type="button"
            onClick={() => setActionError(null)}
            className="ml-auto text-xs text-sev-critical/80 hover:text-sev-critical"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Filter bar */}
      <div className="sticky top-14 z-10 -mx-1 px-1 py-2 bg-background/90 backdrop-blur supports-[backdrop-filter]:bg-background/70">
        <div className="flex h-10 items-center gap-2 rounded-md border border-border bg-card px-2">
          <div className="flex h-8 flex-1 items-center gap-2 rounded-sm bg-surface-2 px-2 min-w-[160px] max-w-md focus-within:ring-1 focus-within:ring-[var(--ring)]">
            <Search size={14} className="shrink-0 text-muted" aria-hidden="true" />
            <input
              type="search"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search target or scan ID…"
              aria-label="Search scans"
              className="h-full w-full bg-transparent text-sm placeholder:text-muted focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-1" role="group" aria-label="Filter by status">
            {STATUS_CHIPS.map((chip) => {
              const active = statusFilter === chip.id;
              const count =
                chip.id === "all"
                  ? statusCounts.all
                  : chip.id === "completed"
                  ? statusCounts.completed
                  : chip.id === "running"
                  ? statusCounts.running
                  : chip.id === "failed"
                  ? statusCounts.failed
                  : statusCounts.cancelled;
              return (
                <button
                  key={chip.id}
                  type="button"
                  onClick={() => setStatusFilter(chip.id)}
                  aria-pressed={active}
                  className={`inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-xs transition-colors ${
                    active
                      ? "border-accent/60 bg-accent-soft text-foreground"
                      : "border-border bg-surface-2 text-muted hover:text-foreground hover:border-border-strong"
                  }`}
                >
                  {chip.id !== "all" && (
                    <StatusIcon
                      status={chip.id === "running" ? "running" : (chip.id as Scan["status"])}
                      size={12}
                    />
                  )}
                  <span>{chip.label}</span>
                  <span className="font-mono tabular-nums opacity-70">{count}</span>
                </button>
              );
            })}
          </div>

          <div className="relative" ref={dateRef}>
            <button
              type="button"
              onClick={() => setDateOpen((v) => !v)}
              aria-haspopup="listbox"
              aria-expanded={dateOpen}
              className="inline-flex h-7 items-center gap-1 rounded-full border border-border bg-surface-2 px-2.5 text-xs text-muted hover:text-foreground hover:border-border-strong"
            >
              <span>{dateLabel}</span>
              <ChevronDown size={12} aria-hidden="true" />
            </button>
            {dateOpen && (
              <ul
                role="listbox"
                className="absolute right-0 top-9 z-20 w-44 overflow-hidden rounded-md border border-border-strong bg-card shadow-lg"
              >
                {DATE_OPTIONS.map((opt) => (
                  <li key={opt.id}>
                    <button
                      type="button"
                      role="option"
                      aria-selected={dateRange === opt.id}
                      onClick={() => {
                        setDateRange(opt.id);
                        setDateOpen(false);
                      }}
                      className={`flex w-full items-center justify-between px-3 py-2 text-left text-sm hover:bg-surface-2 ${
                        dateRange === opt.id ? "text-foreground" : "text-muted"
                      }`}
                    >
                      <span>{opt.label}</span>
                      {dateRange === opt.id && (
                        <span className="text-[0.6875rem] text-accent">●</span>
                      )}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="ml-auto pr-1 text-xs text-muted whitespace-nowrap">
            <span className="font-mono tabular-nums">{sorted.length}</span> of{" "}
            <span className="font-mono tabular-nums">{scans.length}</span> shown
          </div>
        </div>
      </div>

      {/* Filtered-empty state */}
      {sorted.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-md border border-border bg-card py-12 text-center">
          <Search size={20} className="mb-3 text-muted" aria-hidden="true" />
          <h2 className="text-sm font-medium text-foreground">No matching scans</h2>
          <p className="mt-1 text-xs text-muted">
            Try a different search term or widen the date range.
          </p>
          <button
            type="button"
            onClick={resetFilters}
            disabled={!filtersActive}
            className="mt-4 rounded-md border border-border bg-surface-2 px-3 py-1.5 text-xs hover:border-border-strong disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Reset filters
          </button>
        </div>
      ) : (
        <>
          <HistoryTable
            scans={pageRows}
            allScans={scans}
            sort={sort}
            onSortChange={onSortChange}
            onScansUpdate={(updater) => setScans((prev) => updater(prev))}
            onError={setActionError}
          />

          {/* Pagination footer */}
          <div className="flex flex-wrap items-center justify-between gap-3 px-1 text-xs text-muted">
            <div className="flex items-center gap-2">
              <label htmlFor="page-size" className="text-xs">
                Rows per page
              </label>
              <select
                id="page-size"
                value={pageSize}
                onChange={(e) => onPageSizeChange(Number(e.target.value) as PageSize)}
                className="h-7 rounded-md border border-border bg-surface-2 px-2 text-xs text-foreground hover:border-border-strong focus-visible:border-border-strong"
              >
                {VALID_PAGE_SIZES.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
              <span className="ml-2">
                {sliceStart + 1}–{Math.min(sliceStart + pageRows.length, sorted.length)} of{" "}
                <span className="font-mono tabular-nums">{sorted.length}</span>
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => onPageChange(safePage - 1)}
                disabled={safePage <= 1}
                className="inline-flex h-7 items-center rounded-md border border-border bg-surface-2 px-2.5 text-xs text-foreground hover:border-border-strong disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <span className="text-xs">
                Page <span className="font-mono tabular-nums">{safePage}</span> of{" "}
                <span className="font-mono tabular-nums">{totalPages}</span>
              </span>
              <button
                type="button"
                onClick={() => onPageChange(safePage + 1)}
                disabled={safePage >= totalPages}
                className="inline-flex h-7 items-center rounded-md border border-border bg-surface-2 px-2.5 text-xs text-foreground hover:border-border-strong disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default function HistoryPage() {
  return (
    <Suspense fallback={null}>
      <HistoryPageInner />
    </Suspense>
  );
}
