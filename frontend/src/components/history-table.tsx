"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { MoreHorizontal, Eye, GitCompare, RotateCw, StopCircle, Trash2, X } from "lucide-react";
import type { Scan } from "@/lib/api";
import { startScan, cancelScan, deleteScan } from "@/lib/api";
import { DataTable, type Column, type SortState } from "@/components/data-table";
import { StatusIcon } from "@/components/status-icon";
import { RelativeTime } from "@/components/relative-time";

/* ------------------------------------------------------------------ */
/* Local fallbacks for DSH3 primitives (`SeverityPillStrip`).          */
/* When DSH3's component lands, the merge replaces these imports.      */
/* ------------------------------------------------------------------ */

interface SeverityPillStripProps {
  counts: { critical?: number; high?: number; medium?: number; low?: number; info?: number; total?: number };
  size?: "xs" | "sm";
}

function SeverityPillStrip({ counts, size = "xs" }: SeverityPillStripProps) {
  const total =
    counts.total ??
    (counts.critical ?? 0) +
      (counts.high ?? 0) +
      (counts.medium ?? 0) +
      (counts.low ?? 0) +
      (counts.info ?? 0);

  if (total === 0) {
    return (
      <span className={`inline-flex items-center rounded-full border border-border bg-surface-2 px-2 py-0.5 ${size === "xs" ? "text-[0.6875rem]" : "text-xs"} text-muted`}>
        Clean
      </span>
    );
  }

  const known =
    counts.critical !== undefined ||
    counts.high !== undefined ||
    counts.medium !== undefined ||
    counts.low !== undefined ||
    counts.info !== undefined;

  if (!known) {
    return (
      <span className={`inline-flex items-center rounded-full border border-border bg-surface-2 px-2 py-0.5 font-mono tabular-nums ${size === "xs" ? "text-[0.6875rem]" : "text-xs"} text-foreground`}>
        {total}
      </span>
    );
  }

  const pills: { key: string; n: number; cls: string }[] = [
    { key: "C", n: counts.critical ?? 0, cls: "bg-sev-critical-bg text-sev-critical" },
    { key: "H", n: counts.high ?? 0, cls: "bg-sev-high-bg text-sev-high" },
    { key: "M", n: counts.medium ?? 0, cls: "bg-sev-medium-bg text-sev-medium" },
    { key: "L", n: counts.low ?? 0, cls: "bg-sev-low-bg text-sev-low" },
    { key: "I", n: counts.info ?? 0, cls: "bg-sev-info-bg text-sev-info" },
  ];

  return (
    <span className="inline-flex items-center gap-1">
      {pills
        .filter((p) => p.n > 0)
        .map((p) => (
          <span
            key={p.key}
            className={`inline-flex items-center gap-0.5 rounded-full px-1.5 py-0.5 font-mono tabular-nums ${size === "xs" ? "text-[0.6875rem]" : "text-xs"} ${p.cls}`}
          >
            <span className="opacity-70">{p.key}</span>
            <span>{p.n}</span>
          </span>
        ))}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

function truncateMiddle(value: string, max = 48): string {
  if (value.length <= max) return value;
  const keep = Math.floor((max - 1) / 2);
  return `${value.slice(0, keep)}…${value.slice(value.length - keep)}`;
}

function fullTime(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString();
}

function scanDate(s: Scan): string | undefined {
  return s.completed_at ?? s.started_at;
}

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function riskBandColor(score: number | undefined): string {
  if (score == null) return "text-muted";
  if (score >= 76) return "text-sev-critical";
  if (score >= 51) return "text-sev-high";
  if (score >= 26) return "text-sev-medium";
  return "text-sev-low";
}

/* ------------------------------------------------------------------ */
/* Action menu                                                          */
/* ------------------------------------------------------------------ */

interface ActionMenuProps {
  scan: Scan;
  allScans: Scan[];
  onCancel: (id: string) => void | Promise<void>;
  onRerun: (scan: Scan) => void | Promise<void>;
  onCompare: (scan: Scan) => void;
  onDelete: (scan: Scan) => void | Promise<void>;
  busy?: boolean;
}

function ActionMenu({ scan, onCancel, onRerun, onCompare, onDelete, busy }: ActionMenuProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (!ref.current) return;
      if (!ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const canCancel = scan.status === "running" || scan.status === "pending";
  const canDelete = !canCancel;

  return (
    <div className="relative inline-block" ref={ref}>
      <button
        type="button"
        aria-label="Row actions"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-foreground focus-visible:bg-surface-2"
      >
        <MoreHorizontal size={16} aria-hidden="true" />
      </button>
      {open && (
        <div
          role="menu"
          onClick={(e) => e.stopPropagation()}
          className="absolute right-0 top-8 z-20 w-48 overflow-hidden rounded-md border border-border-strong bg-card shadow-lg"
        >
          <Link
            href={`/scan/${scan.id}`}
            role="menuitem"
            className="flex items-center gap-2 px-3 py-2 text-sm hover:bg-surface-2"
            onClick={() => setOpen(false)}
          >
            <Eye size={14} aria-hidden="true" />
            View
          </Link>
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              onCompare(scan);
            }}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-surface-2"
          >
            <GitCompare size={14} aria-hidden="true" />
            Compare with…
          </button>
          <button
            type="button"
            role="menuitem"
            disabled={busy}
            onClick={() => {
              setOpen(false);
              onRerun(scan);
            }}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-surface-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <RotateCw size={14} aria-hidden="true" />
            Re-run
          </button>
          {canCancel && (
            <button
              type="button"
              role="menuitem"
              disabled={busy}
              onClick={() => {
                setOpen(false);
                onCancel(scan.id);
              }}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-sev-critical hover:bg-surface-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <StopCircle size={14} aria-hidden="true" />
              Cancel
            </button>
          )}
          <button
            type="button"
            role="menuitem"
            disabled={busy || !canDelete}
            title={canDelete ? undefined : "Cancel the scan before deleting"}
            onClick={() => {
              setOpen(false);
              onDelete(scan);
            }}
            className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm text-sev-critical hover:bg-surface-2 disabled:opacity-50 disabled:cursor-not-allowed border-t border-border"
          >
            <Trash2 size={14} aria-hidden="true" />
            Delete
          </button>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Compare picker modal                                                 */
/* ------------------------------------------------------------------ */

interface ComparePickerProps {
  base: Scan;
  candidates: Scan[];
  onClose: () => void;
}

function ComparePicker({ base, candidates, onClose }: ComparePickerProps) {
  const [pick, setPick] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const others = candidates.filter(
    (s) => s.id !== base.id && s.target_path === base.target_path && s.status === "completed",
  );

  function confirm() {
    if (!pick) return;
    router.push(`/diff?base=${encodeURIComponent(pick)}&head=${encodeURIComponent(base.id)}`);
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="compare-picker-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-md border border-border-strong bg-card shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 id="compare-picker-title" className="text-sm font-medium">
            Compare with…
          </h2>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-foreground"
          >
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <div className="max-h-80 overflow-y-auto">
          {others.length === 0 ? (
            <p className="px-4 py-6 text-center text-sm text-muted">
              No other completed scans for this target.
            </p>
          ) : (
            <ul className="divide-y divide-border">
              {others.map((s) => {
                const checked = pick === s.id;
                return (
                  <li key={s.id}>
                    <label className="flex cursor-pointer items-start gap-3 px-4 py-3 hover:bg-surface-2">
                      <input
                        type="radio"
                        name="compare-base"
                        className="mt-1 accent-[var(--accent)]"
                        checked={checked}
                        onChange={() => setPick(s.id)}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 text-xs text-muted">
                          <span className="font-mono">{shortId(s.id)}</span>
                          <span>•</span>
                          <RelativeTime iso={scanDate(s)} title={fullTime(scanDate(s))} />
                        </div>
                        <div className="text-sm">
                          {s.findings_count} findings
                          {s.risk_score != null ? ` · risk ${s.risk_score}` : ""}
                        </div>
                      </div>
                    </label>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-border px-4 py-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm hover:border-border-strong"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={confirm}
            disabled={!pick}
            className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-foreground hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Compare
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* History table                                                        */
/* ------------------------------------------------------------------ */

interface HistoryTableProps {
  scans: Scan[];
  allScans: Scan[];
  sort: SortState;
  onSortChange: (next: SortState) => void;
  onScansUpdate: (updater: (prev: Scan[]) => Scan[]) => void;
  onError: (msg: string | null) => void;
  emptyState?: React.ReactNode;
}

export function HistoryTable({
  scans,
  allScans,
  sort,
  onSortChange,
  onScansUpdate,
  onError,
  emptyState,
}: HistoryTableProps) {
  const router = useRouter();
  const [busyIds, setBusyIds] = useState<Set<string>>(new Set());
  const [compareBase, setCompareBase] = useState<Scan | null>(null);

  function markBusy(id: string, on: boolean) {
    setBusyIds((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  async function handleCancel(id: string) {
    onError(null);
    markBusy(id, true);
    try {
      const updated = await cancelScan(id);
      onScansUpdate((prev) => prev.map((s) => (s.id === id ? updated : s)));
    } catch {
      onError("Failed to cancel scan");
    } finally {
      markBusy(id, false);
    }
  }

  async function handleRerun(scan: Scan) {
    onError(null);
    markBusy(scan.id, true);
    try {
      const fresh = await startScan(
        scan.target_path,
        scan.scan_types,
        scan.target_url,
        scan.target_host,
      );
      onScansUpdate((prev) => [fresh, ...prev]);
      router.push(`/scan/${fresh.id}`);
    } catch {
      onError("Failed to re-run scan");
    } finally {
      markBusy(scan.id, false);
    }
  }

  async function handleDelete(scan: Scan) {
    if (
      !window.confirm(
        "Delete this scan? This permanently removes the scan and all its findings.",
      )
    ) {
      return;
    }
    onError(null);
    markBusy(scan.id, true);
    try {
      await deleteScan(scan.id);
      onScansUpdate((prev) => prev.filter((s) => s.id !== scan.id));
    } catch (e) {
      onError(e instanceof Error ? e.message : "Failed to delete scan");
    } finally {
      markBusy(scan.id, false);
    }
  }

  const columns: Column<Scan>[] = [
    {
      key: "status",
      header: "Status",
      width: "w-[88px]",
      cell: (s) => (
        <span className="inline-flex items-center justify-center" title={s.status}>
          <StatusIcon status={s.status} size={16} />
        </span>
      ),
    },
    {
      key: "target",
      header: "Target",
      cell: (s) => {
        const truncated = truncateMiddle(s.target_path, 56);
        return (
          <div className="min-w-0 max-w-[420px]">
            <div className="truncate font-mono text-sm" title={s.target_path}>
              {truncated}
            </div>
            <div className="font-mono text-[0.6875rem] text-muted">{shortId(s.id)}</div>
          </div>
        );
      },
    },
    {
      key: "date",
      header: "Date",
      sortable: true,
      width: "w-[160px]",
      cell: (s) => {
        const iso = scanDate(s);
        return (
          <RelativeTime
            iso={iso}
            title={fullTime(iso)}
            className="text-sm text-foreground/90"
          />
        );
      },
    },
    {
      key: "scanners",
      header: "Scanners",
      width: "w-[200px]",
      cell: (s) => {
        const list = s.scanners_run ?? s.scan_types ?? [];
        const visible = list.slice(0, 3);
        const overflow = list.length - visible.length;
        return (
          <div className="flex items-center gap-1">
            <span className="text-xs text-muted whitespace-nowrap">{list.length} ran</span>
            <span className="flex items-center gap-1 ml-1">
              {visible.map((name) => (
                <span
                  key={name}
                  className="inline-flex items-center rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[0.6875rem] text-muted"
                  title={name}
                >
                  {name}
                </span>
              ))}
              {overflow > 0 && (
                <span
                  className="inline-flex items-center rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[0.6875rem] text-muted"
                  title={list.slice(3).join(", ")}
                >
                  +{overflow} more
                </span>
              )}
            </span>
          </div>
        );
      },
    },
    {
      key: "findings",
      header: "Findings",
      sortable: true,
      width: "w-[160px]",
      cell: (s) =>
        s.status === "completed" ? (
          <SeverityPillStrip counts={{ total: s.findings_count }} size="xs" />
        ) : (
          <span className="text-muted">—</span>
        ),
    },
    {
      key: "risk",
      header: "Risk",
      sortable: true,
      width: "w-[80px]",
      align: "right",
      cell: (s) =>
        s.risk_score != null ? (
          <span className={`font-mono tabular-nums text-sm font-medium ${riskBandColor(s.risk_score)}`}>
            {s.risk_score}
          </span>
        ) : (
          <span className="text-muted">—</span>
        ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "w-[56px]",
      align: "right",
      cell: (s) => (
        <div onClick={(e) => e.stopPropagation()}>
          <ActionMenu
            scan={s}
            allScans={allScans}
            onCancel={handleCancel}
            onRerun={handleRerun}
            onCompare={(target) => setCompareBase(target)}
            onDelete={handleDelete}
            busy={busyIds.has(s.id)}
          />
        </div>
      ),
    },
  ];

  return (
    <>
      <DataTable
        data={scans}
        columns={columns}
        sort={sort}
        onSortChange={onSortChange}
        getRowKey={(s) => s.id}
        onRowClick={(s) => router.push(`/scan/${s.id}`)}
        density="compact"
        emptyState={emptyState}
      />
      {compareBase && (
        <ComparePicker
          base={compareBase}
          candidates={allScans}
          onClose={() => setCompareBase(null)}
        />
      )}
    </>
  );
}
