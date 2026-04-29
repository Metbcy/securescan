"use client";

/*
 * Scan Detail page (DSH5).
 *
 * Owner: DSH5. The header / stat-line / scanner-chip-strip / findings table
 * compose the most-visited surface in SecureScan.
 *
 * Composes DSH3's <PageHeader />, <StatLine />, and <SeverityPillStrip />
 * primitives. Everything below the header is DSH5-owned.
 */

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  Download,
  GitCompareArrows,
  Loader2,
  RefreshCw,
  StopCircle,
  XCircle,
} from "lucide-react";
import {
  cancelScan,
  fetchFindings,
  fetchScan,
  fetchScanSummary,
  getScanEventsUrl,
  scanEventsAvailable,
  startScan,
} from "@/lib/api";
import type { Finding, Scan, ScanSummary } from "@/lib/api";
import { FindingsTable } from "@/components/findings-table";
import { ScannerChipStrip } from "@/components/scanner-chip-strip";
import { PageHeader, StatLine, type StatLineItem } from "@/components/page-header";
import { SeverityPillStrip } from "@/components/severity-pill-strip";
import {
  ScanProgressPanel,
  type ScannerProgress,
} from "@/components/scan-progress-panel";

/* ---------- helpers ---------- */

type ScanStatus = Scan["status"];
type Severity = "critical" | "high" | "medium" | "low" | "info";

const STATUS_TONE: Record<ScanStatus, { dot: string; text: string; label: string }> = {
  completed: { dot: "bg-accent", text: "text-accent", label: "completed" },
  running: { dot: "bg-sev-medium", text: "text-sev-medium", label: "running" },
  pending: { dot: "bg-sev-medium", text: "text-sev-medium", label: "pending" },
  failed: { dot: "bg-sev-critical", text: "text-sev-critical", label: "failed" },
  cancelled: { dot: "bg-muted", text: "text-muted", label: "cancelled" },
};

function truncateMiddle(value: string, max = 56): string {
  if (value.length <= max) return value;
  const half = Math.floor((max - 1) / 2);
  return `${value.slice(0, half)}…${value.slice(value.length - half)}`;
}

function shortId(id: string): string {
  return id.length >= 8 ? id.slice(0, 8) : id;
}

function formatRelative(iso?: string): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const seconds = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.round(days / 30);
  if (months < 12) return `${months}mo ago`;
  const years = Math.round(days / 365);
  return `${years}y ago`;
}

function formatDuration(scan: Scan): string {
  const start = scan.started_at ? new Date(scan.started_at).getTime() : null;
  const end = scan.completed_at ? new Date(scan.completed_at).getTime() : null;
  if (start == null) return "—";
  const ref = end ?? Date.now();
  const ms = Math.max(0, ref - start);
  if (ms < 1000) return `${ms}ms`;
  const totalSec = Math.round(ms / 1000);
  if (totalSec < 60) return `${totalSec}s`;
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  if (m < 60) return s > 0 ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm > 0 ? `${h}h ${rm}m` : `${h}h`;
}

function riskScoreTone(score: number): { text: string; band: string } {
  if (score <= 30) return { text: "text-accent", band: "Low" };
  if (score <= 60) return { text: "text-sev-medium", band: "Medium" };
  if (score <= 80) return { text: "text-sev-high", band: "High" };
  return { text: "text-sev-critical", band: "Critical" };
}

function deriveSummaryFromFindings(findings: Finding[]): ScanSummary {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const s = (f.severity?.toLowerCase() ?? "info") as Severity;
    if (s in counts) counts[s] += 1;
  }
  return {
    total_findings: findings.length,
    critical: counts.critical,
    high: counts.high,
    medium: counts.medium,
    low: counts.low,
    info: counts.info,
    risk_score: 0,
    scanners_run: [],
  };
}

/* ---------- DSH5-local helpers ---------- */

/* ---------- buttons ---------- */

function ActionButton({
  children,
  onClick,
  href,
  variant = "secondary",
  disabled,
  title,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  href?: string;
  variant?: "primary" | "secondary" | "destructive";
  disabled?: boolean;
  title?: string;
}) {
  const base =
    "inline-flex items-center gap-1.5 px-3 h-8 rounded-md text-xs font-medium border transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  const v =
    variant === "primary"
      ? "bg-accent text-accent-foreground border-accent hover:bg-accent/90"
      : variant === "destructive"
      ? "border-sev-critical/40 text-sev-critical hover:bg-sev-critical-bg bg-transparent"
      : "border-border bg-surface-2 text-foreground hover:border-border-strong";
  const cn = `${base} ${v}`;
  if (href) {
    return (
      <a href={href} className={cn} title={title}>
        {children}
      </a>
    );
  }
  return (
    <button type="button" onClick={onClick} disabled={disabled} className={cn} title={title}>
      {children}
    </button>
  );
}

/* ---------- skeleton ---------- */

function ScanDetailSkeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div className="space-y-2">
          <div className="h-3 w-24 bg-surface-2 rounded" />
          <div className="h-7 w-72 bg-surface-2 rounded" />
          <div className="h-3 w-48 bg-surface-2 rounded" />
        </div>
        <div className="flex gap-2">
          <div className="h-8 w-24 bg-surface-2 rounded-md" />
          <div className="h-8 w-24 bg-surface-2 rounded-md" />
        </div>
      </div>
      <div className="rounded-md border border-border bg-card px-5 py-4">
        <div className="flex flex-wrap gap-x-8 gap-y-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="space-y-2">
              <div className="h-3 w-16 bg-surface-2 rounded" />
              <div className="h-6 w-24 bg-surface-2 rounded" />
              <div className="h-3 w-32 bg-surface-2 rounded" />
            </div>
          ))}
        </div>
      </div>
      <div className="h-10 rounded-md border border-border bg-card" />
      <div className="rounded-md border border-border bg-card divide-y divide-border">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="h-11 px-3 flex items-center gap-3">
            <div className="h-4 w-16 bg-surface-2 rounded" />
            <div className="h-4 w-32 bg-surface-2 rounded" />
            <div className="h-4 flex-1 bg-surface-2 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- page ---------- */

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params?.id as string | undefined;

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [retrying, setRetrying] = useState(false);

  // Live SSE progress, keyed by scanner name. Populated only while the scan
  // is running; cleared (along with totalScanners) when a new scan begins.
  const [scannerProgress, setScannerProgress] = useState<
    Record<string, ScannerProgress>
  >({});
  const [totalScanners, setTotalScanners] = useState<number | undefined>(
    undefined,
  );

  // Used to force the relative-time labels to refresh while running.
  const [, setTick] = useState(0);

  /*
   * Two-phase loader:
   *   - statusOnly=true  : just refresh the scan record (cheap; safe to call every 2s).
   *   - statusOnly=false : also fetch findings + summary (expensive; only on mount,
   *                        on user refresh, and once when status flips to completed).
   *
   * Polling previously refetched the entire findings array every 2 seconds. With
   * a 20k-finding scan that's a 14 MB JSON parse + a full re-sort/re-filter of the
   * memoized table on every tick, which locks up the browser and prevents the
   * "running" badge from ever repainting to "completed".
   */
  const load = useCallback(
    async (silent = false, statusOnly = false) => {
      if (!id) return;
      try {
        if (!silent) setLoading(true);
        const scanData = await fetchScan(id);
        setScan(scanData);

        if (statusOnly && scanData.status !== "completed") {
          // Lightweight poll path: don't touch findings while still running.
          setError(null);
          return;
        }

        if (scanData.status === "completed") {
          const [fin, sum] = await Promise.all([fetchFindings(id), fetchScanSummary(id)]);
          setFindings(fin);
          setSummary(sum);
        } else if (scanData.status === "running" || scanData.status === "pending") {
          // Initial load only — fetch any partial findings the backend has so far.
          try {
            const fin = await fetchFindings(id);
            setFindings(fin);
            setSummary(deriveSummaryFromFindings(fin));
          } catch {
            // Server may not return findings until complete; ignore.
          }
        } else {
          setFindings([]);
          setSummary(null);
        }
        setError(null);
      } catch {
        if (!silent) setError("Failed to load scan details");
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [id],
  );

  useEffect(() => {
    void load(false, false);
  }, [load]);

  /*
   * Live progress: subscribe to the SSE event stream while the scan is
   * running/pending. Replaces the v0.6.x 2-second status poll. We still
   * tick a 1-second interval so duration labels refresh smoothly, and we
   * still call `load(false, false)` once after a terminal event so the
   * findings table + summary repopulate without a manual refresh.
   *
   * Fallback policy:
   *   - If `NEXT_PUBLIC_SECURESCAN_API_KEY` is set, EventSource cannot send
   *     it, so the backend will reject the connection. Skip SSE entirely
   *     and poll like before.
   *   - If the EventSource constructor throws or the stream errors out
   *     once open, close the EventSource FIRST and only then start the
   *     2s poll. Never run both in parallel — the browser auto-reconnects
   *     EventSource on transport errors and we'd otherwise burn requests.
   */
  useEffect(() => {
    const scanId = scan?.id;
    const status = scan?.status;
    if (!scanId) return;
    const isLive = status === "running" || status === "pending";
    if (!isLive) return;

    const labelTick = setInterval(() => setTick((n) => n + 1), 1000);

    let es: EventSource | null = null;
    let pollFallback: ReturnType<typeof setInterval> | null = null;

    const startPollFallback = () => {
      if (pollFallback) return;
      pollFallback = setInterval(() => {
        void load(true, true);
      }, 2000);
    };

    const handle = (e: MessageEvent, eventName: string) => {
      let data: { [k: string]: unknown } = {};
      try {
        data = JSON.parse(e.data);
      } catch {
        // Malformed payloads are ignored — the keepalive comments and
        // empty-data heartbeats both fall through here harmlessly.
      }
      const scannerName = typeof data.scanner === "string" ? data.scanner : "";
      switch (eventName) {
        case "scan.start":
          if (typeof data.scanner_count === "number") {
            setTotalScanners(data.scanner_count);
          }
          break;
        case "scanner.start":
          if (scannerName) {
            setScannerProgress((p) => ({
              ...p,
              [scannerName]: { state: "running" },
            }));
          }
          break;
        case "scanner.complete":
          if (scannerName) {
            setScannerProgress((p) => ({
              ...p,
              [scannerName]: {
                state: "complete",
                duration_s:
                  typeof data.duration_s === "number" ? data.duration_s : undefined,
                findings_count:
                  typeof data.findings_count === "number"
                    ? data.findings_count
                    : undefined,
              },
            }));
          }
          break;
        case "scanner.skipped":
          if (scannerName) {
            setScannerProgress((p) => ({
              ...p,
              [scannerName]: {
                state: "skipped",
                reason: typeof data.reason === "string" ? data.reason : undefined,
              },
            }));
          }
          break;
        case "scanner.failed":
          if (scannerName) {
            setScannerProgress((p) => ({
              ...p,
              [scannerName]: {
                state: "failed",
                duration_s:
                  typeof data.duration_s === "number" ? data.duration_s : undefined,
                error: typeof data.error === "string" ? data.error : undefined,
              },
            }));
          }
          break;
        case "scan.complete":
        case "scan.failed":
        case "scan.cancelled":
          if (es) {
            es.close();
            es = null;
          }
          // Final refresh: pulls findings + summary now that scan is done.
          void load(true, false);
          break;
      }
    };

    if (scanEventsAvailable()) {
      try {
        es = new EventSource(getScanEventsUrl(scanId));
      } catch {
        es = null;
        startPollFallback();
      }
    } else {
      // API-key auth blocks EventSource — go straight to polling.
      startPollFallback();
    }

    if (es) {
      const eventNames = [
        "scan.start",
        "scanner.start",
        "scanner.complete",
        "scanner.skipped",
        "scanner.failed",
        "scan.complete",
        "scan.failed",
        "scan.cancelled",
      ] as const;
      for (const name of eventNames) {
        es.addEventListener(name, (e) => handle(e as MessageEvent, name));
      }
      es.onerror = () => {
        // CRITICAL: close EventSource before falling back. The browser
        // auto-reconnects on transport errors, so leaving it open while
        // polling would run two recovery loops in parallel.
        if (es) {
          es.close();
          es = null;
        }
        startPollFallback();
      };
    }

    return () => {
      clearInterval(labelTick);
      if (es) {
        es.close();
        es = null;
      }
      if (pollFallback) {
        clearInterval(pollFallback);
        pollFallback = null;
      }
    };
  }, [scan?.id, scan?.status, load]);

  // Reset live progress state when the scan id changes (rescans, navigation).
  useEffect(() => {
    setScannerProgress({});
    setTotalScanners(undefined);
  }, [id]);

  const handleCancel = useCallback(async () => {
    if (!id) return;
    setCancelling(true);
    try {
      await cancelScan(id);
      await load(true);
    } catch {
      setError("Failed to cancel scan");
    } finally {
      setCancelling(false);
    }
  }, [id, load]);

  const handleRetry = useCallback(async () => {
    if (!scan) return;
    setRetrying(true);
    try {
      const next = await startScan(
        scan.target_path,
        scan.scan_types ?? [],
        scan.target_url,
        scan.target_host,
      );
      router.push(`/scan/${next.id}`);
    } catch {
      setError("Failed to start a new scan");
      setRetrying(false);
    }
  }, [scan, router]);

  /* ---------- render ---------- */

  if (loading && !scan) return <ScanDetailSkeleton />;

  if (error || !scan) {
    return (
      <div className="space-y-6">
        <Link
          href="/history"
          className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-foreground"
        >
          <ArrowLeft size={16} strokeWidth={1.5} /> Back to History
        </Link>
        <div
          role="alert"
          className="rounded-md border border-sev-critical/30 bg-sev-critical-bg p-5"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle size={20} strokeWidth={1.5} className="text-sev-critical shrink-0" />
            <div>
              <p className="text-sm font-medium text-sev-critical">
                {error || "Scan not found"}
              </p>
              <p className="mt-1 text-xs text-muted">
                The scan {id ? <span className="font-mono">{shortId(id)}</span> : "you requested"}{" "}
                couldn&apos;t be loaded.
              </p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const tone = STATUS_TONE[scan.status] ?? STATUS_TONE.pending;
  const startedRel = formatRelative(scan.started_at);
  const duration = formatDuration(scan);

  // Header actions vary by status.
  const actions: React.ReactNode = (() => {
    if (scan.status === "running" || scan.status === "pending") {
      return (
        <ActionButton variant="destructive" onClick={handleCancel} disabled={cancelling}>
          {cancelling ? (
            <>
              <Loader2 size={14} strokeWidth={1.5} className="animate-spin" />
              Cancelling…
            </>
          ) : (
            <>
              <StopCircle size={14} strokeWidth={1.5} />
              Cancel
            </>
          )}
        </ActionButton>
      );
    }
    if (scan.status === "failed") {
      return (
        <ActionButton variant="secondary" onClick={handleRetry} disabled={retrying}>
          {retrying ? (
            <Loader2 size={14} strokeWidth={1.5} className="animate-spin" />
          ) : (
            <RefreshCw size={14} strokeWidth={1.5} />
          )}
          Retry
        </ActionButton>
      );
    }
    if (scan.status === "completed") {
      return (
        <>
          <ActionButton variant="secondary" onClick={handleRetry} disabled={retrying}>
            {retrying ? (
              <Loader2 size={14} strokeWidth={1.5} className="animate-spin" />
            ) : (
              <RefreshCw size={14} strokeWidth={1.5} />
            )}
            Re-scan
          </ActionButton>
          <ActionButton
            variant="secondary"
            href={`/api/v1/scans/${scan.id}/report?format=sarif`}
            title="Download SARIF report"
          >
            <Download size={14} strokeWidth={1.5} />
            Download SARIF
          </ActionButton>
          <ActionButton
            variant="secondary"
            href={`/diff?base=${encodeURIComponent(scan.id)}`}
            title="Compare against another scan"
          >
            <GitCompareArrows size={14} strokeWidth={1.5} />
            Compare
          </ActionButton>
        </>
      );
    }
    if (scan.status === "cancelled") {
      return (
        <ActionButton variant="secondary" onClick={handleRetry} disabled={retrying}>
          {retrying ? (
            <Loader2 size={14} strokeWidth={1.5} className="animate-spin" />
          ) : (
            <RefreshCw size={14} strokeWidth={1.5} />
          )}
          Re-scan
        </ActionButton>
      );
    }
    return null;
  })();

  // Scanners that are queued/running but not yet in scanners_run.
  const ran = scan.scanners_run ?? [];
  const skipped = scan.scanners_skipped ?? [];
  const runningScanners =
    scan.status === "running"
      ? (scan.scan_types ?? []).filter(
          (s) => !ran.includes(s) && !skipped.some((sk) => sk.name === s),
        )
      : [];

  const showStatLine = scan.status === "completed";
  const isFailed = scan.status === "failed";

  const findingsTotal = summary?.total_findings ?? findings.length;
  const usableSummary: ScanSummary | null =
    summary ?? (findings.length > 0 ? deriveSummaryFromFindings(findings) : null);

  return (
    <div className="space-y-6">
      <Link
        href="/history"
        className="inline-flex items-center gap-1.5 text-xs text-muted hover:text-foreground"
      >
        <ArrowLeft size={14} strokeWidth={1.5} /> Back to History
      </Link>

      <PageHeader
        eyebrow={<>Scan <span className="text-foreground">{shortId(scan.id)}</span></>}
        title={`Scan · ${truncateMiddle(scan.target_path, 64)}`}
        meta={
          <span
            className="flex flex-wrap items-center gap-x-3 gap-y-1"
            title={scan.target_path}
          >
            <span className={`inline-flex items-center gap-1.5 ${tone.text}`}>
              <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${tone.dot}`} />
              {tone.label}
              {scan.status === "running" && (
                <Loader2 size={12} strokeWidth={1.5} className="animate-spin" />
              )}
            </span>
            {scan.started_at && (
              <>
                <span aria-hidden>·</span>
                <span>
                  started{" "}
                  <span className="text-foreground" title={new Date(scan.started_at).toLocaleString()}>
                    {startedRel}
                  </span>
                </span>
              </>
            )}
            {(scan.status === "completed" || scan.status === "running") && (
              <>
                <span aria-hidden>·</span>
                <span>
                  duration <span className="text-foreground tabular-nums">{duration}</span>
                </span>
              </>
            )}
          </span>
        }
        actions={actions}
      />

      {/* Failed-scan alert — replaces stat line + findings entirely. */}
      {isFailed && (
        <div
          role="alert"
          className="rounded-md border border-sev-critical/30 bg-sev-critical-bg px-5 py-4"
        >
          <div className="flex items-start gap-3">
            <XCircle size={18} strokeWidth={1.5} className="text-sev-critical shrink-0 mt-0.5" />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-sev-critical">Scan failed</p>
              {scan.error && (
                <pre className="mt-2 text-xs font-mono text-foreground whitespace-pre-wrap break-words max-w-[80ch]">
                  {scan.error}
                </pre>
              )}
            </div>
            <ActionButton variant="secondary" onClick={handleRetry} disabled={retrying}>
              {retrying ? (
                <Loader2 size={14} strokeWidth={1.5} className="animate-spin" />
              ) : (
                <RefreshCw size={14} strokeWidth={1.5} />
              )}
              Retry
            </ActionButton>
          </div>
        </div>
      )}

      {/* Cancelled note — concise; user can rescan from header. */}
      {scan.status === "cancelled" && scan.error && (
        <div className="rounded-md border border-border bg-card px-5 py-3 text-sm text-muted">
          <span className="text-foreground font-medium">Cancelled.</span>{" "}
          <span className="font-mono">{scan.error}</span>
        </div>
      )}

      {/* Stat line (completed only). */}
      {showStatLine && usableSummary && (
        <>
          <StatLine
            items={
              [
                {
                  label: "Risk score",
                  value: summary ? (
                    <span
                      className={`tabular-nums ${riskScoreTone(summary.risk_score).text}`}
                    >
                      {summary.risk_score}
                    </span>
                  ) : (
                    <span className="text-muted">—</span>
                  ),
                  trail: summary ? riskScoreTone(summary.risk_score).band : null,
                },
                {
                  label: "Findings",
                  value: <span className="tabular-nums">{findingsTotal}</span>,
                  trail:
                    findingsTotal > 0 ? (
                      <SeverityPillStrip counts={usableSummary} size="xs" />
                    ) : (
                      "none"
                    ),
                },
                {
                  label: "Scanners",
                  value: (
                    <span className="tabular-nums">{ran.length}</span>
                  ),
                  trail: (
                    <span>
                      ran
                      {skipped.length > 0 && (
                        <>
                          {" · "}
                          <span className="tabular-nums">{skipped.length}</span> skipped
                        </>
                      )}
                    </span>
                  ),
                },
                {
                  label: "Duration",
                  value: <span className="tabular-nums">{duration}</span>,
                  trail: scan.completed_at ? (
                    <span title={new Date(scan.completed_at).toLocaleString()}>
                      finished {formatRelative(scan.completed_at)}
                    </span>
                  ) : null,
                },
              ] satisfies StatLineItem[]
            }
          />
          {/* Scanner chip strip lives directly under the stat line per DSH5 spec. */}
          {(ran.length > 0 || skipped.length > 0) && (
            <div className="-mt-2">
              <ScannerChipStrip ran={ran} skipped={skipped} />
            </div>
          )}
        </>
      )}

      {/* Running surface — partial scanner chips + spinner, no stat line yet. */}
      {(scan.status === "running" || scan.status === "pending") && !isFailed && (
        <>
          <ScanProgressPanel
            scanners={scannerProgress}
            totalScanners={totalScanners ?? scan.scan_types?.length}
          />
          <StatLine
            items={
              [
                {
                  label: "Status",
                  value: (
                    <span className="inline-flex items-center gap-2 text-sev-medium">
                      <Loader2 size={14} strokeWidth={1.5} className="animate-spin" />
                      {scan.status === "pending" ? "Queued" : "Running"}
                    </span>
                  ),
                  trail: duration,
                },
                {
                  label: "Scanners",
                  value: (
                    <span>
                      <span className="tabular-nums">{ran.length}</span>
                      {scan.scan_types && scan.scan_types.length > 0 && (
                        <span className="text-muted">/{scan.scan_types.length}</span>
                      )}
                    </span>
                  ),
                  trail: "done",
                },
                ...(findings.length > 0
                  ? [
                      {
                        label: "Partial findings",
                        value: <span className="tabular-nums">{findings.length}</span>,
                        trail: (
                          <SeverityPillStrip
                            counts={deriveSummaryFromFindings(findings)}
                            size="xs"
                          />
                        ),
                      },
                    ]
                  : []),
              ] satisfies StatLineItem[]
            }
          />
          <div className="-mt-2">
            <ScannerChipStrip ran={ran} skipped={skipped} running={runningScanners} />
          </div>
        </>
      )}

      {/* AI Summary (rendered with restrained accent, not blue marketing). */}
      {scan.status === "completed" && scan.summary && (
        <section className="rounded-md border border-border bg-card px-5 py-4">
          <h2 className="text-[0.6875rem] uppercase tracking-wider text-muted mb-1.5">
            Summary
          </h2>
          <p className="text-sm text-foreground leading-relaxed whitespace-pre-wrap max-w-[80ch]">
            {scan.summary}
          </p>
        </section>
      )}

      {/* Findings — hidden on failed; shown on completed and on running (partial). */}
      {!isFailed && (scan.status === "completed" || findings.length > 0) && (
        <section aria-label="Findings" className="space-y-3">
          <h2 className="text-lg font-semibold text-foreground-strong">Findings</h2>
          <FindingsTable
            findings={findings}
            scannersRanCount={ran.length}
            stickyTop="top-14"
          />
        </section>
      )}
    </div>
  );
}
