"use client";

import { useEffect, useState, useCallback } from "react";
import { ScanSearch, Loader2, CheckCircle, XCircle, FolderOpen, StopCircle, Download, AlertTriangle } from "lucide-react";
import { startScan, fetchScan, fetchFindings, fetchScanSummary, cancelScan, getReportUrl, fetchScannerStatus } from "@/lib/api";
import type { Scan, Finding, ScanSummary, ScannerStatus } from "@/lib/api";
import { FindingsTable } from "@/components/findings-table";
import { SeverityChart } from "@/components/severity-chart";
import { RiskScore } from "@/components/risk-score";
import { DirectoryPicker } from "@/components/directory-picker";

const SCAN_TYPES = [
  { id: "code", label: "Code Analysis" },
  { id: "dependency", label: "Dependency Scan" },
  { id: "iac", label: "IaC Analysis" },
  { id: "baseline", label: "Baseline Scan" },
  { id: "dast", label: "DAST (Web App)" },
  { id: "network", label: "Network Scan" },
];

const DEFAULT_SELECTION = ["code", "dependency"];

interface CategoryAvailability {
  available: number;
  total: number;
  unavailable: { name: string; install_hint: string }[];
}

function aggregateAvailability(scanners: ScannerStatus[]): Map<string, CategoryAvailability> {
  const map = new Map<string, CategoryAvailability>();
  for (const t of SCAN_TYPES) {
    map.set(t.id, { available: 0, total: 0, unavailable: [] });
  }
  for (const s of scanners) {
    const entry = map.get(s.scan_type);
    if (!entry) continue;
    entry.total += 1;
    if (s.available) {
      entry.available += 1;
    } else {
      entry.unavailable.push({
        name: s.name,
        install_hint: s.install_hint ?? "",
      });
    }
  }
  return map;
}

function pickDefaultSelection(availability: Map<string, CategoryAvailability>): Set<string> {
  const usable = DEFAULT_SELECTION.filter((id) => (availability.get(id)?.available ?? 0) > 0);
  if (usable.length > 0) return new Set(usable);
  let bestId: string | null = null;
  let bestAvailable = 0;
  for (const t of SCAN_TYPES) {
    const a = availability.get(t.id);
    if (a && a.available > bestAvailable) {
      bestAvailable = a.available;
      bestId = t.id;
    }
  }
  return bestId ? new Set([bestId]) : new Set();
}

export default function NewScanPage() {
  const [targetPath, setTargetPath] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<Set<string>>(new Set(DEFAULT_SELECTION));
  const [targetUrl, setTargetUrl] = useState("");
  const [targetHost, setTargetHost] = useState("");
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [availability, setAvailability] = useState<Map<string, CategoryAvailability> | null>(null);
  const [availabilityLoading, setAvailabilityLoading] = useState(true);
  const [availabilityError, setAvailabilityError] = useState<string | null>(null);

  // Fetch scanner availability on mount; default selection adapts to what's installed.
  useEffect(() => {
    let cancelled = false;
    setAvailabilityLoading(true);
    fetchScannerStatus()
      .then((scanners) => {
        if (cancelled) return;
        const agg = aggregateAvailability(scanners);
        setAvailability(agg);
        setSelectedTypes(pickDefaultSelection(agg));
        setAvailabilityError(null);
      })
      .catch(() => {
        if (cancelled) return;
        setAvailability(null);
        setAvailabilityError(
          "Could not load scanner availability. Showing all categories — your scan may produce zero findings if scanners are not installed."
        );
      })
      .finally(() => {
        if (!cancelled) setAvailabilityLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const toggleType = (id: string) => {
    setSelectedTypes((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const totalAvailable = availability
    ? Array.from(availability.values()).reduce((sum, a) => sum + a.available, 0)
    : 0;
  const totalScanners = availability
    ? Array.from(availability.values()).reduce((sum, a) => sum + a.total, 0)
    : 0;
  const someDisabled = availability
    ? Array.from(availability.values()).some((a) => a.total > 0 && a.available === 0)
    : false;

  const poll = useCallback(async (scanId: string) => {
    try {
      const updated = await fetchScan(scanId);
      setScan(updated);

      if (updated.status === "completed") {
        localStorage.removeItem("securescan_active_scan");
        const [fin, sum] = await Promise.all([
          fetchFindings(scanId),
          fetchScanSummary(scanId),
        ]);
        setFindings(fin);
        setSummary(sum);
      } else if (updated.status === "failed" || updated.status === "cancelled") {
        localStorage.removeItem("securescan_active_scan");
        setError(updated.error || (updated.status === "cancelled" ? "Scan cancelled" : "Scan failed"));
      } else {
        setTimeout(() => poll(scanId), 2000);
      }
    } catch {
      setError("Failed to poll scan status");
    }
  }, []);

  // Restore active scan on mount
  useEffect(() => {
    const activeScan = localStorage.getItem("securescan_active_scan");
    if (activeScan) {
      try {
        const { scanId, targetPath: savedPath } = JSON.parse(activeScan);
        setTargetPath(savedPath || "");
        fetchScan(scanId).then((s) => {
          setScan(s);
          if (s.status === "completed") {
            localStorage.removeItem("securescan_active_scan");
            Promise.all([fetchFindings(scanId), fetchScanSummary(scanId)]).then(
              ([fin, sum]) => { setFindings(fin); setSummary(sum); }
            );
          } else if (s.status === "failed" || s.status === "cancelled") {
            localStorage.removeItem("securescan_active_scan");
            setError(s.error || (s.status === "cancelled" ? "Scan cancelled" : "Scan failed"));
          } else {
            poll(scanId);
          }
        }).catch(() => {
          localStorage.removeItem("securescan_active_scan");
        });
      } catch {
        localStorage.removeItem("securescan_active_scan");
      }
    }
  }, [poll]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetPath.trim() || selectedTypes.size === 0) return;

    setSubmitting(true);
    setError(null);
    setScan(null);
    setFindings([]);
    setSummary(null);

    try {
      const newScan = await startScan(
        targetPath.trim(),
        Array.from(selectedTypes),
        targetUrl.trim() || undefined,
        targetHost.trim() || undefined,
      );
      setScan(newScan);
      // Persist active scan to localStorage
      localStorage.setItem("securescan_active_scan", JSON.stringify({
        scanId: newScan.id,
        targetPath: targetPath.trim(),
      }));
      if (newScan.status === "completed" || newScan.status === "failed" || newScan.status === "cancelled") {
        localStorage.removeItem("securescan_active_scan");
        if (newScan.status === "completed") {
          const [fin, sum] = await Promise.all([
            fetchFindings(newScan.id),
            fetchScanSummary(newScan.id),
          ]);
          setFindings(fin);
          setSummary(sum);
        } else {
          setError(newScan.error || (newScan.status === "cancelled" ? "Scan cancelled" : "Scan failed"));
        }
      } else {
        poll(newScan.id);
      }
    } catch {
      setError("Failed to start scan. Is the backend running?");
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancel = async () => {
    if (!scan) return;
    setCancelling(true);
    setError(null);
    try {
      const updated = await cancelScan(scan.id);
      setScan(updated);
      localStorage.removeItem("securescan_active_scan");
      setError(updated.error || "Scan cancelled");
    } catch {
      setError("Failed to stop scan");
    } finally {
      setCancelling(false);
    }
  };

  const isRunning = scan && (scan.status === "pending" || scan.status === "running");

  return (
    <div className="space-y-6 max-w-3xl">
      <h1 className="text-2xl font-bold tracking-tight">New Scan</h1>

      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Target path */}
        <div>
          <label className="block text-sm font-medium text-[#a1a1aa] mb-2">
            Target Path
          </label>
          <div className="flex">
            <input
              type="text"
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              placeholder="/path/to/your/project"
              disabled={!!isRunning}
              className="flex-1 px-4 py-2.5 rounded-l-lg bg-[#141414] border border-[#262626] border-r-0 text-[#ededed] placeholder-[#52525b] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors disabled:opacity-50"
            />
            <button
              type="button"
              onClick={() => setPickerOpen(true)}
              disabled={!!isRunning}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-r-lg bg-[#141414] border border-[#262626] text-[#a1a1aa] hover:bg-[#1a1a1a] hover:text-[#ededed] transition-colors disabled:opacity-50"
            >
              <FolderOpen size={16} />
              <span className="text-sm">Browse</span>
            </button>
          </div>
        </div>

        <DirectoryPicker
          isOpen={pickerOpen}
          onClose={() => setPickerOpen(false)}
          onSelect={(path) => {
            setTargetPath(path);
            setPickerOpen(false);
          }}
          initialPath={targetPath || undefined}
        />

        {/* Scan types */}
        <div>
          <label className="block text-sm font-medium text-[#a1a1aa] mb-3">
            Scan Types
          </label>

          {availabilityLoading && (
            <div className="flex items-center gap-2 text-xs text-[#a1a1aa] mb-3">
              <Loader2 size={14} className="animate-spin" />
              Loading scanner availability…
            </div>
          )}

          {availabilityError && (
            <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 mb-3 flex items-start gap-2">
              <AlertTriangle size={14} className="text-yellow-400 shrink-0 mt-0.5" />
              <p className="text-xs text-yellow-300">{availabilityError}</p>
            </div>
          )}

          {availability && !availabilityLoading && (
            <p className="text-xs text-[#a1a1aa] mb-3">
              Available scanners: {totalAvailable} of {totalScanners}.
              {someDisabled && " Some categories are disabled because their scanners are not installed."}
            </p>
          )}

          <div className="grid grid-cols-2 gap-3">
            {SCAN_TYPES.map((t) => {
              const info = availability?.get(t.id);
              const hasInfo = !!info && info.total > 0;
              const allUnavailable = hasInfo && info.available === 0;
              const partial = hasInfo && info.available > 0 && info.available < info.total;
              const checked = selectedTypes.has(t.id);
              const showWarning = checked && allUnavailable;
              const installHints = info
                ? info.unavailable
                    .map((u) => u.install_hint)
                    .filter((h) => h && h.length > 0)
                : [];
              const tooltip = allUnavailable && installHints.length > 0
                ? `Install: ${installHints.join(", ")}`
                : undefined;
              const labelText = partial
                ? `${t.label} (${info!.available} of ${info!.total} available)`
                : t.label;
              const disabledControl = !!isRunning || availabilityLoading;
              return (
                <div key={t.id} className="space-y-1">
                  <label
                    title={tooltip}
                    className={`flex items-center gap-3 px-4 py-3 rounded-lg border transition-colors ${
                      disabledControl ? "cursor-not-allowed" : "cursor-pointer"
                    } ${
                      checked
                        ? "border-blue-500/40 bg-blue-500/10"
                        : "border-[#262626] bg-[#141414] hover:border-[#404040]"
                    } ${allUnavailable ? "opacity-60" : ""}`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleType(t.id)}
                      disabled={disabledControl}
                      className="sr-only"
                    />
                    <div
                      className={`w-4 h-4 rounded border flex items-center justify-center ${
                        checked
                          ? "bg-blue-600 border-blue-600"
                          : "border-[#52525b]"
                      }`}
                    >
                      {checked && (
                        <svg width="10" height="8" viewBox="0 0 10 8" fill="none">
                          <path d="M1 4L3.5 6.5L9 1" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      )}
                    </div>
                    <span className={`text-sm font-medium ${allUnavailable ? "text-[#a1a1aa]" : ""}`}>
                      {labelText}
                    </span>
                  </label>

                  {allUnavailable && installHints.length > 0 && (
                    <p className="px-1 text-[11px] text-[#71717a]">
                      Install: {installHints.join(", ")}
                    </p>
                  )}

                  {showWarning && (
                    <p className="flex items-start gap-1 px-1 text-[11px] text-yellow-300">
                      <AlertTriangle size={11} className="shrink-0 mt-0.5" />
                      No scanners available; this scan will produce no findings for this category.
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {selectedTypes.has("dast") && (
          <div>
            <label className="block text-sm font-medium text-[#a1a1aa] mb-2">Target URL (for DAST)</label>
            <input
              type="url"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              disabled={!!isRunning}
              className="w-full px-4 py-2.5 rounded-lg bg-[#141414] border border-[#262626] text-[#ededed] placeholder-[#52525b] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors disabled:opacity-50"
            />
          </div>
        )}

        {selectedTypes.has("network") && (
          <div>
            <label className="block text-sm font-medium text-[#a1a1aa] mb-2">Target Host (for Network Scan)</label>
            <input
              type="text"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              placeholder="192.168.1.1 or hostname"
              disabled={!!isRunning}
              className="w-full px-4 py-2.5 rounded-lg bg-[#141414] border border-[#262626] text-[#ededed] placeholder-[#52525b] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors disabled:opacity-50"
            />
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={submitting || !!isRunning || availabilityLoading || !targetPath.trim() || selectedTypes.size === 0}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting || isRunning ? (
            <>
              <Loader2 size={16} className="animate-spin" />
              {submitting ? "Starting…" : "Scanning…"}
            </>
          ) : (
            <>
              <ScanSearch size={16} />
              Start Scan
            </>
          )}
        </button>
      </form>

      {/* Error */}
      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 flex items-center gap-3">
          <XCircle size={18} className="text-red-400 shrink-0" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Running status */}
      {isRunning && (
        <div className="rounded-xl border border-blue-500/20 bg-blue-500/10 p-6 text-center">
          <Loader2 size={28} className="mx-auto mb-3 text-blue-400 animate-spin" />
          <p className="text-blue-400 font-medium">Scan in progress…</p>
          <p className="text-xs text-blue-400/60 mt-1">
            Status: {scan.status} • Polling every 2s
          </p>
          <button
            type="button"
            onClick={handleCancel}
            disabled={cancelling}
            className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-red-500/30 bg-red-500/10 text-red-300 hover:bg-red-500/20 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {cancelling ? (
              <>
                <Loader2 size={14} className="animate-spin" />
                Stopping…
              </>
            ) : (
              <>
                <StopCircle size={14} />
                Stop Scan
              </>
            )}
          </button>
        </div>
      )}

      {/* Completed results */}
      {scan?.status === "completed" && (
        <div className="space-y-6">
          <div className="flex items-center gap-2 text-green-400">
            <CheckCircle size={18} />
            <span className="font-medium">Scan completed</span>
          </div>

          <div className="flex gap-3">
            <a
              href={getReportUrl(scan.id, "pdf")}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#262626] bg-[#141414] hover:bg-[#1a1a1a] text-sm font-medium text-[#ededed] transition-colors"
            >
              <Download size={14} />
              PDF Report
            </a>
            <a
              href={getReportUrl(scan.id, "html")}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#262626] bg-[#141414] hover:bg-[#1a1a1a] text-sm font-medium text-[#ededed] transition-colors"
            >
              <Download size={14} />
              HTML Report
            </a>
          </div>

          {/* AI Summary */}
          {scan.summary && (
            <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-5">
              <h3 className="text-sm font-medium text-blue-400 mb-2">AI Summary</h3>
              <p className="text-sm text-[#a1a1aa] leading-relaxed whitespace-pre-wrap">
                {scan.summary}
              </p>
            </div>
          )}

          {summary && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="rounded-xl border border-[#262626] bg-[#141414] p-6 flex items-center justify-center">
                <RiskScore score={summary.risk_score} />
              </div>
              <div className="rounded-xl border border-[#262626] bg-[#141414] p-6">
                <h3 className="text-sm font-medium text-[#a1a1aa] mb-4">Findings by Severity</h3>
                <SeverityChart
                  critical={summary.critical}
                  high={summary.high}
                  medium={summary.medium}
                  low={summary.low}
                  info={summary.info}
                />
              </div>
            </div>
          )}

          {findings.length > 0 && (
            <div>
              <h3 className="text-lg font-semibold mb-3">Findings</h3>
              <FindingsTable findings={findings} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
