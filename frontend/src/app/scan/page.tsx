"use client";

import { useEffect, useState, useCallback } from "react";
import { ScanSearch, Loader2, CheckCircle, XCircle, FolderOpen } from "lucide-react";
import { startScan, fetchScan, fetchFindings, fetchScanSummary } from "@/lib/api";
import type { Scan, Finding, ScanSummary } from "@/lib/api";
import { FindingsTable } from "@/components/findings-table";
import { SeverityChart } from "@/components/severity-chart";
import { RiskScore } from "@/components/risk-score";
import { DirectoryPicker } from "@/components/directory-picker";

const SCAN_TYPES = [
  { id: "code", label: "Code Analysis" },
  { id: "dependency", label: "Dependency Scan" },
  { id: "iac", label: "IaC Analysis" },
  { id: "baseline", label: "Baseline Scan" },
];

export default function NewScanPage() {
  const [targetPath, setTargetPath] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<Set<string>>(new Set(["code", "dependency"]));
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);

  const toggleType = (id: string) => {
    setSelectedTypes((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const poll = useCallback(async (scanId: string) => {
    try {
      const updated = await fetchScan(scanId);
      setScan(updated);

      if (updated.status === "completed") {
        const [fin, sum] = await Promise.all([
          fetchFindings(scanId),
          fetchScanSummary(scanId),
        ]);
        setFindings(fin);
        setSummary(sum);
      } else if (updated.status === "failed") {
        setError(updated.error || "Scan failed");
      } else {
        setTimeout(() => poll(scanId), 2000);
      }
    } catch {
      setError("Failed to poll scan status");
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetPath.trim() || selectedTypes.size === 0) return;

    setSubmitting(true);
    setError(null);
    setScan(null);
    setFindings([]);
    setSummary(null);

    try {
      const newScan = await startScan(targetPath.trim(), Array.from(selectedTypes));
      setScan(newScan);
      if (newScan.status === "completed" || newScan.status === "failed") {
        if (newScan.status === "completed") {
          const [fin, sum] = await Promise.all([
            fetchFindings(newScan.id),
            fetchScanSummary(newScan.id),
          ]);
          setFindings(fin);
          setSummary(sum);
        } else {
          setError(newScan.error || "Scan failed");
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
          <div className="grid grid-cols-2 gap-3">
            {SCAN_TYPES.map((t) => (
              <label
                key={t.id}
                className={`flex items-center gap-3 px-4 py-3 rounded-lg border cursor-pointer transition-colors ${
                  selectedTypes.has(t.id)
                    ? "border-blue-500/40 bg-blue-500/10"
                    : "border-[#262626] bg-[#141414] hover:border-[#404040]"
                }`}
              >
                <input
                  type="checkbox"
                  checked={selectedTypes.has(t.id)}
                  onChange={() => toggleType(t.id)}
                  disabled={!!isRunning}
                  className="sr-only"
                />
                <div
                  className={`w-4 h-4 rounded border flex items-center justify-center ${
                    selectedTypes.has(t.id)
                      ? "bg-blue-600 border-blue-600"
                      : "border-[#52525b]"
                  }`}
                >
                  {selectedTypes.has(t.id) && (
                    <svg width="10" height="8" viewBox="0 0 10 8" fill="none">
                      <path d="M1 4L3.5 6.5L9 1" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  )}
                </div>
                <span className="text-sm font-medium">{t.label}</span>
              </label>
            ))}
          </div>
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={submitting || !!isRunning || !targetPath.trim() || selectedTypes.size === 0}
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
        </div>
      )}

      {/* Completed results */}
      {scan?.status === "completed" && (
        <div className="space-y-6">
          <div className="flex items-center gap-2 text-green-400">
            <CheckCircle size={18} />
            <span className="font-medium">Scan completed</span>
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
