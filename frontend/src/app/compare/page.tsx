"use client";

import { useEffect, useState } from "react";
import { ArrowLeftRight, ChevronDown, ChevronRight, AlertTriangle } from "lucide-react";
import type { Scan, CompareResult, Finding } from "@/lib/api";
import { fetchScans, compareScans } from "@/lib/api";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400",
  high: "bg-orange-500/20 text-orange-400",
  medium: "bg-yellow-500/20 text-yellow-400",
  low: "bg-blue-500/20 text-blue-400",
  info: "bg-neutral-500/20 text-neutral-400",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${SEVERITY_COLORS[severity] || ""}`}>
      {severity}
    </span>
  );
}

function FindingsTable({ findings, label }: { findings: Finding[]; label: string }) {
  if (findings.length === 0) {
    return <p className="text-sm text-[#71717a] italic">No {label.toLowerCase()}</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#262626] text-left text-[#a1a1aa]">
            <th className="pb-2 pr-4 font-medium">Severity</th>
            <th className="pb-2 pr-4 font-medium">Title</th>
            <th className="pb-2 font-medium">File</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.id} className="border-b border-[#1a1a1a]">
              <td className="py-2 pr-4"><SeverityBadge severity={f.severity} /></td>
              <td className="py-2 pr-4 text-[#ededed]">{f.title}</td>
              <td className="py-2 text-[#a1a1aa] font-mono text-xs">
                {f.file_path || "—"}{f.line_start ? `:${f.line_start}` : ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CollapsibleSection({
  title,
  icon,
  count,
  colorClass,
  defaultOpen = false,
  children,
}: {
  title: string;
  icon: string;
  count: number;
  colorClass: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="rounded-xl border border-[#262626] bg-[#141414] overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-[#1a1a1a] transition-colors"
      >
        {open ? <ChevronDown size={16} className="text-[#71717a]" /> : <ChevronRight size={16} className="text-[#71717a]" />}
        <span className="text-lg">{icon}</span>
        <span className="font-medium text-[#ededed]">{title}</span>
        <span className={`ml-auto px-2.5 py-0.5 rounded-full text-xs font-semibold ${colorClass}`}>
          {count}
        </span>
      </button>
      {open && <div className="px-5 pb-5 border-t border-[#262626] pt-4">{children}</div>}
    </div>
  );
}

function scanLabel(scan: Scan): string {
  const date = scan.completed_at
    ? new Date(scan.completed_at).toLocaleDateString()
    : scan.started_at
    ? new Date(scan.started_at).toLocaleDateString()
    : "pending";
  const path = scan.target_path.split("/").pop() || scan.target_path;
  return `${path} — ${date} (${scan.status})`;
}

export default function ComparePage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [scanAId, setScanAId] = useState("");
  const [scanBId, setScanBId] = useState("");
  const [result, setResult] = useState<CompareResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scansLoading, setScansLoading] = useState(true);

  useEffect(() => {
    fetchScans()
      .then((data) => {
        setScans(data.filter((s) => s.status === "completed"));
      })
      .catch(() => setError("Failed to load scans"))
      .finally(() => setScansLoading(false));
  }, []);

  async function handleCompare() {
    if (!scanAId || !scanBId) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await compareScans(scanAId, scanBId);
      setResult(data);
    } catch {
      setError("Failed to compare scans. Make sure both scans are valid.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight flex items-center gap-3">
        <ArrowLeftRight size={24} className="text-blue-500" />
        Compare Scans
      </h1>

      {/* Scan selectors */}
      <div className="rounded-xl border border-[#262626] bg-[#141414] p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-[#a1a1aa] mb-2">
              Scan A (Baseline)
            </label>
            <select
              value={scanAId}
              onChange={(e) => setScanAId(e.target.value)}
              disabled={scansLoading}
              className="w-full rounded-lg border border-[#262626] bg-[#0a0a0a] text-[#ededed] px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            >
              <option value="">Select baseline scan…</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>{scanLabel(s)}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-[#a1a1aa] mb-2">
              Scan B (Latest)
            </label>
            <select
              value={scanBId}
              onChange={(e) => setScanBId(e.target.value)}
              disabled={scansLoading}
              className="w-full rounded-lg border border-[#262626] bg-[#0a0a0a] text-[#ededed] px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            >
              <option value="">Select latest scan…</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>{scanLabel(s)}</option>
              ))}
            </select>
          </div>
        </div>

        <button
          onClick={handleCompare}
          disabled={!scanAId || !scanBId || loading || scanAId === scanBId}
          className="mt-4 inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
        >
          <ArrowLeftRight size={16} />
          {loading ? "Comparing…" : "Compare"}
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 flex items-center gap-3">
          <AlertTriangle size={18} className="text-red-400 shrink-0" />
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-center">
              <p className="text-2xl font-bold text-red-400">{result.summary.new_count}</p>
              <p className="text-xs text-red-400/70 mt-1">New (Regressions)</p>
            </div>
            <div className="rounded-xl border border-green-500/20 bg-green-500/5 p-4 text-center">
              <p className="text-2xl font-bold text-green-400">{result.summary.fixed_count}</p>
              <p className="text-xs text-green-400/70 mt-1">Fixed (Resolved)</p>
            </div>
            <div className="rounded-xl border border-[#262626] bg-[#141414] p-4 text-center">
              <p className="text-2xl font-bold text-[#a1a1aa]">{result.summary.unchanged_count}</p>
              <p className="text-xs text-[#71717a] mt-1">Unchanged</p>
            </div>
            <div className={`rounded-xl border p-4 text-center ${
              result.summary.risk_delta > 0
                ? "border-red-500/20 bg-red-500/5"
                : result.summary.risk_delta < 0
                ? "border-green-500/20 bg-green-500/5"
                : "border-[#262626] bg-[#141414]"
            }`}>
              <p className={`text-2xl font-bold ${
                result.summary.risk_delta > 0
                  ? "text-red-400"
                  : result.summary.risk_delta < 0
                  ? "text-green-400"
                  : "text-[#a1a1aa]"
              }`}>
                {result.summary.risk_delta > 0 ? "+" : ""}{result.summary.risk_delta}
              </p>
              <p className="text-xs text-[#71717a] mt-1">Risk Delta</p>
            </div>
          </div>

          {/* Findings sections */}
          <CollapsibleSection
            title="New Findings (Regressions)"
            icon="🔴"
            count={result.summary.new_count}
            colorClass="bg-red-500/20 text-red-400"
            defaultOpen={result.summary.new_count > 0}
          >
            <FindingsTable findings={result.new_findings} label="new findings" />
          </CollapsibleSection>

          <CollapsibleSection
            title="Fixed Findings (Resolved)"
            icon="✅"
            count={result.summary.fixed_count}
            colorClass="bg-green-500/20 text-green-400"
            defaultOpen={result.summary.fixed_count > 0}
          >
            <FindingsTable findings={result.fixed_findings} label="fixed findings" />
          </CollapsibleSection>

          <CollapsibleSection
            title="Unchanged Findings"
            icon="⚪"
            count={result.summary.unchanged_count}
            colorClass="bg-neutral-500/20 text-neutral-400"
          >
            <FindingsTable findings={result.unchanged_findings} label="unchanged findings" />
          </CollapsibleSection>
        </div>
      )}
    </div>
  );
}
