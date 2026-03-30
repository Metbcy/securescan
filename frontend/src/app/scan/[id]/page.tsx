"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { ArrowLeft, AlertTriangle, Clock, CheckCircle, XCircle } from "lucide-react";
import Link from "next/link";
import { fetchScan, fetchFindings, fetchScanSummary } from "@/lib/api";
import type { Scan, Finding, ScanSummary } from "@/lib/api";
import { RiskScore } from "@/components/risk-score";
import { SeverityChart } from "@/components/severity-chart";
import { FindingsTable } from "@/components/findings-table";

const STATUS_ICON: Record<string, React.ElementType> = {
  completed: CheckCircle,
  running: Clock,
  failed: XCircle,
  pending: Clock,
};

const STATUS_COLOR: Record<string, string> = {
  completed: "text-green-400",
  running: "text-blue-400",
  failed: "text-red-400",
  pending: "text-zinc-400",
};

export default function ScanDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    async function load() {
      try {
        const scanData = await fetchScan(id);
        setScan(scanData);

        if (scanData.status === "completed") {
          const [fin, sum] = await Promise.all([
            fetchFindings(id),
            fetchScanSummary(id),
          ]);
          setFindings(fin);
          setSummary(sum);
        }
      } catch {
        setError("Failed to load scan details");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id]);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-48 bg-[#141414] rounded animate-pulse" />
        <div className="h-32 bg-[#141414] border border-[#262626] rounded-xl animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="h-64 bg-[#141414] border border-[#262626] rounded-xl animate-pulse" />
          <div className="h-64 bg-[#141414] border border-[#262626] rounded-xl animate-pulse" />
        </div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="space-y-6">
        <Link href="/history" className="inline-flex items-center gap-1.5 text-sm text-[#a1a1aa] hover:text-white transition-colors">
          <ArrowLeft size={16} /> Back to History
        </Link>
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-6 text-center">
          <AlertTriangle size={32} className="mx-auto mb-3 text-red-400" />
          <p className="text-red-400 font-medium">{error || "Scan not found"}</p>
        </div>
      </div>
    );
  }

  const StatusIcon = STATUS_ICON[scan.status] ?? Clock;

  return (
    <div className="space-y-6">
      <Link href="/history" className="inline-flex items-center gap-1.5 text-sm text-[#a1a1aa] hover:text-white transition-colors">
        <ArrowLeft size={16} /> Back to History
      </Link>

      {/* Scan metadata */}
      <div className="rounded-xl border border-[#262626] bg-[#141414] p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold tracking-tight mb-1">{scan.target_path}</h1>
            <div className="flex flex-wrap items-center gap-3 text-sm text-[#a1a1aa]">
              <span className={`inline-flex items-center gap-1 ${STATUS_COLOR[scan.status]}`}>
                <StatusIcon size={14} />
                {scan.status}
              </span>
              <span>{scan.findings_count} findings</span>
              {scan.scan_types && (
                <span>{scan.scan_types.join(", ")}</span>
              )}
              {scan.started_at && (
                <span>{new Date(scan.started_at).toLocaleString()}</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* AI Summary */}
      {scan.summary && (
        <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-5">
          <h2 className="text-sm font-medium text-blue-400 mb-2">AI Summary</h2>
          <p className="text-sm text-[#a1a1aa] leading-relaxed whitespace-pre-wrap">
            {scan.summary}
          </p>
        </div>
      )}

      {/* Risk Score + Chart */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-xl border border-[#262626] bg-[#141414] p-6 flex items-center justify-center">
            <RiskScore score={summary.risk_score} />
          </div>
          <div className="rounded-xl border border-[#262626] bg-[#141414] p-6">
            <h2 className="text-sm font-medium text-[#a1a1aa] mb-4">Findings by Severity</h2>
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

      {/* Findings table */}
      {findings.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-3">All Findings</h2>
          <FindingsTable findings={findings} />
        </div>
      )}

      {/* Error info */}
      {scan.status === "failed" && scan.error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-5">
          <h2 className="text-sm font-medium text-red-400 mb-2">Error</h2>
          <p className="text-sm text-red-300 font-mono">{scan.error}</p>
        </div>
      )}
    </div>
  );
}
