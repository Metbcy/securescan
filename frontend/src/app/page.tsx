"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ScanSearch, AlertTriangle, BarChart3, TrendingUp } from "lucide-react";
import { StatCard } from "@/components/stat-card";
import { RiskScore } from "@/components/risk-score";
import { SeverityChart } from "@/components/severity-chart";
import { TrendChart } from "@/components/trend-chart";
import { FindingsTable } from "@/components/findings-table";
import type { DashboardStats, Scan, ScanSummary, Finding, TrendPoint } from "@/lib/api";
import {
  fetchDashboardStats,
  fetchScans,
  fetchScanSummary,
  fetchFindings,
  fetchTrends,
} from "@/lib/api";

export default function Home() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [latestScan, setLatestScan] = useState<Scan | null>(null);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [trends, setTrends] = useState<TrendPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [statsData, scans] = await Promise.all([
          fetchDashboardStats(),
          fetchScans(),
        ]);
        setStats(statsData);

        // Fetch trends (non-blocking — don't fail the page if this errors)
        fetchTrends(30).then(setTrends).catch(() => {});

        if (scans.length > 0) {
          const latest = scans[0];
          setLatestScan(latest);

          if (latest.status === "completed") {
            const [sum, fin] = await Promise.all([
              fetchScanSummary(latest.id),
              fetchFindings(latest.id),
            ]);
            setSummary(sum);
            setFindings(fin);
          }
        }
      } catch {
        setError("Backend not connected. Make sure the API server is running on port 8000.");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold tracking-tight">Overview</h1>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-28 rounded-xl bg-[#141414] border border-[#262626] animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="h-64 rounded-xl bg-[#141414] border border-[#262626] animate-pulse" />
          <div className="h-64 rounded-xl bg-[#141414] border border-[#262626] animate-pulse" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold tracking-tight">Overview</h1>
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-6 text-center">
          <AlertTriangle size={32} className="mx-auto mb-3 text-red-400" />
          <p className="text-red-400 font-medium">{error}</p>
        </div>
      </div>
    );
  }

  if (!stats || stats.total_scans === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold tracking-tight">Overview</h1>
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <ScanSearch size={48} className="text-[#52525b] mb-4" />
          <h2 className="text-xl font-semibold mb-2">No scans yet</h2>
          <p className="text-[#a1a1aa] mb-6">Run your first security scan to get started.</p>
          <Link
            href="/scan"
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition-colors"
          >
            <ScanSearch size={16} />
            New Scan
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Overview</h1>

      {/* Stats row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard title="Total Scans" value={stats.total_scans} icon={ScanSearch} />
        <StatCard title="Total Findings" value={stats.total_findings} icon={AlertTriangle} />
        <StatCard
          title="Avg Risk Score"
          value={Math.round(stats.average_risk_score)}
          icon={BarChart3}
        />
      </div>

      {/* Risk Score + Severity Chart */}
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

      {/* Trend Chart */}
      {trends.length > 0 && (
        <div className="rounded-xl border border-[#262626] bg-[#141414] p-6">
          <h2 className="text-sm font-medium text-[#a1a1aa] mb-4 flex items-center gap-2">
            <TrendingUp size={16} />
            Security Trends (30 days)
          </h2>
          <TrendChart data={trends} />
        </div>
      )}

      {/* Latest scan findings */}
      {findings.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-3">
            Latest Scan Findings
            {latestScan && (
              <span className="text-sm font-normal text-[#a1a1aa] ml-2">
                {latestScan.target_path}
              </span>
            )}
          </h2>
          <FindingsTable findings={findings} />
        </div>
      )}
    </div>
  );
}
