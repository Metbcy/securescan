"use client";

import { useEffect, useState } from "react";
import { History, AlertTriangle } from "lucide-react";
import { fetchScans } from "@/lib/api";
import type { Scan } from "@/lib/api";
import { ScanCard } from "@/components/scan-card";

export default function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchScans()
      .then(setScans)
      .catch(() => setError("Failed to load scan history"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold tracking-tight">Scan History</h1>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <div key={i} className="h-28 rounded-xl bg-[#141414] border border-[#262626] animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold tracking-tight">Scan History</h1>
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-6 text-center">
          <AlertTriangle size={32} className="mx-auto mb-3 text-red-400" />
          <p className="text-red-400 font-medium">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Scan History</h1>

      {scans.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <History size={48} className="text-[#52525b] mb-4" />
          <h2 className="text-xl font-semibold mb-2">No scans found</h2>
          <p className="text-[#a1a1aa]">Your scan history will appear here.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {scans.map((scan) => (
            <ScanCard key={scan.id} scan={scan} />
          ))}
        </div>
      )}
    </div>
  );
}
