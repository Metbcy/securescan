"use client";

import { useEffect, useState } from "react";
import { History, AlertTriangle } from "lucide-react";
import { fetchScans, cancelScan } from "@/lib/api";
import type { Scan } from "@/lib/api";
import { ScanCard } from "@/components/scan-card";

export default function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [cancellingIds, setCancellingIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    fetchScans()
      .then(setScans)
      .catch(() => setLoadError("Failed to load scan history"))
      .finally(() => setLoading(false));
  }, []);

  const handleCancel = async (scanId: string) => {
    setActionError(null);
    setCancellingIds((prev) => new Set(prev).add(scanId));
    try {
      const updated = await cancelScan(scanId);
      setScans((prev) => prev.map((scan) => (scan.id === scanId ? updated : scan)));
    } catch {
      setActionError("Failed to stop scan");
    } finally {
      setCancellingIds((prev) => {
        const next = new Set(prev);
        next.delete(scanId);
        return next;
      });
    }
  };

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

  if (loadError) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold tracking-tight">Scan History</h1>
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-6 text-center">
          <AlertTriangle size={32} className="mx-auto mb-3 text-red-400" />
          <p className="text-red-400 font-medium">{loadError}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Scan History</h1>

      {actionError && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 flex items-center gap-3">
          <AlertTriangle size={18} className="text-red-400 shrink-0" />
          <p className="text-red-400 text-sm">{actionError}</p>
        </div>
      )}

      {scans.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <History size={48} className="text-[#52525b] mb-4" />
          <h2 className="text-xl font-semibold mb-2">No scans found</h2>
          <p className="text-[#a1a1aa]">Your scan history will appear here.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {scans.map((scan) => (
            <ScanCard
              key={scan.id}
              scan={scan}
              onCancel={handleCancel}
              cancelling={cancellingIds.has(scan.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
