"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle, XCircle, Settings } from "lucide-react";
import { fetchScannerStatus } from "@/lib/api";
import type { ScannerStatus } from "@/lib/api";

export default function ScannersPage() {
  const [scanners, setScanners] = useState<ScannerStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchScannerStatus()
      .then(setScanners)
      .catch(() => setError("Failed to load scanner status"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold tracking-tight">Scanners</h1>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-36 rounded-xl bg-[#141414] border border-[#262626] animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold tracking-tight">Scanners</h1>
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-6 text-center">
          <AlertTriangle size={32} className="mx-auto mb-3 text-red-400" />
          <p className="text-red-400 font-medium">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Scanners</h1>

      {scanners.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-24 text-center">
          <Settings size={48} className="text-[#52525b] mb-4" />
          <h2 className="text-xl font-semibold mb-2">No scanners configured</h2>
          <p className="text-[#a1a1aa]">Configure scanners in the backend to get started.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {scanners.map((scanner) => (
            <div
              key={scanner.name}
              className="rounded-xl border border-[#262626] bg-[#141414] p-5"
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <h3 className="font-semibold">{scanner.name}</h3>
                  <p className="text-xs text-[#a1a1aa] mt-0.5">{scanner.scan_type}</p>
                </div>
                {scanner.available ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/15 text-green-400">
                    <CheckCircle size={12} />
                    Available
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/15 text-red-400">
                    <XCircle size={12} />
                    Unavailable
                  </span>
                )}
              </div>
              <p className="text-sm text-[#a1a1aa] leading-relaxed">{scanner.message}</p>
              {!scanner.available && (
                <div className="mt-3 p-3 rounded-lg bg-[#0e0e0e] border border-[#1a1a1a]">
                  <p className="text-xs text-[#52525b]">
                    Install the scanner tool to enable this scan type. Check the backend documentation for setup instructions.
                  </p>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
