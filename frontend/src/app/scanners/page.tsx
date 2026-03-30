"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle, XCircle, Settings, Shield, ChevronDown, ChevronUp } from "lucide-react";
import { fetchScannerStatus } from "@/lib/api";
import type { ScannerStatus } from "@/lib/api";

const TYPE_LABELS: Record<string, string> = {
  code: "Code Analysis",
  dependency: "Dependency Scan",
  iac: "Infrastructure as Code",
  baseline: "System Configuration",
};

export default function ScannersPage() {
  const [scanners, setScanners] = useState<ScannerStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleExpand = (name: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  useEffect(() => {
    fetchScannerStatus()
      .then(setScanners)
      .catch(() => setError("Failed to load scanner status. Is the backend running?"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold tracking-tight">Scanners</h1>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <div key={i} className="h-48 rounded-xl bg-[#141414] border border-[#262626] animate-pulse" />
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
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Scanners</h1>
        <p className="text-[#a1a1aa] text-sm mt-1">
          {scanners.filter((s) => s.available).length} of {scanners.length} scanners available
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {scanners.map((scanner) => {
          const isExpanded = expanded.has(scanner.name);
          return (
            <div
              key={scanner.name}
              className="rounded-xl border border-[#262626] bg-[#141414] overflow-hidden"
            >
              <div className="p-5">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2.5">
                    <Shield size={18} className={scanner.available ? "text-blue-400" : "text-[#52525b]"} />
                    <div>
                      <h3 className="font-semibold capitalize">{scanner.name}</h3>
                      <p className="text-xs text-[#71717a] mt-0.5">
                        {TYPE_LABELS[scanner.scan_type] || scanner.scan_type}
                      </p>
                    </div>
                  </div>
                  {scanner.available ? (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/15 text-green-400">
                      <CheckCircle size={12} />
                      Active
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-500/15 text-red-400">
                      <XCircle size={12} />
                      Not Installed
                    </span>
                  )}
                </div>

                <p className="text-sm text-[#a1a1aa] leading-relaxed mt-3">
                  {scanner.description}
                </p>

                <button
                  onClick={() => toggleExpand(scanner.name)}
                  className="flex items-center gap-1 mt-3 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                >
                  {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  {isExpanded ? "Hide" : "Show"} what it checks ({scanner.checks.length})
                </button>
              </div>

              {isExpanded && (
                <div className="px-5 pb-5 pt-0">
                  <ul className="space-y-1.5 border-t border-[#1e1e1e] pt-3">
                    {scanner.checks.map((check, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-[#a1a1aa]">
                        <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-blue-500/60 shrink-0" />
                        {check}
                      </li>
                    ))}
                  </ul>

                  {!scanner.available && scanner.install_hint && (
                    <div className="mt-3 p-3 rounded-lg bg-[#0e0e0e] border border-[#1a1a1a]">
                      <p className="text-xs text-[#71717a] font-mono">
                        Install: {scanner.install_hint}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
