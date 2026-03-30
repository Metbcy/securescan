import Link from "next/link";
import { AlertTriangle, CheckCircle, Loader2, Clock, XCircle } from "lucide-react";
import type { Scan } from "@/lib/api";

interface ScanCardProps {
  scan: Scan;
}

const STATUS_CONFIG: Record<
  string,
  { color: string; bg: string; icon: React.ElementType; pulse?: boolean }
> = {
  completed: { color: "text-green-400", bg: "bg-green-500/15", icon: CheckCircle },
  running: { color: "text-blue-400", bg: "bg-blue-500/15", icon: Loader2, pulse: true },
  failed: { color: "text-red-400", bg: "bg-red-500/15", icon: XCircle },
  pending: { color: "text-zinc-400", bg: "bg-zinc-500/15", icon: Clock },
};

export function ScanCard({ scan }: ScanCardProps) {
  const cfg = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.pending;
  const Icon = cfg.icon;
  const date = scan.completed_at ?? scan.started_at;

  return (
    <Link
      href={`/scan/${scan.id}`}
      className="block rounded-xl border border-[#262626] bg-[#141414] p-5 hover:border-[#404040] hover:bg-[#1a1a1a] transition-all"
    >
      <div className="flex items-start justify-between gap-3 mb-3">
        <p className="text-sm font-medium truncate flex-1" title={scan.target_path}>
          {scan.target_path}
        </p>
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${cfg.bg} ${cfg.color}`}
        >
          <Icon size={12} className={cfg.pulse ? "animate-spin" : ""} />
          {scan.status}
        </span>
      </div>

      <div className="flex items-center gap-4 text-xs text-[#a1a1aa]">
        <span className="flex items-center gap-1">
          <AlertTriangle size={12} />
          {scan.findings_count} findings
        </span>
        {scan.risk_score != null && (
          <span>Risk: {scan.risk_score}</span>
        )}
        {date && (
          <span className="ml-auto">
            {new Date(date).toLocaleDateString()}
          </span>
        )}
      </div>
    </Link>
  );
}
