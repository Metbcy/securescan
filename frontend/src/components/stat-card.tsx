import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
}

export function StatCard({ title, value, icon: Icon, trend }: StatCardProps) {
  return (
    <div className="rounded-xl border border-[#262626] bg-[#141414] p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-3xl font-bold tracking-tight tabular-nums">{value}</p>
          <p className="text-sm text-[#a1a1aa] mt-1">{title}</p>
          {trend && (
            <p className="text-xs text-blue-500 mt-1.5">{trend}</p>
          )}
        </div>
        <div className="p-2.5 rounded-lg bg-[#1a1a1a]">
          <Icon size={20} className="text-[#52525b]" />
        </div>
      </div>
    </div>
  );
}
