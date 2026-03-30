"use client";

import { Fragment, useState } from "react";
import { ChevronDown, ChevronRight, FileCode } from "lucide-react";
import type { Finding } from "@/lib/api";

interface FindingsTableProps {
  findings: Finding[];
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/20",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/20",
  info: "bg-zinc-500/15 text-zinc-400 border-zinc-500/20",
};

export function FindingsTable({ findings }: FindingsTableProps) {
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const sorted = [...findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
  );

  const toggle = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-[#52525b]">
        <FileCode size={40} className="mb-3" />
        <p className="text-sm">No findings to display</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-[#262626]">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#262626] text-left text-xs text-[#a1a1aa] uppercase tracking-wider">
            <th className="px-4 py-3 w-8" />
            <th className="px-4 py-3">Severity</th>
            <th className="px-4 py-3">Scanner</th>
            <th className="px-4 py-3">Title</th>
            <th className="px-4 py-3">File</th>
            <th className="px-4 py-3">Line</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((f) => {
            const expanded = expandedIds.has(f.id);
            return (
              <Fragment key={f.id}>
                <tr
                  onClick={() => toggle(f.id)}
                  className="border-b border-[#1a1a1a] cursor-pointer hover:bg-[#141414] transition-colors"
                >
                  <td className="px-4 py-3 text-[#52525b]">
                    {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-block px-2.5 py-0.5 rounded-full text-xs font-medium border ${
                        SEVERITY_COLORS[f.severity] ?? ""
                      }`}
                    >
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[#a1a1aa]">{f.scanner}</td>
                  <td className="px-4 py-3 font-medium max-w-xs truncate">{f.title}</td>
                  <td className="px-4 py-3 text-[#a1a1aa] font-mono text-xs max-w-[200px] truncate">
                    {f.file_path ?? "—"}
                  </td>
                  <td className="px-4 py-3 text-[#a1a1aa] font-mono text-xs">
                    {f.line_start != null ? f.line_start : "—"}
                  </td>
                </tr>
                {expanded && (
                  <tr className="bg-[#0e0e0e]">
                    <td colSpan={6} className="px-6 py-4">
                      <div className="space-y-3 text-sm">
                        {f.description && (
                          <div>
                            <p className="text-xs text-[#52525b] uppercase tracking-wider mb-1">
                              Description
                            </p>
                            <p className="text-[#a1a1aa] leading-relaxed">{f.description}</p>
                          </div>
                        )}
                        {f.remediation && (
                          <div>
                            <p className="text-xs text-[#52525b] uppercase tracking-wider mb-1">
                              Remediation
                            </p>
                            <p className="text-[#a1a1aa] leading-relaxed">{f.remediation}</p>
                          </div>
                        )}
                        {f.cwe && (
                          <p className="text-xs text-[#52525b]">
                            CWE: <span className="text-[#a1a1aa]">{f.cwe}</span>
                          </p>
                        )}
                        {f.rule_id && (
                          <p className="text-xs text-[#52525b]">
                            Rule: <span className="text-[#a1a1aa]">{f.rule_id}</span>
                          </p>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
