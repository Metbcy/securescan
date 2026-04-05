"use client";

import { useState, useMemo, useEffect } from "react";
import { Package, Loader2, Download, FolderOpen, ChevronDown, ChevronRight, Search, History, Clock, FolderCode, Eye } from "lucide-react";
import { generateSBOM, fetchSBOMHistory, exportSBOM } from "@/lib/api";
import type { SBOMHistoryEntry } from "@/lib/api";
import { DirectoryPicker } from "@/components/directory-picker";

interface ParsedComponent {
  name: string;
  version: string;
  type: string;
  purl: string;
  license: string;
  ecosystem: string;
}

function parseComponents(doc: Record<string, unknown>, format: string): ParsedComponent[] {
  if (format === "cyclonedx") {
    const components = (doc.components ?? []) as Record<string, unknown>[];
    return components.map((c) => {
      const purl = (c.purl as string) || "";
      return {
        name: (c.name as string) || "",
        version: (c.version as string) || "",
        type: (c.type as string) || "library",
        purl,
        license: ((c.licenses as { license?: { name?: string; id?: string } }[])?.[0]?.license?.name
          || (c.licenses as { license?: { name?: string; id?: string } }[])?.[0]?.license?.id
          || ""),
        ecosystem: purlToEcosystem(purl),
      };
    });
  } else {
    // SPDX
    const packages = (doc.packages ?? []) as Record<string, unknown>[];
    return packages.map((p) => {
      const refs = (p.externalRefs ?? []) as { referenceType?: string; referenceLocator?: string }[];
      const purlRef = refs.find((r) => r.referenceType === "purl");
      const purl = purlRef?.referenceLocator || "";
      const license = (p.licenseDeclared as string) || (p.licenseConcluded as string) || "";
      return {
        name: (p.name as string) || "",
        version: (p.versionInfo as string) || "",
        type: "library",
        purl,
        license: license === "NOASSERTION" ? "" : license,
        ecosystem: purlToEcosystem(purl),
      };
    });
  }
}

function purlToEcosystem(purl: string): string {
  if (!purl) return "unknown";
  const match = purl.match(/^pkg:(\w+)\//);
  if (!match) return "unknown";
  const map: Record<string, string> = {
    npm: "npm",
    pypi: "Python",
    golang: "Go",
    cargo: "Rust",
    gem: "Ruby",
    composer: "PHP",
    maven: "Java",
    nuget: ".NET",
  };
  return map[match[1]] || match[1];
}

const ECOSYSTEM_COLORS: Record<string, string> = {
  npm: "bg-red-500/15 text-red-400 border-red-500/20",
  Python: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
  Go: "bg-cyan-500/15 text-cyan-400 border-cyan-500/20",
  Rust: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  Ruby: "bg-pink-500/15 text-pink-400 border-pink-500/20",
  PHP: "bg-purple-500/15 text-purple-400 border-purple-500/20",
  Java: "bg-blue-500/15 text-blue-400 border-blue-500/20",
  ".NET": "bg-violet-500/15 text-violet-400 border-violet-500/20",
};

export default function SBOMPage() {
  const [targetPath, setTargetPath] = useState("");
  const [format, setFormat] = useState<"cyclonedx" | "spdx">("cyclonedx");
  const [loading, setLoading] = useState(false);
  const [sbom, setSbom] = useState<{ sbom_id: string; component_count: number; document: Record<string, unknown> } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [showRawJson, setShowRawJson] = useState(false);
  const [tab, setTab] = useState<"generate" | "history">("generate");
  const [history, setHistory] = useState<SBOMHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [viewingSbomId, setViewingSbomId] = useState<string | null>(null);
  const [viewingLoading, setViewingLoading] = useState(false);

  useEffect(() => {
    if (tab === "history") {
      setHistoryLoading(true);
      setHistoryError(null);
      fetchSBOMHistory()
        .then(setHistory)
        .catch(() => setHistoryError("Failed to load SBOM history. Is the backend running?"))
        .finally(() => setHistoryLoading(false));
    }
  }, [tab]);

  const handleViewSbom = async (entry: SBOMHistoryEntry) => {
    setViewingLoading(true);
    setViewingSbomId(entry.id);
    try {
      const exported = await exportSBOM(entry.id, entry.format);
      setSbom({ sbom_id: entry.id, component_count: entry.component_count, document: exported });
      setFormat(entry.format as "cyclonedx" | "spdx");
      setSearch("");
      setShowRawJson(false);
      setTab("generate");
    } catch {
      setHistoryError("Failed to load SBOM details");
    } finally {
      setViewingLoading(false);
      setViewingSbomId(null);
    }
  };

  const components = useMemo(() => {
    if (!sbom) return [];
    return parseComponents(sbom.document, format);
  }, [sbom, format]);

  const filtered = useMemo(() => {
    if (!search.trim()) return components;
    const q = search.toLowerCase();
    return components.filter(
      (c) => c.name.toLowerCase().includes(q) || c.version.includes(q) || c.ecosystem.toLowerCase().includes(q) || c.purl.toLowerCase().includes(q)
    );
  }, [components, search]);

  const ecosystemStats = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const c of components) {
      counts[c.ecosystem] = (counts[c.ecosystem] || 0) + 1;
    }
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [components]);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetPath.trim()) return;
    setLoading(true);
    setError(null);
    setSbom(null);
    setSearch("");
    setShowRawJson(false);
    try {
      const result = await generateSBOM(targetPath.trim(), format);
      setSbom(result);
      // Refresh history in background so new entry appears
      fetchSBOMHistory().then(setHistory).catch(() => {});
    } catch {
      setError("Failed to generate SBOM. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = () => {
    if (!sbom) return;
    const blob = new Blob([JSON.stringify(sbom.document, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sbom-${sbom.sbom_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-5xl">
      <h1 className="text-2xl font-bold tracking-tight">SBOM Generator</h1>
      <p className="text-sm text-[#a1a1aa]">Generate a Software Bill of Materials for any project directory.</p>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[#262626]">
        {([
          { key: "generate" as const, label: "Generate", icon: Package },
          { key: "history" as const, label: "History", icon: History },
        ]).map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px ${
              tab === key
                ? "border-blue-500 text-blue-500"
                : "border-transparent text-[#a1a1aa] hover:text-[#ededed] hover:border-[#404040]"
            }`}
          >
            <Icon size={16} />
            {label}
          </button>
        ))}
      </div>

      {/* History tab */}
      {tab === "history" && (
        <div className="space-y-4">
          {historyLoading && (
            <div className="flex items-center justify-center py-16">
              <Loader2 size={24} className="animate-spin text-[#52525b]" />
            </div>
          )}
          {historyError && (
            <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4">
              <p className="text-sm text-red-400">{historyError}</p>
            </div>
          )}
          {!historyLoading && !historyError && history.length === 0 && (
            <div className="flex flex-col items-center justify-center py-24 text-center">
              <Package size={48} className="text-[#52525b] mb-4" />
              <h2 className="text-xl font-semibold mb-2">No SBOMs generated yet</h2>
              <p className="text-[#a1a1aa]">Generate your first SBOM and it will appear here.</p>
            </div>
          )}
          {!historyLoading && history.length > 0 && (
            <div className="rounded-xl border border-[#262626] overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-[#141414]">
                  <tr className="border-b border-[#262626]">
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Target Path</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Format</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Components</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Generated</th>
                    <th className="px-4 py-3 text-right text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#262626]">
                  {history.map((entry) => (
                    <tr key={entry.id} className="hover:bg-[#141414]/50 transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <FolderCode size={14} className="text-[#52525b] shrink-0" />
                          <span className="font-mono text-xs text-[#ededed] truncate max-w-[300px]" title={entry.target_path}>
                            {entry.target_path}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="inline-block px-2 py-0.5 rounded text-xs font-medium border bg-blue-500/10 text-blue-400 border-blue-500/20">
                          {entry.format === "cyclonedx" ? "CycloneDX" : "SPDX"}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[#a1a1aa] font-medium">{entry.component_count}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5 text-xs text-[#a1a1aa]">
                          <Clock size={12} />
                          {new Date(entry.created_at).toLocaleString()}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => handleViewSbom(entry)}
                          disabled={viewingLoading && viewingSbomId === entry.id}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#262626] bg-[#141414] text-xs hover:bg-[#1a1a1a] transition-colors disabled:opacity-50"
                        >
                          {viewingLoading && viewingSbomId === entry.id ? (
                            <Loader2 size={12} className="animate-spin" />
                          ) : (
                            <Eye size={12} />
                          )}
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Generate tab */}
      {tab === "generate" && <>
      <form onSubmit={handleGenerate} className="space-y-5">
        <div>
          <label className="block text-sm font-medium text-[#a1a1aa] mb-2">Target Path</label>
          <div className="flex">
            <input type="text" value={targetPath} onChange={(e) => setTargetPath(e.target.value)}
              placeholder="/path/to/your/project"
              className="flex-1 px-4 py-2.5 rounded-l-lg bg-[#141414] border border-[#262626] border-r-0 text-[#ededed] placeholder-[#52525b] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors" />
            <button type="button" onClick={() => setPickerOpen(true)}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-r-lg bg-[#141414] border border-[#262626] text-[#a1a1aa] hover:bg-[#1a1a1a] hover:text-[#ededed] transition-colors">
              <FolderOpen size={16} /><span className="text-sm">Browse</span>
            </button>
          </div>
        </div>

        <DirectoryPicker isOpen={pickerOpen} onClose={() => setPickerOpen(false)}
          onSelect={(path) => { setTargetPath(path); setPickerOpen(false); }}
          initialPath={targetPath || undefined} />

        <div>
          <label className="block text-sm font-medium text-[#a1a1aa] mb-2">Format</label>
          <div className="flex gap-3">
            {(["cyclonedx", "spdx"] as const).map((f) => (
              <label key={f} className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border cursor-pointer transition-colors ${format === f ? "border-blue-500/40 bg-blue-500/10" : "border-[#262626] bg-[#141414] hover:border-[#404040]"}`}>
                <input type="radio" name="format" value={f} checked={format === f} onChange={() => setFormat(f)} className="sr-only" />
                <span className="text-sm font-medium">{f === "cyclonedx" ? "CycloneDX 1.5" : "SPDX 2.3"}</span>
              </label>
            ))}
          </div>
        </div>

        <button type="submit" disabled={loading || !targetPath.trim()}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
          {loading ? (<><Loader2 size={16} className="animate-spin" />Generating...</>) : (<><Package size={16} />Generate SBOM</>)}
        </button>
      </form>

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {sbom && (
        <div className="space-y-5">
          {/* Header with stats */}
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold">SBOM Generated</h3>
              <p className="text-sm text-[#a1a1aa]">{sbom.component_count} components found</p>
            </div>
            <button onClick={handleDownload}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#262626] bg-[#141414] text-sm hover:bg-[#1a1a1a] transition-colors">
              <Download size={14} />Download {format === "cyclonedx" ? "CycloneDX" : "SPDX"} JSON
            </button>
          </div>

          {/* Ecosystem breakdown */}
          {ecosystemStats.length > 0 && (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
              {ecosystemStats.map(([eco, count]) => (
                <div key={eco} className="rounded-lg border border-[#262626] bg-[#141414] p-3 text-center">
                  <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium mb-2 border ${ECOSYSTEM_COLORS[eco] || "bg-[#262626] text-[#a1a1aa] border-[#404040]"}`}>
                    {eco}
                  </span>
                  <p className="text-xl font-bold">{count}</p>
                </div>
              ))}
            </div>
          )}

          {/* Search */}
          <div className="relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#52525b]" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter components by name, version, or ecosystem..."
              className="w-full pl-9 pr-4 py-2 rounded-lg bg-[#141414] border border-[#262626] text-sm text-[#ededed] placeholder-[#52525b] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors"
            />
          </div>

          {/* Components table */}
          <div className="rounded-xl border border-[#262626] overflow-hidden">
            <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="bg-[#141414] sticky top-0 z-10">
                  <tr className="border-b border-[#262626]">
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Name</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Version</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Ecosystem</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">License</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">PURL</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#262626]">
                  {filtered.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-[#52525b]">
                        {search ? "No components match your search" : "No components found"}
                      </td>
                    </tr>
                  ) : (
                    filtered.map((c, i) => (
                      <tr key={i} className="hover:bg-[#141414]/50 transition-colors">
                        <td className="px-4 py-2.5 font-medium text-[#ededed]">{c.name}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-[#a1a1aa]">{c.version}</td>
                        <td className="px-4 py-2.5">
                          <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium border ${ECOSYSTEM_COLORS[c.ecosystem] || "bg-[#262626] text-[#a1a1aa] border-[#404040]"}`}>
                            {c.ecosystem}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-[#a1a1aa] text-xs">{c.license || <span className="text-[#52525b]">—</span>}</td>
                        <td className="px-4 py-2.5 font-mono text-[10px] text-[#52525b] max-w-[200px] truncate">{c.purl || "—"}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            {search && filtered.length !== components.length && (
              <div className="px-4 py-2 bg-[#141414] border-t border-[#262626] text-xs text-[#52525b]">
                Showing {filtered.length} of {components.length} components
              </div>
            )}
          </div>

          {/* Raw JSON toggle */}
          <button
            onClick={() => setShowRawJson(!showRawJson)}
            className="inline-flex items-center gap-1.5 text-xs text-[#52525b] hover:text-[#a1a1aa] transition-colors"
          >
            {showRawJson ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            Raw JSON
          </button>
          {showRawJson && (
            <div className="rounded-xl border border-[#262626] bg-[#141414] p-4 max-h-72 overflow-auto">
              <pre className="text-xs text-[#a1a1aa] whitespace-pre-wrap">{JSON.stringify(sbom.document, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
      </>}
    </div>
  );
}
