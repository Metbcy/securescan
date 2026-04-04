"use client";

import { useState } from "react";
import { Package, Loader2, Download, FolderOpen } from "lucide-react";
import { generateSBOM } from "@/lib/api";
import { DirectoryPicker } from "@/components/directory-picker";

export default function SBOMPage() {
  const [targetPath, setTargetPath] = useState("");
  const [format, setFormat] = useState<"cyclonedx" | "spdx">("cyclonedx");
  const [loading, setLoading] = useState(false);
  const [sbom, setSbom] = useState<{ sbom_id: string; component_count: number; document: Record<string, unknown> } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetPath.trim()) return;
    setLoading(true);
    setError(null);
    setSbom(null);
    try {
      const result = await generateSBOM(targetPath.trim(), format);
      setSbom(result);
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
    <div className="space-y-6 max-w-3xl">
      <h1 className="text-2xl font-bold tracking-tight">SBOM Generator</h1>
      <p className="text-sm text-[#a1a1aa]">Generate a Software Bill of Materials for any project directory.</p>

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
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-medium">SBOM Generated</h3>
              <p className="text-sm text-[#a1a1aa]">{sbom.component_count} components found</p>
            </div>
            <button onClick={handleDownload}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#262626] bg-[#141414] text-sm hover:bg-[#1a1a1a] transition-colors">
              <Download size={14} />Download JSON
            </button>
          </div>
          <div className="rounded-xl border border-[#262626] bg-[#141414] p-4 max-h-96 overflow-auto">
            <pre className="text-xs text-[#a1a1aa] whitespace-pre-wrap">{JSON.stringify(sbom.document, null, 2)}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
