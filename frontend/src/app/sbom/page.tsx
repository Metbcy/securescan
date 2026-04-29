"use client";

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ChevronsUpDown,
  Download,
  FolderOpen,
  Loader2,
  Package,
  Search,
  X,
} from "lucide-react";
import {
  exportSBOM,
  fetchSBOMHistory,
  generateSBOM,
} from "@/lib/api";
import type { SBOMHistoryEntry } from "@/lib/api";
import { DirectoryPicker } from "@/components/directory-picker";

// ──────────────────────────────────────────────────────────────────────────────
// Inline page header (DSH3 primitive not yet on origin/main).
// ──────────────────────────────────────────────────────────────────────────────

function PageHeader({
  title,
  meta,
  actions,
}: {
  title: string;
  meta: string;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between md:gap-6">
      <div className="space-y-1.5 min-w-0">
        <h1 className="text-3xl font-semibold tracking-tight text-foreground-strong leading-tight">
          {title}
        </h1>
        <p className="text-sm text-muted max-w-prose leading-relaxed">{meta}</p>
      </div>
      {actions ? (
        <div className="flex shrink-0 items-center gap-2">{actions}</div>
      ) : null}
    </header>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Component-row model. Normalised across CycloneDX + SPDX so the table is the
// same in both formats.
// ──────────────────────────────────────────────────────────────────────────────

interface ComponentRow {
  name: string;
  version: string;
  license: string;
  source: string;
  vulnerable: "critical" | "high" | "medium" | "low" | "info" | null;
  purl: string;
}

function purlEcosystem(purl: string): string {
  if (!purl) return "unknown";
  const m = purl.match(/^pkg:([^/]+)\//);
  if (!m) return "unknown";
  const map: Record<string, string> = {
    npm: "npm",
    pypi: "PyPI",
    golang: "Go",
    cargo: "Cargo",
    gem: "RubyGems",
    composer: "Composer",
    maven: "Maven",
    nuget: "NuGet",
    deb: "deb",
    rpm: "rpm",
    apk: "apk",
    docker: "Docker",
    oci: "OCI",
    generic: "generic",
  };
  return map[m[1]] ?? m[1];
}

function parseComponents(
  doc: Record<string, unknown> | null,
  format: string,
): ComponentRow[] {
  if (!doc) return [];
  if (format === "cyclonedx") {
    const components = (doc.components ?? []) as Record<string, unknown>[];
    return components.map((c) => {
      const purl = (c.purl as string) ?? "";
      const licenses = (c.licenses ?? []) as {
        license?: { name?: string; id?: string };
        expression?: string;
      }[];
      const license =
        licenses[0]?.license?.id ??
        licenses[0]?.license?.name ??
        licenses[0]?.expression ??
        "";
      return {
        name: (c.name as string) ?? "",
        version: (c.version as string) ?? "",
        license,
        source: purlEcosystem(purl),
        vulnerable: null,
        purl,
      };
    });
  }
  // SPDX
  const packages = (doc.packages ?? []) as Record<string, unknown>[];
  return packages.map((p) => {
    const refs = (p.externalRefs ?? []) as {
      referenceType?: string;
      referenceLocator?: string;
    }[];
    const purl = refs.find((r) => r.referenceType === "purl")?.referenceLocator ?? "";
    const declared = (p.licenseDeclared as string) ?? "";
    const concluded = (p.licenseConcluded as string) ?? "";
    const license =
      declared && declared !== "NOASSERTION"
        ? declared
        : concluded && concluded !== "NOASSERTION"
        ? concluded
        : "";
    return {
      name: (p.name as string) ?? "",
      version: (p.versionInfo as string) ?? "",
      license,
      source: purlEcosystem(purl),
      vulnerable: null,
      purl,
    };
  });
}

// ──────────────────────────────────────────────────────────────────────────────
// Tokens for severity pills (used when a component has known vulns — placeholder
// today, but the column is wired up so when CVE matching lands the colours are
// already correct).
// ──────────────────────────────────────────────────────────────────────────────

const SEV_PILL: Record<NonNullable<ComponentRow["vulnerable"]>, string> = {
  critical: "bg-sev-critical-bg text-sev-critical",
  high: "bg-sev-high-bg text-sev-high",
  medium: "bg-sev-medium-bg text-sev-medium",
  low: "bg-sev-low-bg text-sev-low",
  info: "bg-sev-info-bg text-sev-info",
};

// ──────────────────────────────────────────────────────────────────────────────
// Sortable component table.
// ──────────────────────────────────────────────────────────────────────────────

type SortKey = "name" | "version" | "license" | "source";
type SortDir = "asc" | "desc";

function SortIcon({ active, dir }: { active: boolean; dir: SortDir }) {
  if (!active) return <ChevronsUpDown size={12} className="text-muted/60" />;
  return dir === "asc" ? (
    <ArrowUp size={12} className="text-foreground-strong" />
  ) : (
    <ArrowDown size={12} className="text-foreground-strong" />
  );
}

function ComponentTable({ rows }: { rows: ComponentRow[] }) {
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  const sorted = useMemo(() => {
    const copy = [...rows];
    copy.sort((a, b) => {
      const av = (a[sortKey] ?? "").toString().toLowerCase();
      const bv = (b[sortKey] ?? "").toString().toLowerCase();
      const cmp = av < bv ? -1 : av > bv ? 1 : 0;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return copy;
  }, [rows, sortKey, sortDir]);

  const toggle = (key: SortKey) => {
    if (key === sortKey) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const headerCell = (key: SortKey, label: string, width?: string) => (
    <th
      key={key}
      className={`px-4 py-2.5 text-left text-xs font-medium text-muted ${width ?? ""}`}
    >
      <button
        type="button"
        onClick={() => toggle(key)}
        className="inline-flex items-center gap-1.5 uppercase tracking-wider hover:text-foreground-strong transition-colors"
      >
        {label}
        <SortIcon active={sortKey === key} dir={sortDir} />
      </button>
    </th>
  );

  if (rows.length === 0) {
    return (
      <div className="rounded-md border border-border bg-card px-4 py-12 text-center">
        <Package size={20} className="mx-auto mb-3 text-muted" />
        <p className="text-sm text-muted">No components match this filter.</p>
      </div>
    );
  }

  return (
    <div className="rounded-md border border-border bg-card overflow-hidden">
      <div className="overflow-x-auto max-h-[560px] overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-surface-2 border-b border-border">
            <tr>
              {headerCell("name", "Name")}
              {headerCell("version", "Version", "w-[140px]")}
              {headerCell("license", "License", "w-[180px]")}
              <th className="px-4 py-2.5 text-left text-xs font-medium text-muted uppercase tracking-wider w-[120px]">
                Vulnerable
              </th>
              {headerCell("source", "Source", "w-[120px]")}
            </tr>
          </thead>
          <tbody>
            {sorted.map((c, i) => (
              <tr
                key={`${c.name}-${c.version}-${i}`}
                className="border-b border-border/60 last:border-0 hover:bg-surface-2/50 transition-colors"
              >
                <td className="px-4 py-2 align-top">
                  <div className="font-mono text-sm text-foreground-strong leading-tight">
                    {c.name || <span className="text-muted">unnamed</span>}
                  </div>
                  {c.purl && (
                    <div
                      className="font-mono text-[0.6875rem] text-muted truncate max-w-[44ch] mt-0.5"
                      title={c.purl}
                    >
                      {c.purl}
                    </div>
                  )}
                </td>
                <td className="px-4 py-2 font-mono text-xs text-muted align-top">
                  {c.version || "—"}
                </td>
                <td className="px-4 py-2 align-top">
                  {c.license ? (
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-surface-2 text-muted text-[0.6875rem] font-medium leading-none">
                      {c.license}
                    </span>
                  ) : (
                    <span className="text-muted">—</span>
                  )}
                </td>
                <td className="px-4 py-2 align-top">
                  {c.vulnerable ? (
                    <span
                      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[0.6875rem] font-medium leading-none ${SEV_PILL[c.vulnerable]}`}
                    >
                      <span aria-hidden>●</span>
                      <span className="capitalize">{c.vulnerable}</span>
                    </span>
                  ) : (
                    <span className="text-muted">—</span>
                  )}
                </td>
                <td className="px-4 py-2 align-top">
                  <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-surface-2 text-muted text-[0.6875rem] font-medium leading-none">
                    {c.source}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// SBOM detail card — summary strip, search, table, downloads.
// ──────────────────────────────────────────────────────────────────────────────

interface ActiveSBOM {
  id: string;
  format: "cyclonedx" | "spdx";
  document: Record<string, unknown>;
  componentCount: number;
  targetPath: string;
  createdAt?: string;
}

function SBOMDetail({
  sbom,
  onClose,
  onDownload,
  downloading,
}: {
  sbom: ActiveSBOM;
  onClose: () => void;
  onDownload: (format: "cyclonedx" | "spdx") => void;
  downloading: "cyclonedx" | "spdx" | null;
}) {
  const [search, setSearch] = useState("");
  const components = useMemo(
    () => parseComponents(sbom.document, sbom.format),
    [sbom.document, sbom.format],
  );

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return components;
    return components.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.version.toLowerCase().includes(q) ||
        c.license.toLowerCase().includes(q) ||
        c.source.toLowerCase().includes(q) ||
        c.purl.toLowerCase().includes(q),
    );
  }, [components, search]);

  const stats = useMemo(() => {
    const licenses = new Set<string>();
    let vulnerable = 0;
    for (const c of components) {
      if (c.license) licenses.add(c.license);
      if (c.vulnerable) vulnerable += 1;
    }
    return {
      components: components.length,
      licenses: licenses.size,
      vulnerable,
    };
  }, [components]);

  return (
    <div className="rounded-md border border-border bg-card overflow-hidden">
      <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
        <div className="space-y-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-base font-semibold text-foreground-strong">
              SBOM detail
            </h3>
            <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-surface-2 text-muted text-[0.6875rem] font-medium uppercase tracking-wider">
              {sbom.format === "cyclonedx" ? "CycloneDX" : "SPDX"}
            </span>
          </div>
          <p
            className="text-xs font-mono text-muted truncate"
            title={sbom.targetPath}
          >
            {sbom.targetPath}
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close SBOM detail"
          className="shrink-0 inline-flex items-center justify-center rounded-md border border-border bg-surface-2 text-muted hover:text-foreground-strong hover:bg-border transition-colors h-8 w-8"
        >
          <X size={14} />
        </button>
      </div>

      <div className="border-b border-border bg-surface-2/40 px-5 py-3 text-sm text-muted">
        <span className="text-foreground-strong font-medium">
          {stats.components}
        </span>{" "}
        components{" · "}
        <span className="text-foreground-strong font-medium">
          {stats.licenses}
        </span>{" "}
        licenses{" · "}
        <span
          className={
            stats.vulnerable > 0
              ? "text-sev-critical font-semibold"
              : "text-foreground-strong font-medium"
          }
        >
          {stats.vulnerable}
        </span>{" "}
        vulnerable
      </div>

      <div className="px-5 py-4 space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative flex-1 max-w-md">
            <Search
              size={14}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-muted pointer-events-none"
            />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by name, version, license, source…"
              className="w-full pl-9 pr-3 h-9 rounded-md border border-border bg-surface-2 text-sm text-foreground placeholder:text-muted focus:outline-none focus:border-border-strong focus:ring-2 focus:ring-ring transition-colors"
            />
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onDownload("cyclonedx")}
              disabled={downloading === "cyclonedx"}
              className="inline-flex items-center gap-1.5 px-3 h-9 rounded-md border border-border bg-surface-2 text-foreground-strong text-xs font-medium hover:bg-border transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {downloading === "cyclonedx" ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Download size={14} />
              )}
              CycloneDX JSON
            </button>
            <button
              type="button"
              onClick={() => onDownload("spdx")}
              disabled={downloading === "spdx"}
              className="inline-flex items-center gap-1.5 px-3 h-9 rounded-md border border-border bg-surface-2 text-foreground-strong text-xs font-medium hover:bg-border transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {downloading === "spdx" ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Download size={14} />
              )}
              SPDX JSON
            </button>
          </div>
        </div>

        <div className="text-xs text-muted">
          {search ? (
            <>
              Showing {filtered.length} of {components.length} components.
            </>
          ) : (
            <>{components.length} components.</>
          )}
        </div>

        <ComponentTable rows={filtered} />
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Page.
// ──────────────────────────────────────────────────────────────────────────────

export default function SBOMPage() {
  const [targetPath, setTargetPath] = useState("");
  const [format, setFormat] = useState<"cyclonedx" | "spdx">("cyclonedx");
  const [generating, setGenerating] = useState(false);
  const [generateError, setGenerateError] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);

  const [history, setHistory] = useState<SBOMHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState<string | null>(null);

  const [active, setActive] = useState<ActiveSBOM | null>(null);
  const [activeLoadingId, setActiveLoadingId] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<"cyclonedx" | "spdx" | null>(
    null,
  );

  const refreshHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const data = await fetchSBOMHistory();
      setHistory(data);
    } catch {
      setHistoryError(
        "Failed to load SBOM history. Is the backend running on /api/v1?",
      );
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshHistory();
  }, [refreshHistory]);

  const handleGenerate = useCallback(
    async (e?: React.FormEvent) => {
      if (e) e.preventDefault();
      const path = targetPath.trim();
      if (!path || generating) return;
      setGenerating(true);
      setGenerateError(null);
      try {
        const result = await generateSBOM(path, format);
        setActive({
          id: result.sbom_id,
          format,
          document: result.document,
          componentCount: result.component_count,
          targetPath: path,
          createdAt: new Date().toISOString(),
        });
        void refreshHistory();
      } catch {
        setGenerateError(
          "Failed to generate SBOM. Make sure the path exists and the backend is reachable.",
        );
      } finally {
        setGenerating(false);
      }
    },
    [targetPath, format, generating, refreshHistory],
  );

  const handleViewEntry = useCallback(async (entry: SBOMHistoryEntry) => {
    if (active?.id === entry.id) {
      setActive(null);
      return;
    }
    setActiveLoadingId(entry.id);
    try {
      const fmt: "cyclonedx" | "spdx" =
        entry.format === "spdx" ? "spdx" : "cyclonedx";
      const doc = await exportSBOM(entry.id, fmt);
      setActive({
        id: entry.id,
        format: fmt,
        document: doc,
        componentCount: entry.component_count,
        targetPath: entry.target_path,
        createdAt: entry.created_at,
      });
    } catch {
      setHistoryError("Failed to load SBOM detail for this entry.");
    } finally {
      setActiveLoadingId(null);
    }
  }, [active?.id]);

  const handleDownload = useCallback(
    async (fmt: "cyclonedx" | "spdx") => {
      if (!active) return;
      setDownloading(fmt);
      try {
        const doc =
          fmt === active.format
            ? active.document
            : await exportSBOM(active.id, fmt);
        const blob = new Blob([JSON.stringify(doc, null, 2)], {
          type: "application/json",
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `sbom-${active.id}.${fmt}.json`;
        a.click();
        URL.revokeObjectURL(url);
      } catch {
        setHistoryError(`Failed to download ${fmt.toUpperCase()} document.`);
      } finally {
        setDownloading(null);
      }
    },
    [active],
  );

  const generateButton = (
    <button
      type="button"
      onClick={() => handleGenerate()}
      disabled={generating || !targetPath.trim()}
      className="inline-flex items-center gap-2 h-9 px-4 rounded-md bg-accent text-accent-foreground text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
    >
      {generating ? (
        <>
          <Loader2 size={14} className="animate-spin" />
          Generating…
        </>
      ) : (
        <>
          <Package size={14} />
          Generate SBOM
        </>
      )}
    </button>
  );

  return (
    <div className="space-y-6 max-w-6xl">
      <PageHeader
        title="SBOM"
        meta="Software bill of materials — every dependency, version, and license."
        actions={generateButton}
      />

      {/* Generate panel */}
      <section className="rounded-md border border-border bg-card p-5 space-y-4">
        <form onSubmit={handleGenerate} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-3 md:gap-4 md:items-end">
            <div className="space-y-1.5">
              <label
                htmlFor="sbom-target"
                className="block text-xs font-medium text-muted uppercase tracking-wider"
              >
                Target path
              </label>
              <div className="flex">
                <input
                  id="sbom-target"
                  type="text"
                  value={targetPath}
                  onChange={(e) => setTargetPath(e.target.value)}
                  placeholder="/path/to/your/project"
                  className="flex-1 h-9 px-3 rounded-l-md border border-border border-r-0 bg-surface-2 text-sm text-foreground placeholder:text-muted focus:outline-none focus:border-border-strong focus:ring-2 focus:ring-ring transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setPickerOpen(true)}
                  className="inline-flex items-center gap-1.5 h-9 px-3 rounded-r-md border border-border bg-surface-2 text-muted hover:text-foreground-strong hover:bg-border transition-colors"
                >
                  <FolderOpen size={14} />
                  <span className="text-xs font-medium">Browse</span>
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              <span className="block text-xs font-medium text-muted uppercase tracking-wider">
                Format
              </span>
              <div
                role="radiogroup"
                aria-label="SBOM format"
                className="inline-flex h-9 rounded-md border border-border bg-surface-2 p-0.5"
              >
                {(["cyclonedx", "spdx"] as const).map((f) => (
                  <label
                    key={f}
                    className={`inline-flex items-center px-3 rounded-sm text-xs font-medium cursor-pointer transition-colors ${
                      format === f
                        ? "bg-accent text-accent-foreground"
                        : "text-muted hover:text-foreground-strong"
                    }`}
                  >
                    <input
                      type="radio"
                      name="format"
                      value={f}
                      checked={format === f}
                      onChange={() => setFormat(f)}
                      className="sr-only"
                    />
                    {f === "cyclonedx" ? "CycloneDX 1.5" : "SPDX 2.3"}
                  </label>
                ))}
              </div>
            </div>
          </div>

          <DirectoryPicker
            isOpen={pickerOpen}
            onClose={() => setPickerOpen(false)}
            onSelect={(path) => {
              setTargetPath(path);
              setPickerOpen(false);
            }}
            initialPath={targetPath || undefined}
          />

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={generating || !targetPath.trim()}
              className="inline-flex items-center gap-2 h-9 px-4 rounded-md bg-accent text-accent-foreground text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {generating ? (
                <>
                  <Loader2 size={14} className="animate-spin" />
                  Generating…
                </>
              ) : (
                <>
                  <Package size={14} />
                  Generate
                </>
              )}
            </button>
            {generating && (
              <span className="text-xs text-muted">
                Resolving manifests, parsing lockfiles, building components…
              </span>
            )}
          </div>

          {generating && (
            <div
              role="progressbar"
              aria-label="Generating SBOM"
              className="h-1 w-full overflow-hidden rounded-full bg-surface-2"
            >
              <div className="h-full w-1/3 bg-accent animate-[sbomprogress_1.4s_ease-in-out_infinite]" />
              <style jsx>{`
                @keyframes sbomprogress {
                  0% { transform: translateX(-100%); }
                  100% { transform: translateX(400%); }
                }
              `}</style>
            </div>
          )}
        </form>

        {generateError && (
          <div
            role="alert"
            className="flex items-start gap-2 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
          >
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>{generateError}</span>
          </div>
        )}
      </section>

      {/* History */}
      <section className="space-y-3">
        <div className="flex items-end justify-between">
          <div>
            <h2 className="text-lg font-semibold text-foreground-strong">
              SBOM history
            </h2>
            <p className="text-xs text-muted mt-0.5">
              Past generations. Click a row to inspect the components.
            </p>
          </div>
          {history.length > 0 && (
            <span className="text-xs text-muted">
              {history.length} {history.length === 1 ? "entry" : "entries"}
            </span>
          )}
        </div>

        {historyError && (
          <div
            role="alert"
            className="flex items-start gap-2 rounded-md border border-sev-critical/30 bg-sev-critical-bg px-3 py-2 text-sm text-sev-critical"
          >
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>{historyError}</span>
          </div>
        )}

        <div className="rounded-md border border-border bg-card overflow-hidden">
          {historyLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 size={18} className="animate-spin text-muted" />
            </div>
          ) : history.length === 0 ? (
            <div className="px-4 py-12 text-center">
              <Package size={20} className="mx-auto mb-3 text-muted" />
              <p className="text-sm text-foreground-strong font-medium">
                No SBOMs generated yet
              </p>
              <p className="text-xs text-muted mt-1">
                Pick a target above and run Generate to create your first SBOM.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-surface-2 border-b border-border">
                  <tr>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-muted uppercase tracking-wider w-[180px]">
                      Date
                    </th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-muted uppercase tracking-wider">
                      Target
                    </th>
                    <th className="px-4 py-2.5 text-right text-xs font-medium text-muted uppercase tracking-wider w-[120px]">
                      Components
                    </th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-muted uppercase tracking-wider w-[120px]">
                      Format
                    </th>
                    <th className="px-4 py-2.5 text-right text-xs font-medium text-muted uppercase tracking-wider w-[180px]">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((entry) => {
                    const isActive = active?.id === entry.id;
                    const isLoading = activeLoadingId === entry.id;
                    return (
                      <tr
                        key={entry.id}
                        onClick={() => handleViewEntry(entry)}
                        className={`border-b border-border/60 last:border-0 cursor-pointer transition-colors ${
                          isActive
                            ? "bg-accent-soft/40"
                            : "hover:bg-surface-2/60"
                        }`}
                      >
                        <td className="px-4 py-2.5 text-xs text-muted whitespace-nowrap">
                          {new Date(entry.created_at).toLocaleString()}
                        </td>
                        <td
                          className="px-4 py-2.5 font-mono text-xs text-foreground-strong truncate max-w-[40ch]"
                          title={entry.target_path}
                        >
                          {entry.target_path}
                        </td>
                        <td className="px-4 py-2.5 text-right text-sm tabular-nums text-foreground-strong">
                          {entry.component_count}
                        </td>
                        <td className="px-4 py-2.5">
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-surface-2 text-muted text-[0.6875rem] font-medium uppercase tracking-wider">
                            {entry.format === "cyclonedx" ? "CycloneDX" : "SPDX"}
                          </span>
                        </td>
                        <td
                          className="px-4 py-2.5 text-right"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <div className="inline-flex items-center gap-1.5">
                            <button
                              type="button"
                              onClick={() => handleViewEntry(entry)}
                              disabled={isLoading}
                              className="inline-flex items-center gap-1 h-7 px-2 rounded border border-border bg-surface-2 text-muted hover:text-foreground-strong hover:bg-border text-xs font-medium transition-colors disabled:opacity-60"
                            >
                              {isLoading ? (
                                <Loader2 size={12} className="animate-spin" />
                              ) : null}
                              {isActive ? "Hide" : "View"}
                            </button>
                            <button
                              type="button"
                              onClick={async () => {
                                setActiveLoadingId(entry.id);
                                try {
                                  const fmt: "cyclonedx" | "spdx" =
                                    entry.format === "spdx"
                                      ? "spdx"
                                      : "cyclonedx";
                                  const doc = await exportSBOM(entry.id, fmt);
                                  const blob = new Blob(
                                    [JSON.stringify(doc, null, 2)],
                                    { type: "application/json" },
                                  );
                                  const url = URL.createObjectURL(blob);
                                  const a = document.createElement("a");
                                  a.href = url;
                                  a.download = `sbom-${entry.id}.${fmt}.json`;
                                  a.click();
                                  URL.revokeObjectURL(url);
                                } catch {
                                  setHistoryError(
                                    "Failed to download SBOM document.",
                                  );
                                } finally {
                                  setActiveLoadingId(null);
                                }
                              }}
                              disabled={isLoading}
                              className="inline-flex items-center gap-1 h-7 px-2 rounded border border-border bg-surface-2 text-muted hover:text-foreground-strong hover:bg-border text-xs font-medium transition-colors disabled:opacity-60"
                            >
                              <Download size={12} />
                              Download
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {active && (
          <SBOMDetail
            sbom={active}
            onClose={() => setActive(null)}
            onDownload={handleDownload}
            downloading={downloading}
          />
        )}
      </section>
    </div>
  );
}
