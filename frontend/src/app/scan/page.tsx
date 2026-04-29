"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Loader2,
  FolderOpen,
  ChevronDown,
  ChevronRight,
  Check,
  AlertTriangle,
  Sparkles,
  Code,
  Container,
  Key,
  Layers,
  RefreshCw,
  ArrowRight,
  Terminal,
  Tag,
  X,
} from "lucide-react";
import { startScan, fetchScannerStatus } from "@/lib/api";
import type { ScannerStatus } from "@/lib/api";
import { DirectoryPicker } from "@/components/directory-picker";

/**
 * Local fallback PageHeader. DSH3 owns `@/components/page-header` and will
 * land it in parallel; once that file exists in `main`, the merge will
 * keep DSH3's canonical implementation and this fallback can be removed.
 */
function PageHeader({
  title,
  meta,
  action,
}: {
  title: string;
  meta?: string;
  action?: React.ReactNode;
}) {
  return (
    <header className="mb-8 flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-3xl font-semibold tracking-tight text-foreground-strong">
          {title}
        </h1>
        {meta && <p className="mt-1.5 text-sm text-muted">{meta}</p>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </header>
  );
}

const TYPE_LABELS: Record<string, string> = {
  code: "Code analysis",
  dependency: "Dependencies",
  iac: "Infrastructure as code",
  baseline: "System baseline",
  dast: "Web application (DAST)",
  network: "Network",
};

const TYPE_ORDER = ["code", "dependency", "iac", "baseline", "dast", "network"];

const PRESET_CODE = new Set(["semgrep", "bandit"]);
const PRESET_CONTAINERS = new Set(["trivy", "checkov"]);
const PRESET_SECRETS = new Set(["gitleaks"]);

const RECENT_KEY = "securescan:recent-targets";
const PRESETS_KEY = "securescan:scan-presets";

type SeverityThreshold = "none" | "low" | "medium" | "high" | "critical";

const SEVERITY_OPTIONS: { value: SeverityThreshold; label: string }[] = [
  { value: "none", label: "Report all severities" },
  { value: "low", label: "Treat low and below as advisory" },
  { value: "medium", label: "Treat medium and below as advisory" },
  { value: "high", label: "Treat high and below as advisory" },
  { value: "critical", label: "Only criticals are findings" },
];

function readRecentTargets(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed)
      ? parsed.filter((x): x is string => typeof x === "string").slice(0, 6)
      : [];
  } catch {
    return [];
  }
}

function pushRecentTarget(path: string) {
  if (typeof window === "undefined") return;
  try {
    const current = readRecentTargets();
    const next = [path, ...current.filter((p) => p !== path)].slice(0, 6);
    window.localStorage.setItem(RECENT_KEY, JSON.stringify(next));
  } catch {
    /* ignore */
  }
}

interface SavedPreset {
  name: string;
  scanners: string[];
  savedAt: string;
}

function savePreset(preset: SavedPreset) {
  if (typeof window === "undefined") return;
  try {
    const raw = window.localStorage.getItem(PRESETS_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    const list: SavedPreset[] = Array.isArray(parsed) ? parsed : [];
    list.unshift(preset);
    window.localStorage.setItem(PRESETS_KEY, JSON.stringify(list.slice(0, 12)));
  } catch {
    /* ignore */
  }
}

function estimateDuration(count: number): string {
  if (count === 0) return "—";
  if (count === 1) return "~1–2 minutes";
  if (count <= 3) return "~2–5 minutes";
  if (count <= 5) return "~5–10 minutes";
  return "~10+ minutes";
}

export default function NewScanPage() {
  const router = useRouter();

  const [scanners, setScanners] = useState<ScannerStatus[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [targetPath, setTargetPath] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [targetHost, setTargetHost] = useState("");
  const [pickerOpen, setPickerOpen] = useState(false);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [installOpen, setInstallOpen] = useState<Set<string>>(new Set());

  const [optionsOpen, setOptionsOpen] = useState(false);
  const [tagInput, setTagInput] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [description, setDescription] = useState("");
  const [severityThreshold, setSeverityThreshold] =
    useState<SeverityThreshold>("none");

  const [recentTargets, setRecentTargets] = useState<string[]>([]);

  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [presetSaved, setPresetSaved] = useState(false);

  useEffect(() => {
    queueMicrotask(() => setRecentTargets(readRecentTargets()));
  }, []);

  const loadScanners = () => {
    setLoading(true);
    setLoadError(null);
    fetchScannerStatus()
      .then((list) => {
        setScanners(list);
        setSelected((prev) => {
          if (prev.size > 0) return prev;
          const defaults = list
            .filter((s) => s.available && (s.scan_type === "code" || s.scan_type === "dependency"))
            .map((s) => s.name);
          if (defaults.length > 0) return new Set(defaults);
          const firstAvailable = list.find((s) => s.available);
          return firstAvailable ? new Set([firstAvailable.name]) : new Set();
        });
      })
      .catch(() =>
        setLoadError(
          "Could not load scanner availability. Check that the SecureScan backend is running.",
        ),
      )
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    let cancelled = false;
    fetchScannerStatus()
      .then((list) => {
        if (cancelled) return;
        setScanners(list);
        setSelected((prev) => {
          if (prev.size > 0) return prev;
          const defaults = list
            .filter((s) => s.available && (s.scan_type === "code" || s.scan_type === "dependency"))
            .map((s) => s.name);
          if (defaults.length > 0) return new Set(defaults);
          const firstAvailable = list.find((s) => s.available);
          return firstAvailable ? new Set([firstAvailable.name]) : new Set();
        });
      })
      .catch(() => {
        if (cancelled) return;
        setLoadError(
          "Could not load scanner availability. Check that the SecureScan backend is running.",
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const grouped = useMemo(() => {
    const map = new Map<string, ScannerStatus[]>();
    if (!scanners) return map;
    for (const s of scanners) {
      const list = map.get(s.scan_type) ?? [];
      list.push(s);
      map.set(s.scan_type, list);
    }
    return map;
  }, [scanners]);

  const totalAvailable = scanners?.filter((s) => s.available).length ?? 0;
  const totalScanners = scanners?.length ?? 0;
  const noneInstalled = scanners !== null && totalAvailable === 0 && totalScanners > 0;

  const selectedAvailable = useMemo(() => {
    if (!scanners) return [] as ScannerStatus[];
    return scanners.filter((s) => selected.has(s.name) && s.available);
  }, [scanners, selected]);

  const derivedScanTypes = useMemo(
    () => Array.from(new Set(selectedAvailable.map((s) => s.scan_type))),
    [selectedAvailable],
  );

  const needsUrl = derivedScanTypes.includes("dast");
  const needsHost = derivedScanTypes.includes("network");

  const canSubmit =
    !submitting &&
    !!targetPath.trim() &&
    selectedAvailable.length > 0 &&
    (!needsUrl || !!targetUrl.trim()) &&
    (!needsHost || !!targetHost.trim());

  const toggleScanner = (s: ScannerStatus) => {
    if (!s.available) return;
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(s.name)) next.delete(s.name);
      else next.add(s.name);
      return next;
    });
  };

  const toggleInstall = (name: string) => {
    setInstallOpen((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const selectAll = () => {
    if (!scanners) return;
    setSelected(new Set(scanners.filter((s) => s.available).map((s) => s.name)));
  };

  const deselectAll = () => setSelected(new Set());

  const applyPreset = (matcher: (s: ScannerStatus) => boolean) => {
    if (!scanners) return;
    setSelected(new Set(scanners.filter((s) => s.available && matcher(s)).map((s) => s.name)));
  };

  const addTag = () => {
    const t = tagInput.trim();
    if (!t) return;
    if (tags.includes(t)) {
      setTagInput("");
      return;
    }
    setTags((prev) => [...prev, t]);
    setTagInput("");
  };

  const removeTag = (t: string) => setTags((prev) => prev.filter((x) => x !== t));

  const handleSavePreset = () => {
    if (selectedAvailable.length === 0) return;
    savePreset({
      name: tags[0] || `Preset ${new Date().toLocaleDateString()}`,
      scanners: selectedAvailable.map((s) => s.name),
      savedAt: new Date().toISOString(),
    });
    setPresetSaved(true);
    window.setTimeout(() => setPresetSaved(false), 2000);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;

    setSubmitting(true);
    setSubmitError(null);

    try {
      const newScan = await startScan(
        targetPath.trim(),
        derivedScanTypes,
        targetUrl.trim() || undefined,
        targetHost.trim() || undefined,
      );
      pushRecentTarget(targetPath.trim());
      router.push(`/scan/${newScan.id}`);
    } catch {
      setSubmitError("Failed to start scan. Is the backend running?");
      setSubmitting(false);
    }
  };

  // ---- Loading skeleton ---- //
  if (loading) {
    return (
      <div className="max-w-6xl">
        <PageHeader
          title="New scan"
          meta="Configure scanners and target, then run."
        />
        <div className="grid gap-8 lg:grid-cols-[1fr_320px]">
          <div className="space-y-6">
            <SkeletonBlock label="Target" lines={2} />
            <SkeletonBlock label="Scanners" lines={5} />
            <SkeletonBlock label="Options" lines={1} />
          </div>
          <div className="hidden lg:block">
            <div className="rounded-lg border border-border bg-surface-2 p-5 space-y-3">
              <div className="h-3 w-16 rounded bg-border animate-pulse" />
              <div className="h-4 w-full rounded bg-border animate-pulse" />
              <div className="h-4 w-3/4 rounded bg-border animate-pulse" />
              <div className="h-9 w-full rounded bg-border animate-pulse mt-4" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl">
      <PageHeader
        title="New scan"
        meta="Configure scanners and target, then run."
        action={
          <Link
            href="/scanners"
            className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-foreground transition-colors"
          >
            View installed scanners
            <ArrowRight size={14} />
          </Link>
        }
      />

      {loadError && (
        <div className="mb-6 rounded-md border border-sev-critical/40 bg-sev-critical-bg text-sev-critical p-4 flex items-start gap-3">
          <AlertTriangle size={16} className="shrink-0 mt-0.5" />
          <div className="flex-1 text-sm">
            <p className="font-medium">{loadError}</p>
            <button
              onClick={loadScanners}
              className="mt-2 inline-flex items-center gap-1.5 text-xs font-medium underline-offset-2 hover:underline"
            >
              <RefreshCw size={12} />
              Retry
            </button>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="grid gap-8 lg:grid-cols-[1fr_320px]">
        {/* ---- LEFT: form ---- */}
        <div className="space-y-8 min-w-0">
          {/* Target */}
          <Section
            title="Target"
            helper="Path to scan. SecureScan walks the directory and runs each enabled scanner against the contents."
          >
            <div className="flex">
              <input
                type="text"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                placeholder="/path/to/your/project"
                className="flex-1 px-3.5 py-2.5 rounded-l-md bg-surface border border-border border-r-0 text-foreground placeholder:text-muted text-sm focus:outline-none focus:ring-2 focus:ring-ring focus:border-border-strong transition-colors"
              />
              <button
                type="button"
                onClick={() => setPickerOpen(true)}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-r-md bg-card border border-border text-foreground hover:bg-surface-2 transition-colors text-sm"
              >
                <FolderOpen size={14} />
                Browse
              </button>
            </div>

            {needsUrl && (
              <div className="mt-3">
                <label className="block text-xs font-medium text-muted mb-1.5">
                  Target URL — required for DAST scanners
                </label>
                <input
                  type="url"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full px-3.5 py-2.5 rounded-md bg-surface border border-border text-foreground placeholder:text-muted text-sm focus:outline-none focus:ring-2 focus:ring-ring transition-colors"
                />
              </div>
            )}

            {needsHost && (
              <div className="mt-3">
                <label className="block text-xs font-medium text-muted mb-1.5">
                  Target host — required for network scanners
                </label>
                <input
                  type="text"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                  placeholder="192.168.1.1 or hostname"
                  className="w-full px-3.5 py-2.5 rounded-md bg-surface border border-border text-foreground placeholder:text-muted text-sm focus:outline-none focus:ring-2 focus:ring-ring transition-colors"
                />
              </div>
            )}

            {recentTargets.length > 0 && (
              <div className="mt-3">
                <p className="text-2xs uppercase tracking-wide text-muted mb-2">
                  Recent
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {recentTargets.map((p) => (
                    <button
                      key={p}
                      type="button"
                      onClick={() => setTargetPath(p)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-surface-2 border border-border text-xs text-muted hover:text-foreground hover:border-border-strong transition-colors max-w-xs"
                      title={p}
                    >
                      <span className="truncate">{p}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </Section>

          {/* Scanners */}
          <Section
            title="Scanners"
            rightSlot={
              <span className="text-xs text-muted">
                {selectedAvailable.length} of {totalAvailable} enabled
              </span>
            }
          >
            {/* Quick presets */}
            <div className="flex flex-wrap items-center gap-2 mb-3">
              <PresetButton
                icon={<Sparkles size={12} />}
                label="All available"
                onClick={() => applyPreset(() => true)}
              />
              <PresetButton
                icon={<Code size={12} />}
                label="Code only"
                onClick={() => applyPreset((s) => PRESET_CODE.has(s.name) || s.scan_type === "code")}
              />
              <PresetButton
                icon={<Container size={12} />}
                label="Containers only"
                onClick={() =>
                  applyPreset((s) => PRESET_CONTAINERS.has(s.name) || s.scan_type === "iac")
                }
              />
              <PresetButton
                icon={<Key size={12} />}
                label="Secrets only"
                onClick={() => applyPreset((s) => PRESET_SECRETS.has(s.name))}
              />
              <div className="ml-auto flex items-center gap-3 text-xs">
                <button
                  type="button"
                  onClick={selectAll}
                  className="text-muted hover:text-foreground transition-colors"
                >
                  Select all
                </button>
                <span className="text-border-strong">·</span>
                <button
                  type="button"
                  onClick={deselectAll}
                  className="text-muted hover:text-foreground transition-colors"
                >
                  Deselect all
                </button>
              </div>
            </div>

            {scanners && scanners.length === 0 && (
              <NoScannersInstalledHint />
            )}

            {noneInstalled && (
              <div className="mb-3 rounded-md border border-sev-low/30 bg-sev-low-bg text-sev-low p-3 text-xs flex items-start gap-2">
                <AlertTriangle size={14} className="shrink-0 mt-0.5" />
                <p className="leading-relaxed">
                  No scanners are installed yet. Use the install hints below or
                  visit{" "}
                  <Link href="/scanners" className="underline font-medium">
                    Scanners
                  </Link>{" "}
                  to set them up.
                </p>
              </div>
            )}

            {/* Scanner rows grouped by category */}
            <div className="rounded-lg border border-border bg-surface divide-y divide-border overflow-hidden">
              {TYPE_ORDER.filter((t) => grouped.has(t)).map((scanType) => {
                const list = grouped.get(scanType)!;
                return (
                  <div key={scanType}>
                    <div className="px-4 py-2 bg-surface-2 text-2xs uppercase tracking-wide text-muted font-medium flex items-center gap-2">
                      <Layers size={11} />
                      {TYPE_LABELS[scanType] ?? scanType}
                    </div>
                    {list.map((s) => (
                      <ScannerRow
                        key={s.name}
                        scanner={s}
                        checked={selected.has(s.name)}
                        installOpen={installOpen.has(s.name)}
                        onToggle={() => toggleScanner(s)}
                        onToggleInstall={() => toggleInstall(s.name)}
                      />
                    ))}
                  </div>
                );
              })}
            </div>
          </Section>

          {/* Options (collapsible) */}
          <Section
            title="Options"
            rightSlot={
              <button
                type="button"
                onClick={() => setOptionsOpen((v) => !v)}
                className="inline-flex items-center gap-1 text-xs text-muted hover:text-foreground transition-colors"
              >
                {optionsOpen ? "Hide" : "Show"}
                {optionsOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
              </button>
            }
          >
            {optionsOpen && (
              <div className="space-y-5">
                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5 flex items-center gap-1.5">
                    <Tag size={12} /> Tags
                  </label>
                  <div className="flex flex-wrap items-center gap-1.5 px-2 py-1.5 rounded-md bg-surface border border-border focus-within:ring-2 focus-within:ring-ring transition-colors">
                    {tags.map((t) => (
                      <span
                        key={t}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-accent-soft text-accent text-xs font-medium"
                      >
                        {t}
                        <button
                          type="button"
                          onClick={() => removeTag(t)}
                          className="hover:opacity-70"
                          aria-label={`Remove tag ${t}`}
                        >
                          <X size={11} />
                        </button>
                      </span>
                    ))}
                    <input
                      type="text"
                      value={tagInput}
                      onChange={(e) => setTagInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === ",") {
                          e.preventDefault();
                          addTag();
                        } else if (e.key === "Backspace" && !tagInput && tags.length) {
                          setTags((prev) => prev.slice(0, -1));
                        }
                      }}
                      onBlur={addTag}
                      placeholder={tags.length === 0 ? "release-candidate, monthly, …" : ""}
                      className="flex-1 min-w-[120px] bg-transparent text-sm text-foreground placeholder:text-muted focus:outline-none py-1"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    Description (optional)
                  </label>
                  <textarea
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    rows={3}
                    placeholder="Why is this scan being run? Context shows up on the scan detail page."
                    className="w-full px-3.5 py-2.5 rounded-md bg-surface border border-border text-foreground placeholder:text-muted text-sm focus:outline-none focus:ring-2 focus:ring-ring transition-colors resize-y"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-muted mb-1.5">
                    Severity threshold
                  </label>
                  <select
                    value={severityThreshold}
                    onChange={(e) =>
                      setSeverityThreshold(e.target.value as SeverityThreshold)
                    }
                    className="w-full px-3.5 py-2.5 rounded-md bg-surface border border-border text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring transition-colors"
                  >
                    {SEVERITY_OPTIONS.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                  <p className="mt-1 text-2xs text-muted">
                    Findings below the threshold are tagged advisory and excluded
                    from the risk score.
                  </p>
                </div>
              </div>
            )}
          </Section>
        </div>

        {/* ---- RIGHT: preview ---- */}
        <aside className="hidden lg:block">
          <div className="sticky top-20 rounded-lg border border-border bg-surface-2 p-5 space-y-4">
            <p className="text-xs uppercase tracking-wide text-muted font-medium">
              Preview
            </p>

            <div>
              <p className="text-2xs uppercase tracking-wide text-muted mb-1">
                Target
              </p>
              <p
                className="text-sm font-mono text-foreground truncate"
                title={targetPath || "—"}
              >
                {targetPath || <span className="text-muted">Not set</span>}
              </p>
            </div>

            <div>
              <p className="text-2xs uppercase tracking-wide text-muted mb-2">
                Scanners ({selectedAvailable.length})
              </p>
              {selectedAvailable.length === 0 ? (
                <p className="text-xs text-muted">No scanners selected.</p>
              ) : (
                <ul className="space-y-1">
                  {selectedAvailable.map((s) => (
                    <li
                      key={s.name}
                      className="flex items-center gap-2 text-xs text-foreground"
                    >
                      <Check size={12} className="text-accent shrink-0" />
                      <span className="truncate">{s.name}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <p className="text-2xs uppercase tracking-wide text-muted mb-1">
                Estimated duration
              </p>
              <p className="text-sm text-foreground">
                {estimateDuration(selectedAvailable.length)}
              </p>
            </div>

            <div className="pt-2 space-y-2">
              <button
                type="submit"
                disabled={!canSubmit}
                className="w-full inline-flex items-center justify-center gap-2 bg-accent text-accent-foreground py-2.5 rounded-md font-medium text-sm hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting ? (
                  <>
                    <Loader2 size={14} className="animate-spin" /> Starting…
                  </>
                ) : (
                  "Run scan"
                )}
              </button>

              {!canSubmit && !submitting && (
                <p className="text-2xs text-muted text-center leading-snug">
                  {!targetPath.trim()
                    ? "Enter a target path to continue."
                    : selectedAvailable.length === 0
                      ? "Select at least one scanner to continue."
                      : needsUrl && !targetUrl.trim()
                        ? "DAST scanners require a target URL."
                        : needsHost && !targetHost.trim()
                          ? "Network scanners require a target host."
                          : ""}
                </p>
              )}

              <button
                type="button"
                onClick={handleSavePreset}
                disabled={selectedAvailable.length === 0}
                className="w-full inline-flex items-center justify-center gap-2 py-2 rounded-md bg-transparent text-foreground text-xs font-medium hover:bg-surface transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {presetSaved ? (
                  <>
                    <Check size={12} /> Preset saved
                  </>
                ) : (
                  "Save as preset"
                )}
              </button>
            </div>

            {submitError && (
              <div className="rounded-md border border-sev-critical/40 bg-sev-critical-bg text-sev-critical p-3 text-xs">
                {submitError}
              </div>
            )}
          </div>
        </aside>
      </form>

      {/* Mobile preview / submit (when sidebar isn't shown) */}
      <div className="lg:hidden mt-6 rounded-lg border border-border bg-surface-2 p-5 space-y-3">
        <p className="text-xs uppercase tracking-wide text-muted font-medium">
          Preview
        </p>
        <p className="text-sm font-mono text-foreground truncate">
          {targetPath || <span className="text-muted">No target set</span>}
        </p>
        <p className="text-xs text-muted">
          {selectedAvailable.length} scanner{selectedAvailable.length === 1 ? "" : "s"} •{" "}
          {estimateDuration(selectedAvailable.length)}
        </p>
        <button
          type="button"
          onClick={(e) => handleSubmit(e as unknown as React.FormEvent)}
          disabled={!canSubmit}
          className="w-full inline-flex items-center justify-center gap-2 bg-accent text-accent-foreground py-2.5 rounded-md font-medium text-sm hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting ? (
            <>
              <Loader2 size={14} className="animate-spin" /> Starting…
            </>
          ) : (
            "Run scan"
          )}
        </button>
        {submitError && (
          <p className="text-xs text-sev-critical">{submitError}</p>
        )}
      </div>

      <DirectoryPicker
        isOpen={pickerOpen}
        onClose={() => setPickerOpen(false)}
        onSelect={(p) => {
          setTargetPath(p);
          setPickerOpen(false);
        }}
        initialPath={targetPath || undefined}
        noScannersInstalled={noneInstalled}
      />
    </div>
  );
}

// ---- Building blocks ---- //

function Section({
  title,
  helper,
  rightSlot,
  children,
}: {
  title: string;
  helper?: string;
  rightSlot?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section>
      <div className="flex items-center justify-between gap-3 mb-2">
        <h2 className="text-base font-semibold text-foreground-strong">
          {title}
        </h2>
        {rightSlot}
      </div>
      {helper && <p className="text-sm text-muted mb-3 max-w-prose">{helper}</p>}
      {children}
    </section>
  );
}

function PresetButton({
  icon,
  label,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-card border border-border text-xs text-foreground hover:bg-surface-2 hover:border-border-strong transition-colors"
    >
      {icon}
      {label}
    </button>
  );
}

function ScannerRow({
  scanner,
  checked,
  installOpen,
  onToggle,
  onToggleInstall,
}: {
  scanner: ScannerStatus;
  checked: boolean;
  installOpen: boolean;
  onToggle: () => void;
  onToggleInstall: () => void;
}) {
  const available = scanner.available;
  return (
    <div className={`px-4 py-3 ${available ? "" : "opacity-70"}`}>
      <label
        className={`flex items-start gap-3 ${
          available ? "cursor-pointer" : "cursor-not-allowed"
        }`}
      >
        <input
          type="checkbox"
          checked={checked}
          onChange={onToggle}
          disabled={!available}
          className="sr-only"
        />
        <span
          className={`mt-0.5 w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors ${
            checked
              ? "bg-accent border-accent"
              : available
                ? "border-border-strong bg-surface"
                : "border-border bg-surface"
          }`}
          aria-hidden
        >
          {checked && (
            <Check size={11} className="text-accent-foreground" strokeWidth={3} />
          )}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-foreground truncate">
              {scanner.name}
            </span>
            {available ? (
              <span className="text-2xs font-medium px-1.5 py-0.5 rounded bg-accent-soft text-accent">
                Available
              </span>
            ) : (
              <span className="text-2xs font-medium px-1.5 py-0.5 rounded bg-sev-low-bg text-sev-low">
                Not installed
              </span>
            )}
          </div>
          {scanner.description && (
            <p className="mt-0.5 text-xs text-muted leading-relaxed">
              {scanner.description}
            </p>
          )}
        </div>
        {!available && scanner.install_hint && (
          <button
            type="button"
            onClick={(e) => {
              e.preventDefault();
              onToggleInstall();
            }}
            className="shrink-0 inline-flex items-center gap-1 text-xs text-muted hover:text-foreground transition-colors"
          >
            How to install
            {installOpen ? (
              <ChevronDown size={12} />
            ) : (
              <ChevronRight size={12} />
            )}
          </button>
        )}
      </label>

      {!available && installOpen && scanner.install_hint && (
        <div className="mt-2 ml-7 rounded-md bg-surface-2 border border-border px-3 py-2">
          <div className="flex items-center gap-1.5 text-2xs uppercase tracking-wide text-muted mb-1">
            <Terminal size={11} />
            Install command
          </div>
          <code className="block text-xs font-mono text-foreground whitespace-pre-wrap break-all">
            {scanner.install_hint}
          </code>
        </div>
      )}
    </div>
  );
}

function NoScannersInstalledHint() {
  return (
    <div className="rounded-lg border border-border bg-surface p-6 text-center">
      <p className="text-sm font-medium text-foreground-strong">
        No scanners detected
      </p>
      <p className="mt-1 text-xs text-muted max-w-sm mx-auto leading-relaxed">
        Run <code className="px-1 py-0.5 rounded bg-surface-2 text-foreground font-mono">pip install securescan[all]</code> or visit Scanners to install individual tools.
      </p>
      <Link
        href="/scanners"
        className="mt-3 inline-flex items-center gap-1.5 text-xs text-accent hover:underline font-medium"
      >
        Go to Scanners
        <ArrowRight size={12} />
      </Link>
    </div>
  );
}

function SkeletonBlock({ label, lines }: { label: string; lines: number }) {
  return (
    <section>
      <div className="flex items-center justify-between mb-3">
        <div className="h-5 w-24 rounded bg-border animate-pulse" />
        <div className="h-3 w-16 rounded bg-border animate-pulse" />
      </div>
      <div className="rounded-lg border border-border bg-surface p-4 space-y-3">
        <span className="sr-only">Loading {label}</span>
        {Array.from({ length: lines }).map((_, i) => (
          <div
            key={i}
            className="h-9 rounded bg-surface-2 animate-pulse"
            style={{ width: `${85 - i * 7}%` }}
          />
        ))}
      </div>
    </section>
  );
}
