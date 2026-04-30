"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  Check,
  Copy,
  Loader2,
  RefreshCw,
  Search,
  Wand2,
} from "lucide-react";
import { fetchScannerStatusEnvelope, installScanner } from "@/lib/api";
import type { ScannerStatus } from "@/lib/api";

type Status = "available" | "not_installed" | "misconfigured" | "disabled";

type CategoryKey =
  | "code"
  | "dependency"
  | "container"
  | "secrets"
  | "network"
  | "web"
  | "other";

const CATEGORIES: { key: CategoryKey; label: string }[] = [
  { key: "code", label: "Code analysis" },
  { key: "dependency", label: "Dependencies" },
  { key: "container", label: "Containers & IaC" },
  { key: "secrets", label: "Secrets" },
  { key: "network", label: "Network" },
  { key: "web", label: "Web" },
  { key: "other", label: "Other" },
];

const SCANNER_CATEGORY: Record<string, CategoryKey> = {
  semgrep: "code",
  bandit: "code",
  "eslint-security": "code",
  eslint: "code",
  safety: "dependency",
  "trivy-fs": "dependency",
  trivy: "container",
  checkov: "container",
  gitleaks: "secrets",
  nmap: "network",
  zap: "web",
};

const SCAN_TYPE_CATEGORY: Record<string, CategoryKey> = {
  code: "code",
  dependency: "dependency",
  iac: "container",
  container: "container",
  secrets: "secrets",
  network: "network",
  dast: "web",
  baseline: "other",
};

function categoryFor(s: ScannerStatus): CategoryKey {
  return (
    SCANNER_CATEGORY[s.name.toLowerCase()] ??
    SCAN_TYPE_CATEGORY[s.scan_type?.toLowerCase()] ??
    "other"
  );
}

function statusOf(s: ScannerStatus): Status {
  if (s.available) return "available";
  if (s.installable) return "not_installed";
  return "misconfigured";
}

const STATUS_LABEL: Record<Status, string> = {
  available: "Available",
  not_installed: "Not installed",
  misconfigured: "Misconfigured",
  disabled: "Disabled",
};

const STATUS_CHIP: Record<Status, string> = {
  available: "bg-accent text-accent-foreground",
  not_installed: "bg-sev-low-bg text-sev-low",
  misconfigured: "bg-sev-medium-bg text-sev-medium",
  disabled: "bg-surface-2 text-muted",
};

const STATUS_DOT: Record<Status, string> = {
  available: "bg-accent-foreground",
  not_installed: "bg-sev-low",
  misconfigured: "bg-sev-medium",
  disabled: "bg-muted",
};

interface ScannerWithExtras extends ScannerStatus {
  version?: string | null;
  last_used?: string | null;
}

function getVersion(s: ScannerWithExtras): string | null {
  if (s.version) return s.version;
  const m = s.message?.match(/v?(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)/);
  return m ? m[1] : null;
}

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diff = Date.now() - then;
  const s = Math.round(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d}d ago`;
  const mo = Math.round(d / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.round(mo / 12)}y ago`;
}

export default function ScannersPage() {
  const [scanners, setScanners] = useState<ScannerWithExtras[]>([]);
  const [checkedAt, setCheckedAt] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [installing, setInstalling] = useState<Set<string>>(new Set());
  const [bulkProgress, setBulkProgress] = useState<{
    done: number;
    total: number;
  } | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const envelope = await fetchScannerStatusEnvelope();
      setScanners(envelope.scanners as ScannerWithExtras[]);
      setCheckedAt(envelope.checked_at);
    } catch {
      setError("Failed to load scanner status. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    return () => {
      if (copyTimer.current) clearTimeout(copyTimer.current);
    };
  }, []);

  const handleCopy = async (name: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(name);
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(null), 1400);
    } catch {
      // clipboard unavailable — silently ignore
    }
  };

  const installOne = useCallback(async (name: string) => {
    setInstalling((p) => {
      const n = new Set(p);
      n.add(name);
      return n;
    });
    try {
      await installScanner(name);
    } catch {
      // surfaced via subsequent refetch + status
    } finally {
      setInstalling((p) => {
        const n = new Set(p);
        n.delete(name);
        return n;
      });
    }
  }, []);

  const handleInstallAll = async () => {
    const targets = scanners.filter((s) => statusOf(s) === "not_installed");
    if (targets.length === 0) return;
    setBulkProgress({ done: 0, total: targets.length });
    for (let i = 0; i < targets.length; i++) {
      await installOne(targets[i].name);
      setBulkProgress({ done: i + 1, total: targets.length });
    }
    await load();
    setBulkProgress(null);
  };

  const handleRefresh = async () => {
    setLoading(true);
    await load();
  };

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return scanners;
    return scanners.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.description?.toLowerCase().includes(q),
    );
  }, [scanners, query]);

  const grouped = useMemo(() => {
    const buckets = new Map<CategoryKey, ScannerWithExtras[]>();
    for (const s of filtered) {
      const k = categoryFor(s);
      const arr = buckets.get(k) ?? [];
      arr.push(s);
      buckets.set(k, arr);
    }
    for (const arr of buckets.values()) {
      arr.sort((a, b) => a.name.localeCompare(b.name));
    }
    return buckets;
  }, [filtered]);

  const notInstalledCount = useMemo(
    () => scanners.filter((s) => statusOf(s) === "not_installed").length,
    [scanners],
  );

  return (
    <div className="space-y-6">
      <PageHeaderInline
        title="Scanners"
        meta="Configure which security scanners SecureScan runs."
      />

      <StatusLegend
        query={query}
        onQuery={setQuery}
        notInstalledCount={notInstalledCount}
        bulkProgress={bulkProgress}
        onInstallAll={handleInstallAll}
        onRefresh={handleRefresh}
        refreshing={loading && scanners.length > 0}
        bulkBusy={bulkProgress !== null}
        checkedAt={checkedAt}
      />

      {loading && scanners.length === 0 ? (
        <LoadingSkeleton />
      ) : error ? (
        <ErrorAlert message={error} onRetry={handleRefresh} />
      ) : scanners.length === 0 ? (
        <EmptyState />
      ) : (
        <div className="space-y-8">
          {CATEGORIES.map(({ key, label }) => {
            const items = grouped.get(key);
            if (!items || items.length === 0) return null;
            return (
              <section key={key}>
                <h2 className="text-xs font-medium text-muted uppercase tracking-wider mb-3">
                  {label}
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {items.map((s) => (
                    <ScannerCard
                      key={s.name}
                      scanner={s}
                      installing={installing.has(s.name)}
                      copied={copied === s.name}
                      onCopy={handleCopy}
                      onInstall={installOne}
                    />
                  ))}
                </div>
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}

function PageHeaderInline({ title, meta }: { title: string; meta: string }) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
      <h1 className="text-3xl font-semibold tracking-tight text-foreground-strong">
        {title}
      </h1>
      <p className="text-sm text-muted">{meta}</p>
    </div>
  );
}

function StatusLegend({
  query,
  onQuery,
  notInstalledCount,
  bulkProgress,
  onInstallAll,
  onRefresh,
  refreshing,
  bulkBusy,
  checkedAt,
}: {
  query: string;
  onQuery: (v: string) => void;
  notInstalledCount: number;
  bulkProgress: { done: number; total: number } | null;
  onInstallAll: () => void;
  onRefresh: () => void;
  refreshing: boolean;
  bulkBusy: boolean;
  checkedAt: string | null;
}) {
  const statuses: Status[] = [
    "available",
    "not_installed",
    "misconfigured",
    "disabled",
  ];
  // Tick once a second while idle so "X seconds ago" stays accurate
  // without re-fetching.
  const [, setNow] = useState(Date.now());
  useEffect(() => {
    if (!checkedAt) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [checkedAt]);

  const checkedLabel = checkedAt ? relativeTime(checkedAt) : null;
  return (
    <div className="sticky top-14 z-10 -mx-4 md:-mx-8 px-4 md:px-8 bg-background/90 backdrop-blur supports-[backdrop-filter]:bg-background/75 border-b border-border">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-3 py-3">
        <ul className="flex flex-wrap items-center gap-1.5">
          {statuses.map((s) => (
            <li key={s}>
              <span
                className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-2xs font-medium ${STATUS_CHIP[s]}`}
              >
                <span
                  className={`inline-block h-1.5 w-1.5 rounded-full ${STATUS_DOT[s]}`}
                  aria-hidden
                />
                {STATUS_LABEL[s]}
              </span>
            </li>
          ))}
        </ul>

        <div className="ml-auto flex flex-wrap items-center gap-2">
          <label className="relative">
            <Search
              size={14}
              strokeWidth={1.5}
              className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted"
              aria-hidden
            />
            <input
              type="search"
              value={query}
              onChange={(e) => onQuery(e.target.value)}
              placeholder="Search scanners…"
              aria-label="Search scanners"
              className="w-56 rounded-md border border-border bg-surface pl-7 pr-2.5 py-1.5 text-sm text-foreground placeholder:text-muted focus-visible:border-border-strong"
            />
          </label>
          <button
            type="button"
            onClick={onInstallAll}
            disabled={notInstalledCount === 0 || bulkBusy}
            className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-accent-foreground transition-colors hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {bulkProgress ? (
              <>
                <Loader2 size={14} strokeWidth={1.5} className="animate-spin" />
                Installing {bulkProgress.done}/{bulkProgress.total}…
              </>
            ) : (
              <>
                <Wand2 size={14} strokeWidth={1.5} />
                Install all available
                {notInstalledCount > 0 ? ` (${notInstalledCount})` : ""}
              </>
            )}
          </button>
          <button
            type="button"
            onClick={onRefresh}
            disabled={refreshing || bulkBusy}
            title={checkedLabel ? `Last checked ${checkedLabel}` : undefined}
            className="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-surface-2 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw
              size={14}
              strokeWidth={1.5}
              className={refreshing ? "animate-spin" : ""}
            />
            {refreshing ? "Checking…" : "Refresh status"}
            {checkedLabel && !refreshing ? (
              <span className="text-muted ml-1 font-normal">· {checkedLabel}</span>
            ) : null}
          </button>
        </div>
      </div>
    </div>
  );
}

function ScannerCard({
  scanner,
  installing,
  copied,
  onCopy,
  onInstall,
}: {
  scanner: ScannerWithExtras;
  installing: boolean;
  copied: boolean;
  onCopy: (name: string, text: string) => void;
  onInstall: (name: string) => void;
}) {
  const status = statusOf(scanner);
  const version = getVersion(scanner);
  const installCmd = scanner.install_hint?.trim();

  return (
    <article className="flex h-full flex-col rounded-md border border-border bg-card p-5 transition-colors hover:border-border-strong">
      <header className="flex items-start justify-between gap-3">
        <h3 className="text-base font-semibold text-foreground-strong">
          {scanner.name}
        </h3>
        <span
          className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2 py-0.5 text-2xs font-medium ${STATUS_CHIP[status]}`}
        >
          <span
            className={`inline-block h-1.5 w-1.5 rounded-full ${STATUS_DOT[status]}`}
            aria-hidden
          />
          {STATUS_LABEL[status]}
        </span>
      </header>

      <p className="mt-2 line-clamp-2 text-sm text-muted">
        {scanner.description || scanner.message || "—"}
      </p>

      {version && (
        <p className="mt-2 text-2xs text-muted">Version {version}</p>
      )}

      <footer className="mt-auto pt-4">
        {status === "available" &&
          (scanner.last_used ? (
            <Link
              href={`/history?scanner=${encodeURIComponent(scanner.name)}`}
              className="text-xs text-muted transition-colors hover:text-foreground"
            >
              Last used {relativeTime(scanner.last_used)}
            </Link>
          ) : (
            <Link
              href={`/history?scanner=${encodeURIComponent(scanner.name)}`}
              className="text-xs text-muted transition-colors hover:text-foreground"
            >
              View history →
            </Link>
          ))}

        {status === "not_installed" && (
          <div className="space-y-2">
            {installCmd ? (
              <div className="relative">
                <pre className="whitespace-pre-wrap break-all rounded border border-border bg-surface-2 px-2.5 py-1.5 pr-9 text-2xs font-mono text-muted">
                  {installCmd}
                </pre>
                <button
                  type="button"
                  onClick={() => onCopy(scanner.name, installCmd)}
                  aria-label={`Copy install command for ${scanner.name}`}
                  className="absolute right-1 top-1 inline-flex h-6 w-6 items-center justify-center rounded text-muted transition-colors hover:bg-surface hover:text-foreground"
                >
                  {copied ? (
                    <Check size={12} strokeWidth={1.5} />
                  ) : (
                    <Copy size={12} strokeWidth={1.5} />
                  )}
                </button>
              </div>
            ) : (
              <p className="text-2xs text-muted">
                Install instructions unavailable.
              </p>
            )}
            {scanner.installable && (
              <button
                type="button"
                onClick={() => onInstall(scanner.name)}
                disabled={installing}
                className="inline-flex items-center gap-1.5 rounded-md bg-accent px-2.5 py-1 text-2xs font-medium text-accent-foreground transition-colors hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {installing ? (
                  <>
                    <Loader2
                      size={12}
                      strokeWidth={1.5}
                      className="animate-spin"
                    />
                    Installing…
                  </>
                ) : (
                  "Install"
                )}
              </button>
            )}
          </div>
        )}

        {status === "misconfigured" && (
          <Link
            href={`/scanners/${encodeURIComponent(scanner.name)}/configure`}
            className="text-xs font-medium text-sev-medium transition-colors hover:opacity-80"
          >
            Configure →
          </Link>
        )}

        {status === "disabled" && (
          <span className="text-xs text-muted">Disabled</span>
        )}
      </footer>
    </article>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-8">
      {[0, 1].map((g) => (
        <section key={g}>
          <div className="mb-3 h-3 w-24 animate-pulse rounded bg-surface-2" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div
                key={i}
                className="h-36 animate-pulse rounded-md border border-border bg-card"
              />
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

function ErrorAlert({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <div className="flex items-start gap-3 rounded-md border border-sev-critical/40 bg-sev-critical-bg p-4 text-sev-critical">
      <AlertTriangle size={16} strokeWidth={1.5} className="mt-0.5 shrink-0" />
      <div className="flex-1">
        <p className="text-sm font-medium">{message}</p>
        <button
          type="button"
          onClick={onRetry}
          className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-sev-critical/40 px-2.5 py-1 text-xs font-medium text-sev-critical transition-colors hover:bg-sev-critical/10"
        >
          <RefreshCw size={12} strokeWidth={1.5} />
          Retry
        </button>
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="rounded-md border border-border bg-card p-8 text-center">
      <h2 className="text-base font-medium text-foreground-strong">
        No scanners detected
      </h2>
      <p className="mx-auto mt-2 max-w-prose text-sm text-muted">
        SecureScan didn&apos;t find any scanner plugins on this host.
      </p>
      <pre className="mx-auto mt-4 inline-block rounded border border-border bg-surface-2 px-3 py-2 text-2xs font-mono text-muted">
        pip install securescan[all]
      </pre>
      <p className="mt-2 text-xs text-muted">
        installs the default scanner bundle.
      </p>
    </div>
  );
}
