"use client";

import {
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle,
  ChevronDown,
  GitCompare,
  Loader2,
  X,
} from "lucide-react";
import { fetchScanDiff, fetchScans } from "@/lib/api";
import type { CompareResult, Finding, Scan } from "@/lib/api";
import { DiffFindingRow, type DiffKind } from "@/components/diff-finding-row";

type Tab = "new" | "resolved" | "unchanged";

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function shortId(id: string): string {
  return id.slice(0, 8);
}

function fmtDate(s?: string): string {
  if (!s) return "—";
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function targetLabel(scan: Scan): string {
  const path = scan.target_path;
  const tail = path.split("/").filter(Boolean).pop() || path || "—";
  return tail;
}

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const ra = SEVERITY_RANK[a.severity] ?? 99;
    const rb = SEVERITY_RANK[b.severity] ?? 99;
    if (ra !== rb) return ra - rb;
    return (a.file_path ?? "").localeCompare(b.file_path ?? "");
  });
}

/* ---------- inline primitives — placeholders until DSH3 / DSH5 land ---------- */

function PageHeader({
  title,
  meta,
  actions,
}: {
  title: string;
  meta?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 pb-2">
      <div className="min-w-0">
        <h1 className="text-3xl font-semibold tracking-tight text-foreground-strong leading-none">
          {title}
        </h1>
        {meta ? (
          <p className="mt-2 text-sm text-muted">{meta}</p>
        ) : null}
      </div>
      {actions ? <div className="flex items-center gap-3">{actions}</div> : null}
    </div>
  );
}

function StatLine({
  items,
}: {
  items: { label: string; value: string; tone?: "default" | "critical" | "accent" | "muted" }[];
}) {
  const toneClass: Record<string, string> = {
    default: "text-foreground-strong",
    critical: "text-sev-critical",
    accent: "text-accent",
    muted: "text-muted",
  };
  return (
    <dl className="flex flex-wrap items-center gap-x-6 gap-y-2">
      {items.map((it) => (
        <div key={it.label} className="flex items-baseline gap-2">
          <dt className="text-2xs uppercase tracking-wider text-muted">
            {it.label}
          </dt>
          <dd
            className={`text-lg font-semibold tabular-nums ${toneClass[it.tone ?? "default"]}`}
          >
            {it.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/* ---------- scan picker dropdown ---------- */

interface ScanPickerProps {
  label: string;
  scans: Scan[];
  value: string;
  onChange: (id: string) => void;
  placeholder: string;
  disabled?: boolean;
}

function ScanPicker({
  label,
  scans,
  value,
  onChange,
  placeholder,
  disabled,
}: ScanPickerProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (!ref.current) return;
      if (!ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const selected = scans.find((s) => s.id === value);

  return (
    <div ref={ref} className="relative flex flex-col gap-1.5 min-w-0 flex-1">
      <span className="text-2xs uppercase tracking-wider text-muted">
        {label}
      </span>
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className={`
          group flex items-center justify-between gap-2 min-w-0
          h-9 px-3 rounded-md border bg-surface text-sm
          transition-colors
          ${selected ? "text-foreground-strong" : "text-muted"}
          ${disabled
            ? "opacity-50 cursor-not-allowed border-border"
            : "border-border hover:border-border-strong focus-visible:border-accent"}
        `}
      >
        <span className="truncate text-left">
          {selected ? (
            <ScanPickerLabel scan={selected} />
          ) : (
            placeholder
          )}
        </span>
        <ChevronDown
          size={14}
          strokeWidth={1.5}
          className={`shrink-0 text-muted transition-transform ${open ? "rotate-180" : ""}`}
          aria-hidden
        />
      </button>

      {open && (
        <ul
          role="listbox"
          className="
            absolute z-30 top-full left-0 right-0 mt-1
            max-h-72 overflow-y-auto
            rounded-md border border-border bg-surface
            shadow-lg shadow-black/20
            py-1
          "
        >
          {scans.length === 0 ? (
            <li className="px-3 py-2 text-xs text-muted italic">
              No matching scans
            </li>
          ) : (
            scans.map((s) => {
              const active = s.id === value;
              return (
                <li key={s.id}>
                  <button
                    type="button"
                    role="option"
                    aria-selected={active}
                    onClick={() => {
                      onChange(s.id);
                      setOpen(false);
                    }}
                    className={`
                      flex w-full items-center gap-3 px-3 py-1.5 text-left text-sm
                      transition-colors
                      ${active
                        ? "bg-accent-soft text-accent"
                        : "text-foreground hover:bg-surface-2"}
                    `}
                  >
                    <ScanPickerLabel scan={s} />
                  </button>
                </li>
              );
            })
          )}
        </ul>
      )}
    </div>
  );
}

function ScanPickerLabel({ scan }: { scan: Scan }) {
  return (
    <span className="flex items-baseline gap-2 min-w-0">
      <span className="truncate text-sm">{targetLabel(scan)}</span>
      <span className="font-mono text-2xs text-muted shrink-0">
        {shortId(scan.id)}
      </span>
      <span className="text-2xs text-muted shrink-0">
        · {fmtDate(scan.completed_at ?? scan.started_at)}
      </span>
    </span>
  );
}

/* ---------- empty / status states ---------- */

function PromptEmpty() {
  return (
    <div className="rounded-md border border-border bg-surface p-12 flex flex-col items-center text-center">
      <GitCompare
        size={24}
        strokeWidth={1.5}
        className="text-muted mb-3"
        aria-hidden
      />
      <p className="text-base font-medium text-foreground-strong">
        Pick a base scan to compare against.
      </p>
      <p className="mt-1 text-sm text-muted max-w-prose">
        Diff is the PR-style view: pick two scans of the same target and see
        what changed. The base is the older scan; the head is the newer one.
      </p>
    </div>
  );
}

function NoChangesEmpty() {
  return (
    <div className="rounded-md border border-border bg-surface p-12 flex flex-col items-center text-center">
      <CheckCircle
        size={24}
        strokeWidth={1.5}
        className="text-accent mb-3"
        aria-hidden
      />
      <p className="text-base font-medium text-foreground-strong">
        No changes between these scans.
      </p>
      <p className="mt-1 text-sm text-muted max-w-prose">
        Every finding in the head matches the base. Risk score is unchanged.
      </p>
    </div>
  );
}

function ErrorBanner({
  message,
  onDismiss,
}: {
  message: string;
  onDismiss: () => void;
}) {
  return (
    <div
      role="alert"
      className="
        flex items-center gap-2.5 rounded-md
        border border-sev-critical/30 bg-sev-critical-bg
        px-3 py-2 text-sm text-foreground-strong
      "
    >
      <AlertTriangle
        size={16}
        strokeWidth={1.5}
        className="text-sev-critical shrink-0"
        aria-hidden
      />
      <span className="flex-1">{message}</span>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss"
        className="text-muted hover:text-foreground-strong p-0.5 rounded"
      >
        <X size={14} strokeWidth={1.5} aria-hidden />
      </button>
    </div>
  );
}

function ResultSkeleton() {
  return (
    <div className="space-y-4">
      <div className="h-6 w-2/3 rounded bg-surface-2 animate-pulse" />
      <div className="h-px bg-border" />
      <div className="space-y-1.5">
        {[0, 1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className="h-9 rounded bg-surface-2 animate-pulse"
            style={{ animationDelay: `${i * 50}ms` }}
          />
        ))}
      </div>
    </div>
  );
}

/* ---------- diff results: tabs + table ---------- */

interface DiffResultProps {
  result: CompareResult;
  baseId: string;
  headId: string;
}

function DiffResult({ result, baseId, headId }: DiffResultProps) {
  const [tab, setTab] = useState<Tab>("new");

  const newFindings = useMemo(
    () => sortBySeverity(result.new_findings),
    [result.new_findings],
  );
  const resolvedFindings = useMemo(
    () => sortBySeverity(result.fixed_findings),
    [result.fixed_findings],
  );
  const unchangedFindings = useMemo(
    () => sortBySeverity(result.unchanged_findings),
    [result.unchanged_findings],
  );

  const { new_count, fixed_count, unchanged_count, risk_delta } = result.summary;
  const totalChanged = new_count + fixed_count;

  if (totalChanged === 0) {
    return <NoChangesEmpty />;
  }

  const hasCriticalNew = newFindings.some((f) => f.severity === "critical");

  const riskTone: "critical" | "accent" | "muted" =
    risk_delta > 0 ? "critical" : risk_delta < 0 ? "accent" : "muted";
  const riskLabel =
    risk_delta > 0 ? `+${risk_delta}` : risk_delta < 0 ? `${risk_delta}` : "0";

  const rows: { kind: DiffKind; list: Finding[]; linkScanId: string } =
    tab === "new"
      ? { kind: "new", list: newFindings, linkScanId: headId }
      : tab === "resolved"
      ? { kind: "resolved", list: resolvedFindings, linkScanId: baseId }
      : { kind: "unchanged", list: unchangedFindings, linkScanId: headId };

  return (
    <div className="space-y-5">
      {/* Summary strip */}
      <div className="rounded-md border border-border bg-surface px-5 py-4">
        <StatLine
          items={[
            {
              label: "New",
              value: `+${new_count}`,
              tone: hasCriticalNew ? "critical" : new_count > 0 ? "default" : "muted",
            },
            {
              label: "Resolved",
              value: `−${fixed_count}`,
              tone: fixed_count > 0 ? "accent" : "muted",
            },
            {
              label: "Unchanged",
              value: `=${unchanged_count}`,
              tone: "muted",
            },
            {
              label: "Risk Δ",
              value: riskLabel,
              tone: riskTone,
            },
          ]}
        />
      </div>

      {/* Tabs */}
      <div className="border-b border-border">
        <div role="tablist" className="flex items-end gap-1 -mb-px">
          <DiffTab
            active={tab === "new"}
            edge="bg-sev-critical"
            onClick={() => setTab("new")}
            label="New"
            count={new_count}
          />
          <DiffTab
            active={tab === "resolved"}
            edge="bg-accent"
            onClick={() => setTab("resolved")}
            label="Resolved"
            count={fixed_count}
          />
          <DiffTab
            active={tab === "unchanged"}
            edge="bg-border-strong"
            onClick={() => setTab("unchanged")}
            label="Unchanged"
            count={unchanged_count}
          />
        </div>
      </div>

      {/* Findings table */}
      {rows.list.length === 0 ? (
        <div className="rounded-md border border-border bg-surface p-10 text-center">
          <p className="text-sm text-muted">
            {tab === "new" && "No new findings introduced."}
            {tab === "resolved" && "No findings were resolved."}
            {tab === "unchanged" && "No unchanged findings carried forward."}
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-md border border-border bg-surface">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="border-b border-border bg-surface-2">
                <th className="w-1" aria-hidden />
                <th className="w-6" aria-hidden />
                <th className="px-3 py-2 w-28 text-left text-2xs uppercase tracking-wider font-medium text-muted">
                  Severity
                </th>
                <th className="px-3 py-2 text-left text-2xs uppercase tracking-wider font-medium text-muted">
                  File
                </th>
                <th className="px-3 py-2 text-left text-2xs uppercase tracking-wider font-medium text-muted">
                  Finding
                </th>
                <th className="px-3 py-2 w-28 text-left text-2xs uppercase tracking-wider font-medium text-muted">
                  Scanner
                </th>
                <th className="px-3 py-2 w-[7.5rem] text-right text-2xs uppercase tracking-wider font-medium text-muted">
                  Action
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.list.map((f) => (
                <DiffFindingRow
                  key={`${rows.kind}:${f.fingerprint || f.id}`}
                  finding={f}
                  kind={rows.kind}
                  linkScanId={rows.linkScanId}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function DiffTab({
  active,
  edge,
  label,
  count,
  onClick,
}: {
  active: boolean;
  edge: string;
  label: string;
  count: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={`
        relative inline-flex items-center gap-2
        px-4 py-2.5 text-sm font-medium
        border-b-2 transition-colors
        ${active
          ? "border-foreground-strong text-foreground-strong"
          : "border-transparent text-muted hover:text-foreground"}
      `}
    >
      <span
        aria-hidden
        className={`absolute left-0 top-1.5 bottom-1.5 w-[2px] rounded-full ${edge}`}
      />
      <span className="pl-2">{label}</span>
      <span
        className={`
          inline-flex items-center justify-center min-w-5 px-1.5
          rounded text-2xs font-medium tabular-nums
          ${active ? "bg-surface-2 text-foreground" : "text-muted"}
        `}
      >
        {count}
      </span>
    </button>
  );
}

/* ---------- main page ---------- */

function DiffPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const baseFromUrl = searchParams.get("base") ?? "";
  const headFromUrl = searchParams.get("head") ?? "";

  const [scans, setScans] = useState<Scan[]>([]);
  const [scansLoading, setScansLoading] = useState(true);
  const [scansError, setScansError] = useState<string | null>(null);

  const [base, setBase] = useState(baseFromUrl);
  const [head, setHead] = useState(headFromUrl);
  const [error, setError] = useState<string | null>(null);

  const [result, setResult] = useState<CompareResult | null>(null);
  const [running, setRunning] = useState(false);
  const lastRunKey = useRef<string>("");

  // Load completed scans once.
  useEffect(() => {
    fetchScans()
      .then((all) => {
        setScans(all.filter((s) => s.status === "completed"));
      })
      .catch(() => setScansError("Failed to load scans"))
      .finally(() => setScansLoading(false));
  }, []);

  // Sync local state when URL params change (e.g. on back/forward).
  useEffect(() => {
    setBase(baseFromUrl);
  }, [baseFromUrl]);
  useEffect(() => {
    setHead(headFromUrl);
  }, [headFromUrl]);

  const baseScan = useMemo(
    () => scans.find((s) => s.id === base) ?? null,
    [scans, base],
  );

  const baseChoices = scans;
  const headChoices = useMemo(() => {
    // Show every scan except the currently-selected base. Cross-target
    // diffs (fork vs upstream, service-A vs service-B) are valid since
    // the v0.11.8 /compare → /diff merge — the backend handles them
    // and the headChoices filter shouldn't pretend otherwise.
    if (!baseScan) return scans;
    return scans.filter((s) => s.id !== baseScan.id);
  }, [scans, baseScan]);

  const writeUrl = useCallback(
    (nextBase: string, nextHead: string) => {
      const sp = new URLSearchParams();
      if (nextBase) sp.set("base", nextBase);
      if (nextHead) sp.set("head", nextHead);
      const qs = sp.toString();
      router.replace(qs ? `/diff?${qs}` : "/diff", { scroll: false });
    },
    [router],
  );

  const runDiff = useCallback(
    async (nextBase: string, nextHead: string) => {
      if (!nextBase || !nextHead) return;
      const key = `${nextBase}::${nextHead}`;
      lastRunKey.current = key;
      setRunning(true);
      setError(null);
      setResult(null);
      try {
        const data = await fetchScanDiff({ base: nextBase, head: nextHead });
        if (lastRunKey.current === key) {
          setResult(data);
        }
      } catch {
        if (lastRunKey.current === key) {
          setError("Failed to compute diff. Please try again.");
        }
      } finally {
        if (lastRunKey.current === key) {
          setRunning(false);
        }
      }
    },
    [],
  );

  const validateAndRun = useCallback(
    async (b: string, h: string) => {
      if (b && h && b === h) {
        setError("Pick two different scans.");
        setResult(null);
        return;
      }
      // The v0.11.8 consolidation merged /compare into /diff. Before
      // that merge this branch refused cross-target pairs and
      // suggested "Use Compare for cross-target diffs" — but Compare
      // is gone now and the backend's /api/v1/scans/compare endpoint
      // handles cross-target fine. Cross-target diffs are useful
      // (fork vs upstream, service-A vs service-B), so allow them.
      // Same-scan (b === h) is the only real input error.
      setError(null);
      await runDiff(b, h);
    },
    [runDiff],
  );

  function handleBaseChange(id: string) {
    setBase(id);
    writeUrl(id, head);
    if (id && head) {
      void validateAndRun(id, head);
    } else {
      setResult(null);
    }
  }

  function handleHeadChange(id: string) {
    setHead(id);
    writeUrl(base, id);
    if (base && id) {
      void validateAndRun(base, id);
    } else {
      setResult(null);
    }
  }

  // Auto-run when both ids are pre-filled from the URL and scans are loaded.
  const autoRanRef = useRef(false);
  useEffect(() => {
    if (autoRanRef.current) return;
    if (scansLoading) return;
    if (!baseFromUrl || !headFromUrl) return;
    autoRanRef.current = true;
    void validateAndRun(baseFromUrl, headFromUrl);
  }, [scansLoading, baseFromUrl, headFromUrl, validateAndRun]);

  const canRun = Boolean(base && head) && base !== head;

  return (
    <div className="space-y-6 pb-12">
      <PageHeader
        title="Diff"
        meta="See what's new, gone, or unchanged between two scans."
      />

      {/* Sticky selector row */}
      <div
        className="
          sticky top-14 z-20 -mx-4 md:-mx-8
          bg-background/85 backdrop-blur
          border-b border-border
          px-4 md:px-8 py-3
        "
      >
        <div className="flex flex-wrap items-end gap-3">
          <ScanPicker
            label="Base scan"
            scans={baseChoices}
            value={base}
            onChange={handleBaseChange}
            placeholder={scansLoading ? "Loading scans…" : "Select base scan…"}
            disabled={scansLoading || !!scansError}
          />

          <div className="pb-1.5 px-1 text-muted shrink-0" aria-hidden>
            <ArrowRight size={16} strokeWidth={1.5} />
          </div>

          <ScanPicker
            label="Head scan"
            scans={headChoices}
            value={head}
            onChange={handleHeadChange}
            placeholder={
              !base
                ? "Pick a base first…"
                : headChoices.length === 0
                ? "No other scans for this target"
                : "Select head scan…"
            }
            disabled={scansLoading || !!scansError || !base}
          />

          <button
            type="button"
            onClick={() => canRun && validateAndRun(base, head)}
            disabled={!canRun || running}
            className="
              shrink-0 inline-flex items-center gap-2 h-9 px-4 rounded-md
              bg-accent text-accent-foreground text-sm font-medium
              transition-colors
              hover:bg-accent/90
              disabled:opacity-40 disabled:cursor-not-allowed
            "
          >
            {running ? (
              <Loader2 size={14} strokeWidth={1.5} className="animate-spin" />
            ) : (
              <GitCompare size={14} strokeWidth={1.5} />
            )}
            <span>{running ? "Running…" : "Run diff"}</span>
          </button>
        </div>
      </div>

      {scansError && (
        <ErrorBanner
          message={scansError}
          onDismiss={() => setScansError(null)}
        />
      )}
      {error && (
        <ErrorBanner message={error} onDismiss={() => setError(null)} />
      )}

      {/* Body */}
      {!base ? (
        <PromptEmpty />
      ) : running ? (
        <ResultSkeleton />
      ) : !head ? (
        <div className="rounded-md border border-border bg-surface p-10 text-center text-sm text-muted">
          Pick a head scan to diff against{" "}
          <span className="font-mono text-foreground">
            {baseScan ? targetLabel(baseScan) : ""}
            {baseScan ? ` · ${shortId(baseScan.id)}` : ""}
          </span>
          .
        </div>
      ) : result ? (
        <DiffResult result={result} baseId={base} headId={head} />
      ) : null}
    </div>
  );
}

export default function DiffPage() {
  return (
    <Suspense fallback={<ResultSkeleton />}>
      <DiffPageInner />
    </Suspense>
  );
}
