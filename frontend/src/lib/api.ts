const API_HOST = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
// SecureScan v0.6.0+ exposes the versioned /api/v1/* mount as the preferred
// path. The unprefixed /api/* paths still work for older callers but
// respond with a Deprecation header. Override with NEXT_PUBLIC_API_PREFIX
// (e.g. "/api") if you need to talk to a pre-0.6.0 backend.
const API_PREFIX = process.env.NEXT_PUBLIC_API_PREFIX || "/api/v1";
const API_BASE = `${API_HOST}${API_PREFIX}`;

const API_KEY = process.env.NEXT_PUBLIC_SECURESCAN_API_KEY;

function withApiKey(init: RequestInit = {}): RequestInit {
  if (!API_KEY) return init;
  const headers = new Headers(init.headers ?? {});
  if (!headers.has("X-API-Key")) headers.set("X-API-Key", API_KEY);
  return { ...init, headers };
}

export function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  return fetch(input, withApiKey(init));
}

// SSE endpoint URL for live scan-progress events. EventSource is a built-in
// browser API and doesn't need a fetch wrapper, but we centralise the URL
// here so the same API_HOST/API_PREFIX rules apply.
export function getScanEventsUrl(scanId: string): string {
  return `${API_BASE}/scans/${scanId}/events`;
}

// EventSource cannot attach custom headers (no X-API-Key). When the deploy
// is configured with an API key, the SSE endpoint will reject the request
// and we must transparently fall back to status polling.
export function scanEventsAvailable(): boolean {
  return !API_KEY;
}

export type TriageStatus =
  | "new"
  | "triaged"
  | "false_positive"
  | "accepted_risk"
  | "fixed"
  | "wont_fix";

export const TRIAGE_STATUSES: readonly TriageStatus[] = [
  "new",
  "triaged",
  "false_positive",
  "accepted_risk",
  "fixed",
  "wont_fix",
] as const;

export interface FindingState {
  fingerprint: string;
  status: TriageStatus;
  note: string | null;
  updated_at: string;
  updated_by: string | null;
}

export interface FindingComment {
  id: string;
  fingerprint: string;
  text: string;
  author: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  scanner: string;
  scan_type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
  rule_id?: string;
  cwe?: string;
  remediation?: string;
  fingerprint?: string;
  state?: FindingState | null;
  metadata: Record<string, unknown>;
  compliance_tags: string[];
}

export interface ScannerSkip {
  name: string;
  reason: string;
  install_hint?: string | null;
}

export interface Scan {
  id: string;
  target_path: string;
  scan_types: string[];
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  started_at?: string;
  completed_at?: string;
  findings_count: number;
  risk_score?: number;
  summary?: string;
  error?: string;
  target_url?: string;
  target_host?: string;
  scanners_run?: string[];
  scanners_skipped?: ScannerSkip[];
}

export interface ScanSummary {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  risk_score: number;
  scanners_run: string[];
}

export interface DashboardStats {
  total_scans: number;
  total_findings: number;
  average_risk_score: number;
}

export interface ScannerStatus {
  name: string;
  scan_type: string;
  available: boolean;
  message: string;
  description: string;
  checks: string[];
  install_hint: string | null;
  installable: boolean;
}

export async function installScanner(name: string): Promise<{ success: boolean; message: string }> {
  const res = await apiFetch(`${API_BASE}/dashboard/install/${name}`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to install scanner");
  return res.json();
}

export async function fetchScans(): Promise<Scan[]> {
  const res = await apiFetch(`${API_BASE}/scans`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch scans");
  return res.json();
}

export async function fetchScan(id: string): Promise<Scan> {
  const res = await apiFetch(`${API_BASE}/scans/${id}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch scan");
  return res.json();
}

export async function fetchFindings(scanId: string, severity?: string): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  const res = await apiFetch(`${API_BASE}/scans/${scanId}/findings?${params}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch findings");
  return res.json();
}

export async function fetchScanSummary(scanId: string): Promise<ScanSummary> {
  const res = await apiFetch(`${API_BASE}/scans/${scanId}/summary`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch summary");
  return res.json();
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const res = await apiFetch(`${API_BASE}/dashboard/stats`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch stats");
  return res.json();
}

export async function fetchScannerStatus(): Promise<ScannerStatus[]> {
  const res = await apiFetch(`${API_BASE}/dashboard/status`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch status");
  const data = await res.json();
  return data.scanners ?? data;
}

export async function startScan(
  targetPath: string,
  scanTypes: string[],
  targetUrl?: string,
  targetHost?: string,
): Promise<Scan> {
  const res = await apiFetch(`${API_BASE}/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target_path: targetPath,
      scan_types: scanTypes,
      target_url: targetUrl || undefined,
      target_host: targetHost || undefined,
    }),
  });
  if (!res.ok) throw new Error("Failed to start scan");
  return res.json();
}

export async function cancelScan(scanId: string): Promise<Scan> {
  const res = await apiFetch(`${API_BASE}/scans/${scanId}/cancel`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to cancel scan");
  return res.json();
}

export async function deleteScan(scanId: string): Promise<void> {
  const res = await apiFetch(`${API_BASE}/scans/${scanId}`, { method: "DELETE" });
  if (!res.ok) {
    if (res.status === 409) throw new Error("Cannot delete a running scan. Cancel it first.");
    if (res.status === 404) throw new Error("Scan not found.");
    throw new Error(`Failed to delete scan (${res.status})`);
  }
}

// --- Triage (per-finding state + comments) -------------------------------
//
// Endpoints:
//   PATCH  /findings/{fingerprint}/state
//   GET    /findings/{fingerprint}/comments
//   POST   /findings/{fingerprint}/comments
//   DELETE /findings/{fingerprint}/comments/{comment_id}
//
// While the backend is rolling these out, every helper falls back to a
// browser-local store on a 404 so the UI is exercisable end-to-end. The
// fallback is a no-op once the real endpoints respond — the real response
// takes precedence and the local store is only re-read when fetchFindings
// returns `state: null` (see getCachedFindingState below).
const TRIAGE_LS_PREFIX = "securescan.v0.7.triage.";
const COMMENTS_LS_PREFIX = "securescan.v0.7.comments.";

function lsAvailable(): boolean {
  try {
    return typeof window !== "undefined" && !!window.localStorage;
  } catch {
    return false;
  }
}

function lsReadJSON<T>(key: string): T | null {
  if (!lsAvailable()) return null;
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

function lsWriteJSON(key: string, value: unknown): void {
  if (!lsAvailable()) return;
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* quota / private mode — degrade silently */
  }
}

/**
 * Read a previously-applied triage state from the local fallback store.
 * Used by the UI to hydrate findings whose `state` came back null from a
 * backend that hasn't yet shipped the triage tables.
 */
export function getCachedFindingState(fingerprint: string): FindingState | null {
  if (!fingerprint) return null;
  return lsReadJSON<FindingState>(`${TRIAGE_LS_PREFIX}${fingerprint}`);
}

function newCommentId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `c_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

export async function patchFindingState(
  fingerprint: string,
  body: { status: TriageStatus; note?: string | null; updated_by?: string | null },
): Promise<FindingState> {
  const res = await apiFetch(`${API_BASE}/findings/${encodeURIComponent(fingerprint)}/state`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.ok) {
    const state = (await res.json()) as FindingState;
    lsWriteJSON(`${TRIAGE_LS_PREFIX}${fingerprint}`, state);
    return state;
  }
  if (res.status === 404) {
    const fallback: FindingState = {
      fingerprint,
      status: body.status,
      note: body.note ?? null,
      updated_at: new Date().toISOString(),
      updated_by: body.updated_by ?? null,
    };
    lsWriteJSON(`${TRIAGE_LS_PREFIX}${fingerprint}`, fallback);
    return fallback;
  }
  throw new Error(`Failed to update triage status (${res.status})`);
}

export async function listFindingComments(fingerprint: string): Promise<FindingComment[]> {
  const res = await apiFetch(
    `${API_BASE}/findings/${encodeURIComponent(fingerprint)}/comments`,
    { cache: "no-store" },
  );
  if (res.ok) return (await res.json()) as FindingComment[];
  if (res.status === 404) {
    return lsReadJSON<FindingComment[]>(`${COMMENTS_LS_PREFIX}${fingerprint}`) ?? [];
  }
  throw new Error(`Failed to load comments (${res.status})`);
}

export async function addFindingComment(
  fingerprint: string,
  body: { text: string; author?: string | null },
): Promise<FindingComment> {
  const res = await apiFetch(
    `${API_BASE}/findings/${encodeURIComponent(fingerprint)}/comments`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
  if (res.ok) return (await res.json()) as FindingComment;
  if (res.status === 404) {
    const comment: FindingComment = {
      id: newCommentId(),
      fingerprint,
      text: body.text,
      author: body.author ?? null,
      created_at: new Date().toISOString(),
    };
    const key = `${COMMENTS_LS_PREFIX}${fingerprint}`;
    const list = lsReadJSON<FindingComment[]>(key) ?? [];
    list.push(comment);
    lsWriteJSON(key, list);
    return comment;
  }
  throw new Error(`Failed to add comment (${res.status})`);
}

export async function deleteFindingComment(
  fingerprint: string,
  commentId: string,
): Promise<void> {
  const res = await apiFetch(
    `${API_BASE}/findings/${encodeURIComponent(fingerprint)}/comments/${encodeURIComponent(commentId)}`,
    { method: "DELETE" },
  );
  if (res.ok || res.status === 204) return;
  if (res.status === 404) {
    const key = `${COMMENTS_LS_PREFIX}${fingerprint}`;
    const list = lsReadJSON<FindingComment[]>(key);
    if (list) {
      const filtered = list.filter((c) => c.id !== commentId);
      // Only "miss" if the comment really doesn't exist locally either —
      // otherwise this is just the fallback path operating normally.
      if (filtered.length !== list.length) {
        lsWriteJSON(key, filtered);
        return;
      }
    }
    throw new Error("Comment not found");
  }
  throw new Error(`Failed to delete comment (${res.status})`);
}

// --- Directory browser ---

export interface BrowseEntry {
  name: string;
  path: string;
  is_dir: boolean;
}

export interface BrowseResult {
  current: string;
  parent: string | null;
  entries: BrowseEntry[];
}

export async function browsePath(path?: string): Promise<BrowseResult> {
  const params = path ? `?path=${encodeURIComponent(path)}` : "";
  const res = await apiFetch(`${API_BASE}/browse${params}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to browse path");
  return res.json();
}

// --- Scan comparison ---

export interface CompareResult {
  scan_a: Scan;
  scan_b: Scan;
  new_findings: Finding[];
  fixed_findings: Finding[];
  unchanged_findings: Finding[];
  summary: {
    new_count: number;
    fixed_count: number;
    unchanged_count: number;
    risk_delta: number;
  };
}

export async function compareScans(scanAId: string, scanBId: string): Promise<CompareResult> {
  const res = await apiFetch(
    `${API_BASE}/scans/compare?scan_a=${encodeURIComponent(scanAId)}&scan_b=${encodeURIComponent(scanBId)}`,
    { cache: "no-store" }
  );
  if (!res.ok) throw new Error("Failed to compare scans");
  return res.json();
}

// PR-style diff: thin wrapper over compareScans that takes a {base, head}
// argument shape. Used by the /diff dashboard page (FEAT1) to mirror the
// CLI's `compare` subcommand semantics (base = older, head = newer).
export function fetchScanDiff({ base, head }: { base: string; head: string }): Promise<CompareResult> {
  return compareScans(base, head);
}

// --- Trends ---

export interface TrendPoint {
  date: string;
  risk_score: number;
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export async function fetchTrends(days: number = 30): Promise<TrendPoint[]> {
  const res = await apiFetch(`${API_BASE}/dashboard/trends?days=${days}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch trends");
  const data = await res.json();
  return data.data;
}

// --- Compliance ---

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  total_controls: number;
}

export interface ComplianceCoverage {
  framework: string;
  framework_id: string;
  version: string;
  total_controls: number;
  controls_violated: string[];
  controls_clear: string[];
  violated_details: { id: string; name: string }[];
  coverage_percentage: number;
}

export async function fetchComplianceFrameworks(): Promise<ComplianceFramework[]> {
  const res = await apiFetch(`${API_BASE}/compliance/frameworks`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch compliance frameworks");
  const data = await res.json();
  return data.frameworks;
}

export async function fetchComplianceCoverage(scanId: string): Promise<ComplianceCoverage[]> {
  const res = await apiFetch(`${API_BASE}/compliance/coverage?scan_id=${encodeURIComponent(scanId)}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch compliance coverage");
  const data = await res.json();
  return data.coverage;
}

export function getReportUrl(scanId: string, format: "pdf" | "html"): string {
  return `${API_BASE}/scans/${scanId}/report?format=${format}`;
}

// --- SBOM ---

export interface SBOMComponent {
  id: string;
  sbom_id: string;
  name: string;
  version: string;
  type: string;
  purl?: string;
  license?: string;
  supplier?: string;
}

export interface SBOMDocument {
  id: string;
  scan_id?: string;
  target_path: string;
  format: string;
  components: SBOMComponent[];
  created_at: string;
}

export interface SBOMHistoryEntry {
  id: string;
  scan_id: string | null;
  target_path: string;
  format: string;
  created_at: string;
  component_count: number;
}

export async function fetchSBOMHistory(): Promise<SBOMHistoryEntry[]> {
  const res = await apiFetch(`${API_BASE}/sbom/history`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch SBOM history");
  return res.json();
}

export async function generateSBOM(
  targetPath: string,
  format: string = "cyclonedx",
  scanId?: string,
): Promise<{ sbom_id: string; format: string; component_count: number; document: Record<string, unknown> }> {
  const params = new URLSearchParams({ target_path: targetPath, format });
  if (scanId) params.set("scan_id", scanId);
  const res = await apiFetch(`${API_BASE}/sbom/generate?${params}`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to generate SBOM");
  return res.json();
}

export async function fetchSBOM(sbomId: string): Promise<SBOMDocument> {
  const res = await apiFetch(`${API_BASE}/sbom/${sbomId}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch SBOM");
  return res.json();
}

export async function exportSBOM(sbomId: string, format: string = "cyclonedx"): Promise<Record<string, unknown>> {
  const res = await apiFetch(`${API_BASE}/sbom/${sbomId}/export?format=${format}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to export SBOM");
  return res.json();
}
