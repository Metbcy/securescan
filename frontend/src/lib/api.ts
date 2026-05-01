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

export async function fetchFindings(
  scanId: string,
  options?: { severity?: string; limit?: number },
): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (options?.severity) params.set("severity", options.severity);
  if (options?.limit != null) params.set("limit", String(options.limit));
  const qs = params.toString();
  const url = qs
    ? `${API_BASE}/scans/${scanId}/findings?${qs}`
    : `${API_BASE}/scans/${scanId}/findings`;
  const res = await apiFetch(url, { cache: "no-store" });
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

export interface ScannerStatusResponse {
  scanners: ScannerStatus[];
  /** ISO 8601 server-side timestamp of when this fresh check ran. */
  checked_at: string | null;
}

export async function fetchScannerStatus(): Promise<ScannerStatus[]> {
  const res = await apiFetch(`${API_BASE}/dashboard/status`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch status");
  const data = await res.json();
  return data.scanners ?? data;
}

/** v0.10.1+: returns the full envelope including `checked_at` so the UI
 * can show "Last refreshed Xs ago" and confirm manual refresh did fresh
 * work. Falls back gracefully when the backend is pre-v0.10.1. */
export async function fetchScannerStatusEnvelope(): Promise<ScannerStatusResponse> {
  const res = await apiFetch(`${API_BASE}/dashboard/status`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch status");
  const data = await res.json();
  return {
    scanners: data.scanners ?? data,
    checked_at: data.checked_at ?? null,
  };
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

// --- SSE event-token (v0.9.0) -------------------------------------------
//
// EventSource cannot attach custom headers, so authenticated deployments
// can't send X-API-Key on the /events stream. The v0.9 backend exposes a
// short-lived, scan-bound token that the FE mints up-front and passes as
// `?event_token=<token>` on the /events URL. The token is HMAC-signed,
// scoped to the originating API key, and typically expires in 5 minutes
// (the FE rotates at half-life — see scan/[id]/page.tsx).
//
// On a pre-v0.9 backend the mint endpoint 404s; the page-level effect
// catches that and falls through to the v0.7-style headerless EventSource
// (which works in dev mode without a token).

export type EventTokenResponse = { token: string; expires_in: number };

export async function mintScanEventToken(scanId: string): Promise<EventTokenResponse> {
  const res = await apiFetch(`${API_BASE}/scans/${scanId}/event-token`, {
    method: "POST",
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Failed to mint event token (${res.status})`);
  }
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

// --- API keys (admin) ---------------------------------------------------
//
// Endpoints (all behind require_scope("admin")):
//   POST   /keys           {name, scopes}        → 201 ApiKeyCreated
//   GET    /keys                                 → ApiKeyView[]
//   GET    /keys/me                              → ApiKeyView (caller's own)
//   DELETE /keys/{key_id}                        → 204
//
// While BE-AUTH-KEYS is in flight we mirror the v0.7.0 triage pattern: when
// the backend responds 404 Not Found (router not yet mounted), the helpers
// fall through to a browser-local mock store keyed by KEYS_LS_KEY. Once the
// real endpoint ships, the live response wins and the mock is ignored. Any
// other non-success status is surfaced as an error.

export type ApiKeyScope = "read" | "write" | "admin";

export interface ApiKeyView {
  id: string;
  name: string;
  prefix: string;
  scopes: ApiKeyScope[];
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface ApiKeyCreated extends ApiKeyView {
  // FULL key — only returned on create. Treat as a one-shot secret.
  key: string;
}

const KEYS_LS_KEY = "securescan.v0.8.api-keys";

function mockKeysAvailable(): boolean {
  return lsAvailable();
}

function readMockKeys(): ApiKeyView[] {
  return lsReadJSON<ApiKeyView[]>(KEYS_LS_KEY) ?? [];
}

function writeMockKeys(keys: ApiKeyView[]): void {
  lsWriteJSON(KEYS_LS_KEY, keys);
}

function randomPrefix(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let body = "";
  for (let i = 0; i < 10; i += 1) {
    body += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  let tail = "";
  for (let i = 0; i < 2; i += 1) {
    tail += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return `ssk_${body}_${tail}`;
}

function randomKeyId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `k_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function randomKeyBody(): string {
  // ~32 chars of entropy after the prefix to look like a real secret in the
  // mock-only flow; the real backend returns a server-generated value.
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 32; i += 1) {
    out += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return out;
}

export async function listApiKeys(): Promise<ApiKeyView[]> {
  const res = await apiFetch(`${API_BASE}/keys`, { cache: "no-store" });
  if (res.ok) return (await res.json()) as ApiKeyView[];
  if (res.status === 404 && mockKeysAvailable()) return readMockKeys();
  throw new Error(`Failed to load API keys (${res.status})`);
}

export async function createApiKey(body: {
  name: string;
  scopes: ApiKeyScope[];
}): Promise<ApiKeyCreated> {
  const res = await apiFetch(`${API_BASE}/keys`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.ok) return (await res.json()) as ApiKeyCreated;
  if (res.status === 404 && mockKeysAvailable()) {
    const prefix = randomPrefix();
    const created: ApiKeyCreated = {
      id: randomKeyId(),
      name: body.name,
      prefix,
      scopes: body.scopes,
      created_at: new Date().toISOString(),
      last_used_at: null,
      revoked_at: null,
      key: `${prefix}.${randomKeyBody()}`,
    };
    const list = readMockKeys();
    // Persist only the view; the full key is one-shot and never stored.
    const view: ApiKeyView = {
      id: created.id,
      name: created.name,
      prefix: created.prefix,
      scopes: created.scopes,
      created_at: created.created_at,
      last_used_at: created.last_used_at,
      revoked_at: created.revoked_at,
    };
    list.unshift(view);
    writeMockKeys(list);
    return created;
  }
  if (res.status === 400 || res.status === 422) {
    let detail = "Invalid key request.";
    try {
      const data = (await res.json()) as { detail?: string };
      if (data?.detail) detail = data.detail;
    } catch {
      /* keep default */
    }
    throw new Error(detail);
  }
  throw new Error(`Failed to create API key (${res.status})`);
}

export async function getApiKeyMe(): Promise<ApiKeyView | null> {
  let res: Response;
  try {
    res = await apiFetch(`${API_BASE}/keys/me`, { cache: "no-store" });
  } catch {
    return null;
  }
  if (res.ok) return (await res.json()) as ApiKeyView;
  if (res.status === 404 || res.status === 401 || res.status === 403) return null;
  throw new Error(`Failed to load current API key (${res.status})`);
}

// --- Notifications ------------------------------------------------------
//
// Endpoints (all under /api/v1/notifications, read scope unless noted):
//   GET   /notifications?unread_only=<bool>&limit=<int>   → Notification[]
//   GET   /notifications/unread-count                     → {count}
//   PATCH /notifications/{id}/read       (write)          → Notification
//   PATCH /notifications/read-all        (write)          → {marked_read}
//
// While BE-NOTIFY is in flight (or the user is authenticated with an API key
// scoped below `read`), every helper falls through to a browser-local mock
// store on a 404 so the bell + /notifications page stay exercisable. The
// mock mirrors the same Notification shape so swapping in the real backend
// is transparent. Mocked rows are seeded by other parts of the dashboard
// writing to NOTIFS_LS_KEY directly (e.g. from the agent-browser smoke).

export type NotificationSeverity = "info" | "warning" | "error";

export interface Notification {
  id: string;
  type: string;
  title: string;
  body: string | null;
  link: string | null;
  severity: NotificationSeverity;
  created_at: string;
  read_at: string | null;
}

const NOTIFS_LS_KEY = "securescan.v0.9.notifications";
const NOTIFS_TIMEOUT_MS = 4_000;

function fetchNotifications(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), NOTIFS_TIMEOUT_MS);
  return apiFetch(`${API_BASE}${path}`, { ...init, signal: ctl.signal }).finally(
    () => clearTimeout(timer),
  );
}

function readMockNotifications(): Notification[] {
  return lsReadJSON<Notification[]>(NOTIFS_LS_KEY) ?? [];
}

function writeMockNotifications(list: Notification[]): void {
  lsWriteJSON(NOTIFS_LS_KEY, list);
}

function sortNotificationsNewestFirst(list: Notification[]): Notification[] {
  return [...list].sort(
    (a, b) =>
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  );
}

export async function listNotifications(
  opts: { unread_only?: boolean; limit?: number } = {},
): Promise<Notification[]> {
  const params = new URLSearchParams();
  if (opts.unread_only) params.set("unread_only", "true");
  if (opts.limit != null) params.set("limit", String(opts.limit));
  const qs = params.toString();
  let res: Response;
  try {
    res = await fetchNotifications(
      `/notifications${qs ? `?${qs}` : ""}`,
      { cache: "no-store" },
    );
  } catch {
    // Backend unreachable / timed out — fall through to the local mock so
    // the UI is exercisable. Same contract as the 404 path below.
    if (lsAvailable()) return readLocalNotifications(opts);
    throw new Error("Failed to load notifications");
  }
  if (res.ok) return (await res.json()) as Notification[];
  if (res.status === 404 && lsAvailable()) return readLocalNotifications(opts);
  throw new Error(`Failed to load notifications (${res.status})`);
}

function readLocalNotifications(opts: {
  unread_only?: boolean;
  limit?: number;
}): Notification[] {
  let list = sortNotificationsNewestFirst(readMockNotifications());
  if (opts.unread_only) list = list.filter((n) => n.read_at == null);
  if (opts.limit != null) list = list.slice(0, opts.limit);
  return list;
}

export async function getUnreadNotificationCount(): Promise<number> {
  let res: Response;
  try {
    res = await fetchNotifications(`/notifications/unread-count`, {
      cache: "no-store",
    });
  } catch {
    if (lsAvailable()) {
      return readMockNotifications().filter((n) => n.read_at == null).length;
    }
    throw new Error("Failed to load unread count");
  }
  if (res.ok) {
    const data = (await res.json()) as { count: number };
    return data.count ?? 0;
  }
  if (res.status === 404 && lsAvailable()) {
    return readMockNotifications().filter((n) => n.read_at == null).length;
  }
  throw new Error(`Failed to load unread count (${res.status})`);
}

export async function markNotificationRead(id: string): Promise<Notification> {
  let res: Response;
  try {
    res = await fetchNotifications(
      `/notifications/${encodeURIComponent(id)}/read`,
      { method: "PATCH" },
    );
  } catch {
    if (lsAvailable()) return localMarkRead(id);
    throw new Error("Failed to mark notification read");
  }
  if (res.ok) return (await res.json()) as Notification;
  if (res.status === 404 && lsAvailable()) return localMarkRead(id);
  throw new Error(`Failed to mark notification read (${res.status})`);
}

function localMarkRead(id: string): Notification {
  const list = readMockNotifications();
  const idx = list.findIndex((n) => n.id === id);
  if (idx === -1) throw new Error("Notification not found");
  if (!list[idx].read_at) {
    list[idx] = { ...list[idx], read_at: new Date().toISOString() };
    writeMockNotifications(list);
  }
  return list[idx];
}

export async function markAllNotificationsRead(): Promise<{
  marked_read: number;
}> {
  let res: Response;
  try {
    res = await fetchNotifications(`/notifications/read-all`, {
      method: "PATCH",
    });
  } catch {
    if (lsAvailable()) return localMarkAllRead();
    throw new Error("Failed to mark all read");
  }
  if (res.ok) return (await res.json()) as { marked_read: number };
  if (res.status === 404 && lsAvailable()) return localMarkAllRead();
  throw new Error(`Failed to mark all read (${res.status})`);
}

function localMarkAllRead(): { marked_read: number } {
  const list = readMockNotifications();
  const now = new Date().toISOString();
  let count = 0;
  const updated = list.map((n) => {
    if (n.read_at) return n;
    count += 1;
    return { ...n, read_at: now };
  });
  writeMockNotifications(updated);
  return { marked_read: count };
}

// --- Webhooks (admin) ---------------------------------------------------
//
// Endpoints (all behind require_scope("admin")):
//   POST   /webhooks                              → 201 WebhookCreated
//   GET    /webhooks                              → Webhook[]
//   PATCH  /webhooks/{id}                         → Webhook (updated)
//   DELETE /webhooks/{id}                         → 204
//   GET    /webhooks/{id}/deliveries              → WebhookDelivery[] (last 100)
//   POST   /webhooks/{id}/test                    → {delivery_id: string}
//
// While BE-WEBHOOKS is in flight we follow the v0.8.0 keys pattern: a 404
// response means the router isn't mounted yet, so we transparently fall
// through to a browser-local mock. Any other non-success status is surfaced
// as an error. The mocked POST /test endpoint synthesises a `webhook.test`
// delivery row that flips to `succeeded` (URL parses as https?://) or
// `failed` after ~1s so the auto-refresh in the delivery drawer is
// exercisable end-to-end.

export type WebhookEventType = "scan.complete" | "scan.failed" | "scanner.failed";

export interface Webhook {
  id: string;
  name: string;
  url: string;
  event_filter: WebhookEventType[];
  enabled: boolean;
  created_at: string;
}

export interface WebhookCreated extends Webhook {
  // Signing secret. Only returned on create; treat as a one-shot value.
  secret: string;
}

export type WebhookDeliveryStatus =
  | "pending"
  | "delivering"
  | "succeeded"
  | "failed";

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event: string;
  status: WebhookDeliveryStatus;
  attempt: number;
  next_attempt_at: string;
  created_at: string;
  updated_at: string;
  response_code: number | null;
  response_body: string | null;
}

const WEBHOOKS_LS_KEY = "securescan.v0.9.webhooks";
const WEBHOOK_DELIVERIES_LS_KEY = "securescan.v0.9.webhook-deliveries";

function mockWebhooksAvailable(): boolean {
  return lsAvailable();
}

function readMockWebhooks(): Webhook[] {
  return lsReadJSON<Webhook[]>(WEBHOOKS_LS_KEY) ?? [];
}

function writeMockWebhooks(list: Webhook[]): void {
  lsWriteJSON(WEBHOOKS_LS_KEY, list);
}

function readMockDeliveries(): Record<string, WebhookDelivery[]> {
  return lsReadJSON<Record<string, WebhookDelivery[]>>(WEBHOOK_DELIVERIES_LS_KEY) ?? {};
}

function writeMockDeliveries(map: Record<string, WebhookDelivery[]>): void {
  lsWriteJSON(WEBHOOK_DELIVERIES_LS_KEY, map);
}

function randomWebhookId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `wh_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function randomDeliveryId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `whd_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function randomWebhookSecret(): string {
  // 48 hex chars — looks like an HMAC-grade secret in the mock-only flow.
  const alphabet = "0123456789abcdef";
  let out = "whsec_";
  for (let i = 0; i < 48; i += 1) {
    out += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return out;
}

function pushMockDelivery(webhookId: string, delivery: WebhookDelivery): void {
  const map = readMockDeliveries();
  const list = map[webhookId] ?? [];
  list.unshift(delivery);
  // Preserve newest-first; cap at 100 to mirror the backend contract.
  map[webhookId] = list.slice(0, 100);
  writeMockDeliveries(map);
}

function updateMockDelivery(
  webhookId: string,
  deliveryId: string,
  patch: Partial<WebhookDelivery>,
): void {
  const map = readMockDeliveries();
  const list = map[webhookId];
  if (!list) return;
  const idx = list.findIndex((d) => d.id === deliveryId);
  if (idx === -1) return;
  list[idx] = { ...list[idx], ...patch, updated_at: new Date().toISOString() };
  map[webhookId] = list;
  writeMockDeliveries(map);
}

// Short-timeout wrapper. Returns the Response on success, or null on a
// network error / abort. The caller treats a null response the same as a
// 404, falling through to the localStorage mock. This keeps the page
// usable while BE-WEBHOOKS is in flight (when the backend may be missing,
// half-deployed, or unresponsive).
const WEBHOOK_FETCH_TIMEOUT_MS = 4000;

async function webhookFetch(
  input: string,
  init: RequestInit = {},
): Promise<Response | null> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), WEBHOOK_FETCH_TIMEOUT_MS);
  try {
    return await apiFetch(input, { ...init, signal: ctl.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function listWebhooks(): Promise<Webhook[]> {
  const res = await webhookFetch(`${API_BASE}/webhooks`, { cache: "no-store" });
  if (res?.ok) return (await res.json()) as Webhook[];
  if ((!res || res.status === 404) && mockWebhooksAvailable()) {
    return readMockWebhooks();
  }
  throw new Error(`Failed to load webhooks (${res?.status ?? "network"})`);
}

export async function createWebhook(body: {
  name: string;
  url: string;
  event_filter: WebhookEventType[];
}): Promise<WebhookCreated> {
  const res = await webhookFetch(`${API_BASE}/webhooks`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res?.ok) return (await res.json()) as WebhookCreated;
  if ((!res || res.status === 404) && mockWebhooksAvailable()) {
    const now = new Date().toISOString();
    const created: WebhookCreated = {
      id: randomWebhookId(),
      name: body.name,
      url: body.url,
      event_filter: body.event_filter,
      enabled: true,
      created_at: now,
      secret: randomWebhookSecret(),
    };
    const list = readMockWebhooks();
    const view: Webhook = {
      id: created.id,
      name: created.name,
      url: created.url,
      event_filter: created.event_filter,
      enabled: created.enabled,
      created_at: created.created_at,
    };
    list.unshift(view);
    writeMockWebhooks(list);
    return created;
  }
  if (res && (res.status === 400 || res.status === 422)) {
    let detail = "Invalid webhook request.";
    try {
      const data = (await res.json()) as { detail?: string };
      if (data?.detail) detail = data.detail;
    } catch {
      /* keep default */
    }
    throw new Error(detail);
  }
  throw new Error(`Failed to create webhook (${res?.status ?? "network"})`);
}

export async function patchWebhook(
  id: string,
  body: Partial<Pick<Webhook, "name" | "url" | "event_filter" | "enabled">>,
): Promise<Webhook> {
  const res = await webhookFetch(
    `${API_BASE}/webhooks/${encodeURIComponent(id)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
  if (res?.ok) return (await res.json()) as Webhook;
  if ((!res || res.status === 404) && mockWebhooksAvailable()) {
    const list = readMockWebhooks();
    const idx = list.findIndex((w) => w.id === id);
    if (idx === -1) throw new Error("Webhook not found.");
    const updated: Webhook = { ...list[idx], ...body };
    list[idx] = updated;
    writeMockWebhooks(list);
    return updated;
  }
  if (res?.status === 404) throw new Error("Webhook not found.");
  throw new Error(`Failed to update webhook (${res?.status ?? "network"})`);
}

export async function deleteWebhook(id: string): Promise<void> {
  const res = await webhookFetch(
    `${API_BASE}/webhooks/${encodeURIComponent(id)}`,
    { method: "DELETE" },
  );
  if (res && (res.ok || res.status === 204)) return;
  if ((!res || res.status === 404) && mockWebhooksAvailable()) {
    const list = readMockWebhooks();
    const next = list.filter((w) => w.id !== id);
    if (next.length === list.length) throw new Error("Webhook not found.");
    writeMockWebhooks(next);
    // Clean up associated deliveries so we don't leak them.
    const map = readMockDeliveries();
    if (map[id]) {
      delete map[id];
      writeMockDeliveries(map);
    }
    return;
  }
  if (res?.status === 404) throw new Error("Webhook not found.");
  throw new Error(`Failed to delete webhook (${res?.status ?? "network"})`);
}

export async function listWebhookDeliveries(id: string): Promise<WebhookDelivery[]> {
  const res = await webhookFetch(
    `${API_BASE}/webhooks/${encodeURIComponent(id)}/deliveries`,
    { cache: "no-store" },
  );
  if (res?.ok) return (await res.json()) as WebhookDelivery[];
  if ((!res || res.status === 404) && mockWebhooksAvailable()) {
    const map = readMockDeliveries();
    return map[id] ?? [];
  }
  if (res?.status === 404) throw new Error("Webhook not found.");
  throw new Error(`Failed to load deliveries (${res?.status ?? "network"})`);
}

export async function testWebhook(id: string): Promise<{ delivery_id: string }> {
  const res = await webhookFetch(
    `${API_BASE}/webhooks/${encodeURIComponent(id)}/test`,
    { method: "POST" },
  );
  if (res?.ok) return (await res.json()) as { delivery_id: string };
  if ((!res || res.status === 404) && mockWebhooksAvailable()) {
    const list = readMockWebhooks();
    const wh = list.find((w) => w.id === id);
    if (!wh) throw new Error("Webhook not found.");
    const now = new Date().toISOString();
    const delivery: WebhookDelivery = {
      id: randomDeliveryId(),
      webhook_id: id,
      event: "webhook.test",
      status: "delivering",
      attempt: 1,
      next_attempt_at: now,
      created_at: now,
      updated_at: now,
      response_code: null,
      response_body: null,
    };
    pushMockDelivery(id, delivery);
    // Flip status after ~1s based on URL validity so the delivery drawer's
    // 5s auto-refresh has something to land on.
    const looksValid = /^https?:\/\//i.test(wh.url) && !/example\.invalid/i.test(wh.url);
    setTimeout(() => {
      if (looksValid) {
        updateMockDelivery(id, delivery.id, {
          status: "succeeded",
          response_code: 200,
          response_body:
            '{"ok":true,"received_at":"' + new Date().toISOString() + '"}',
        });
      } else {
        updateMockDelivery(id, delivery.id, {
          status: "failed",
          response_code: 0,
          response_body: "connection refused / DNS failure (mock)",
        });
      }
    }, 1000);
    return { delivery_id: delivery.id };
  }
  if (res?.status === 404) throw new Error("Webhook not found.");
  throw new Error(`Failed to fire test webhook (${res?.status ?? "network"})`);
}

export async function revokeApiKey(keyId: string): Promise<void> {
  const res = await apiFetch(`${API_BASE}/keys/${encodeURIComponent(keyId)}`, {
    method: "DELETE",
  });
  if (res.ok || res.status === 204) return;
  if (res.status === 404 && mockKeysAvailable()) {
    const list = readMockKeys();
    const idx = list.findIndex((k) => k.id === keyId);
    if (idx === -1) throw new Error("Key not found.");
    if (list[idx].revoked_at) return;
    // Guard the mock against revoking the last admin key, mirroring the
    // backend's 409 contract so the UI message is exercisable.
    const isAdmin = list[idx].scopes.includes("admin");
    if (isAdmin) {
      const otherActiveAdmins = list.filter(
        (k, i) => i !== idx && !k.revoked_at && k.scopes.includes("admin"),
      );
      if (otherActiveAdmins.length === 0) {
        throw new Error(
          "Cannot revoke the last admin key while AUTH_REQUIRED is set.",
        );
      }
    }
    list[idx] = { ...list[idx], revoked_at: new Date().toISOString() };
    writeMockKeys(list);
    return;
  }
  if (res.status === 409) {
    throw new Error(
      "Cannot revoke the last admin key while AUTH_REQUIRED is set.",
    );
  }
  if (res.status === 404) throw new Error("Key not found.");
  throw new Error(`Failed to revoke API key (${res.status})`);
}
