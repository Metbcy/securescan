const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

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
  metadata: Record<string, unknown>;
}

export interface Scan {
  id: string;
  target_path: string;
  scan_types: string[];
  status: "pending" | "running" | "completed" | "failed";
  started_at?: string;
  completed_at?: string;
  findings_count: number;
  risk_score?: number;
  summary?: string;
  error?: string;
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
}

export async function fetchScans(): Promise<Scan[]> {
  const res = await fetch(`${API_BASE}/api/scans`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch scans");
  return res.json();
}

export async function fetchScan(id: string): Promise<Scan> {
  const res = await fetch(`${API_BASE}/api/scans/${id}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch scan");
  return res.json();
}

export async function fetchFindings(scanId: string, severity?: string): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/findings?${params}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch findings");
  return res.json();
}

export async function fetchScanSummary(scanId: string): Promise<ScanSummary> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/summary`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch summary");
  return res.json();
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const res = await fetch(`${API_BASE}/api/dashboard/stats`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch stats");
  return res.json();
}

export async function fetchScannerStatus(): Promise<ScannerStatus[]> {
  const res = await fetch(`${API_BASE}/api/dashboard/status`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch status");
  const data = await res.json();
  return data.scanners ?? data;
}

export async function startScan(targetPath: string, scanTypes: string[]): Promise<Scan> {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_path: targetPath, scan_types: scanTypes }),
  });
  if (!res.ok) throw new Error("Failed to start scan");
  return res.json();
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
  const res = await fetch(`${API_BASE}/api/browse${params}`, { cache: "no-store" });
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
  const res = await fetch(
    `${API_BASE}/api/scans/compare?scan_a=${encodeURIComponent(scanAId)}&scan_b=${encodeURIComponent(scanBId)}`,
    { cache: "no-store" }
  );
  if (!res.ok) throw new Error("Failed to compare scans");
  return res.json();
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
  const res = await fetch(`${API_BASE}/api/dashboard/trends?days=${days}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch trends");
  const data = await res.json();
  return data.data;
}
