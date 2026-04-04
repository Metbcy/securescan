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
  compliance_tags: string[];
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
  const res = await fetch(`${API_BASE}/api/dashboard/install/${name}`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to install scanner");
  return res.json();
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

export async function startScan(
  targetPath: string,
  scanTypes: string[],
  targetUrl?: string,
  targetHost?: string,
): Promise<Scan> {
  const res = await fetch(`${API_BASE}/api/scans`, {
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
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/cancel`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to cancel scan");
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
  const res = await fetch(`${API_BASE}/api/compliance/frameworks`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch compliance frameworks");
  const data = await res.json();
  return data.frameworks;
}

export async function fetchComplianceCoverage(scanId: string): Promise<ComplianceCoverage[]> {
  const res = await fetch(`${API_BASE}/api/compliance/coverage?scan_id=${encodeURIComponent(scanId)}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch compliance coverage");
  const data = await res.json();
  return data.coverage;
}

export function getReportUrl(scanId: string, format: "pdf" | "html"): string {
  return `${API_BASE}/api/scans/${scanId}/report?format=${format}`;
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

export async function generateSBOM(
  targetPath: string,
  format: string = "cyclonedx",
  scanId?: string,
): Promise<{ sbom_id: string; format: string; component_count: number; document: Record<string, unknown> }> {
  const params = new URLSearchParams({ target_path: targetPath, format });
  if (scanId) params.set("scan_id", scanId);
  const res = await fetch(`${API_BASE}/api/sbom/generate?${params}`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to generate SBOM");
  return res.json();
}

export async function fetchSBOM(sbomId: string): Promise<SBOMDocument> {
  const res = await fetch(`${API_BASE}/api/sbom/${sbomId}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch SBOM");
  return res.json();
}

export async function exportSBOM(sbomId: string, format: string = "cyclonedx"): Promise<Record<string, unknown>> {
  const res = await fetch(`${API_BASE}/api/sbom/${sbomId}/export?format=${format}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to export SBOM");
  return res.json();
}
