from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
import uuid


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanType(str, Enum):
    CODE = "code"
    DEPENDENCY = "dependency"
    IAC = "iac"
    BASELINE = "baseline"
    DAST = "dast"
    NETWORK = "network"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    scanner: str
    scan_type: ScanType
    severity: Severity
    title: str
    description: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    rule_id: Optional[str] = None
    cwe: Optional[str] = None
    remediation: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
    compliance_tags: list[str] = Field(default_factory=list)
    fingerprint: str = ""  # populated by populate_fingerprints() before save


class ScannerSkip(BaseModel):
    """A scanner that was skipped during a scan run.

    Surfacing the install_hint here (instead of forcing the UI to re-fetch
    /api/dashboard/status) lets the scan-detail page render an actionable
    "Skipped (N)" section without an extra round-trip. Sorted alphabetically
    by name at persistence time for deterministic output.
    """
    name: str
    reason: str
    install_hint: Optional[str] = None


class Scan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_path: str
    scan_types: list[ScanType]
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    risk_score: Optional[float] = None
    summary: Optional[str] = None
    error: Optional[str] = None
    target_url: Optional[str] = None
    target_host: Optional[str] = None
    scanners_run: list[str] = Field(default_factory=list)
    scanners_skipped: list[ScannerSkip] = Field(default_factory=list)


class ScanRequest(BaseModel):
    target_path: str
    scan_types: list[ScanType] = Field(default=[ScanType.CODE, ScanType.DEPENDENCY], min_length=1)
    target_url: Optional[str] = None
    target_host: Optional[str] = None


class ScanSummary(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    risk_score: float
    scanners_run: list[str]


class TriageStatus(str, Enum):
    """User-assigned verdict for a finding (cross-scan, identified by fingerprint).

    `NEW` is the implicit default for any finding that has never been triaged --
    we do NOT create a `finding_states` row for findings still in this state, so
    a missing row is read as `state=None` (UI shows "new") rather than as a
    `NEW` row. The other values represent explicit user verdicts that should
    survive subsequent rescans of the same target.
    """
    NEW = "new"
    TRIAGED = "triaged"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    WONT_FIX = "wont_fix"


class FindingState(BaseModel):
    """Per-fingerprint triage verdict.

    Keyed on the cross-scan-stable `fingerprint` (see fingerprint.py), so a
    user's "false positive" verdict survives rescans, line shifts, and trivial
    code edits. Orphan rows (rule_id renamed, file moved out of the project)
    are intentionally tolerated -- the UI just won't surface them.
    """
    fingerprint: str
    status: TriageStatus
    note: Optional[str] = None
    updated_at: datetime
    updated_by: Optional[str] = None


class FindingComment(BaseModel):
    """A free-text comment on a finding's fingerprint.

    Multiple comments per fingerprint are allowed; they are listed in
    `created_at` ASC order so a triage thread reads top-to-bottom.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint: str
    text: str
    author: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FindingWithState(Finding):
    """A `Finding` enriched with optional triage state.

    Used ONLY by `GET /scans/{id}/findings` so the UI can render verdict
    badges in a single round-trip. Bare `Finding` is intentionally left
    untouched -- SARIF / JSON / baseline / CLI exporters all `model_dump`
    Findings, and adding fields there would silently change their JSON
    contracts.
    """
    state: Optional[FindingState] = None


class ApiKeyScope(str, Enum):
    """Scopes attached to an issued API key.

    Scopes are independent (no implicit hierarchy): a key with only
    `write` cannot read. The `require_scope` dependency tests for set
    intersection so a route that accepts `read` will also accept any
    other scope listed alongside it on the route - the route author
    controls the policy, not the scope enum.
    """
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class ApiKeyView(BaseModel):
    """List / get response for an API key. Never includes the secret.

    `prefix` is the first 16 chars of the full key (`ssk_<id>_<1ch>`),
    safe to display in admin UIs so a user can recognise their own keys
    without ever seeing the secret again after creation.
    """
    id: str
    name: str
    prefix: str
    scopes: list[ApiKeyScope]
    created_at: datetime
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None


class ApiKeyCreated(ApiKeyView):
    """Creation response. Includes the full plaintext key EXACTLY ONCE.

    Subsequent GETs return ApiKeyView (no `key`). The DB only ever
    stores the salted hash, so a lost key cannot be recovered - it
    must be revoked and re-issued.
    """
    key: str


class SBOMComponent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sbom_id: str
    name: str
    version: str
    type: str = "library"
    purl: Optional[str] = None
    license: Optional[str] = None
    supplier: Optional[str] = None


class SBOMDocument(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: Optional[str] = None
    target_path: str
    format: str = "cyclonedx"
    components: list[SBOMComponent] = []
    created_at: datetime = Field(default_factory=datetime.now)
