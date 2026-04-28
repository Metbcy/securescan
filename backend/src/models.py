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
