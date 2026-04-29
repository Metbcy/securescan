"""Compliance framework API endpoints."""
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth import require_scope
from ..compliance import ComplianceMapper
from ..config import settings
from ..database import get_findings, get_scan

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


def _get_mapper() -> ComplianceMapper:
    data_dir = Path(settings.compliance_data_dir)
    if not data_dir.exists():
        raise HTTPException(status_code=500, detail="Compliance data directory not found")
    return ComplianceMapper(data_dir)


@router.get("/frameworks", dependencies=[Depends(require_scope("read"))])
async def list_frameworks():
    """List available compliance frameworks and their control counts."""
    mapper = _get_mapper()
    return {"frameworks": mapper.list_frameworks()}


@router.get("/coverage", dependencies=[Depends(require_scope("read"))])
async def compliance_coverage(scan_id: str = Query(..., description="Scan ID")):
    """Get per-framework compliance coverage for a scan."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = await get_findings(scan_id)
    mapper = _get_mapper()
    return {"coverage": mapper.get_coverage(findings)}
