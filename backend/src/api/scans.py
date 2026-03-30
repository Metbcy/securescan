from datetime import datetime
import asyncio
import logging
import os
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query

from ..database import (
    get_findings,
    get_scan,
    get_scan_summary,
    get_scans,
    save_findings,
    save_scan,
)
from ..dedup import deduplicate_findings, dedup_key
from ..models import (
    Finding,
    Scan,
    ScanRequest,
    ScanStatus,
    ScanSummary,
    Severity,
)
from ..scanners import get_scanners_for_types
from ..scoring import build_summary
from ..ai import AIEnricher

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])


def validate_target_path(path: str) -> str:
    """Validate and normalize target path. Raises ValueError if invalid."""
    normalized = os.path.abspath(path)
    if not os.path.exists(normalized):
        raise ValueError(f"Path does not exist: {path}")
    if not os.path.isdir(normalized) and not os.path.isfile(normalized):
        raise ValueError(f"Path is not a file or directory: {path}")
    # Prevent scanning sensitive system directories
    sensitive = ['/etc/shadow', '/root/.ssh', '/proc', '/sys']
    for s in sensitive:
        if normalized.startswith(s):
            raise ValueError(f"Scanning system path not allowed: {path}")
    return normalized


async def _run_scan(scan: Scan) -> None:
    """Background task: execute scanners in parallel and persist results."""
    try:
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now()
        await save_scan(scan)

        scanners = get_scanners_for_types(scan.scan_types)
        all_findings: list[Finding] = []
        scanners_run: list[str] = []

        # Filter to available scanners
        available_scanners = []
        for scanner in scanners:
            available = await scanner.is_available()
            if not available:
                continue
            available_scanners.append(scanner)

        # Run scanners in parallel
        if available_scanners:
            logger.info("Running scanners in parallel: %s", [s.name for s in available_scanners])

            async def _run_one(scanner):
                results = await scanner.scan(scan.target_path, scan.id)
                return scanner.name, results

            tasks = [_run_one(s) for s in available_scanners]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.error("Scanner error: %s", result)
                    continue
                name, findings = result
                all_findings.extend(findings)
                scanners_run.append(name)

        # Deduplicate findings
        all_findings = deduplicate_findings(all_findings)

        summary = build_summary(all_findings, scanners_run)

        # AI enrichment (optional)
        enricher = AIEnricher()
        if enricher.is_available:
            await enricher.enrich_findings(all_findings)
            ai_summary = await enricher.generate_summary(all_findings, summary)
            scan.summary = ai_summary

        # Save findings AFTER AI enrichment so remediation text is persisted
        await save_findings(all_findings)

        scan.findings_count = summary.total_findings
        scan.risk_score = summary.risk_score
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now()
        await save_scan(scan)
    except Exception as e:
        scan.status = ScanStatus.FAILED
        scan.error = str(e)
        scan.completed_at = datetime.now()
        await save_scan(scan)


@router.post("", response_model=Scan)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan."""
    try:
        validated_path = validate_target_path(request.target_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan = Scan(
        target_path=validated_path,
        scan_types=request.scan_types,
    )
    await save_scan(scan)
    background_tasks.add_task(_run_scan, scan)
    return scan


@router.get("", response_model=list[Scan])
async def list_scans():
    """List all scans."""
    return await get_scans()


@router.get("/{scan_id}", response_model=Scan)
async def read_scan(scan_id: str):
    """Get scan details."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/findings", response_model=list[Finding])
async def list_findings(
    scan_id: str,
    severity: Optional[str] = None,
    scan_type: Optional[str] = None,
):
    """Get findings for a scan, optionally filtered by severity or scan_type."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return await get_findings(scan_id, severity=severity, scan_type=scan_type)


@router.get("/compare")
async def compare_scans(
    scan_a: str = Query(..., description="Baseline scan ID"),
    scan_b: str = Query(..., description="Latest scan ID"),
):
    """Compare two scans and show new, fixed, and unchanged findings."""
    a = await get_scan(scan_a)
    b = await get_scan(scan_b)
    if a is None:
        raise HTTPException(status_code=404, detail="Scan A not found")
    if b is None:
        raise HTTPException(status_code=404, detail="Scan B not found")

    findings_a = await get_findings(scan_a)
    findings_b = await get_findings(scan_b)

    keyed_a = {dedup_key(f): f for f in findings_a}
    keyed_b = {dedup_key(f): f for f in findings_b}

    keys_a = set(keyed_a.keys())
    keys_b = set(keyed_b.keys())

    new_findings = [keyed_b[k] for k in keys_b - keys_a]
    fixed_findings = [keyed_a[k] for k in keys_a - keys_b]
    unchanged_findings = [keyed_b[k] for k in keys_a & keys_b]

    risk_a = a.risk_score or 0.0
    risk_b = b.risk_score or 0.0

    return {
        "scan_a": a,
        "scan_b": b,
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "unchanged_findings": unchanged_findings,
        "summary": {
            "new_count": len(new_findings),
            "fixed_count": len(fixed_findings),
            "unchanged_count": len(unchanged_findings),
            "risk_delta": round(risk_b - risk_a, 2),
        },
    }


@router.get("/{scan_id}/summary", response_model=ScanSummary)
async def read_scan_summary(scan_id: str):
    """Get summary statistics for a scan."""
    summary = await get_scan_summary(scan_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return summary
