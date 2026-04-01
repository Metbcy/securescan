from datetime import datetime
import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, Response

from ..database import (
    get_findings,
    get_scan,
    get_scan_summary,
    get_scans,
    save_findings,
    save_scan,
)
from ..compliance import ComplianceMapper
from ..dedup import deduplicate_findings, dedup_key
from ..models import (
    Finding,
    Scan,
    ScanRequest,
    ScanStatus,
    ScanSummary,
)
from ..scanners import get_scanners_for_types
from ..config import settings
from ..reports import ReportGenerator
from ..scoring import build_summary
from ..ai import AIEnricher

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])
_RUNNING_SCAN_TASKS: dict[str, asyncio.Task[None]] = {}
_CANCELLED_BY_USER = "Scan cancelled by user"


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


async def _run_scan(scan_id: str) -> None:
    """Background task: execute scanners in parallel and persist results."""
    scan = await get_scan(scan_id)
    if scan is None:
        logger.warning("Scan not found when trying to run: %s", scan_id)
        return

    if scan.status == ScanStatus.CANCELLED:
        return

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

        latest_scan = await get_scan(scan.id)
        if latest_scan is not None and latest_scan.status == ScanStatus.CANCELLED:
            return

        # Deduplicate findings
        all_findings = deduplicate_findings(all_findings)

        # Compliance tagging
        compliance_data_dir = Path(settings.compliance_data_dir)
        if compliance_data_dir.exists():
            mapper = ComplianceMapper(compliance_data_dir)
            mapper.tag_findings(all_findings)

        summary = build_summary(all_findings, scanners_run)

        # AI enrichment (optional)
        enricher = AIEnricher()
        if enricher.is_available:
            await enricher.enrich_findings(all_findings)
            ai_summary = await enricher.generate_summary(all_findings, summary)
            scan.summary = ai_summary

        latest_scan = await get_scan(scan.id)
        if latest_scan is not None and latest_scan.status == ScanStatus.CANCELLED:
            return

        # Save findings AFTER AI enrichment so remediation text is persisted
        await save_findings(all_findings)

        scan.findings_count = summary.total_findings
        scan.risk_score = summary.risk_score
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now()
        await save_scan(scan)
    except asyncio.CancelledError:
        latest_scan = await get_scan(scan_id)
        if latest_scan is not None and latest_scan.status != ScanStatus.CANCELLED:
            latest_scan.status = ScanStatus.CANCELLED
            latest_scan.error = _CANCELLED_BY_USER
            latest_scan.completed_at = datetime.now()
            await save_scan(latest_scan)
    except Exception as e:
        latest_scan = await get_scan(scan_id)
        if latest_scan is not None and latest_scan.status != ScanStatus.CANCELLED:
            latest_scan.status = ScanStatus.FAILED
            latest_scan.error = str(e)
            latest_scan.completed_at = datetime.now()
            await save_scan(latest_scan)
    finally:
        _RUNNING_SCAN_TASKS.pop(scan_id, None)


@router.post("", response_model=Scan)
async def create_scan(request: ScanRequest):
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
    task = asyncio.create_task(_run_scan(scan.id))
    _RUNNING_SCAN_TASKS[scan.id] = task
    task.add_done_callback(lambda _: _RUNNING_SCAN_TASKS.pop(scan.id, None))
    return scan


@router.get("", response_model=list[Scan])
async def list_scans():
    """List all scans."""
    return await get_scans()


@router.post("/{scan_id}/cancel", response_model=Scan)
async def cancel_scan(scan_id: str):
    """Cancel an active scan."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot cancel scan in '{scan.status.value}' state",
        )

    scan.status = ScanStatus.CANCELLED
    scan.error = _CANCELLED_BY_USER
    scan.completed_at = datetime.now()
    await save_scan(scan)

    running_task = _RUNNING_SCAN_TASKS.get(scan_id)
    if running_task is not None and not running_task.done():
        running_task.cancel()

    return scan


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


@router.get("/{scan_id}/report")
async def generate_report(
    scan_id: str,
    format: str = Query("html", description="Report format: html or pdf"),
):
    """Generate a security assessment report for a scan."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan must be completed to generate a report")

    findings_list = await get_findings(scan_id)
    summary_data = await get_scan_summary(scan_id)

    compliance_coverage = []
    compliance_data_dir = Path(settings.compliance_data_dir)
    if compliance_data_dir.exists():
        mapper = ComplianceMapper(compliance_data_dir)
        compliance_coverage = mapper.get_coverage(findings_list)

    generator = ReportGenerator(Path(settings.report_template_dir))

    if format == "pdf":
        pdf_bytes = generator.generate_pdf(scan, findings_list, summary_data, compliance_coverage)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="securescan-report-{scan_id[:8]}.pdf"'},
        )
    else:
        html = generator.generate_html(scan, findings_list, summary_data, compliance_coverage)
        return HTMLResponse(content=html)


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
    compliance: Optional[str] = None,
):
    """Get findings for a scan, optionally filtered by severity, scan_type, or compliance tag."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return await get_findings(scan_id, severity=severity, scan_type=scan_type, compliance=compliance)


@router.get("/{scan_id}/summary", response_model=ScanSummary)
async def read_scan_summary(scan_id: str):
    """Get summary statistics for a scan."""
    summary = await get_scan_summary(scan_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return summary
