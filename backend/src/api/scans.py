from datetime import datetime
import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException

from ..database import (
    get_findings,
    get_scan,
    get_scan_summary,
    get_scans,
    save_findings,
    save_scan,
)
from ..dedup import deduplicate_findings
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

        await save_findings(all_findings)

        summary = build_summary(all_findings, scanners_run)

        # AI enrichment (optional)
        enricher = AIEnricher()
        if enricher.is_available:
            await enricher.enrich_findings(all_findings)
            ai_summary = await enricher.generate_summary(all_findings, summary)
            scan.summary = ai_summary

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
    scan = Scan(
        target_path=request.target_path,
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


@router.get("/{scan_id}/summary", response_model=ScanSummary)
async def read_scan_summary(scan_id: str):
    """Get summary statistics for a scan."""
    summary = await get_scan_summary(scan_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return summary
