from fastapi import APIRouter

from ..database import get_scans
from ..scanners import ALL_SCANNERS

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/status")
async def scanner_status():
    """Return availability status for all registered scanners."""
    statuses = []
    for scanner in ALL_SCANNERS:
        available, message = await scanner.check_or_warn()
        statuses.append({
            "name": scanner.name,
            "scan_type": scanner.scan_type.value,
            "available": available,
            "message": message,
        })
    return {"scanners": statuses}


@router.get("/stats")
async def aggregate_stats():
    """Return aggregate statistics across all scans."""
    scans = await get_scans()
    total_scans = len(scans)
    total_findings = sum(s.findings_count for s in scans)
    completed = [s for s in scans if s.risk_score is not None]
    avg_risk = (
        sum(s.risk_score for s in completed) / len(completed)
        if completed
        else 0.0
    )
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "average_risk_score": round(avg_risk, 2),
        "completed_scans": len(completed),
    }
