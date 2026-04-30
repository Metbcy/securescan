from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from ..auth import require_scope
from ..database import get_scans, get_findings
from ..scanners import ALL_SCANNERS

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

# ---------------------------------------------------------------------------
# Directory browser (mounted at /api/browse via browse_router)
# ---------------------------------------------------------------------------

browse_router = APIRouter(prefix="/api", tags=["browse"])

# Files whose presence indicates a project root
PROJECT_INDICATOR_FILES = {
    "package.json", "pyproject.toml", "Cargo.toml",
    "go.mod", "Makefile", "Dockerfile",
}

# Directories to always skip when listing
SKIP_DIRS = {"node_modules", "venv", "__pycache__", ".next", "dist", "build"}

MAX_ENTRIES = 100


@browse_router.get("/browse", dependencies=[Depends(require_scope("read"))])
async def browse_directory(path: str | None = Query(default=None)):
    """List directory entries for the directory picker UI."""
    target = Path(path) if path else Path.home()

    # Resolve symlinks and validate
    try:
        target = target.resolve(strict=True)
    except (OSError, ValueError):
        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid or non-existent path"},
        )

    if not target.is_dir():
        return JSONResponse(
            status_code=400,
            content={"detail": "Path is not a directory"},
        )

    parent = str(target.parent) if target != target.parent else None

    dirs: list[dict] = []
    files: list[dict] = []

    try:
        for entry in target.iterdir():
            name = entry.name

            if entry.is_dir():
                # Skip hidden dirs except .git
                if name.startswith(".") and name != ".git":
                    continue
                if name in SKIP_DIRS:
                    continue
                dirs.append({"name": name, "path": str(entry), "is_dir": True})
            elif entry.is_file() and name in PROJECT_INDICATOR_FILES:
                files.append({"name": name, "path": str(entry), "is_dir": False})
    except PermissionError:
        return JSONResponse(
            status_code=403,
            content={"detail": "Permission denied"},
        )

    dirs.sort(key=lambda e: e["name"].lower())
    files.sort(key=lambda e: e["name"].lower())

    entries = (dirs + files)[:MAX_ENTRIES]

    return {
        "current": str(target),
        "parent": parent,
        "entries": entries,
    }

# ---------------------------------------------------------------------------
# Dashboard endpoints
# ---------------------------------------------------------------------------

import asyncio as _asyncio

# Installable scanners with their install method
INSTALLABLE_SCANNERS = {
    "checkov": {"method": "pip", "package": "checkov"},
    "semgrep": {"method": "pip", "package": "semgrep"},
    "bandit": {"method": "pip", "package": "bandit"},
    "safety": {"method": "pip", "package": "safety"},
    "licenses": {"method": "pip", "package": "pip-licenses"},
}


@router.get("/status", dependencies=[Depends(require_scope("read"))])
async def scanner_status():
    """Return availability status for all registered scanners.

    Each call performs a LIVE check (no caching). The response carries
    `checked_at` so the dashboard can show "Last refreshed Xs ago" and
    users know the manual-refresh button is doing fresh work.
    """
    from datetime import datetime, timezone
    statuses = []
    for scanner in ALL_SCANNERS:
        available, message = await scanner.check_or_warn()
        installable = scanner.name in INSTALLABLE_SCANNERS
        statuses.append({
            "name": scanner.name,
            "scan_type": scanner.scan_type.value,
            "available": available,
            "message": message,
            "description": scanner.description,
            "checks": scanner.checks,
            "install_hint": scanner.install_hint if not available else None,
            "installable": installable,
        })
    return {
        "scanners": statuses,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/install/{scanner_name}", dependencies=[Depends(require_scope("admin"))])
async def install_scanner(scanner_name: str):
    """Install a scanner via pip or a custom script."""
    if scanner_name not in INSTALLABLE_SCANNERS:
        raise HTTPException(status_code=400, detail=f"Scanner '{scanner_name}' cannot be auto-installed. Install it manually.")

    info = INSTALLABLE_SCANNERS[scanner_name]
    method = info["method"]

    try:
        if method == "pip":
            import sys
            cmd = [sys.executable, "-m", "pip", "install", info["package"]]
        elif method == "script":
            cmd = info["command"]
        else:
            raise HTTPException(status_code=400, detail=f"Unknown install method '{method}'")

        proc = await _asyncio.create_subprocess_exec(
            *cmd,
            stdout=_asyncio.subprocess.PIPE,
            stderr=_asyncio.subprocess.PIPE,
        )
        stdout, stderr = await _asyncio.wait_for(proc.communicate(), timeout=120)

        if proc.returncode == 0:
            return {
                "success": True,
                "message": f"Successfully installed {scanner_name}",
                "output": stdout.decode(errors="ignore").strip(),
            }
        else:
            return {
                "success": False,
                "message": f"Failed to install {scanner_name}",
                "output": stderr.decode(errors="ignore").strip(),
            }
    except _asyncio.TimeoutError:
        return {"success": False, "message": f"Installation of {scanner_name} timed out"}
    except Exception as e:
        return {"success": False, "message": f"Error installing {scanner_name}: {str(e)}"}


@router.get("/stats", dependencies=[Depends(require_scope("read"))])
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


@router.get("/trends", dependencies=[Depends(require_scope("read"))])
async def trends(days: int = Query(30, ge=1, le=365)):
    """Return time-series trend data from scan history."""
    scans = await get_scans()

    # Filter to completed scans with a completed_at timestamp
    completed = [
        s for s in scans
        if s.status.value == "completed" and s.completed_at is not None
    ]

    if not completed:
        return {"data": []}

    # Sort by completed_at ascending
    from datetime import timedelta, datetime as dt

    cutoff = dt.now() - timedelta(days=days)
    daily: dict[str, object] = {}  # date_str -> scan

    for scan in completed:
        if scan.completed_at < cutoff:
            continue
        date_str = scan.completed_at.strftime("%Y-%m-%d")
        daily[date_str] = scan  # last one wins (most recent per day)

    # Build response with severity counts
    data = []
    for date_str, scan in sorted(daily.items()):
        findings = await get_findings(scan.id)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.value
            if sev in severity_counts:
                severity_counts[sev] += 1

        data.append({
            "date": date_str,
            "risk_score": scan.risk_score or 0.0,
            "total_findings": len(findings),
            **severity_counts,
        })

    return {"data": data}
