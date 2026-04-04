"""SBOM API endpoints."""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from ..database import get_sbom, get_sboms_for_scan, save_sbom
from ..models import SBOMDocument
from ..sbom import SBOMGenerator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sbom", tags=["sbom"])


@router.post("/generate")
async def generate_sbom(
    target_path: str = Query(..., description="Path to the project directory"),
    format: str = Query("cyclonedx", description="Export format: cyclonedx or spdx"),
    scan_id: Optional[str] = Query(None, description="Linked scan ID"),
):
    """Generate an SBOM for the given target path, save it to the database, and return the result."""
    if format not in ("cyclonedx", "spdx"):
        raise HTTPException(status_code=400, detail="format must be 'cyclonedx' or 'spdx'")

    generator = SBOMGenerator(target_path=target_path, scan_id=scan_id)
    try:
        doc = await generator.generate()
    except Exception as exc:
        logger.exception("SBOM generation failed for %s", target_path)
        raise HTTPException(status_code=500, detail=f"SBOM generation failed: {exc}") from exc

    doc.format = format
    await save_sbom(doc)

    if format == "cyclonedx":
        exported = generator.export_cyclonedx(doc)
    else:
        exported = generator.export_spdx(doc)

    return {
        "sbom_id": doc.id,
        "format": format,
        "component_count": len(doc.components),
        "document": exported,
    }


@router.get("/{sbom_id}")
async def get_sbom_document(sbom_id: str):
    """Retrieve a stored SBOM document by ID."""
    doc = await get_sbom(sbom_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return doc


@router.get("/{sbom_id}/export")
async def export_sbom(
    sbom_id: str,
    format: str = Query("cyclonedx", description="Export format: cyclonedx or spdx"),
):
    """Export a stored SBOM in the specified format."""
    if format not in ("cyclonedx", "spdx"):
        raise HTTPException(status_code=400, detail="format must be 'cyclonedx' or 'spdx'")

    doc = await get_sbom(sbom_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="SBOM not found")

    generator = SBOMGenerator(target_path=doc.target_path)
    if format == "cyclonedx":
        return generator.export_cyclonedx(doc)
    else:
        return generator.export_spdx(doc)


@router.get("/scan/{scan_id}")
async def get_sboms_for_scan_endpoint(scan_id: str):
    """Get all SBOM documents linked to a specific scan."""
    docs = await get_sboms_for_scan(scan_id)
    return docs
