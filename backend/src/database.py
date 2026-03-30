import json
from datetime import datetime
from typing import Optional

import aiosqlite

from .config import settings
from .models import (
    Finding,
    Scan,
    ScanStatus,
    ScanSummary,
    ScanType,
    Severity,
)

_db_path: str = settings.database_path


def set_db_path(path: str) -> None:
    global _db_path
    _db_path = path


async def _get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(_db_path)
    db.row_factory = aiosqlite.Row
    return db


async def init_db() -> None:
    db = await _get_db()
    try:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_path TEXT NOT NULL,
                scan_types TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                findings_count INTEGER DEFAULT 0,
                risk_score REAL,
                summary TEXT,
                error TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                scanner TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                file_path TEXT,
                line_start INTEGER,
                line_end INTEGER,
                rule_id TEXT,
                cwe TEXT,
                remediation TEXT,
                metadata TEXT DEFAULT '{}',
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        await db.commit()
    finally:
        await db.close()


async def save_scan(scan: Scan) -> None:
    db = await _get_db()
    try:
        await db.execute(
            """INSERT OR REPLACE INTO scans
               (id, target_path, scan_types, status, started_at, completed_at,
                findings_count, risk_score, summary, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan.id,
                scan.target_path,
                json.dumps([t.value for t in scan.scan_types]),
                scan.status.value,
                scan.started_at.isoformat() if scan.started_at else None,
                scan.completed_at.isoformat() if scan.completed_at else None,
                scan.findings_count,
                scan.risk_score,
                scan.summary,
                scan.error,
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def save_findings(findings: list[Finding]) -> None:
    if not findings:
        return
    db = await _get_db()
    try:
        await db.executemany(
            """INSERT OR REPLACE INTO findings
               (id, scan_id, scanner, scan_type, severity, title, description,
                file_path, line_start, line_end, rule_id, cwe, remediation, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    f.id,
                    f.scan_id,
                    f.scanner,
                    f.scan_type.value,
                    f.severity.value,
                    f.title,
                    f.description,
                    f.file_path,
                    f.line_start,
                    f.line_end,
                    f.rule_id,
                    f.cwe,
                    f.remediation,
                    json.dumps(f.metadata),
                )
                for f in findings
            ],
        )
        await db.commit()
    finally:
        await db.close()


def _row_to_scan(row: aiosqlite.Row) -> Scan:
    return Scan(
        id=row["id"],
        target_path=row["target_path"],
        scan_types=[ScanType(t) for t in json.loads(row["scan_types"])],
        status=ScanStatus(row["status"]),
        started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
        completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
        findings_count=row["findings_count"],
        risk_score=row["risk_score"],
        summary=row["summary"],
        error=row["error"],
    )


def _row_to_finding(row: aiosqlite.Row) -> Finding:
    return Finding(
        id=row["id"],
        scan_id=row["scan_id"],
        scanner=row["scanner"],
        scan_type=ScanType(row["scan_type"]),
        severity=Severity(row["severity"]),
        title=row["title"],
        description=row["description"],
        file_path=row["file_path"],
        line_start=row["line_start"],
        line_end=row["line_end"],
        rule_id=row["rule_id"],
        cwe=row["cwe"],
        remediation=row["remediation"],
        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
    )


async def get_scan(scan_id: str) -> Optional[Scan]:
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_scan(row)
    finally:
        await db.close()


async def get_scans() -> list[Scan]:
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans ORDER BY started_at DESC")
        rows = await cursor.fetchall()
        return [_row_to_scan(row) for row in rows]
    finally:
        await db.close()


async def get_findings(
    scan_id: str,
    severity: Optional[str] = None,
    scan_type: Optional[str] = None,
) -> list[Finding]:
    db = await _get_db()
    try:
        query = "SELECT * FROM findings WHERE scan_id = ?"
        params: list = [scan_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if scan_type:
            query += " AND scan_type = ?"
            params.append(scan_type)
        query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
        cursor = await db.execute(query, params)
        rows = await cursor.fetchall()
        return [_row_to_finding(row) for row in rows]
    finally:
        await db.close()


async def get_scan_summary(scan_id: str) -> Optional[ScanSummary]:
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan_row = await cursor.fetchone()
        if scan_row is None:
            return None

        cursor = await db.execute(
            """SELECT severity, COUNT(*) as cnt
               FROM findings WHERE scan_id = ?
               GROUP BY severity""",
            (scan_id,),
        )
        severity_counts = {row["severity"]: row["cnt"] for row in await cursor.fetchall()}

        cursor = await db.execute(
            "SELECT DISTINCT scanner FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
        scanners = [row["scanner"] for row in await cursor.fetchall()]

        total = sum(severity_counts.values())
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)
        medium = severity_counts.get("medium", 0)
        low = severity_counts.get("low", 0)
        info = severity_counts.get("info", 0)

        risk_score = critical * 10 + high * 5 + medium * 2 + low * 0.5 + info * 0

        return ScanSummary(
            total_findings=total,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            info=info,
            risk_score=risk_score,
            scanners_run=scanners,
        )
    finally:
        await db.close()
