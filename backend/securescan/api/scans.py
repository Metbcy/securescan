import asyncio
import json
import logging
import os
import time
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel

from .. import event_tokens
from ..ai import AIEnricher
from ..auth import Principal, require_api_key, require_scope
from ..compliance import ComplianceMapper
from ..config import settings
from ..database import (
    delete_scan_cascade,
    get_findings,
    get_findings_with_state,
    get_scan,
    get_scan_summary,
    get_scans,
    insert_notification,
    save_findings,
    save_scan,
)
from ..dedup import dedup_key, deduplicate_findings
from ..events import TERMINAL, bus
from ..fingerprint import populate_fingerprints
from ..models import (
    Finding,
    FindingWithState,
    NotificationSeverity,
    Scan,
    ScannerSkip,
    ScanRequest,
    ScanStatus,
    ScanSummary,
)
from ..reports import ReportGenerator
from ..scanners import get_scanners_for_types
from ..scoring import build_summary

logger = logging.getLogger(__name__)

# Dedicated lifecycle logger so `tail -f securescan-backend.log` shows
# scanner subprocess progress for in-flight scans. Existing per-request
# log line on `securescan.request` is unchanged; we add `securescan.scan`
# for the orchestrator's lifecycle events (scan.start/scanner.start/...).
_scan_logger = logging.getLogger("securescan.scan")

# scanner.failed `error` field cap. Stack traces are common and we don't
# want to flood the log when a scanner crashes hard.
_SCAN_ERROR_TRUNCATE = 200


# Outbound-webhook (BE-WEBHOOKS) event allow-list. Only these scan
# events are surfaced to subscribers; per-scanner lifecycle noise
# (scanner.start/complete/skipped, scan.start, scan.cancelled) stays
# internal so the public webhook contract is small and stable.
WEBHOOK_RELEVANT_EVENTS: frozenset[str] = frozenset(
    {
        "scan.complete",
        "scan.failed",
        "scanner.failed",
    }
)


def _format_event_value(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def _log_scan_event(event: str, *, scan_id: str, **fields: Any) -> None:
    """Emit a structured INFO line on the `securescan.scan` logger.

    Message is human-readable (`event k=v k=v scan_id=...`) so it is useful
    in the dev text log, and the same fields are passed via ``extra=`` so
    the JSON formatter can pick them up if its allowlist is widened later.
    ``scan_id`` is always emitted last to match the request-log convention
    of the most-stable correlation key trailing.

    The event is also fan-out-published to the in-process SSE bus
    (``securescan.events.bus``) so live dashboard subscribers see scan
    progress in real time. The publish is fire-and-forget via
    ``asyncio.create_task`` because the helper is synchronous and many
    of its callers (``_run_scan`` and friends) hold the event loop —
    blocking on ``await bus.publish`` would serialize logging behind
    the slowest subscriber. The bus's ``publish`` does not actually
    suspend, so the scheduled task drains in a single loop iteration.

    For a small filtered subset of events we ALSO create a persistent
    in-app notification (BE-NOTIFY) so the dashboard topbar bell can
    surface them after the SSE stream has closed. See
    ``_create_notification_for_event`` for the filtering rules.
    """
    parts = [f"{key}={_format_event_value(val)}" for key, val in fields.items()]
    parts.append(f"scan_id={scan_id}")
    extra = {**fields, "scan_id": scan_id}
    _scan_logger.info(f"{event} {' '.join(parts)}", extra=extra)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No event loop active (e.g., a test that calls
        # ``_log_scan_event`` directly outside an asyncio context).
        # Logging fired; SSE delivery just isn't relevant here.
        return
    asyncio.create_task(bus.publish(scan_id, event, dict(fields)))
    try:
        asyncio.create_task(_create_notification_for_event(event, scan_id, dict(fields)))
    except RuntimeError:
        # No running loop -- already short-circuited above, but the
        # belt-and-braces try/except matches the agreed-on pattern in
        # the spec so a future refactor that splits the two branches
        # can't accidentally crash the synchronous logging path.
        pass

    # Outbound webhooks (BE-WEBHOOKS). For the small set of events
    # that webhooks subscribe to, fan out to enabled subscriptions
    # whose event_filter matches. Each match becomes one
    # `webhook_deliveries` row in status='pending'; the dispatcher
    # worker (started in main.py) drains them. We reuse the same
    # "no running loop -> skip" pattern as the SSE/notification
    # branches above so synchronous tests of the orchestrator stay
    # side-effect-free.
    if event in WEBHOOK_RELEVANT_EVENTS:
        try:
            asyncio.create_task(_enqueue_webhook_deliveries(event, scan_id, dict(fields)))
        except RuntimeError:
            pass


# Cap for `body` text on `scan.failed` notifications. Stack traces from
# scanner subprocesses can be huge; the dropdown only renders ~2 lines
# of body text anyway.
_NOTIF_BODY_TRUNCATE = 200
_NOTIF_SCANNER_ERROR_TRUNCATE = 100


async def _create_notification_for_event(event: str, scan_id: str, fields: dict[str, Any]) -> None:
    """Persist a notification for the small subset of events that warrant one.

    Filtering rules (deliberately conservative -- the bell should
    surface signal, not be a duplicate of the SSE feed):

    * ``scan.complete`` — only when ``findings_count > 0``. Severity
      is ``warning`` whenever findings were found, ``info`` otherwise.
      Per spec we use the simple count-based rule rather than fetching
      the scan summary to count critical/high (extra DB call per
      event). When findings_count == 0 we don't notify at all, so
      the ``info`` branch is structurally unreachable today; it's
      kept for symmetry in case the filter is loosened later.
    * ``scan.failed`` — always notify; severity ``error``.
    * ``scanner.failed`` — always notify; severity ``warning``.
    * Everything else (scan.start, scanner.start, scanner.complete,
      scanner.skipped, scan.cancelled) — no notification. Those
      events are loud on the SSE stream while the dashboard is open;
      persisting them all would drown the bell.

    Errors here are swallowed (logged-only) so a notification-write
    failure can't break a live scan. The DB layer's exceptions would
    otherwise propagate up the ``asyncio.create_task`` boundary as
    unawaited exceptions and surface as test warnings.
    """
    try:
        if event == "scan.complete":
            findings_count = int(fields.get("findings_count", 0) or 0)
            if findings_count <= 0:
                return
            target_path = fields.get("target") or fields.get("target_path") or ""
            severity = (
                NotificationSeverity.WARNING if findings_count > 0 else NotificationSeverity.INFO
            )
            await insert_notification(
                type="scan.complete",
                title="Scan complete",
                body=f"{findings_count} findings on {target_path}",
                link=f"/scan/{scan_id}",
                severity=severity,
            )
            return

        if event == "scan.failed":
            error = str(fields.get("error", "") or "")[:_NOTIF_BODY_TRUNCATE]
            await insert_notification(
                type="scan.failed",
                title="Scan failed",
                body=error or None,
                link=f"/scan/{scan_id}",
                severity=NotificationSeverity.ERROR,
            )
            return

        if event == "scanner.failed":
            scanner = fields.get("scanner", "scanner")
            error = str(fields.get("error", "") or "")[:_NOTIF_SCANNER_ERROR_TRUNCATE]
            await insert_notification(
                type="scanner.failed",
                title="Scanner failed",
                body=f"{scanner} failed: {error}",
                link=f"/scan/{scan_id}",
                severity=NotificationSeverity.WARNING,
            )
            return
        # All other events: silently ignored.
    except Exception:
        logger.exception(
            "notifications: failed to persist for event=%s scan_id=%s",
            event,
            scan_id,
        )


async def _enqueue_webhook_deliveries(event: str, scan_id: str, fields: dict[str, Any]) -> None:
    """Persist one `webhook_deliveries` row per matching subscription.

    For every enabled webhook whose `event_filter` includes ``event``,
    insert a `pending` row whose payload is the original ``data`` dict
    (the dispatcher will reshape per-receiver in
    ``webhook_formatters.format_payload``). The ``scan_id`` is folded
    into the data dict so receivers always see it without needing to
    parse the event name.

    Errors here are swallowed (logged-only): a webhook subscription
    failing to enqueue must NEVER break the scan that triggered the
    event. The dispatcher handles dispatch-time failures separately.
    """
    try:
        from ..database import insert_webhook_delivery, list_webhooks

        data = {"scan_id": scan_id, **fields}
        payload_json = json.dumps(data)
        now = datetime.utcnow()
        webhooks = await list_webhooks(only_enabled=True)
        for wh in webhooks:
            if event not in {e.value for e in wh.event_filter}:
                continue
            await insert_webhook_delivery(
                id=str(uuid.uuid4()),
                webhook_id=wh.id,
                event=event,
                payload=payload_json,
                next_attempt_at=now,
                created_at=now,
            )
    except Exception:
        logger.exception(
            "webhooks: failed to enqueue for event=%s scan_id=%s",
            event,
            scan_id,
        )


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
    sensitive = ["/etc/shadow", "/root/.ssh", "/proc", "/sys"]
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
        _log_scan_event("scan.cancelled", scan_id=scan_id)
        return

    scan_started_perf = time.perf_counter()
    try:
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now()
        await save_scan(scan)

        scanners = get_scanners_for_types(scan.scan_types)
        all_findings: list[Finding] = []
        scanners_run: list[str] = []

        _log_scan_event(
            "scan.start",
            scan_id=scan.id,
            target=scan.target_path,
            scanner_count=len(scanners),
        )

        # Filter to available scanners. Record skipped ones so the dashboard
        # can show which scanners did NOT run (PG2: closes UX gap #2 where
        # users saw "0 findings" with no signal that nothing actually ran).
        available_scanners = []
        scanners_skipped: list[ScannerSkip] = []
        for scanner in scanners:
            if not await scanner.is_available():
                install_hint = getattr(scanner, "install_hint", None)
                reason = "not installed" if install_hint else "unavailable"
                scanners_skipped.append(
                    ScannerSkip(
                        name=scanner.name,
                        reason=reason,
                        install_hint=install_hint,
                    )
                )
                _log_scan_event(
                    "scanner.skipped",
                    scan_id=scan.id,
                    scanner=scanner.name,
                    reason=reason,
                )
                continue
            available_scanners.append(scanner)

        # Run scanners in parallel
        if available_scanners:
            logger.info("Running scanners in parallel: %s", [s.name for s in available_scanners])

            async def _run_one(scanner):
                _log_scan_event(
                    "scanner.start",
                    scan_id=scan.id,
                    scanner=scanner.name,
                )
                started = time.perf_counter()
                try:
                    results = await scanner.scan(
                        scan.target_path,
                        scan.id,
                        target_url=scan.target_url,
                        target_host=scan.target_host,
                    )
                except Exception as exc:
                    duration_s = round(time.perf_counter() - started, 2)
                    _log_scan_event(
                        "scanner.failed",
                        scan_id=scan.id,
                        scanner=scanner.name,
                        duration_s=duration_s,
                        error=str(exc)[:_SCAN_ERROR_TRUNCATE],
                    )
                    raise
                duration_s = round(time.perf_counter() - started, 2)
                _log_scan_event(
                    "scanner.complete",
                    scan_id=scan.id,
                    scanner=scanner.name,
                    duration_s=duration_s,
                    findings_count=len(results),
                )
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
            _log_scan_event("scan.cancelled", scan_id=scan.id)
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
            _log_scan_event("scan.cancelled", scan_id=scan.id)
            return

        # Save findings AFTER AI enrichment so remediation text is persisted.
        # Populate fingerprints first so the diff classifier (SS4) and
        # PR-comment renderer (SS7) get a stable identity for every finding.
        populate_fingerprints(all_findings)
        await save_findings(all_findings)

        scan.findings_count = summary.total_findings
        scan.risk_score = summary.risk_score
        scan.scanners_run = sorted(scanners_run)
        scan.scanners_skipped = sorted(scanners_skipped, key=lambda s: s.name)
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now()
        await save_scan(scan)

        _log_scan_event(
            "scan.complete",
            scan_id=scan.id,
            duration_s=round(time.perf_counter() - scan_started_perf, 2),
            scanner_count=len(scanners_run),
            findings_count=summary.total_findings,
        )
    except asyncio.CancelledError:
        latest_scan = await get_scan(scan_id)
        if latest_scan is not None and latest_scan.status != ScanStatus.CANCELLED:
            latest_scan.status = ScanStatus.CANCELLED
            latest_scan.error = _CANCELLED_BY_USER
            latest_scan.completed_at = datetime.now()
            await save_scan(latest_scan)
        _log_scan_event("scan.cancelled", scan_id=scan_id)
    except Exception as e:
        latest_scan = await get_scan(scan_id)
        if latest_scan is not None and latest_scan.status != ScanStatus.CANCELLED:
            latest_scan.status = ScanStatus.FAILED
            latest_scan.error = str(e)
            latest_scan.completed_at = datetime.now()
            # Preserve partial-run scanners_run/skipped on failure so the UI
            # still shows what was attempted vs. unavailable.
            latest_scan.scanners_run = sorted(scanners_run)
            latest_scan.scanners_skipped = sorted(scanners_skipped, key=lambda s: s.name)
            await save_scan(latest_scan)
        _log_scan_event(
            "scan.failed",
            scan_id=scan_id,
            error=str(e)[:_SCAN_ERROR_TRUNCATE],
        )
    finally:
        _RUNNING_SCAN_TASKS.pop(scan_id, None)


@router.post("", response_model=Scan, dependencies=[Depends(require_scope("write"))])
async def create_scan(request: ScanRequest):
    """Start a new scan."""
    try:
        validated_path = validate_target_path(request.target_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    scan = Scan(
        target_path=validated_path,
        scan_types=request.scan_types,
        target_url=request.target_url,
        target_host=request.target_host,
    )
    await save_scan(scan)
    task = asyncio.create_task(_run_scan(scan.id))
    _RUNNING_SCAN_TASKS[scan.id] = task
    task.add_done_callback(lambda _: _RUNNING_SCAN_TASKS.pop(scan.id, None))
    return scan


@router.get("", response_model=list[Scan], dependencies=[Depends(require_scope("read"))])
async def list_scans():
    """List all scans."""
    return await get_scans()


@router.delete("/{scan_id}", status_code=204, dependencies=[Depends(require_scope("write"))])
async def delete_scan(scan_id: str) -> Response:
    """Delete a scan, its findings, and any per-scan rows that reference it.

    Refuses to delete a live scan (pending or running) with 409 -- the
    caller must POST `/cancel` first to put it in a terminal state. This
    matches the precedent set by the cancel endpoint, which uses 409 for
    the symmetric "wrong state for this transition" condition.
    A second DELETE on the same id returns 404 (idempotent from the
    caller's perspective: the resource is gone either way).
    """
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status in {ScanStatus.PENDING, ScanStatus.RUNNING}:
        raise HTTPException(
            status_code=409,
            detail=(f"Cannot delete scan in '{scan.status.value}' state; cancel it first"),
        )

    await delete_scan_cascade(scan_id)
    return Response(status_code=204)


@router.post(
    "/{scan_id}/cancel", response_model=Scan, dependencies=[Depends(require_scope("write"))]
)
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


@router.get("/compare", dependencies=[Depends(require_scope("read"))])
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


@router.get("/{scan_id}/report", dependencies=[Depends(require_scope("read"))])
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
            headers={
                "Content-Disposition": f'attachment; filename="securescan-report-{scan_id[:8]}.pdf"'
            },
        )
    else:
        html = generator.generate_html(scan, findings_list, summary_data, compliance_coverage)
        return HTMLResponse(content=html)


@router.get("/{scan_id}", response_model=Scan, dependencies=[Depends(require_scope("read"))])
async def read_scan(scan_id: str):
    """Get scan details."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _sse_format(event: str, payload: dict) -> bytes:
    """Format a single SSE message frame.

    Per the SSE spec: a single ``event:`` line names the event, a
    single ``data:`` line carries the JSON payload, and a blank line
    terminates the frame. ``json.dumps`` with the default separators
    keeps the body on one line (no embedded ``\\n``) which is required
    for SSE multi-line semantics not to apply.
    """
    return f"event: {event}\ndata: {json.dumps(payload)}\n\n".encode()


_TERMINAL_STATUSES = {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}
_STATUS_TO_TERMINAL_EVENT = {
    ScanStatus.COMPLETED: "scan.complete",
    ScanStatus.FAILED: "scan.failed",
    ScanStatus.CANCELLED: "scan.cancelled",
}
_SSE_KEEPALIVE_SECONDS = 15.0


@router.get("/{scan_id}/events", dependencies=[Depends(require_scope("read"))])
async def stream_scan_events(scan_id: str) -> StreamingResponse:
    """Server-Sent Events stream of lifecycle events for a single scan.

    The stream replays any prior events for ``scan_id`` (so a frontend
    that subscribes after the scan started still sees ``scan.start``)
    and then forwards new events live until a terminal event is
    emitted, at which point the stream closes.

    For an already-terminal scan whose replay buffer is gone (backend
    restart, or the 30s grace window has elapsed), a synthesized
    terminal event is emitted from the persisted scan status so the
    client closes cleanly without polling.

    Sends a ``: keepalive`` comment frame every 15 seconds of
    inactivity so intermediaries (nginx, ALBs) don't kill the
    connection during long quiet stretches.
    """
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_stream() -> AsyncGenerator[bytes, None]:
        # Subscribe FIRST so any event published while we're setting
        # up makes it onto our queue (the bus seeds the queue from the
        # replay buffer atomically inside subscribe()).
        q = bus.subscribe(scan_id)
        try:
            # If the scan is already terminal AND the replay buffer is
            # empty (backend restarted, or the 30s grace expired),
            # synthesize a single terminal event from DB state so the
            # client can close cleanly. Otherwise the replay buffer
            # already has the real terminal event queued and we just
            # let the normal loop deliver it.
            if scan.status in _TERMINAL_STATUSES and not bus.has_replay(scan_id):
                terminal_event = _STATUS_TO_TERMINAL_EVENT[scan.status]
                yield _sse_format(terminal_event, {"status": scan.status.value})
                return

            while True:
                try:
                    event, payload = await asyncio.wait_for(q.get(), timeout=_SSE_KEEPALIVE_SECONDS)
                except asyncio.TimeoutError:
                    yield b": keepalive\n\n"
                    continue
                yield _sse_format(event, payload)
                if event in TERMINAL:
                    return
        finally:
            bus.unsubscribe(scan_id, q)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


class EventTokenResponse(BaseModel):
    token: str
    expires_in: int


@router.post(
    "/{scan_id}/event-token",
    response_model=EventTokenResponse,
    dependencies=[Depends(require_scope("read"))],
)
async def create_event_token(
    scan_id: str,
    principal: Principal | None = Depends(require_api_key),
):
    """Mint a short-lived signed token for the SSE ``/events`` stream.

    EventSource can't send custom headers, so this endpoint trades an
    authenticated POST for a token the FE then passes as
    ``?event_token=...`` on the SSE GET. The token is bound to
    ``(scan_id, key_id)`` and re-validated against the live key state
    at connect time, so revocation takes effect immediately.

    In dev mode (no auth configured) ``principal`` is None; we still
    issue a token bound to ``"env"`` so the FE flow stays uniform
    across dev and prod.
    """
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Bind the token to the caller's identity so revocation propagates.
    # In dev mode (principal None), use a "dev" sentinel — verification
    # will accept this only while the system remains in dev mode; if
    # credentials are added later, the token is invalidated.
    if principal is None:
        key_id = "dev"
    else:
        key_id = principal.id
    token, expires_in = event_tokens.mint(scan_id, key_id)
    response = EventTokenResponse(token=token, expires_in=expires_in)
    # Don't cache; tokens are single-use-ish and shouldn't stick in
    # proxies or access logs longer than necessary.
    return JSONResponse(
        content=response.model_dump(),
        headers={"Cache-Control": "no-store"},
    )


@router.get(
    "/{scan_id}/findings",
    response_model=list[FindingWithState],
    dependencies=[Depends(require_scope("read"))],
)
async def list_findings(
    scan_id: str,
    severity: str | None = None,
    scan_type: str | None = None,
    compliance: str | None = None,
):
    """Get findings for a scan, optionally filtered by severity, scan_type, or compliance tag.

    Each finding is enriched with its triage `state` (or `null` when no
    user verdict has been recorded). State is keyed on the cross-scan
    `fingerprint`, so a "false positive" verdict on one scan shows up
    on every later rescan of the same target. This is the ONLY endpoint
    that returns the enriched payload -- SARIF / JSON / baseline / CLI
    exporters all keep using the bare `Finding` shape via `get_findings`.
    """
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return await get_findings_with_state(
        scan_id, severity=severity, scan_type=scan_type, compliance=compliance
    )


@router.get(
    "/{scan_id}/summary", response_model=ScanSummary, dependencies=[Depends(require_scope("read"))]
)
async def read_scan_summary(scan_id: str):
    """Get summary statistics for a scan."""
    summary = await get_scan_summary(scan_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return summary
