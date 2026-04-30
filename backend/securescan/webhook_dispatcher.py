"""Durable webhook delivery worker (BE-WEBHOOKS).

Persists every outbound delivery as a `webhook_deliveries` row before
attempting the HTTP call. The worker polls pending rows, dispatches,
and updates status. On startup, stale `delivering` rows (left over
from a crash or restart) are reset to `pending` -- retry is idempotent
on the receiver side because of the `(timestamp, signature)` pair on
every request, so receivers can dedupe.

Retry policy
------------
* Full-jitter exponential backoff capped at ``MAX_BACKOFF_SECONDS``.
* Max delivery age ``MAX_AGE_SECONDS`` (30 minutes) -- past that we
  mark the row `failed` and stop.

FIFO per webhook
----------------
Deliveries for the same `webhook_id` are processed in `created_at`
order. We achieve this with TWO layers:

* In-process: ``_inflight_per_webhook`` set guards a webhook from
  being dispatched concurrently within one process. The poll loop
  skips any pending row whose webhook_id is already inflight; the
  next tick will pick it up once the prior delivery finishes.
* Persistence: ``mark_delivery_delivering`` is an atomic
  ``UPDATE ... WHERE status='pending'`` with a rowcount check. If
  another coroutine somehow claimed the row first, the second one
  bails. This handles process restarts (where the in-process set is
  empty) and any race between the poll-batch and the dispatch task.

Deterministic-test hooks
------------------------
The retry timing constants and the polling interval are module-level
attributes so tests can monkeypatch them down to tiny values without
having to wait actual seconds. The HTTP transport (`._client`) is
also overridable -- tests inject a stub object with an ``async post``
that records the request and returns a canned response.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import random
import time
from datetime import datetime, timedelta

import httpx

from .database import (
    get_webhook_row,
    list_pending_deliveries,
    mark_delivery_delivering,
    reset_stale_delivering_deliveries,
    update_delivery_status,
)
from .webhook_formatters import format_payload

# Tunables. Module-level so tests can monkeypatch them without
# relaunching the dispatcher.
MAX_AGE_SECONDS: float = 30 * 60
BASE_BACKOFF_SECONDS: float = 5.0
MAX_BACKOFF_SECONDS: float = 300.0
HTTP_TIMEOUT_SECONDS: float = 10.0
POLL_INTERVAL_SECONDS: float = 1.0


logger = logging.getLogger("securescan.webhooks")


class WebhookDispatcher:
    """Long-lived asyncio worker that drains the deliveries queue.

    One instance per process is the intended usage; the module-level
    ``dispatcher`` singleton is what main.py wires into the FastAPI
    startup/shutdown hooks. Tests construct fresh instances when they
    need isolation from the singleton.
    """

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        # Per-webhook FIFO guard. A webhook_id sitting in this set
        # has an in-flight delivery and we will not start a second
        # one for it until the first completes (success, retry, or
        # terminal failure).
        self._inflight_per_webhook: set[str] = set()
        self._client: httpx.AsyncClient | None = None

    @property
    def client(self) -> httpx.AsyncClient | None:
        """Public so tests can swap in a stub or real httpx client."""
        return self._client

    @client.setter
    def client(self, value) -> None:
        self._client = value

    async def start(self) -> None:
        """Open the HTTP client, reset stale rows, and launch the loop.

        Called from the FastAPI startup hook. Idempotent in the sense
        that calling start() twice without an intervening stop() is
        a programmer bug -- the second call will replace the client
        but the existing task keeps running, which is wasteful but
        not incorrect. We log the warning instead of raising so a
        misconfigured test does not break the suite.
        """
        if self._task is not None and not self._task.done():
            logger.warning("WebhookDispatcher.start() called while already running")
            return
        self._stop = asyncio.Event()
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS)
        # Critical for crash recovery -- see module docstring.
        try:
            n = await reset_stale_delivering_deliveries()
            if n:
                logger.info("reset %d stale delivering rows on startup", n)
        except Exception:
            logger.exception("failed to reset stale delivering rows")
        self._task = asyncio.create_task(self._run(), name="webhook-dispatcher")

    async def stop(self) -> None:
        """Signal the loop to exit and wait for it to drain.

        Closes the underlying httpx client too. Safe to call multiple
        times: stop()-then-stop() is a no-op on the second call.
        """
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            try:
                await task
            except Exception:
                logger.exception("dispatcher task raised on shutdown")
        client = self._client
        self._client = None
        if client is not None:
            try:
                await client.aclose()
            except Exception:
                logger.exception("error closing httpx client on shutdown")

    async def run_once(self) -> int:
        """Single iteration of the poll-and-dispatch loop.

        Useful from tests to drive deliveries deterministically without
        starting the long-running task. Returns the number of
        deliveries scheduled this tick (excluding ones skipped by the
        FIFO guard).
        """
        rows = await list_pending_deliveries(limit=20)
        scheduled = 0
        for row in rows:
            wid = row["webhook_id"]
            if wid in self._inflight_per_webhook:
                continue
            self._inflight_per_webhook.add(wid)
            asyncio.create_task(self._deliver_one(row), name=f"webhook-deliver-{row['id']}")
            scheduled += 1
        return scheduled

    async def _run(self) -> None:
        """Poll loop. Sleeps `POLL_INTERVAL_SECONDS` between ticks."""
        while not self._stop.is_set():
            try:
                await self.run_once()
            except Exception:
                logger.exception("dispatcher loop error")
            try:
                # asyncio.wait_for with the stop-event lets shutdown
                # be near-instant instead of waiting out the full
                # POLL_INTERVAL_SECONDS.
                await asyncio.wait_for(self._stop.wait(), timeout=POLL_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass

    async def _deliver_one(self, row: dict) -> None:
        """Dispatch a single delivery row end-to-end.

        Always clears the FIFO guard in `finally` so a thrown
        exception does not deadlock subsequent deliveries for the same
        webhook. Status transitions are persisted incrementally so an
        observer (admin UI polling deliveries) sees progress.
        """
        delivery_id = row["id"]
        webhook_id = row["webhook_id"]
        try:
            claimed = await mark_delivery_delivering(delivery_id)
            if not claimed:
                # Another worker (or a previous restart) already
                # picked this row up. Bail without changing state --
                # whoever owns the 'delivering' marker will resolve it.
                return

            webhook_row = await get_webhook_row(webhook_id)
            if webhook_row is None or not bool(webhook_row.get("enabled", 1)):
                await update_delivery_status(
                    delivery_id,
                    status="failed",
                    response_body="webhook deleted/disabled",
                )
                return

            await self._send_and_record(
                row=row,
                webhook_row=webhook_row,
            )
        except Exception:
            # Any unhandled error -> mark failed so the row does not
            # sit in 'delivering' forever (the next startup would
            # reset it but a long-running process should not need
            # that crutch for code-level bugs).
            logger.exception("delivery %s crashed", delivery_id)
            try:
                await update_delivery_status(
                    delivery_id,
                    status="failed",
                    response_body="dispatcher internal error",
                )
            except Exception:
                logger.exception("failed to record terminal-failure status")
        finally:
            self._inflight_per_webhook.discard(webhook_id)

    async def _send_and_record(self, *, row: dict, webhook_row: dict) -> None:
        """Build, sign, send, then transition state based on response.

        Splitting this from _deliver_one keeps the FIFO/claim logic
        small and the HTTP-construction logic easy to follow on its
        own.
        """
        delivery_id = row["id"]
        url: str = webhook_row["url"]
        secret: str = webhook_row["secret"]

        payload = format_payload(url, row["event"], json.loads(row["payload"]))
        # Compact separators are part of the signature contract -- we
        # sign the literal bytes we send. If a receiver re-serializes
        # the body before re-signing, signatures will not match.
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ts = int(time.time())
        sig = hmac.new(
            secret.encode("utf-8"),
            f"{ts}.".encode() + body,
            hashlib.sha256,
        ).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SecureScan-Webhook/0.9",
            "X-SecureScan-Signature": f"t={ts},v1={sig}",
            "X-SecureScan-Event": row["event"],
            "X-SecureScan-Webhook-Id": webhook_row["id"],
        }

        client = self._client
        if client is None:
            # Should not happen in production -- start() always opens
            # a client. Treat as a transport error so retry logic kicks
            # in rather than terminal-failing the row.
            await self._maybe_retry(
                row,
                attempt=row["attempt"] + 1,
                response_code=None,
                response_body="dispatcher: no http client available",
            )
            return

        try:
            resp = await client.post(url, content=body, headers=headers)
        except (httpx.RequestError, asyncio.TimeoutError) as exc:
            await self._maybe_retry(
                row,
                attempt=row["attempt"] + 1,
                response_code=None,
                response_body=f"transport: {exc!r}"[:2000],
            )
            return

        status_code = getattr(resp, "status_code", 0)
        body_text = getattr(resp, "text", "") or ""
        if 200 <= status_code < 300:
            await update_delivery_status(
                delivery_id,
                status="succeeded",
                attempt=row["attempt"] + 1,
                response_code=status_code,
                response_body=body_text[:2000],
            )
            return
        # 3xx/4xx/5xx -> retry path. We deliberately retry 4xx too;
        # a misconfigured receiver that returns 401 for a few seconds
        # while it loads its keys should not lose deliveries within
        # MAX_AGE_SECONDS.
        await self._maybe_retry(
            row,
            attempt=row["attempt"] + 1,
            response_code=status_code,
            response_body=body_text[:2000],
        )

    async def _maybe_retry(
        self,
        row: dict,
        *,
        attempt: int,
        response_code: int | None,
        response_body: str | None,
    ) -> None:
        """Either schedule a retry or terminal-fail when too old."""
        delivery_id = row["id"]
        try:
            created_at = datetime.fromisoformat(row["created_at"])
        except Exception:
            created_at = datetime.utcnow()
        age_seconds = (datetime.utcnow() - created_at).total_seconds()
        if age_seconds > MAX_AGE_SECONDS:
            await update_delivery_status(
                delivery_id,
                status="failed",
                attempt=attempt,
                response_code=response_code,
                response_body=response_body,
            )
            return

        # Full-jitter capped exponential. attempt=1 -> uniform[0, base];
        # attempt=2 -> uniform[0, 2*base]; ... clamped at MAX_BACKOFF.
        cap = min(BASE_BACKOFF_SECONDS * (2 ** max(attempt - 1, 0)), MAX_BACKOFF_SECONDS)
        delay = random.uniform(0, cap)
        next_at = datetime.utcnow() + timedelta(seconds=delay)
        await update_delivery_status(
            delivery_id,
            status="pending",
            attempt=attempt,
            next_attempt_at=next_at,
            response_code=response_code,
            response_body=response_body,
        )


# Process-wide singleton wired into FastAPI's startup/shutdown hooks.
dispatcher = WebhookDispatcher()
