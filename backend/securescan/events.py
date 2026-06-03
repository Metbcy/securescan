"""Per-scan-id event bus for real-time SSE delivery.

A late subscriber (frontend mounting after the scan started) gets the
full event sequence via a replay buffer; the buffer is retained for
``RETAIN_AFTER_TERMINAL_S`` seconds after a terminal event so a tab
refresh during the closing window still gets a complete picture.

Bounded queue per subscriber (``QUEUE_CAP`` events). On overflow we
evict the OLDEST NON-TERMINAL event so terminal events
(``scan.complete`` / ``scan.failed`` / ``scan.cancelled``) are NEVER
dropped — a subscriber that loses ``scan.complete`` would sit in
'running' forever.

Module-level singleton.
"""

from __future__ import annotations

import asyncio
import logging

from .pubsub import PubSubBackend, get_pubsub_backend

logger = logging.getLogger("securescan.events")

TERMINAL: frozenset[str] = frozenset({"scan.complete", "scan.failed", "scan.cancelled"})


class ScanEventBus:
    """Pub/sub for scan-lifecycle events keyed by ``scan_id``.

    Supports in-process and Redis backends via ``PubSubBackend``.
    """

    REPLAY_CAP: int = 200
    QUEUE_CAP: int = 200
    RETAIN_AFTER_TERMINAL_S: float = 30.0

    def __init__(self, backend: PubSubBackend | None = None) -> None:
        self.backend = backend or get_pubsub_backend()
        self._subs: dict[str, list[asyncio.Queue]] = {}
        # Track local subscriber loops
        self._sub_tasks: dict[asyncio.Queue, asyncio.Task] = {}

    async def subscribe(self, scan_id: str) -> asyncio.Queue:
        """Register a new subscriber and seed it with the replay buffer."""
        q: asyncio.Queue = asyncio.Queue(maxsize=self.QUEUE_CAP)
        self._subs.setdefault(scan_id, []).append(q)

        # 1. Prime with replay buffer
        replays = await self.backend.fetch_replay(scan_id)
        for item in replays:
            self._safe_put(q, item["event"], item["payload"])

        # 2. Start background task to forward live events
        task = asyncio.create_task(self._forward_events(scan_id, q))
        self._sub_tasks[q] = task

        return q

    async def _forward_events(self, scan_id: str, q: asyncio.Queue) -> None:
        try:
            async for msg in self.backend.subscribe(scan_id):
                self._safe_put(q, msg["event"], msg["payload"])
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Error in event forwarder for scan %s", scan_id)

    def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        subs = self._subs.get(scan_id)
        if subs and q in subs:
            subs.remove(q)
        if subs is not None and not subs:
            self._subs.pop(scan_id, None)

        task = self._sub_tasks.pop(q, None)
        if task:
            task.cancel()

    async def publish(self, scan_id: str, event: str, payload: dict) -> None:
        """Append to the replay buffer and fan out to every subscriber."""
        msg = {"event": event, "payload": payload}

        # 1. Update replay buffer
        await self.backend.add_to_replay(scan_id, msg, self.REPLAY_CAP)

        # 2. Publish live
        await self.backend.publish(scan_id, msg)

        # 3. Handle terminal event cleanup
        if event in TERMINAL:
            # For Redis, we could set a shorter expiry.
            # For now, let's keep it simple: the backend add_to_replay sets an expiry.
            # If we want RETAIN_AFTER_TERMINAL_S specifically:
            from .pubsub import RedisBackend

            if isinstance(self.backend, RedisBackend):
                key = f"{self.backend.prefix}replay:{scan_id}"
                await self.backend.redis.expire(key, int(self.RETAIN_AFTER_TERMINAL_S))
            # InProcessBackend doesn't have an auto-expiry for replays yet,
            # but we can schedule it here.
            else:
                asyncio.create_task(self._cleanup_in_process(scan_id))

    async def _cleanup_in_process(self, scan_id: str) -> None:
        await asyncio.sleep(self.RETAIN_AFTER_TERMINAL_S)
        if not self._subs.get(scan_id):
            await self.backend.clear_replay(scan_id)

    def _safe_put(self, q: asyncio.Queue, event: str, payload: dict) -> None:
        """Enqueue ``(event, payload)``; on overflow, evict an oldest
        non-terminal item to make room. Terminal events are never
        silently dropped.
        """
        try:
            q.put_nowait((event, payload))
            return
        except asyncio.QueueFull:
            pass

        snapshot_size = q.qsize()
        evicted_one = False
        for _ in range(snapshot_size):
            try:
                old_event, old_payload = q.get_nowait()
            except asyncio.QueueEmpty:
                break
            if old_event in TERMINAL:
                try:
                    q.put_nowait((old_event, old_payload))
                except asyncio.QueueFull:
                    pass
                continue
            evicted_one = True
            break

        if evicted_one:
            try:
                q.put_nowait((event, payload))
                return
            except asyncio.QueueFull:
                pass

        if event in TERMINAL:
            try:
                q.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                q.put_nowait((event, payload))
            except asyncio.QueueFull:
                pass

    async def has_replay(self, scan_id: str) -> bool:
        replays = await self.backend.fetch_replay(scan_id)
        return bool(replays)

    async def replay_for(self, scan_id: str) -> list[tuple[str, dict]]:
        """Return a copy of the replay buffer for ``scan_id``. Used by tests."""
        replays = await self.backend.fetch_replay(scan_id)
        return [(item["event"], item["payload"]) for item in replays]

    async def reset(self, scan_id: str | None = None) -> None:
        """Test helper: clear all bus state."""
        if scan_id is None:
            for q in list(self._sub_tasks.keys()):
                self.unsubscribe("", q)  # scan_id doesn't matter for task cancellation
            self._subs.clear()
            # Note: cannot easily clear all replays in Redis without scanning keys
            return

        for q in list(self._subs.get(scan_id, [])):
            self.unsubscribe(scan_id, q)
        await self.backend.clear_replay(scan_id)


bus = ScanEventBus()
