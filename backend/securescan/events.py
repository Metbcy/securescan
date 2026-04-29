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

Module-level singleton. **Multi-worker uvicorn breaks pub/sub**
because the POST that creates the scan and the SSE GET that follows
it may land on different workers. The README documents the
single-worker constraint; a multi-process backplane (Redis pubsub) is
a future feature explicitly out of scope here.
"""
from __future__ import annotations

import asyncio
from typing import Optional


TERMINAL: frozenset[str] = frozenset(
    {"scan.complete", "scan.failed", "scan.cancelled"}
)


class ScanEventBus:
    """In-process pub/sub for scan-lifecycle events keyed by ``scan_id``.

    The bus tracks per-scan subscribers and a per-scan replay buffer.
    Publish is fully synchronous (no awaits) so it can be safely
    invoked from ``asyncio.create_task(bus.publish(...))`` without
    risk of being cancelled before the buffer is updated.
    """

    REPLAY_CAP: int = 200
    QUEUE_CAP: int = 200
    RETAIN_AFTER_TERMINAL_S: float = 30.0

    def __init__(self) -> None:
        self._subs: dict[str, list[asyncio.Queue]] = {}
        self._replay: dict[str, list[tuple[str, dict]]] = {}
        # Track scheduled cleanup tasks so we don't pile up duplicates
        # when several terminal-ish events fire in quick succession.
        self._cleanup_tasks: dict[str, asyncio.Task] = {}

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        """Register a new subscriber and seed it with the replay buffer.

        The queue is registered FIRST and primed in the same
        synchronous call. This prevents a race where ``publish()``
        arrives between snapshotting the buffer and adding the queue
        to ``_subs`` (which would result in a missed event).
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=self.QUEUE_CAP)
        self._subs.setdefault(scan_id, []).append(q)
        for event, payload in self._replay.get(scan_id, ()):
            try:
                q.put_nowait((event, payload))
            except asyncio.QueueFull:
                # Extremely unlikely on a fresh subscribe (the queue
                # starts empty and REPLAY_CAP <= QUEUE_CAP) but handle
                # it defensively rather than crashing the subscriber.
                break
        return q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        subs = self._subs.get(scan_id)
        if subs and q in subs:
            subs.remove(q)
        if subs is not None and not subs:
            self._subs.pop(scan_id, None)

    async def publish(self, scan_id: str, event: str, payload: dict) -> None:
        """Append to the replay buffer and fan out to every subscriber.

        ``async`` purely so callers can ``await`` it directly from
        async code; nothing inside actually awaits, which makes the
        ``asyncio.create_task(bus.publish(...))`` bridge from the
        synchronous ``_log_scan_event`` helper safe.
        """
        buf = self._replay.setdefault(scan_id, [])
        buf.append((event, payload))
        if len(buf) > self.REPLAY_CAP:
            del buf[: len(buf) - self.REPLAY_CAP]

        for q in list(self._subs.get(scan_id, ())):
            self._safe_put(q, event, payload)

        if event in TERMINAL:
            self._schedule_cleanup(scan_id)

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

        # Walk the queue, dropping the first non-terminal item we
        # find. Terminal items are re-enqueued at the tail (FIFO) so
        # they survive — order shifts slightly but the frontend just
        # sees the terminal event arrive a bit late, which is fine.
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
                    # Should be unreachable: we just removed an item.
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

        # Last resort for terminal events: every slot is held by a
        # prior terminal (extremely unusual). Drop one to make room
        # rather than lose the new one — losing scan.complete is the
        # worst possible outcome.
        if event in TERMINAL:
            try:
                q.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                q.put_nowait((event, payload))
            except asyncio.QueueFull:
                pass
        # Non-terminal that couldn't make room: drop. The frontend
        # will reconcile state via the next event (or the REST GET).

    def _schedule_cleanup(self, scan_id: str) -> None:
        existing = self._cleanup_tasks.get(scan_id)
        if existing is not None and not existing.done():
            return
        try:
            task = asyncio.create_task(self._cleanup_after_grace(scan_id))
        except RuntimeError:
            # No running loop (shouldn't happen in real usage —
            # publish is always invoked from async code — but stay
            # defensive in tests).
            return
        self._cleanup_tasks[scan_id] = task

    async def _cleanup_after_grace(self, scan_id: str) -> None:
        try:
            await asyncio.sleep(self.RETAIN_AFTER_TERMINAL_S)
        except asyncio.CancelledError:
            return
        finally:
            # Only drop the task handle if it's still us — a later
            # publish may have replaced it.
            if self._cleanup_tasks.get(scan_id) is not None:
                self._cleanup_tasks.pop(scan_id, None)
        if not self._subs.get(scan_id):
            self._replay.pop(scan_id, None)

    # -- helpers used by tests / observability --------------------------------

    def replay_for(self, scan_id: str) -> list[tuple[str, dict]]:
        """Return a copy of the replay buffer for ``scan_id``."""
        return list(self._replay.get(scan_id, ()))

    def has_replay(self, scan_id: str) -> bool:
        return bool(self._replay.get(scan_id))

    def reset(self, scan_id: Optional[str] = None) -> None:
        """Test helper: clear all bus state (or just one scan_id).

        Cancellation of any in-flight cleanup tasks is best-effort —
        tasks may belong to a previous test's event loop that is
        already closed (in which case ``t.cancel()`` raises
        ``RuntimeError: Event loop is closed``). Either way we drop
        the references; the dead tasks are harmless and get GC'd.
        """
        if scan_id is None:
            self._subs.clear()
            self._replay.clear()
            for t in self._cleanup_tasks.values():
                try:
                    t.cancel()
                except RuntimeError:
                    pass
            self._cleanup_tasks.clear()
            return
        self._subs.pop(scan_id, None)
        self._replay.pop(scan_id, None)
        t = self._cleanup_tasks.pop(scan_id, None)
        if t is not None:
            try:
                t.cancel()
            except RuntimeError:
                pass


bus = ScanEventBus()
