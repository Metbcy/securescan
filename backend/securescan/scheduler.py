"""Background scheduler for cron-driven scan schedules (FEAT-SCHEDULES).

Uses APScheduler's AsyncIOScheduler so jobs run inside the FastAPI event
loop. On startup every enabled schedule is loaded from the DB and wired
as a CronTrigger job. PATCH /schedules/{id} (enable/disable/cron change)
calls reschedule_schedule() or remove_schedule() to keep the live
scheduler in sync without restarting.

Multi-worker safety
-------------------
If SECURESCAN_REDIS_URL is set the scheduler acquires a Redis SET NX EX
lock before creating a scan. A second worker whose cron fires at the same
second will see the lock already held and skip without writing a run row.
In single-process mode (no Redis) the asyncio.Lock on the in-process
backend gives equivalent protection within a single process.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger("securescan.scheduler")

# How long (seconds) the Redis lock is held. Must be longer than the
# expected time between receiving the lock and writing the schedule_run
# row, but short enough that a crashed worker eventually releases it.
_LOCK_TTL = 30


async def _acquire_lock(schedule_id: str) -> bool:
    """Try to acquire the per-schedule distributed lock.

    Returns True if the lock was acquired (this worker should run the
    scan), False if another worker already holds it.
    """
    from .pubsub import get_redis_client

    redis = get_redis_client()
    if redis is None:
        return True  # no Redis -- single-process, always proceed
    key = f"ss:sched:lock:{schedule_id}"
    acquired = await redis.set(key, "1", nx=True, ex=_LOCK_TTL)
    return bool(acquired)


async def _fire_schedule(schedule_id: str) -> None:
    """Job callback: acquire lock, start scan, record run row."""
    from .api.scans import _run_scan
    from .database import (
        get_schedule,
        insert_schedule_run,
        save_scan,
        touch_schedule_last_run,
    )
    from .models import Scan, ScanStatus

    if not await _acquire_lock(schedule_id):
        logger.info("schedule %s: lock held by another worker, skipping", schedule_id)
        return

    schedule = await get_schedule(schedule_id)
    if schedule is None or not schedule.enabled:
        logger.info("schedule %s: not found or disabled, skipping", schedule_id)
        return

    now = datetime.utcnow()
    scan_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())

    scan = Scan(
        id=scan_id,
        target_path=schedule.target_path,
        scan_types=schedule.scan_types,
        status=ScanStatus.PENDING,
    )
    await save_scan(scan)
    await insert_schedule_run(
        id=run_id,
        schedule_id=schedule_id,
        scan_id=scan_id,
        triggered_at=now,
    )
    await touch_schedule_last_run(schedule_id, now)

    logger.info(
        "schedule %s: triggered scan %s for %s",
        schedule_id,
        scan_id,
        schedule.target_path,
    )
    asyncio.create_task(_run_scan(scan_id))


class SchedulerService:
    def __init__(self) -> None:
        self._scheduler = AsyncIOScheduler()

    async def start(self) -> None:
        from .database import list_schedules

        schedules = await list_schedules(only_enabled=True)
        for schedule in schedules:
            self._add_job(schedule.id, schedule.cron_expression)
        self._scheduler.start()
        logger.info("scheduler started with %d job(s)", len(schedules))

    async def stop(self) -> None:
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            logger.info("scheduler stopped")

    def _add_job(self, schedule_id: str, cron_expression: str) -> None:
        try:
            trigger = CronTrigger.from_crontab(cron_expression)
        except Exception as exc:
            logger.warning("schedule %s: invalid cron %r: %s", schedule_id, cron_expression, exc)
            return
        job_id = f"schedule:{schedule_id}"
        self._scheduler.add_job(
            _fire_schedule,
            trigger=trigger,
            id=job_id,
            args=[schedule_id],
            replace_existing=True,
            misfire_grace_time=60,
        )

    def reschedule(self, schedule_id: str, cron_expression: str, *, enabled: bool) -> None:
        """Called after a PATCH to keep the live scheduler in sync."""
        job_id = f"schedule:{schedule_id}"
        if not enabled:
            self.remove(schedule_id)
            return
        try:
            trigger = CronTrigger.from_crontab(cron_expression)
        except Exception as exc:
            logger.warning("schedule %s: invalid cron %r: %s", schedule_id, cron_expression, exc)
            return
        if self._scheduler.get_job(job_id):
            self._scheduler.reschedule_job(job_id, trigger=trigger)
        else:
            self._scheduler.add_job(
                _fire_schedule,
                trigger=trigger,
                id=job_id,
                args=[schedule_id],
                replace_existing=True,
                misfire_grace_time=60,
            )

    def remove(self, schedule_id: str) -> None:
        job_id = f"schedule:{schedule_id}"
        if self._scheduler.get_job(job_id):
            self._scheduler.remove_job(job_id)

    def add(self, schedule_id: str, cron_expression: str) -> None:
        self._add_job(schedule_id, cron_expression)


scheduler = SchedulerService()
