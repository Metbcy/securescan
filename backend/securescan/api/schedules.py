"""CRUD endpoints for cron-driven scan schedules (FEAT-SCHEDULES).

Endpoints
---------
* ``POST   /api/schedules``         - admin: create a new schedule.
* ``GET    /api/schedules``         - admin: list all schedules.
* ``GET    /api/schedules/{id}``    - admin: fetch one schedule.
* ``PATCH  /api/schedules/{id}``    - admin: edit fields.
* ``DELETE /api/schedules/{id}``    - admin: delete and cascade run history.
* ``GET    /api/schedules/{id}/runs`` - admin: last 50 run rows.

All endpoints require the ``admin`` scope.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from apscheduler.triggers.cron import CronTrigger
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from ..auth import require_scope
from ..database import (
    delete_schedule,
    get_schedule,
    insert_schedule,
    list_schedule_runs,
    list_schedules,
    update_schedule,
)
from ..models import ScanType, Schedule, ScheduleRun
from ..scheduler import scheduler as _scheduler

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


def _validate_cron(expr: str) -> str:
    """Reject expressions that APScheduler cannot parse."""
    try:
        CronTrigger.from_crontab(expr)
    except Exception as exc:
        raise ValueError(f"invalid cron expression: {exc}") from exc
    return expr


class CreateScheduleBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target_path: str = Field(min_length=1)
    scan_types: list[ScanType] = Field(
        default_factory=lambda: [ScanType.CODE, ScanType.DEPENDENCY], min_length=1
    )
    cron_expression: str

    @field_validator("cron_expression")
    @classmethod
    def _check_cron(cls, v: str) -> str:
        try:
            return _validate_cron(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


class PatchScheduleBody(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    target_path: str | None = Field(default=None, min_length=1)
    scan_types: list[ScanType] | None = Field(default=None, min_length=1)
    cron_expression: str | None = None
    enabled: bool | None = None

    @field_validator("cron_expression")
    @classmethod
    def _check_cron(cls, v: str | None) -> str | None:
        if v is None:
            return None
        try:
            return _validate_cron(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


@router.post(
    "",
    response_model=Schedule,
    status_code=201,
    dependencies=[Depends(require_scope("admin"))],
)
async def create_schedule(body: CreateScheduleBody) -> Schedule:
    """Create a new cron schedule. Immediately registers a live APScheduler job."""
    schedule_id = str(uuid.uuid4())
    created_at = datetime.utcnow()
    await insert_schedule(
        id=schedule_id,
        name=body.name,
        target_path=body.target_path,
        scan_types=[t.value for t in body.scan_types],
        cron_expression=body.cron_expression,
        enabled=True,
        created_at=created_at,
    )
    _scheduler.add(schedule_id, body.cron_expression)
    sched = await get_schedule(schedule_id)
    if sched is None:
        raise HTTPException(500, "Failed to retrieve created schedule")
    return sched


@router.get(
    "",
    response_model=list[Schedule],
    dependencies=[Depends(require_scope("admin"))],
)
async def get_schedules() -> list[Schedule]:
    """List all schedules, newest first."""
    return await list_schedules()


@router.get(
    "/{schedule_id}",
    response_model=Schedule,
    dependencies=[Depends(require_scope("admin"))],
)
async def get_schedule_endpoint(schedule_id: str) -> Schedule:
    sched = await get_schedule(schedule_id)
    if sched is None:
        raise HTTPException(404, "Schedule not found")
    return sched


@router.patch(
    "/{schedule_id}",
    response_model=Schedule,
    dependencies=[Depends(require_scope("admin"))],
)
async def patch_schedule(schedule_id: str, body: PatchScheduleBody) -> Schedule:
    """Edit any subset of fields. Keeps the live scheduler in sync."""
    sched = await update_schedule(
        schedule_id,
        name=body.name,
        target_path=body.target_path,
        scan_types=[t.value for t in body.scan_types] if body.scan_types is not None else None,
        cron_expression=body.cron_expression,
        enabled=body.enabled,
    )
    if sched is None:
        raise HTTPException(404, "Schedule not found")

    new_cron = sched.cron_expression
    new_enabled = sched.enabled
    _scheduler.reschedule(schedule_id, new_cron, enabled=new_enabled)
    return sched


@router.delete(
    "/{schedule_id}",
    status_code=204,
    dependencies=[Depends(require_scope("admin"))],
)
async def delete_schedule_endpoint(schedule_id: str) -> None:
    """Delete a schedule and cascade-drop all run history."""
    deleted = await delete_schedule(schedule_id)
    if not deleted:
        raise HTTPException(404, "Schedule not found")
    _scheduler.remove(schedule_id)


@router.get(
    "/{schedule_id}/runs",
    response_model=list[ScheduleRun],
    dependencies=[Depends(require_scope("admin"))],
)
async def get_schedule_runs(schedule_id: str) -> list[ScheduleRun]:
    """Last 50 run records for this schedule, newest first."""
    sched = await get_schedule(schedule_id)
    if sched is None:
        raise HTTPException(404, "Schedule not found")
    return await list_schedule_runs(schedule_id, limit=50)
