"""Per-event notification threshold settings (issue #6).

Endpoints
---------
* ``GET   /api/settings/notifications``  - admin: list thresholds.
  Always returns a row per known event type with the default applied
  server-side when the underlying table has no row yet.
* ``PATCH /api/settings/notifications``  - admin: update one or more
  thresholds. Partial updates are allowed; unspecified events keep
  their current (or default) value.

Both endpoints require the ``admin`` scope -- the threshold gates
operator-facing notifications and an attacker who could lower it to
"critical" would silence routine failures.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..auth import require_scope
from ..database import (
    get_notification_settings,
    upsert_notification_threshold,
)
from ..models import (
    NotificationEventType,
    NotificationSettings,
    NotificationThresholdSetting,
    Severity,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


class NotificationThresholdUpdate(BaseModel):
    """Single threshold update entry inside `NotificationSettingsPatch`.

    Pydantic validation rejects unknown event types and severities at
    the boundary, so the handler can persist without re-checking.
    """

    event_type: NotificationEventType
    min_severity: Severity


class NotificationSettingsPatch(BaseModel):
    """PATCH body: a list of (event_type, min_severity) updates.

    Empty list is allowed (no-op) so the UI can submit a clean form
    without special-casing the "nothing changed" path.
    """

    thresholds: list[NotificationThresholdUpdate] = Field(default_factory=list)


@router.get(
    "/notifications",
    response_model=NotificationSettings,
    dependencies=[Depends(require_scope("admin"))],
)
async def get_notification_settings_endpoint() -> NotificationSettings:
    """Return the current threshold for every known event type.

    Defaults are applied server-side (see
    `database.NOTIFICATION_THRESHOLD_DEFAULTS`). The response is
    deterministic in event ordering so the UI can render without
    extra sorting.
    """
    rows = await get_notification_settings()
    return NotificationSettings(thresholds=rows)


@router.patch(
    "/notifications",
    response_model=NotificationSettings,
    dependencies=[Depends(require_scope("admin"))],
)
async def patch_notification_settings_endpoint(
    body: NotificationSettingsPatch,
) -> NotificationSettings:
    """Upsert one or more thresholds; return the full post-update state.

    Duplicate event_type entries in a single request are tolerated;
    the last value wins (insertion order). Unspecified events are
    untouched.
    """
    seen: dict[str, NotificationThresholdSetting] = {}
    for entry in body.thresholds:
        await upsert_notification_threshold(entry.event_type.value, entry.min_severity)
        seen[entry.event_type.value] = NotificationThresholdSetting(
            event_type=entry.event_type,
            min_severity=entry.min_severity,
        )
    rows = await get_notification_settings()
    return NotificationSettings(thresholds=rows)
