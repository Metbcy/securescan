"""In-app notifications API (BE-NOTIFY).

Endpoints under `/api/notifications/...` (also mirrored at `/api/v1/...`
via the legacy alias). Powers the dashboard topbar bell icon: a
polled unread count and a dropdown of recent events.

Single-tenant for v0.9.0 -- there is no per-user scoping. Every
authenticated browser session sees the same notifications. Multi-user
filtering is a future feature; the schema and these endpoints are
shaped so a `user_id` query param can be added later without breaking
existing callers.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth import require_scope
from ..database import (
    count_unread_notifications,
    get_notification,
    list_notifications,
    mark_all_notifications_read,
    mark_notification_read,
)
from ..models import Notification


router = APIRouter(prefix="/api/notifications", tags=["notifications"])

# The dropdown UI shows at most a few dozen items at a time; the cap
# exists to bound payload size and DB scan width when an automated
# caller (script, test) passes a huge limit.
_MAX_LIMIT = 200


@router.get(
    "",
    response_model=list[Notification],
    dependencies=[Depends(require_scope("read"))],
)
async def list_notifications_endpoint(
    unread_only: bool = Query(False, description="Only return unread"),
    limit: int = Query(50, ge=1, description="Max rows; capped at 200"),
) -> list[Notification]:
    """Return notifications, newest first.

    `limit` is silently capped at 200 (rather than 422'd) so a
    polling client that hardcodes a higher value still gets a useful
    response -- the bell dropdown only ever renders the first ~20
    rows anyway.
    """
    effective_limit = min(limit, _MAX_LIMIT)
    return await list_notifications(unread_only=unread_only, limit=effective_limit)


@router.get(
    "/unread-count",
    dependencies=[Depends(require_scope("read"))],
)
async def unread_count_endpoint() -> dict:
    """Return `{"count": int}` for the unread badge.

    The dashboard polls this every 30s; it must stay cheap. The
    underlying query is index-only (`idx_notifications_unread`), so
    even a busy deployment with thousands of historical notifications
    answers this in O(log n).
    """
    count = await count_unread_notifications()
    return {"count": count}


@router.patch(
    "/read-all",
    dependencies=[Depends(require_scope("write"))],
)
async def mark_all_read_endpoint() -> dict:
    """Mark every unread notification read.

    Returns the number of rows modified so the caller can confirm
    the action. Idempotent: a second call returns `{"marked_read": 0}`.
    """
    count = await mark_all_notifications_read()
    return {"marked_read": count}


@router.patch(
    "/{notification_id}/read",
    response_model=Notification,
    dependencies=[Depends(require_scope("write"))],
)
async def mark_read_endpoint(notification_id: str) -> Notification:
    """Mark a single notification read; return the updated row.

    A second PATCH on the same id is a no-op (200 with the same row,
    not 4xx) -- the read state is what matters, not how many times
    the user clicked. An unknown id returns 404 so the frontend can
    distinguish a stale id from a successful idempotent call.
    """
    # mark_notification_read returns False when the id is unknown OR
    # when the row was already read. Look up the row to disambiguate
    # so we 404 only on the truly-unknown case.
    notif = await get_notification(notification_id)
    if notif is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    if notif.read_at is None:
        await mark_notification_read(notification_id)
        notif = await get_notification(notification_id)
        # The row exists (we just read it above); the second lookup
        # is to surface the server-assigned `read_at`.
        assert notif is not None
    return notif
