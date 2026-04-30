"""CRUD + delivery-history + test endpoints for outbound webhooks (BE-WEBHOOKS).

Mounted at ``/api/webhooks`` (legacy) and ``/api/v1/webhooks`` (current)
via ``alias_router_at_v1`` -- single source of truth, both paths share
this router.

Endpoints
---------
* ``POST   /``                     - admin: create. Returns secret ONCE.
* ``GET    /``                     - admin: list (no secrets).
* ``GET    /{id}``                 - admin: fetch one (no secret).
* ``PATCH  /{id}``                 - admin: edit name/url/event_filter/enabled.
                                     Cannot rotate secret.
* ``DELETE /{id}``                 - admin: cascades deliveries.
* ``GET    /{id}/deliveries``      - admin: last 100 delivery rows, newest first.
* ``POST   /{id}/test``            - admin: enqueue a synthetic webhook.test
                                     event through the same dispatcher path.

All endpoints require the ``admin`` scope -- webhooks can leak event
data and an attacker with write access could redirect events to a
sink they control. Read-only access is intentionally not provided in
v0.9.0; the admin UI is the only consumer.
"""
from __future__ import annotations

import json
import secrets as secrets_mod
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from ..auth import require_scope
from ..database import (
    delete_webhook,
    get_webhook,
    insert_webhook,
    insert_webhook_delivery,
    list_deliveries_for_webhook,
    list_webhooks,
    update_webhook,
)
from ..models import (
    Webhook,
    WebhookCreated,
    WebhookDelivery,
    WebhookEventType,
    _validate_webhook_url,
)


router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


class CreateWebhookBody(BaseModel):
    """Request body for ``POST /webhooks``.

    `event_filter` may be empty in principle (the webhook would match
    nothing) but we require at least one event so an operator does not
    accidentally create a permanently-silent subscription.
    """
    name: str = Field(min_length=1, max_length=200)
    url: str
    event_filter: list[WebhookEventType] = Field(min_length=1)

    @field_validator("url")
    @classmethod
    def _check_url(cls, v: str) -> str:
        try:
            return _validate_webhook_url(v)
        except ValueError as exc:
            # Pydantic wraps this into a 422 response that mentions
            # the field name; the message stays operator-readable.
            raise ValueError(str(exc))


class PatchWebhookBody(BaseModel):
    """Request body for ``PATCH /webhooks/{id}``.

    Every field is optional. Omitted fields are not changed. The
    secret is intentionally NOT a field here -- to rotate, delete and
    recreate (per spec).
    """
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    url: Optional[str] = None
    event_filter: Optional[list[WebhookEventType]] = Field(default=None, min_length=1)
    enabled: Optional[bool] = None

    @field_validator("url")
    @classmethod
    def _check_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        try:
            return _validate_webhook_url(v)
        except ValueError as exc:
            raise ValueError(str(exc))


@router.post(
    "",
    response_model=WebhookCreated,
    status_code=201,
    dependencies=[Depends(require_scope("admin"))],
)
async def create_webhook(body: CreateWebhookBody) -> WebhookCreated:
    """Create a new webhook subscription.

    Server generates a fresh URL-safe secret with
    ``secrets.token_urlsafe(32)``. The secret is included in this
    response only -- subsequent reads strip it.
    """
    webhook_id = str(uuid.uuid4())
    secret = secrets_mod.token_urlsafe(32)
    created_at = datetime.utcnow()
    await insert_webhook(
        id=webhook_id,
        name=body.name,
        url=body.url,
        secret=secret,
        event_filter=[e.value for e in body.event_filter],
        enabled=True,
        created_at=created_at,
    )
    return WebhookCreated(
        id=webhook_id,
        name=body.name,
        url=body.url,
        event_filter=body.event_filter,
        enabled=True,
        created_at=created_at,
        secret=secret,
    )


@router.get(
    "",
    response_model=list[Webhook],
    dependencies=[Depends(require_scope("admin"))],
)
async def get_webhooks() -> list[Webhook]:
    """List all webhooks, newest first. Secret is NEVER included."""
    return await list_webhooks()


@router.get(
    "/{webhook_id}",
    response_model=Webhook,
    dependencies=[Depends(require_scope("admin"))],
)
async def get_webhook_endpoint(webhook_id: str) -> Webhook:
    wh = await get_webhook(webhook_id)
    if wh is None:
        raise HTTPException(404, "Webhook not found")
    return wh


@router.patch(
    "/{webhook_id}",
    response_model=Webhook,
    dependencies=[Depends(require_scope("admin"))],
)
async def patch_webhook(webhook_id: str, body: PatchWebhookBody) -> Webhook:
    """Edit any subset of name/url/event_filter/enabled.

    Returns the updated row. 404 if the id does not exist. Cannot
    rotate the secret (the body model has no `secret` field; rotating
    is delete+recreate per the v0.9.0 spec).
    """
    wh = await update_webhook(
        webhook_id,
        name=body.name,
        url=body.url,
        event_filter=(
            [e.value for e in body.event_filter]
            if body.event_filter is not None
            else None
        ),
        enabled=body.enabled,
    )
    if wh is None:
        raise HTTPException(404, "Webhook not found")
    return wh


@router.delete(
    "/{webhook_id}",
    status_code=204,
    dependencies=[Depends(require_scope("admin"))],
)
async def delete_webhook_endpoint(webhook_id: str) -> None:
    """Delete a webhook and all of its delivery history."""
    deleted = await delete_webhook(webhook_id)
    if not deleted:
        raise HTTPException(404, "Webhook not found")


@router.get(
    "/{webhook_id}/deliveries",
    response_model=list[WebhookDelivery],
    dependencies=[Depends(require_scope("admin"))],
)
async def get_webhook_deliveries(webhook_id: str) -> list[WebhookDelivery]:
    """Last 100 delivery attempts for this webhook, newest first."""
    wh = await get_webhook(webhook_id)
    if wh is None:
        raise HTTPException(404, "Webhook not found")
    return await list_deliveries_for_webhook(webhook_id, limit=100)


class TestWebhookResponse(BaseModel):
    """Response from ``POST /webhooks/{id}/test``.

    The UI polls ``/deliveries`` and looks up the row by `delivery_id`
    to surface the result. We do NOT block the request on dispatch --
    the synthetic event flows through the exact same dispatcher path
    as a real one (per spec) so the response returns immediately.
    """
    delivery_id: str
    webhook_id: str
    event: str = "webhook.test"


@router.post(
    "/{webhook_id}/test",
    response_model=TestWebhookResponse,
    status_code=202,
    dependencies=[Depends(require_scope("admin"))],
)
async def test_webhook(webhook_id: str) -> TestWebhookResponse:
    """Enqueue a synthetic ``webhook.test`` delivery for this webhook.

    Bypasses the event_filter (the test is operator-initiated -- the
    operator already knows they want it sent) but otherwise routes
    through the identical durable-queue path. Returns 202 with the new
    delivery id so the UI can poll.
    """
    wh = await get_webhook(webhook_id)
    if wh is None:
        raise HTTPException(404, "Webhook not found")
    now = datetime.utcnow()
    delivery_id = str(uuid.uuid4())
    payload = json.dumps({
        "event": "webhook.test",
        "data": {
            "message": "Test from SecureScan",
            "timestamp": now.isoformat(),
        },
    })
    await insert_webhook_delivery(
        id=delivery_id,
        webhook_id=webhook_id,
        event="webhook.test",
        payload=payload,
        next_attempt_at=now,
        created_at=now,
    )
    return TestWebhookResponse(delivery_id=delivery_id, webhook_id=webhook_id)
