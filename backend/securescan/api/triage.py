"""Triage state + comments API (BE-TRIAGE).

Endpoints under `/api/findings/{fingerprint}/...`:

* `PATCH  /state`             — set or replace the triage verdict
* `GET    /comments`          — list comments for a fingerprint (ASC by created_at)
* `POST   /comments`          — add a comment
* `DELETE /comments/{id}`     — remove a single comment

Fingerprint is the cross-scan identity (see fingerprint.py) so a verdict on
one scan persists across rescans of the same target. We do NOT validate
that the fingerprint corresponds to an existing finding -- the same
fingerprint can pre-date or out-live any individual scan, and orphan
state rows are intentional (they reactivate when a matching finding
reappears in a later scan).
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..database import (
    add_finding_comment,
    delete_finding_comment,
    list_finding_comments,
    upsert_finding_state,
)
from ..models import (
    FindingComment,
    FindingState,
    TriageStatus,
)


router = APIRouter(prefix="/api/findings", tags=["triage"])


class PatchStateBody(BaseModel):
    """Request body for `PATCH /findings/{fp}/state`.

    `note` and `updated_by` are both optional -- omitting them clears the
    prior values (INSERT OR REPLACE on the row, see upsert_finding_state)
    rather than keeping them, which matches the PATCH-as-replace semantic
    we use for state. Comments are the right place for incremental notes.
    """
    status: TriageStatus
    note: Optional[str] = None
    updated_by: Optional[str] = None


class AddCommentBody(BaseModel):
    text: str
    author: Optional[str] = None


@router.patch("/{fingerprint}/state", response_model=FindingState)
async def patch_state(fingerprint: str, body: PatchStateBody) -> FindingState:
    """Create or replace the triage verdict for `fingerprint`.

    `updated_at` is always set server-side to the current UTC wall clock
    so callers can't backdate or skew it. Returns the persisted row.
    """
    state = FindingState(
        fingerprint=fingerprint,
        status=body.status,
        note=body.note,
        updated_at=datetime.utcnow(),
        updated_by=body.updated_by,
    )
    await upsert_finding_state(state)
    return state


@router.get("/{fingerprint}/comments", response_model=list[FindingComment])
async def list_comments(fingerprint: str) -> list[FindingComment]:
    """List comments on `fingerprint`, oldest first.

    Returns `[]` (200) when no comments exist -- the fingerprint is not
    validated against the findings table by design (see module docstring).
    """
    return await list_finding_comments(fingerprint)


@router.post(
    "/{fingerprint}/comments",
    response_model=FindingComment,
    status_code=201,
)
async def add_comment(fingerprint: str, body: AddCommentBody) -> FindingComment:
    """Append a comment to `fingerprint`. Server-assigned id + created_at."""
    comment = FindingComment(
        fingerprint=fingerprint,
        text=body.text,
        author=body.author,
    )
    await add_finding_comment(comment)
    return comment


@router.delete("/{fingerprint}/comments/{comment_id}", status_code=204)
async def delete_comment(fingerprint: str, comment_id: str) -> None:
    """Remove a single comment by id.

    `fingerprint` is part of the path for symmetry/discoverability but the
    delete itself is keyed on `comment_id` (the primary key). A second
    DELETE on the same id returns 404 so the caller can distinguish a
    no-op from a successful first delete.
    """
    deleted = await delete_finding_comment(comment_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Comment not found")
    return None
