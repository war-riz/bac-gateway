"""
GET   /api/v1/notifications           — List notifications (filterable: unread only)
PATCH /api/v1/notifications/read      — Mark one or all as read
GET   /api/v1/notifications/count     — Unread count (for badge in navbar)
"""
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, Query
from gateway.core.dependencies import get_current_admin
from gateway.models.user import User
from gateway.schemas.notification import NotificationOut, NotificationListOut, MarkReadRequest
from gateway.services.notification_service import (
    get_notifications, mark_all_read, mark_one_read, get_unread_count,
)

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=NotificationListOut)
async def list_notifications(
    admin: Annotated[User, Depends(get_current_admin)],
    unread_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
):
    items = await get_notifications(unread_only=unread_only, limit=limit)
    count = await get_unread_count()
    return NotificationListOut(
        items=[_to_out(n) for n in items],
        unread_count=count,
    )


@router.get("/count")
async def unread_count(admin: Annotated[User, Depends(get_current_admin)]):
    """Lightweight endpoint — poll this every 30s to update the navbar badge."""
    return {"unread_count": await get_unread_count()}


@router.patch("/read")
async def mark_read(
    body: MarkReadRequest,
    admin: Annotated[User, Depends(get_current_admin)],
):
    """
    Mark as read:
    - Pass notification_id to mark one specific notification
    - Pass null/omit notification_id to mark ALL as read
    """
    if body.notification_id:
        n = await mark_one_read(body.notification_id)
        return {"marked": 1 if n else 0}
    else:
        count = await mark_all_read()
        return {"marked": count}


def _to_out(n) -> NotificationOut:
    return NotificationOut(
        id=str(n.id),
        type=n.type,
        severity=n.severity,
        title=n.title,
        message=n.message,
        is_read=n.is_read,
        related_event_id=n.related_event_id,
        related_ip=n.related_ip,
        created_at=n.created_at,
    )
