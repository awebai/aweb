"""Explicit team room operations; no mail/chat routing or wake effects."""

from fastapi import APIRouter, Depends, Query, Request

from aweb.deps import get_db
from aweb.messaging.room import (
    RoomPost,
    room_metadata,
    read_room,
    exact_room_message,
    post_room_message,
    present_room,
)
from aweb.team_auth_deps import team_identity_with_grant_scope

router = APIRouter(prefix="/v1/room", tags=["room"])
_read = team_identity_with_grant_scope("chat.read")
_post = team_identity_with_grant_scope("chat.send")


@router.get("")
async def metadata(db=Depends(get_db), actor=Depends(_read)):
    return await room_metadata(db, actor)


@router.get("/messages")
async def history(
    request: Request,
    after: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    db=Depends(get_db),
    actor=Depends(_read),
):
    return await present_room(
        db, request, await read_room(db, actor, after=after, limit=limit)
    )


@router.get("/messages/{message_id}")
async def exact(
    message_id: str, request: Request, db=Depends(get_db), actor=Depends(_read)
):
    return await present_room(
        db, request, await exact_room_message(db, actor, message_id)
    )


@router.post("/messages")
async def post(
    payload: RoomPost, request: Request, db=Depends(get_db), actor=Depends(_post)
):
    output = await post_room_message(
        db, actor, payload, id_chain=getattr(request.state, "id_chain", None)
    )
    return await present_room(db, request, output)
