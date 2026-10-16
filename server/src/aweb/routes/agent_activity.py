"""Agent activity ingress: an agent's host publishes what the agent is doing (docs/agent-activity.md)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from aweb.agent_activity import ActivityEventError, verify_activity_event
from aweb.deps import get_db, get_redis
from aweb.messaging.chat import resolve_session_actor_did
from aweb.service_errors import RESOURCE_NOT_FOUND_DETAIL
from aweb.team_auth_deps import TeamIdentity, team_identity_with_grant_scope

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/agents", tags=["agents"])

MAX_REQUEST_BODY_BYTES = 2048
RATE_WINDOW_SECONDS = 5
RATE_LIMIT = 10
MAX_LATEST_MS = 60_000
REVISION_TTL_SECONDS = 3600

# One fixed window per agent. The increment and the first expiry run together,
# so an interrupted first write cannot leave a counter without a TTL.
_RATE_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return {count, redis.call('TTL', KEYS[1])}
"""

# Assign the agent's next relay revision, store the latest state and publish,
# as one step: revision, latest-state and channel order then agree even when
# two requests for one agent race. ARGV[2] is a JSON object without "rev"; the
# script prefixes it rather than re-encoding it, because Redis cjson would turn
# large integers such as seq into doubles.
_RELAY_SCRIPT = """
local rev = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
local value = '{"rev":' .. rev .. ',' .. string.sub(ARGV[2], 2)
redis.call('SET', KEYS[2], value, 'PX', ARGV[3])
redis.call('PUBLISH', ARGV[4], value)
return rev
"""


def activity_state_key(agent_id: str) -> str:
    return f"agent-activity:{agent_id}"


def activity_channel_name(agent_id: str) -> str:
    return f"agent-activity:{agent_id}"


class PublishActivityRequest(BaseModel):
    model_config = {"extra": "forbid"}

    signed_payload: str
    signature: str


async def _require_small_body(request: Request) -> None:
    if len(await request.body()) > MAX_REQUEST_BODY_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"request_too_large: the request body exceeds {MAX_REQUEST_BODY_BYTES} bytes",
        )


def _unavailable() -> HTTPException:
    return HTTPException(status_code=503, detail="publishing_unavailable: Activity publishing is unavailable")


async def _enforce_rate(redis, agent_id: str) -> None:
    count, ttl = await redis.eval(_RATE_SCRIPT, 1, f"agent-activity-rate:{agent_id}", RATE_WINDOW_SECONDS)
    if int(count) <= RATE_LIMIT:
        return
    retry_after = int(ttl) if int(ttl) > 0 else RATE_WINDOW_SECONDS
    raise HTTPException(
        status_code=429,
        detail=f"rate_limited: at most {RATE_LIMIT} activity events per agent every {RATE_WINDOW_SECONDS} seconds",
        headers={"Retry-After": str(retry_after)},
    )


async def _require_participant(db, identity: TeamIdentity, session_id: str) -> None:
    actor_dids = [did for did in (identity.did_aw, identity.did_key) if did]
    if not await resolve_session_actor_did(db, session_id=UUID(session_id), actor_dids=actor_dids):
        raise HTTPException(status_code=404, detail=RESOURCE_NOT_FOUND_DETAIL)


@router.post("/me/activity", status_code=202, response_class=Response)
async def publish_agent_activity(
    payload: PublishActivityRequest,
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("chat.send")),
    _: None = Depends(_require_small_body),
    db=Depends(get_db),
    redis=Depends(get_redis),
) -> Response:
    """Relay one signed activity event to the chat streams that may show it.

    The event must verify against the key that signed this request: the
    agent's own key, or the grant session key for a grant caller, attributed to
    the grant's subject.
    """
    signer_did = identity.grant.session_did_key if identity.grant is not None else identity.did_key
    now = datetime.now(timezone.utc)
    try:
        event = verify_activity_event(
            payload.signed_payload,
            payload.signature,
            signer_did=signer_did,
            team_id=identity.team_id,
            stable_id=identity.did_aw or None,
            now=now,
        )
    except ActivityEventError as exc:
        logger.info("Refused activity from %s (%s): %s", identity.alias, signer_did, exc)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if redis is None:
        raise _unavailable()

    try:
        await _enforce_rate(redis, identity.agent_id)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Activity rate limit failed for %s", identity.agent_id)
        raise _unavailable() from exc
    if event["session_id"] is not None:
        await _require_participant(db, identity, event["session_id"])

    expires_at = datetime.strptime(event["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    latest_ms = max(1, min(MAX_LATEST_MS, int((expires_at - now).total_seconds() * 1000)))
    relayed = json.dumps(
        {
            "agent_id": identity.agent_id,
            "alias": identity.alias,
            "signed_payload": payload.signed_payload,
            "signature": payload.signature,
            "event": event,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )
    try:
        await redis.eval(
            _RELAY_SCRIPT,
            2,
            f"agent-activity-rev:{identity.agent_id}",
            activity_state_key(identity.agent_id),
            REVISION_TTL_SECONDS,
            relayed,
            latest_ms,
            activity_channel_name(identity.agent_id),
        )
    except Exception as exc:
        logger.exception("Activity relay failed for %s", identity.agent_id)
        raise _unavailable() from exc
    return Response(status_code=202)
