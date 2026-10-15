"""Agent status hosts: who may publish an agent's signed status (docs/agent-health.md)."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from awid.did import validate_did
from awid.dns_auth import verify_signed_json_request
from awid.team_ids import parse_team_id
from aweb.agent_status import StatusDocumentError, verify_status_document
from aweb.deps import get_db, get_redis
from aweb.hooks import fire_mutation_hook
from aweb.team_auth_deps import TeamIdentity, get_team_identity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/agents", tags=["agents"])

PUBLISH_WINDOW_SECONDS = 5


class SetStatusHostRequest(BaseModel):
    model_config = {"extra": "forbid"}

    host_did: str = Field(..., max_length=256)


class ControllerSetStatusHostRequest(BaseModel):
    model_config = {"extra": "forbid"}

    team_id: str = Field(..., min_length=1, max_length=256)
    host_did: str = Field(..., max_length=256)
    previous_host_did: str = Field(..., max_length=256)


class PublishStatusRequest(BaseModel):
    model_config = {"extra": "forbid"}

    signed_payload: str = Field(..., max_length=16384)
    signature: str = Field(..., max_length=256)


class PublishStatusResponse(BaseModel):
    agent_id: str
    alias: str
    seq: int


class StatusHostResponse(BaseModel):
    agent_id: str
    team_id: str
    alias: str
    host_did: Optional[str] = None
    designated_at: Optional[str] = None
    designated_by_did: Optional[str] = None
    host_active: Optional[bool] = None


def _require_did_key(host_did: str) -> str:
    host_did = host_did.strip()
    if not host_did.startswith("did:key:z") or not validate_did(host_did):
        raise HTTPException(status_code=422, detail="host_not_did_key: host_did must be a did:key")
    return host_did


async def _host_is_active_member(db, *, team_id: str, host_did: str) -> bool:
    row = await db.fetch_one(
        """
        SELECT 1 FROM {{tables.agents}}
        WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL
        """,
        team_id,
        host_did,
    )
    return row is not None


async def _require_active_member_host(db, *, team_id: str, host_did: str) -> str:
    host_did = _require_did_key(host_did)
    if not await _host_is_active_member(db, team_id=team_id, host_did=host_did):
        raise HTTPException(status_code=422, detail="host_not_member: host_did is not an active member of this team")
    return host_did


async def _lock_agent(db, agent_id) -> None:
    """Serialize designation changes with status publishes for one agent."""
    await db.fetch_one(
        "SELECT agent_id FROM {{tables.agents}} WHERE agent_id = $1 FOR UPDATE",
        agent_id,
    )


async def _designate(db, *, agent_id, team_id: str, host_did: str, designated_by_did: str) -> None:
    # A new publisher starts fresh: the previous publisher's report and seq go.
    await db.execute(
        "DELETE FROM {{tables.agent_status}} WHERE agent_id = $1 AND publisher_did != $2",
        agent_id,
        host_did,
    )
    await db.execute(
        """
        INSERT INTO {{tables.agent_status_hosts}} (agent_id, team_id, host_did, designated_by_did)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (agent_id) DO UPDATE
        SET host_did = EXCLUDED.host_did,
            designated_at = NOW(),
            designated_by_did = EXCLUDED.designated_by_did
        """,
        agent_id,
        team_id,
        host_did,
        designated_by_did,
    )


async def _clear(db, *, agent_id) -> None:
    await db.execute(
        "DELETE FROM {{tables.agent_status_hosts}} WHERE agent_id = $1",
        agent_id,
    )
    await db.execute(
        "DELETE FROM {{tables.agent_status}} WHERE agent_id = $1",
        agent_id,
    )


async def _status_host_view(db, *, agent_id, team_id: str, alias: str) -> StatusHostResponse:
    row = await db.fetch_one(
        """
        SELECT host_did, designated_at, designated_by_did
        FROM {{tables.agent_status_hosts}}
        WHERE agent_id = $1
        """,
        agent_id,
    )
    if row is None:
        return StatusHostResponse(agent_id=str(agent_id), team_id=team_id, alias=alias)
    return StatusHostResponse(
        agent_id=str(agent_id),
        team_id=team_id,
        alias=alias,
        host_did=row["host_did"],
        designated_at=row["designated_at"].isoformat(),
        designated_by_did=row["designated_by_did"],
        host_active=await _host_is_active_member(db, team_id=team_id, host_did=row["host_did"]),
    )


@router.get("/me/status-host", response_model=StatusHostResponse)
async def get_my_status_host(
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> StatusHostResponse:
    """Return the calling agent's designated status host, if any."""
    aweb_db = db.get_manager("aweb")
    return await _status_host_view(
        aweb_db, agent_id=identity.agent_id, team_id=identity.team_id, alias=identity.alias,
    )


@router.put("/me/status-host", response_model=StatusHostResponse)
async def set_my_status_host(
    payload: SetStatusHostRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> StatusHostResponse:
    """Designate the team member whose signed status reports speak for the caller."""
    aweb_db = db.get_manager("aweb")
    host_did = await _require_active_member_host(aweb_db, team_id=identity.team_id, host_did=payload.host_did)
    async with aweb_db.transaction() as tx:
        await _lock_agent(tx, identity.agent_id)
        await _designate(
            tx,
            agent_id=identity.agent_id,
            team_id=identity.team_id,
            host_did=host_did,
            designated_by_did=identity.did_key,
        )
    return await _status_host_view(
        aweb_db, agent_id=identity.agent_id, team_id=identity.team_id, alias=identity.alias,
    )


@router.delete("/me/status-host", response_model=StatusHostResponse)
async def clear_my_status_host(
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> StatusHostResponse:
    """Clear the calling agent's status host; it may then publish its own status."""
    aweb_db = db.get_manager("aweb")
    async with aweb_db.transaction() as tx:
        await _lock_agent(tx, identity.agent_id)
        await _clear(tx, agent_id=identity.agent_id)
    return await _status_host_view(
        aweb_db, agent_id=identity.agent_id, team_id=identity.team_id, alias=identity.alias,
    )


@router.put("/{alias}/status-host", response_model=StatusHostResponse)
async def controller_set_status_host(
    request: Request,
    alias: str,
    payload: ControllerSetStatusHostRequest,
    db=Depends(get_db),
) -> StatusHostResponse:
    """Set or clear (empty host_did) an agent's status host under team-controller authority.

    previous_host_did must name the current host ("" for none), so a replayed
    controller request cannot undo a later designation.
    """
    alias = alias.strip()
    if not alias:
        raise HTTPException(status_code=422, detail="invalid_request: Agent alias is required")
    team_id = payload.team_id.strip()
    try:
        parse_team_id(team_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid_team_id: {exc}") from exc

    aweb_db = db.get_manager("aweb")
    team = await aweb_db.fetch_one(
        "SELECT team_did_key FROM {{tables.teams}} WHERE team_id = $1",
        team_id,
    )
    if team is None:
        raise HTTPException(status_code=404, detail="team_not_found: Team not found")

    authorizer_did = verify_signed_json_request(
        request,
        payload_dict={
            "operation": "set_agent_status_host",
            "team_id": team_id,
            "agent_alias": alias,
            "host_did": payload.host_did,
            "previous_host_did": payload.previous_host_did,
        },
    )
    if authorizer_did != str(team["team_did_key"]):
        raise HTTPException(
            status_code=403,
            detail="controller_required: Team controller authorization is required to set a status host",
        )

    host_did = payload.host_did.strip()
    if host_did:
        host_did = await _require_active_member_host(aweb_db, team_id=team_id, host_did=host_did)

    async with aweb_db.transaction() as tx:
        agent = await tx.fetch_one(
            """
            SELECT agent_id FROM {{tables.agents}}
            WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
            FOR UPDATE
            """,
            team_id,
            alias,
        )
        if agent is None:
            raise HTTPException(status_code=404, detail="agent_not_found: Agent not found")
        current = await tx.fetch_one(
            "SELECT host_did FROM {{tables.agent_status_hosts}} WHERE agent_id = $1",
            agent["agent_id"],
        )
        current_host_did = current["host_did"] if current else ""
        if current_host_did != payload.previous_host_did.strip():
            raise HTTPException(status_code=409, detail="status_host_changed: Status host changed since previous_host_did")
        if host_did:
            await _designate(
                tx,
                agent_id=agent["agent_id"],
                team_id=team_id,
                host_did=host_did,
                designated_by_did=authorizer_did,
            )
        else:
            await _clear(tx, agent_id=agent["agent_id"])

    return await _status_host_view(aweb_db, agent_id=agent["agent_id"], team_id=team_id, alias=alias)


def _may_publish(identity: TeamIdentity, *, agent_id, host_did: str | None) -> bool:
    if host_did is not None:
        return identity.did_key == host_did
    return str(identity.agent_id) == str(agent_id)


async def _current_host_did(db, agent_id) -> str | None:
    row = await db.fetch_one(
        "SELECT host_did FROM {{tables.agent_status_hosts}} WHERE agent_id = $1",
        agent_id,
    )
    return row["host_did"] if row else None


async def _enforce_publish_rate(redis, agent_id) -> None:
    key = f"agent-status-rate:{agent_id}"
    if await redis.set(key, "1", ex=PUBLISH_WINDOW_SECONDS, nx=True):
        return
    ttl = await redis.ttl(key)
    retry_after = ttl if isinstance(ttl, int) and ttl > 0 else PUBLISH_WINDOW_SECONDS
    raise HTTPException(
        status_code=429,
        detail=f"rate_limited: at most one status per agent every {PUBLISH_WINDOW_SECONDS} seconds",
        headers={"Retry-After": str(retry_after)},
    )


def _verdict(row: Any) -> tuple[Any, Any, Any] | None:
    if row is None:
        return None
    return (row["reachable"], row["reason_code"], row["fixing_by"])


@router.put("/{alias}/status", response_model=PublishStatusResponse)
async def publish_agent_status(
    request: Request,
    alias: str,
    payload: PublishStatusRequest,
    db=Depends(get_db),
    redis=Depends(get_redis),
    identity: TeamIdentity = Depends(get_team_identity),
) -> PublishStatusResponse:
    """Store the signed status document the agent's status host published.

    Only the designated host may publish, or the agent itself when no host is
    designated. The document must verify (docs/agent-health.md),
    name this agent and the authenticated team, and carry a greater seq.
    """
    alias = alias.strip()
    aweb_db = db.get_manager("aweb")
    agent = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias, did_key, did_aw FROM {{tables.agents}}
        WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        identity.team_id,
        alias,
    )
    if agent is None:
        raise HTTPException(status_code=404, detail="agent_not_found: Agent not found")
    agent_id = agent["agent_id"]
    not_host = HTTPException(status_code=403, detail=f"not_status_host: not the status host for {alias}")
    if not _may_publish(identity, agent_id=agent_id, host_did=await _current_host_did(aweb_db, agent_id)):
        raise not_host
    if redis is None:
        raise HTTPException(status_code=503, detail="publishing_unavailable: Status publishing is unavailable")
    await _enforce_publish_rate(redis, agent_id)

    try:
        document = verify_status_document(
            payload.signed_payload,
            payload.signature,
            signer_did=identity.did_key,
            now=datetime.now(timezone.utc),
        )
    except StatusDocumentError as exc:
        logger.info("Refused status for %s from %s: %s", alias, identity.did_key, exc)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if document["team_id"] != identity.team_id:
        raise HTTPException(status_code=422, detail="team_mismatch: team_id is not the authenticated team")
    expected_agent = str(agent["did_aw"] or "").strip() or agent["did_key"]
    if document["agent"] != expected_agent:
        raise HTTPException(status_code=422, detail=f"agent_mismatch: agent does not name {alias}")

    reason = document.get("reason") or {}
    fixing = document.get("fixing") or {}
    async with aweb_db.transaction() as tx:
        await _lock_agent(tx, agent_id)
        if not _may_publish(identity, agent_id=agent_id, host_did=await _current_host_did(tx, agent_id)):
            raise not_host
        previous = await tx.fetch_one(
            "SELECT seq, reachable, reason_code, fixing_by FROM {{tables.agent_status}} WHERE agent_id = $1",
            agent_id,
        )
        if previous is not None and document["seq"] <= previous["seq"]:
            raise HTTPException(status_code=409, detail="stale_seq: seq is not greater than the stored seq")
        stored = await tx.fetch_one(
            """
            INSERT INTO {{tables.agent_status}} (
                agent_id, team_id, publisher_did, seq, reachable, reason_code, fixing_by,
                observed_at, valid_until, signed_payload, signature
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (agent_id) DO UPDATE
            SET team_id = EXCLUDED.team_id,
                publisher_did = EXCLUDED.publisher_did,
                seq = EXCLUDED.seq,
                reachable = EXCLUDED.reachable,
                reason_code = EXCLUDED.reason_code,
                fixing_by = EXCLUDED.fixing_by,
                observed_at = EXCLUDED.observed_at,
                valid_until = EXCLUDED.valid_until,
                signed_payload = EXCLUDED.signed_payload,
                signature = EXCLUDED.signature,
                received_at = NOW()
            WHERE {{tables.agent_status}}.seq < EXCLUDED.seq
            RETURNING reachable, reason_code, fixing_by
            """,
            agent_id,
            identity.team_id,
            identity.did_key,
            document["seq"],
            document["reachable"],
            reason.get("code"),
            fixing.get("by"),
            datetime.fromisoformat(document["observed_at"].replace("Z", "+00:00")),
            datetime.fromisoformat(document["valid_until"].replace("Z", "+00:00")),
            payload.signed_payload,
            payload.signature,
        )
        if stored is None:
            raise HTTPException(status_code=409, detail="stale_seq: seq is not greater than the stored seq")

    if _verdict(stored) != _verdict(previous):
        await fire_mutation_hook(
            request,
            "agent.status",
            {
                "team_id": identity.team_id,
                "agent_id": str(agent_id),
                "alias": alias,
                "publisher_did": identity.did_key,
                "reachable": document["reachable"],
                "reason_code": reason.get("code"),
                "reason_text": reason.get("text"),
                "fixing_by": fixing.get("by"),
                "fixing_text": fixing.get("text"),
                "observed_at": document["observed_at"],
                "valid_until": document["valid_until"],
            },
        )
    return PublishStatusResponse(agent_id=str(agent_id), alias=alias, seq=document["seq"])
