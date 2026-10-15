"""Agent status hosts: who may publish an agent's signed status (docs/agent-health.md)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from awid.did import validate_did
from awid.dns_auth import verify_signed_json_request
from awid.team_ids import parse_team_id
from aweb.deps import get_db
from aweb.team_auth_deps import TeamIdentity, get_team_identity

router = APIRouter(prefix="/v1/agents", tags=["agents"])


class SetStatusHostRequest(BaseModel):
    model_config = {"extra": "forbid"}

    host_did: str = Field(..., max_length=256)


class ControllerSetStatusHostRequest(BaseModel):
    model_config = {"extra": "forbid"}

    team_id: str = Field(..., min_length=1, max_length=256)
    host_did: str = Field(..., max_length=256)
    previous_host_did: str = Field(..., max_length=256)


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
        raise HTTPException(status_code=422, detail="host_did must be a did:key")
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
        raise HTTPException(status_code=422, detail="host_did is not an active member of this team")
    return host_did


async def _designate(db, *, agent_id, team_id: str, host_did: str, designated_by_did: str) -> None:
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
    await _designate(
        aweb_db,
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
    await _clear(aweb_db, agent_id=identity.agent_id)
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
        raise HTTPException(status_code=422, detail="Agent alias is required")
    team_id = payload.team_id.strip()
    try:
        parse_team_id(team_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    aweb_db = db.get_manager("aweb")
    team = await aweb_db.fetch_one(
        "SELECT team_did_key FROM {{tables.teams}} WHERE team_id = $1",
        team_id,
    )
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")

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
            detail="Team controller authorization is required to set a status host",
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
            raise HTTPException(status_code=404, detail="Agent not found")
        current = await tx.fetch_one(
            "SELECT host_did FROM {{tables.agent_status_hosts}} WHERE agent_id = $1",
            agent["agent_id"],
        )
        current_host_did = current["host_did"] if current else ""
        if current_host_did != payload.previous_host_did.strip():
            raise HTTPException(status_code=409, detail="Status host changed since previous_host_did")
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
