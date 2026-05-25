"""Service registration for externally controlled AWID teams."""

from __future__ import annotations

import os
from importlib import metadata
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pgdbm import AsyncDatabaseManager
from pydantic import BaseModel, Field

from awid.dns_auth import enforce_timestamp_skew
from awid.log import canonical_server_origin
from awid.signing import canonical_json_bytes, verify_did_key_signature
from awid.team_ids import parse_team_id
from aweb.config import get_settings
from aweb.deps import get_db

router = APIRouter(prefix="/api/v1", tags=["service-registration"])


class TeamServiceRegisterRequest(BaseModel):
    awid_team_id: str = Field(..., min_length=1)
    service_url: str = Field(..., min_length=1)
    dry_run: bool = False
    timestamp: str = Field(..., min_length=1)
    controller_signature: str = Field(..., min_length=1)


class TeamServiceRegisterNextStep(BaseModel):
    label: str
    command: str
    description: str = ""
    required: bool = False


class TeamServiceRegisterResponse(BaseModel):
    dry_run: bool
    status: str
    awid_team_id: str
    team_id: Optional[str] = None
    team_slug: Optional[str] = None
    owner_slug: Optional[str] = None
    team_did_key: str
    dashboard_url: Optional[str] = None
    next_steps: list[TeamServiceRegisterNextStep] = Field(default_factory=list)
    audit_id: Optional[str] = None


def _safe_package_version(package_name: str) -> str:
    try:
        return metadata.version(package_name)
    except Exception:
        return ""


def _public_service_url() -> str:
    if discovery_origin := (os.getenv("AWEB_DISCOVERY_ORIGIN") or "").strip():
        return canonical_server_origin(discovery_origin).rstrip("/")
    return get_settings().public_origin.rstrip("/")


def _team_service_register_signature_payload(body: TeamServiceRegisterRequest) -> bytes:
    return canonical_json_bytes(
        {
            "operation": "team_service_register",
            "awid_team_id": body.awid_team_id.strip(),
            "service_url": body.service_url.strip().rstrip("/"),
            "dry_run": bool(body.dry_run),
            "timestamp": body.timestamp.strip(),
        }
    )


def _team_service_register_next_steps(
    *,
    canonical_team_id: str,
    service_url: str,
) -> list[TeamServiceRegisterNextStep]:
    return [
        TeamServiceRegisterNextStep(
            label="Initialize each agent workspace",
            command=f"aw service init --service {service_url} --team {canonical_team_id}",
            description=(
                "Run from every agent worktree that already has this team's signing key "
                "and team certificate installed."
            ),
            required=True,
        ),
        TeamServiceRegisterNextStep(
            label="Claim the service account",
            command="aw claim-human --email you@example.com",
            description=(
                "Optional: attach a human email/login for billing and dashboard ownership. "
                "This uses the service's human-claim flow, not AWID team-controller authority."
            ),
            required=False,
        ),
    ]


@router.get("/discovery")
async def discovery() -> dict[str, object]:
    """Public service discovery for CLI onboarding and team registration."""
    settings = get_settings()
    service_url = _public_service_url()
    registry_url = (os.getenv("AWID_PUBLIC_REGISTRY_URL") or settings.awid_registry_url).strip()
    return {
        "onboarding_url": service_url,
        "aweb_url": service_url,
        "registry_url": registry_url,
        "team_registration_url": f"{service_url}/api/v1/teams/service-register",
        "version": _safe_package_version("aweb"),
        "features": ["teams", "service-register"],
    }


async def _ensure_service_registered_team(
    *,
    db: AsyncDatabaseManager,
    canonical_team_id: str,
    team_did_key: str,
    dry_run: bool,
) -> bool:
    namespace, team_name = parse_team_id(canonical_team_id)
    existing = await db.fetch_one(
        """
        SELECT team_id, team_did_key
        FROM {{tables.teams}}
        WHERE team_id = $1
        """,
        canonical_team_id,
    )
    if existing is not None:
        stored_key = str(existing.get("team_did_key") or "").strip()
        if stored_key and stored_key != team_did_key:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "awid_team_controller_mismatch",
                    "message": "Existing service projection is bound to a different AWID team controller.",
                },
            )
        if not dry_run and not stored_key:
            await db.execute(
                """
                UPDATE {{tables.teams}}
                SET team_did_key = $2
                WHERE team_id = $1
                """,
                canonical_team_id,
                team_did_key,
            )
        return False

    if dry_run:
        return True

    await db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        canonical_team_id,
        namespace,
        team_name,
        team_did_key,
    )
    return True


@router.post("/teams/service-register", response_model=TeamServiceRegisterResponse)
async def register_team_with_service(
    body: TeamServiceRegisterRequest,
    request: Request,
    db=Depends(get_db),
) -> TeamServiceRegisterResponse:
    canonical_team_id = body.awid_team_id.strip()
    try:
        domain, team_name = parse_team_id(canonical_team_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": "awid_team_id must be formatted as <team>:<domain>."},
        ) from exc

    service_url = body.service_url.strip().rstrip("/")
    expected_service_url = _public_service_url()
    if service_url != expected_service_url:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "service_url_mismatch",
                "message": f"Signed service_url must match this service ({expected_service_url}).",
            },
        )

    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is None:
        raise HTTPException(status_code=503, detail="AWID registry client is not configured")

    registry_team = await registry_client.get_team(domain, team_name)
    if registry_team is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "awid_team_not_found", "message": "AWID team was not found."},
        )
    team_controller_did = str(registry_team.team_did_key or "").strip()
    if not team_controller_did:
        raise HTTPException(
            status_code=409,
            detail={"code": "awid_team_missing_controller", "message": "AWID team is missing team_did_key."},
        )

    try:
        enforce_timestamp_skew(body.timestamp)
    except HTTPException as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_controller_timestamp",
                "message": "Signed registration request expired. Regenerate it and try again.",
            },
        ) from exc
    try:
        verify_did_key_signature(
            did_key=team_controller_did,
            payload=_team_service_register_signature_payload(body),
            signature_b64=body.controller_signature,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_controller_signature", "message": "Team controller signature did not verify."},
        ) from exc

    aweb_db = db.get_manager("aweb")
    team_created = await _ensure_service_registered_team(
        db=aweb_db,
        canonical_team_id=canonical_team_id,
        team_did_key=team_controller_did,
        dry_run=body.dry_run,
    )
    return TeamServiceRegisterResponse(
        dry_run=body.dry_run,
        status="dry-run" if body.dry_run else ("created" if team_created else "synced"),
        awid_team_id=canonical_team_id,
        team_id=canonical_team_id if not body.dry_run else None,
        team_slug=team_name,
        owner_slug=None,
        team_did_key=team_controller_did,
        dashboard_url=None,
        next_steps=_team_service_register_next_steps(
            canonical_team_id=canonical_team_id,
            service_url=expected_service_url,
        ),
        audit_id=None,
    )
