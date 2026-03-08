from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aweb.auth import validate_agent_alias, validate_namespace_slug, validate_project_slug
from aweb.bootstrap import AliasExhaustedError, bootstrap_identity
from aweb.deps import get_db
from aweb.hooks import fire_mutation_hook

router = APIRouter(prefix="/v1/init", tags=["aweb-init"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    namespace_slug: Optional[str] = Field(default=None, min_length=1, max_length=64)
    project_slug: Optional[str] = Field(default=None, min_length=1, max_length=256)
    project_name: str = Field(default="", max_length=256)
    alias: Optional[str] = Field(default=None, max_length=64)
    human_name: str = Field(default="", max_length=64)
    agent_type: str = Field(default="agent", max_length=32)
    did: Optional[str] = Field(default=None, max_length=256)
    public_key: Optional[str] = Field(
        default=None, max_length=64
    )  # base64url, 43 chars for 32 bytes
    custody: Optional[Literal["self", "custodial"]] = None
    lifetime: Literal["persistent", "ephemeral"] = "persistent"
    role: Optional[str] = Field(default=None, max_length=64)
    program: Optional[str] = Field(default=None, max_length=64)
    context: Optional[dict] = None

    @model_validator(mode="after")
    def _require_at_least_one_slug(self) -> "InitRequest":
        if not self.namespace_slug and not self.project_slug:
            raise ValueError("At least one of namespace_slug or project_slug is required")
        return self

    @field_validator("namespace_slug")
    @classmethod
    def _validate_namespace_slug(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return validate_namespace_slug(v.strip())

    @field_validator("project_slug")
    @classmethod
    def _validate_project_slug(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return validate_project_slug(v.strip())

    @field_validator("alias")
    @classmethod
    def _validate_alias(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        return validate_agent_alias(v)

    @field_validator("agent_type")
    @classmethod
    def _validate_agent_type(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return "agent"
        return v


class InitResponse(BaseModel):
    status: str = "ok"
    created_at: str
    project_id: str
    project_slug: str
    namespace_slug: str
    agent_id: str
    alias: str
    api_key: str
    created: bool
    did: Optional[str] = None
    stable_id: Optional[str] = None
    custody: Optional[str] = None
    lifetime: str = "persistent"


@router.post("", response_model=InitResponse)
async def init(request: Request, payload: InitRequest, db=Depends(get_db)) -> InitResponse:
    """Bootstrap an aweb project, agent, and API key.

    This is an OSS convenience endpoint intended for clean-start deployments.
    Wrapper deployments typically own project creation and API key issuance.
    """
    # If project_slug is not provided, default to namespace_slug.
    project_slug = payload.project_slug or payload.namespace_slug
    # model_validator guarantees at least one is set
    assert project_slug is not None

    try:
        result = await bootstrap_identity(
            db,
            namespace_slug=payload.namespace_slug,
            project_slug=project_slug,
            project_name=payload.project_name or "",
            alias=payload.alias,
            human_name=payload.human_name or "",
            agent_type=payload.agent_type,
            did=payload.did,
            public_key=payload.public_key,
            custody=payload.custody,
            lifetime=payload.lifetime,
            role=payload.role,
            program=payload.program,
            context=payload.context,
        )
    except AliasExhaustedError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    if result.created:
        await fire_mutation_hook(
            request,
            "agent.created",
            {
                "agent_id": result.agent_id,
                "project_id": result.project_id,
                "alias": result.alias,
                "did": result.did or "",
                "custody": result.custody or "",
                "lifetime": result.lifetime,
            },
        )

    return InitResponse(
        created_at=_now_iso(),
        project_id=result.project_id,
        project_slug=result.project_slug,
        namespace_slug=result.namespace_slug,
        agent_id=result.agent_id,
        alias=result.alias,
        api_key=result.api_key,
        created=result.created,
        did=result.did,
        stable_id=result.stable_id,
        custody=result.custody,
        lifetime=result.lifetime,
    )
