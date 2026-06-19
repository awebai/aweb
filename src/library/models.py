from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TeamRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    owner: str | None = Field(default=None, max_length=240)
    display_name: str | None = Field(default=None, max_length=240)


class ProfileBindingRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    profile_ref: str = Field(..., min_length=1, max_length=240)
    profile_version: str = Field(..., min_length=1, max_length=80)
    profile_digest: str = Field(..., min_length=1, max_length=128)
    source_profile_pack_ref: str | None = Field(default=None, max_length=240)


class MaterializeRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent_id: str | None = Field(default=None, max_length=240)
    profile_ref: str | None = Field(default=None, max_length=240)
    profile_version: str | None = Field(default=None, max_length=80)
    runtime_kind: str = Field(..., min_length=1, max_length=80)
    target: str = Field(..., pattern=r"^(local|custodial-mcp)$")


class SetTagsRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tags: list[str] = Field(default_factory=list)


class ImportToShelfRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    source_profile_pack_ref: str = Field(..., min_length=1, max_length=240)
    source_profile_pack_version: str | None = Field(default=None, max_length=80)
    profile_ref: str = Field(..., min_length=1, max_length=240)
    tags: list[str] = Field(default_factory=list)


class ProposalCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target: str = Field(..., pattern=r"^(profile|memory|skill|workflow)$")
    profile_ref: str | None = Field(default=None, max_length=240)
    profile_version: str | None = Field(default=None, max_length=80)
    content: dict[str, Any] = Field(default_factory=dict)
