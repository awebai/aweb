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


class UpdateFromSourceRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target_version: str = Field(..., min_length=1, max_length=80)
    source_profile_pack_version: str | None = Field(default=None, max_length=80)


class NewPackTarget(BaseModel):
    model_config = ConfigDict(extra="ignore")

    pack_ref: str = Field(..., min_length=1, max_length=240)
    name: str = Field(..., min_length=1, max_length=240)
    summary: str | None = Field(default=None, max_length=2000)
    description: str | None = Field(default=None)
    tags: list[str] = Field(default_factory=list)
    readme: str | None = Field(default=None)
    missions: list[str] = Field(default_factory=list)


class ProfilePublishRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    profile_version: str | None = Field(default=None, max_length=80)
    pack_version: str = Field(..., min_length=1, max_length=80)
    target_pack_ref: str | None = Field(default=None, max_length=240)
    new_pack: NewPackTarget | None = Field(default=None)


class ProposalCreateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target: str = Field(..., pattern=r"^(profile|memory|skill|workflow)$")
    profile_ref: str | None = Field(default=None, max_length=240)
    profile_version: str | None = Field(default=None, max_length=80)
    base_profile_version: str | None = Field(default=None, max_length=80)
    base_profile_digest: str | None = Field(default=None, max_length=128)
    content: dict[str, Any] = Field(default_factory=dict)
    summary: str | None = Field(default=None, max_length=2000)
    rationale: str | None = Field(default=None)
