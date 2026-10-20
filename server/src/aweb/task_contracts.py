"""Strict JSON and typed bodies for the C2 task contract."""

from __future__ import annotations

import json
from typing import Annotated, Literal
from datetime import datetime
import unicodedata

from pydantic import BaseModel, ConfigDict, Field, ValidationError as ModelError
from pydantic import field_validator, model_validator
from awid.log import canonical_server_origin

from aweb.service_errors import ValidationError

SafeRevision = Annotated[int, Field(strict=True, ge=0, le=2**53 - 1)]
PositiveRevision = Annotated[int, Field(strict=True, ge=1, le=2**53 - 1)]
OpaqueRef = Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9._-]{1,128}$")]
HexDigest = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]
ProposalDigest = Annotated[str, Field(strict=True, pattern=r"^sha256:[0-9a-f]{64}$")]


def strict_json_bytes(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def integer(value):
        parsed = int(value)
        if abs(parsed) > 2**53 - 1:
            raise ValueError("unsafe integer")
        return parsed

    def reject(_):
        raise ValueError("noninteger number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_int=integer,
                           parse_float=reject, parse_constant=reject)
        def unicode_scalars(item):
            if isinstance(item, str):
                item.encode("utf-8")
            elif isinstance(item, dict):
                for key, child in item.items():
                    unicode_scalars(key)
                    unicode_scalars(child)
            elif isinstance(item, list):
                for child in item:
                    unicode_scalars(child)
        unicode_scalars(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValidationError("schema_invalid") from exc


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AnswerRequest(ContractModel):
    expected_task_rev: PositiveRevision
    answer_key: OpaqueRef
    answer_sha256: HexDigest
    choice: str | None = None
    proposal_rev: SafeRevision | None = None
    proposal_sha256: ProposalDigest | None = None
    body_md: str = Field(min_length=1, max_length=20000)


class AppRequestMetadata(ContractModel):
    external_request_id: OpaqueRef
    resource_ref: OpaqueRef
    action_ref: OpaqueRef
    proposal_rev: SafeRevision | None
    proposal_sha256: ProposalDigest | None
    choices: list[Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]] | None

    @model_validator(mode="after")
    def check_metadata(self):
        if (self.proposal_rev is None) != (self.proposal_sha256 is None):
            raise ValueError("proposal pair")
        if self.choices is not None and (not 1 <= len(self.choices) <= 10 or len(set(self.choices)) != len(self.choices)):
            raise ValueError("choices")
        return self


class AppTask(ContractModel):
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(min_length=1, max_length=2000)
    assignee_did: str = Field(pattern=r"^did:(aw|key):\S+$")
    app_request: AppRequestMetadata

    @field_validator("title", "description")
    @classmethod
    def safe_text(cls, value):
        if value is not None and any(unicodedata.category(c) in {"Cc", "Cs"}
                or c in {"\u061c", "\u200e", "\u200f"}
                or unicodedata.bidirectional(c) in {"LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI"} for c in value):
            raise ValueError("unsafe text")
        return value


class TaskAuthorizationPayload(ContractModel):
    v: Literal[1]
    type: Literal["aweb.app-task-authorization"]
    aud: str
    app_origin: str
    team_id: str
    app_id: str
    installation_id: str = Field(min_length=1, max_length=256)
    installation_generation: PositiveRevision
    external_request_id: OpaqueRef
    actor_did_key: str = Field(pattern=r"^did:key:\S+$")
    certificate_id: str = Field(min_length=1, max_length=256)
    target_did: str = Field(pattern=r"^did:(aw|key):\S+$")
    task_body_sha256: HexDigest
    action_id: OpaqueRef
    proposal_rev: SafeRevision | None
    proposal_sha256: ProposalDigest | None
    issued_at: str = Field(pattern=r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
    expires_at: str = Field(pattern=r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")

    @field_validator("v", mode="before")
    @classmethod
    def integer_version(cls, value):
        if type(value) is not int:
            raise ValueError("version")
        return value

    @field_validator("aud", "app_origin")
    @classmethod
    def canonical_origin(cls, value):
        if canonical_server_origin(value) != value:
            raise ValueError("noncanonical origin")
        return value

    @model_validator(mode="after")
    def validity(self):
        seconds = (datetime.fromisoformat(self.expires_at) - datetime.fromisoformat(self.issued_at)).total_seconds()
        if not 0 < seconds <= 86400 or ((self.proposal_rev is None) != (self.proposal_sha256 is None)):
            raise ValueError("validity")
        return self


class TaskAuthorization(ContractModel):
    payload: TaskAuthorizationPayload
    signature: str
    certificate: str


class AppTaskRequest(ContractModel):
    task: AppTask
    task_authorization: TaskAuthorization


def parse_contract(model, value):
    try:
        return model.model_validate(value)
    except ModelError as exc:
        raise ValidationError("schema_invalid") from exc
