"""Strict JSON and typed bodies for the C2 task contract."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError as ModelError
from aweb_naapp.runtime.task_requests import TaskRequestRefused, parse_json, validate_task

from aweb.service_errors import ValidationError

SafeRevision = Annotated[int, Field(strict=True, ge=0, le=2**53 - 1)]
PositiveRevision = Annotated[int, Field(strict=True, ge=1, le=2**53 - 1)]
OpaqueRef = Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9._-]{1,128}$")]
HexDigest = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]
ProposalDigest = Annotated[str, Field(strict=True, pattern=r"^sha256:[0-9a-f]{64}$")]


def strict_json_bytes(raw: bytes):
    try:
        value = parse_json(raw)
        def unicode_scalars(item):
            if type(item) is int and abs(item) > 2**53 - 1:
                raise ValueError("unsafe integer")
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
    stage_receipt: dict[str, Any] | None = None


def validate_app_task(value):
    try:
        validate_task(value)
    except (TaskRequestRefused, TypeError, UnicodeError) as exc:
        raise ValidationError("schema_invalid") from exc
    return value


def parse_contract(model, value):
    try:
        return model.model_validate(value)
    except ModelError as exc:
        raise ValidationError("schema_invalid") from exc
