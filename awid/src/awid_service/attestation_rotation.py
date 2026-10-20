"""Atomic re-signing of team-key-signed records during a team-key rotation.

docs/principal-attestation.md §5: the rotate request may carry every stored
record re-signed with the new team key. The set must be complete and each
record unchanged apart from ``team_did_key`` and a newer ``issued_at``; the
records are replaced in the rotation's own transaction.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from awid.attestation_records import MEMBER_CUSTODY, MEMBER_PERSON, TEAM_CUSTODIAN, RecordError, verify_record
from awid.signing import canonical_json_bytes

DEFAULT_ROTATE_MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_FUTURE_ISSUED_AT = timedelta(minutes=5)


class SignedRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record: dict[str, Any]
    signature: str = Field(..., min_length=1, max_length=256)


class ResignedRecords(BaseModel):
    model_config = ConfigDict(extra="forbid")

    team_custodians: list[SignedRecord] = Field(default_factory=list)
    member_custody: list[SignedRecord] = Field(default_factory=list)
    member_person: list[SignedRecord] = Field(default_factory=list)


# kind -> (record type, table, key field)
_KINDS: dict[str, tuple[str, str, str]] = {
    "team_custodians": (TEAM_CUSTODIAN, "team_custodians", "custodian_id"),
    "member_custody": (MEMBER_CUSTODY, "member_custody", "certificate_id"),
    "member_person": (MEMBER_PERSON, "member_person", "certificate_id"),
}


def rotate_max_body_bytes_from_env() -> int:
    """The deploy-configured rotate body limit; never below the documented default."""
    raw = (os.getenv("AWID_ROTATE_MAX_BODY_BYTES") or "").strip()
    value = int(raw) if raw else DEFAULT_ROTATE_MAX_BODY_BYTES
    if value < DEFAULT_ROTATE_MAX_BODY_BYTES:
        raise ValueError(
            f"AWID_ROTATE_MAX_BODY_BYTES must be at least {DEFAULT_ROTATE_MAX_BODY_BYTES}, got {value}"
        )
    return value


def issued_at_of(record: dict[str, Any]) -> datetime:
    return datetime.strptime(record["issued_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _comparable(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in ("team_did_key", "issued_at")}


def _verified(kind: str, entry: SignedRecord, *, team_id: str, new_team_did_key: str, now: datetime) -> dict:
    record_type = _KINDS[kind][0]
    record = entry.record
    if record.get("type") != record_type:
        raise HTTPException(status_code=422, detail={"code": "record_invalid", "message": f"{kind} holds another record type"})
    try:
        verify_record(record, entry.signature, team_did_key=new_team_did_key)
    except RecordError as exc:
        raise HTTPException(status_code=422, detail={"code": "record_invalid", "message": f"{kind}: {exc}"}) from exc
    if record["team_id"] != team_id:
        raise HTTPException(status_code=422, detail={"code": "record_invalid", "message": f"{kind}: record is for another team"})
    if issued_at_of(record) > now + MAX_FUTURE_ISSUED_AT:
        raise HTTPException(status_code=422, detail={"code": "issued_at_in_future", "message": f"{kind}: issued_at is ahead"})
    return record


async def apply_resigned_records(
    tx, *, team_uuid, team_id: str, new_team_did_key: str, resigned: ResignedRecords | None,
) -> None:
    """Replace every stored record with its re-signed form, or refuse with nothing changed.

    Without ``resigned`` this is the non-atomic path: the stored records keep the
    old key and verifiers refuse them as stale until they are re-published.
    """
    if resigned is None:
        return
    now = datetime.now(timezone.utc)
    missing: dict[str, list[str]] = {}
    extra: dict[str, list[str]] = {}
    changed: dict[str, list[str]] = {}
    updates: list[tuple[str, str, dict, str]] = []
    for kind, (_, table, key_field) in _KINDS.items():
        rows = await tx.fetch_all(
            f"""
            SELECT {key_field} AS record_key, record_json, issued_at
            FROM {{{{tables.{table}}}}}
            WHERE team_uuid = $1
            FOR UPDATE
            """,
            team_uuid,
        )
        stored = {row["record_key"]: row for row in rows}
        given: dict[str, tuple[dict, str]] = {}
        kind_extra: set[str] = set()
        for entry in getattr(resigned, kind):
            record = _verified(kind, entry, team_id=team_id, new_team_did_key=new_team_did_key, now=now)
            key = record[key_field]
            if key in given or key not in stored:
                kind_extra.add(key)
            given[key] = (record, entry.signature)
        kind_missing = sorted(set(stored) - set(given))
        kind_changed = sorted(
            key for key, (record, _) in given.items()
            if key in stored and key not in kind_extra and (
                _comparable(record) != _comparable(json.loads(stored[key]["record_json"]))
                or issued_at_of(record) <= stored[key]["issued_at"]
            )
        )
        missing[kind], extra[kind], changed[kind] = kind_missing, sorted(kind_extra), kind_changed
        updates.extend((table, key_field, record, signature) for record, signature in given.values())
    if any(missing.values()) or any(extra.values()) or any(changed.values()):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "resigned_records_incomplete",
                "message": "resigned_records must re-sign exactly every stored record",
                "missing": missing, "extra": extra, "changed": changed,
            },
        )
    for table, key_field, record, signature in updates:
        await tx.execute(
            f"""
            UPDATE {{{{tables.{table}}}}}
            SET record_json = $3, signature = $4, team_did_key = $5, issued_at = $6, updated_at = NOW()
            WHERE team_uuid = $1 AND {key_field} = $2
            """,
            team_uuid, record[key_field], canonical_json_bytes(record).decode("utf-8"), signature,
            new_team_did_key, issued_at_of(record),
        )
