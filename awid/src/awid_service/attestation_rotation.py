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
from awid.team_server_record import TeamServerRecordError, verify_team_server_record
from awid.credential_policy import CredentialPolicyError, verify_credential_policy

DEFAULT_ROTATE_MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_FUTURE_ISSUED_AT = timedelta(minutes=5)


class SignedRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record: dict[str, Any]
    signature: str = Field(..., min_length=1, max_length=256)


class ResignedRecords(BaseModel):
    model_config = ConfigDict(extra="forbid")

    team_server: SignedRecord | None = None
    team_credential_policy: SignedRecord | None = None
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


async def _resigned_team_server(
    tx, *, team_uuid, team_id: str, new_team_did_key: str, entry: SignedRecord | None, now: datetime,
) -> tuple[bool, bool, bool, tuple[dict, str, str, datetime] | None]:
    """Check the re-signed aweb.team-server/1 record against the stored one.

    Returns (missing, extra, changed, update). The record must verify exactly as
    PUT .../server would accept it under the new key, and be newer than the
    stored record with the same server.
    """
    stored = await tx.fetch_one(
        "SELECT record_json, issued_at FROM {{tables.team_server_records}} WHERE team_uuid = $1 FOR UPDATE",
        team_uuid,
    )
    if entry is None:
        return stored is not None, False, False, None
    try:
        verified = verify_team_server_record(
            entry.record, entry.signature, team_id=team_id, current_team_did_key=new_team_did_key, now=now,
        )
    except TeamServerRecordError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": f"team_server: {exc}"}) from exc
    if stored is None:
        return False, True, False, None
    unchanged = _comparable(entry.record) == _comparable(json.loads(stored["record_json"]))
    if not unchanged or verified.issued_at <= stored["issued_at"]:
        return False, False, True, None
    return False, False, False, (entry.record, entry.signature, verified.server_url, verified.issued_at)


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
    server_missing, server_extra, server_changed, server_update = await _resigned_team_server(
        tx, team_uuid=team_uuid, team_id=team_id, new_team_did_key=new_team_did_key,
        entry=resigned.team_server, now=now,
    )
    missing: dict[str, Any] = {"team_server": server_missing}
    extra: dict[str, Any] = {"team_server": server_extra}
    changed: dict[str, Any] = {"team_server": server_changed}
    policy = await tx.fetch_one('SELECT record_json,issued_at FROM {{tables.team_credential_policies}} WHERE team_uuid=$1 FOR UPDATE', team_uuid)
    policy_entry = resigned.team_credential_policy
    missing['team_credential_policy'] = policy is not None and policy_entry is None
    extra['team_credential_policy'] = policy is None and policy_entry is not None
    changed['team_credential_policy'] = False
    if policy_entry is not None:
        try:
            verify_credential_policy(policy_entry.record, policy_entry.signature, team_id=team_id, team_did_key=new_team_did_key)
        except CredentialPolicyError as exc:
            raise HTTPException(status_code=422, detail={'code': 'policy_invalid', 'message': str(exc)}) from exc
        if policy is not None:
            changed['team_credential_policy'] = (
                _comparable(policy_entry.record) != _comparable(json.loads(policy['record_json']))
                or issued_at_of(policy_entry.record) <= policy['issued_at']
            )
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
    if policy_entry is not None:
        await tx.execute(
            'UPDATE {{tables.team_credential_policies}} SET record_json=$2,signature=$3,team_did_key=$4,issued_at=$5,updated_at=NOW() WHERE team_uuid=$1',
            team_uuid, canonical_json_bytes(policy_entry.record).decode(), policy_entry.signature, new_team_did_key, issued_at_of(policy_entry.record),
        )
    if server_update is not None:
        record, signature, server_url, issued_at = server_update
        await tx.execute(
            """
            UPDATE {{tables.team_server_records}}
            SET record_json = $2, signature = $3, team_did_key = $4, server_url = $5, issued_at = $6,
                updated_at = NOW()
            WHERE team_uuid = $1
            """,
            team_uuid, canonical_json_bytes(record).decode("utf-8"), signature, new_team_did_key,
            server_url, issued_at,
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
