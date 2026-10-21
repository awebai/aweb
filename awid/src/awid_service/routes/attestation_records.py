"""Team-key-signed records for principal attestation and the member person declaration.

Contracts: docs/principal-attestation.md (team custodian, member custody) and
docs/member-person.md. Writes need team-controller authority in the covering
(v2) controller envelope; reads by exact key are anonymous and return the stored
bytes. The paginated read of all of a team's signed records takes the team key.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response

from awid.attestation_records import (
    MEMBER_CUSTODY,
    MEMBER_PERSON,
    TEAM_CUSTODIAN,
    RecordError,
    verify_record,
)
from awid.controller_request import ControllerAuthRoute
from awid.pagination import encode_cursor, validate_pagination_params
from awid.ratelimit import enforce_rate_limit, rate_limit_dep
from awid.signing import canonical_json_bytes
from awid.team_ids import build_team_id
from awid_service.attestation_rotation import MAX_FUTURE_ISSUED_AT, SignedRecord, issued_at_of
from awid_service.deps import get_db
from awid_service.routes.teams import (
    _presents_trusted_service_token,
    _require_team_controller,
    _verify_path_signature,
)

router = APIRouter(prefix="/v1/namespaces/{domain}/teams", tags=["attestation-records"], route_class=ControllerAuthRoute)

_NOT_FOUND = "Record not found"


def _refuse(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def _require_covering_envelope(request: Request) -> None:
    # These operations have no released clients, so the legacy controller form
    # is never accepted for them.
    if request.headers.get("X-AWEB-Signed-Payload") is None:
        raise HTTPException(status_code=401, detail="Covering AWID controller envelope required")


def verify_published_record(
    body: SignedRecord, *, record_type: str, team_id: str, team_did_key: str, now: datetime,
) -> bytes:
    """Validate and verify a record for publication; returns its canonical bytes."""
    record = body.record
    if record.get("type") != record_type:
        raise _refuse(422, "record_invalid", "Wrong record type")
    try:
        verify_record(record, body.signature, team_did_key=team_did_key)
    except RecordError as exc:
        raise _refuse(422, "record_invalid", str(exc)) from exc
    if record["team_id"] != team_id:
        raise _refuse(422, "record_invalid", "Record is for another team")
    if issued_at_of(record) > now + MAX_FUTURE_ISSUED_AT:
        raise _refuse(422, "issued_at_in_future", "issued_at is more than five minutes ahead")
    return canonical_json_bytes(record)


async def _charge_team_publish(request: Request, response: Response, team) -> None:
    """Count an authenticated publish against the team's own allowance.

    Charged only after the controller signature verified, so unauthenticated
    traffic cannot exhaust a team's allowance; the per-IP bucket bounds that.
    The trusted service token (a custodial deployment's backfill) is exempt.
    """
    if _presents_trusted_service_token(request):
        return
    await enforce_rate_limit(
        request, response, bucket="attestation_record_publish_team", key=str(team["team_uuid"]),
    )


async def _lock_team_key(tx, team) -> None:
    """Hold the team row for the publish, serialising it with a key rotation.

    rotate_team_key takes the row FOR UPDATE, so a publish verified against a
    key that a rotation has since replaced is refused instead of writing an
    old-key record after the atomic swap.
    """
    locked = await tx.fetch_one(
        "SELECT team_did_key FROM {{tables.teams}} WHERE team_uuid = $1 FOR SHARE", team["team_uuid"],
    )
    if locked is None or locked["team_did_key"] != team["team_did_key"]:
        raise _refuse(409, "team_key_changed", "The team key changed during the publish; re-sign and retry")


def _same_publication(row, canonical: bytes, signature: str) -> bool:
    return row["record_json"] == canonical.decode("utf-8") and row["signature"] == signature


def _stored(row) -> dict[str, Any]:
    return {"record": json.loads(row["record_json"]), "signature": row["signature"]}


async def _active_certificate(tx, team_uuid, certificate_id: str):
    return await tx.fetch_one(
        """
        SELECT member_did_key
        FROM {{tables.team_certificates}}
        WHERE team_uuid = $1 AND certificate_id = $2 AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > NOW())
        """,
        team_uuid, certificate_id,
    )


@router.put(
    "/{name}/custodians/{custodian_id}",
    dependencies=[Depends(rate_limit_dep("attestation_record_publish", allow_trusted_service=True))],
)
async def publish_team_custodian(
    request: Request, response: Response, domain: str, name: str, custodian_id: str, body: SignedRecord,
    db_infra=Depends(get_db),
) -> dict:
    _require_covering_envelope(request)
    db = db_infra.get_manager("aweb")
    _, team = await _require_team_controller(
        request, db, domain=domain, name=name, operation="publish_team_custodian", custodian_id=custodian_id,
    )
    await _charge_team_publish(request, response, team)
    canonical = verify_published_record(
        body, record_type=TEAM_CUSTODIAN, team_id=build_team_id(domain, name),
        team_did_key=team["team_did_key"], now=datetime.now(timezone.utc),
    )
    if body.record["custodian_id"] != custodian_id:
        raise _refuse(422, "record_invalid", "custodian_id does not match the path")
    async with db.transaction() as tx:
        await _lock_team_key(tx, team)
        row = await tx.fetch_one(
            """
            SELECT record_json, signature, issued_at
            FROM {{tables.team_custodians}}
            WHERE team_uuid = $1 AND custodian_id = $2
            FOR UPDATE
            """,
            team["team_uuid"], custodian_id,
        )
        if row is not None:
            if _same_publication(row, canonical, body.signature):
                return {"published": True}
            if issued_at_of(body.record) <= row["issued_at"]:
                raise _refuse(409, "record_not_newer", "issued_at must be newer than the stored record")
        await tx.execute(
            """
            INSERT INTO {{tables.team_custodians}}
                (team_uuid, custodian_id, record_json, signature, team_did_key, issued_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (team_uuid, custodian_id) DO UPDATE
            SET record_json = EXCLUDED.record_json, signature = EXCLUDED.signature,
                team_did_key = EXCLUDED.team_did_key, issued_at = EXCLUDED.issued_at,
                updated_at = NOW()
            """,
            team["team_uuid"], custodian_id, canonical.decode("utf-8"), body.signature,
            team["team_did_key"], issued_at_of(body.record),
        )
    return {"published": True}


@router.get(
    "/{name}/custodians/{custodian_id}",
    dependencies=[Depends(rate_limit_dep("attestation_record_get", allow_trusted_service=True))],
)
async def get_team_custodian(domain: str, name: str, custodian_id: str, db_infra=Depends(get_db)) -> dict:
    db = db_infra.get_manager("aweb")
    row = await db.fetch_one(
        """
        SELECT c.record_json, c.signature
        FROM {{tables.team_custodians}} c
        JOIN {{tables.teams}} t ON t.team_uuid = c.team_uuid
        WHERE t.domain = $1 AND t.name = $2 AND t.deleted_at IS NULL AND c.custodian_id = $3
        """,
        domain, name, custodian_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return _stored(row)


def _member_fields_match(record: dict[str, Any], certificate_id: str, certificate) -> None:
    if record["certificate_id"] != certificate_id:
        raise _refuse(422, "record_invalid", "certificate_id does not match the path")
    if certificate is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if record["member_did_key"] != certificate["member_did_key"]:
        raise _refuse(422, "record_invalid", "member_did_key does not match the certificate")


def _without(record: dict[str, Any], *fields: str) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in fields}


@router.put(
    "/{name}/certificates/{certificate_id}/custody",
    dependencies=[Depends(rate_limit_dep("attestation_record_publish", allow_trusted_service=True))],
)
async def publish_member_custody(
    request: Request, response: Response, domain: str, name: str, certificate_id: str, body: SignedRecord,
    db_infra=Depends(get_db),
) -> dict:
    _require_covering_envelope(request)
    db = db_infra.get_manager("aweb")
    _, team = await _require_team_controller(
        request, db, domain=domain, name=name, operation="publish_member_custody", certificate_id=certificate_id,
    )
    await _charge_team_publish(request, response, team)
    canonical = verify_published_record(
        body, record_type=MEMBER_CUSTODY, team_id=build_team_id(domain, name),
        team_did_key=team["team_did_key"], now=datetime.now(timezone.utc),
    )
    record = body.record
    async with db.transaction() as tx:
        await _lock_team_key(tx, team)
        _member_fields_match(record, certificate_id, await _active_certificate(tx, team["team_uuid"], certificate_id))
        custodian = await tx.fetch_one(
            """
            SELECT record_json FROM {{tables.team_custodians}}
            WHERE team_uuid = $1 AND custodian_id = $2
            """,
            team["team_uuid"], record["custodian_id"],
        )
        if custodian is None or not json.loads(custodian["record_json"])["issuer_did_keys"]:
            raise _refuse(409, "custodian_not_registered", "The custodian is not registered for this team")
        row = await tx.fetch_one(
            """
            SELECT record_json, signature, team_did_key, issued_at
            FROM {{tables.member_custody}}
            WHERE team_uuid = $1 AND certificate_id = $2
            FOR UPDATE
            """,
            team["team_uuid"], certificate_id,
        )
        if row is not None:
            if _same_publication(row, canonical, body.signature):
                return {"published": True}
            stored = json.loads(row["record_json"])
            resigned = (
                row["team_did_key"] != team["team_did_key"]
                and _without(stored, "team_did_key", "issued_at") == _without(record, "team_did_key", "issued_at")
                and issued_at_of(record) > row["issued_at"]
            )
            if not resigned:
                raise _refuse(409, "custody_immutable", "A member custody record cannot change")
        await tx.execute(
            """
            INSERT INTO {{tables.member_custody}}
                (team_uuid, certificate_id, custodian_id, record_json, signature, team_did_key, issued_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (team_uuid, certificate_id) DO UPDATE
            SET record_json = EXCLUDED.record_json, signature = EXCLUDED.signature,
                team_did_key = EXCLUDED.team_did_key, issued_at = EXCLUDED.issued_at,
                updated_at = NOW()
            """,
            team["team_uuid"], certificate_id, record["custodian_id"], canonical.decode("utf-8"),
            body.signature, team["team_did_key"], issued_at_of(record),
        )
    return {"published": True}


@router.put(
    "/{name}/certificates/{certificate_id}/person",
    dependencies=[Depends(rate_limit_dep("attestation_record_publish", allow_trusted_service=True))],
)
async def publish_member_person(
    request: Request, response: Response, domain: str, name: str, certificate_id: str, body: SignedRecord,
    db_infra=Depends(get_db),
) -> dict:
    _require_covering_envelope(request)
    db = db_infra.get_manager("aweb")
    _, team = await _require_team_controller(
        request, db, domain=domain, name=name, operation="publish_member_person", certificate_id=certificate_id,
    )
    await _charge_team_publish(request, response, team)
    canonical = verify_published_record(
        body, record_type=MEMBER_PERSON, team_id=build_team_id(domain, name),
        team_did_key=team["team_did_key"], now=datetime.now(timezone.utc),
    )
    record = body.record
    async with db.transaction() as tx:
        await _lock_team_key(tx, team)
        _member_fields_match(record, certificate_id, await _active_certificate(tx, team["team_uuid"], certificate_id))
        row = await tx.fetch_one(
            """
            SELECT record_json, signature, issued_at
            FROM {{tables.member_person}}
            WHERE team_uuid = $1 AND certificate_id = $2
            FOR UPDATE
            """,
            team["team_uuid"], certificate_id,
        )
        if row is not None:
            if _same_publication(row, canonical, body.signature):
                return {"published": True}
            if issued_at_of(record) <= row["issued_at"]:
                raise _refuse(409, "record_not_newer", "issued_at must be newer than the stored record")
        await tx.execute(
            """
            INSERT INTO {{tables.member_person}}
                (team_uuid, certificate_id, single_person, record_json, signature, team_did_key, issued_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (team_uuid, certificate_id) DO UPDATE
            SET single_person = EXCLUDED.single_person, record_json = EXCLUDED.record_json,
                signature = EXCLUDED.signature, team_did_key = EXCLUDED.team_did_key,
                issued_at = EXCLUDED.issued_at, updated_at = NOW()
            """,
            team["team_uuid"], certificate_id, record["single_person"], canonical.decode("utf-8"),
            body.signature, team["team_did_key"], issued_at_of(record),
        )
    return {"published": True}


async def _get_member_record(db, table: str, domain: str, name: str, certificate_id: str) -> dict:
    row = await db.fetch_one(
        f"""
        SELECT r.record_json, r.signature
        FROM {{{{tables.{table}}}}} r
        JOIN {{{{tables.teams}}}} t ON t.team_uuid = r.team_uuid
        WHERE t.domain = $1 AND t.name = $2 AND t.deleted_at IS NULL AND r.certificate_id = $3
        """,
        domain, name, certificate_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail=_NOT_FOUND)
    return _stored(row)


@router.get(
    "/{name}/certificates/{certificate_id}/custody",
    dependencies=[Depends(rate_limit_dep("attestation_record_get", allow_trusted_service=True))],
)
async def get_member_custody(domain: str, name: str, certificate_id: str, db_infra=Depends(get_db)) -> dict:
    return await _get_member_record(db_infra.get_manager("aweb"), "member_custody", domain, name, certificate_id)


@router.get(
    "/{name}/certificates/{certificate_id}/person",
    dependencies=[Depends(rate_limit_dep("attestation_record_get", allow_trusted_service=True))],
)
async def get_member_person(domain: str, name: str, certificate_id: str, db_infra=Depends(get_db)) -> dict:
    return await _get_member_record(db_infra.get_manager("aweb"), "member_person", domain, name, certificate_id)


# Every team-key-signed record a team can store, in the order the paginated
# read returns them: (rank, kind, table, key column). team_server has no key.
_SIGNED_RECORD_KINDS = (
    (0, "team_server", "team_server_records", None),
    (1, "team_custodians", "team_custodians", "custodian_id"),
    (2, "member_custody", "member_custody", "certificate_id"),
    (3, "member_person", "member_person", "certificate_id"),
    (4, "team_credential_policy", "team_credential_policies", None),
)
_TEAM_NOT_FOUND = "Team not found"


def _team_key_reader(request: Request, team, authorization: str | None) -> bool:
    """The team key's path signature, or the trusted service token.

    Members are not readers: the list would show them custodian records that
    are otherwise readable only by exact key, and rotation needs the team key.
    """
    if _presents_trusted_service_token(request):
        return True
    if not authorization:
        return False
    try:
        return _verify_path_signature(request, authorization) == team["team_did_key"]
    except HTTPException:
        return False


@router.get(
    "/{name}/signed-records",
    dependencies=[Depends(rate_limit_dep("attestation_record_list", allow_trusted_service=True))],
)
async def list_signed_records(
    request: Request,
    domain: str,
    name: str,
    limit: int | None = Query(default=None),
    cursor: str | None = Query(default=None),
    authorization: str | None = Header(default=None),
    db_infra=Depends(get_db),
) -> dict:
    """Every record the team key has signed and AWID stores, in stable pages.

    For a team-key rotation, which must re-sign all of them. Only the team key
    or the trusted service token may read, whatever the team's visibility;
    every refusal, including an unknown team, is the same 404.
    """
    db = db_infra.get_manager("aweb")
    team = await db.fetch_one(
        "SELECT team_uuid, team_did_key FROM {{tables.teams}} WHERE domain = $1 AND name = $2 AND deleted_at IS NULL",
        domain, name,
    )
    if team is None or not _team_key_reader(request, team, authorization):
        raise HTTPException(status_code=404, detail=_TEAM_NOT_FOUND)
    try:
        page_size, after = validate_pagination_params(limit, cursor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    after_rank, after_key = -1, ""
    if after is not None:
        after_rank, after_key = after.get("rank"), after.get("key")
        if type(after_rank) is not int or not isinstance(after_key, str):
            raise HTTPException(status_code=400, detail="Invalid cursor")

    selects = []
    for rank, kind, table, key_column in _SIGNED_RECORD_KINDS:
        key = key_column or "''"
        selects.append(
            f"SELECT {rank} AS rank, '{kind}' AS kind, {key} AS key, record_json, signature"
            f" FROM {{{{tables.{table}}}}} WHERE team_uuid = $1"
        )
    rows = await db.fetch_all(
        "SELECT rank, kind, key, record_json, signature FROM (" + " UNION ALL ".join(selects) + ") records"
        " WHERE (rank, key) > ($2, $3) ORDER BY rank, key LIMIT $4",
        team["team_uuid"], after_rank, after_key, page_size + 1,
    )
    has_more = len(rows) > page_size
    rows = rows[:page_size]
    key_columns = {kind: key_column for _, kind, _, key_column in _SIGNED_RECORD_KINDS}
    items = [
        {"kind": row["kind"], "key": row["key"] if key_columns[row["kind"]] is not None else None, **_stored(row)}
        for row in rows
    ]
    next_cursor = encode_cursor({"rank": rows[-1]["rank"], "key": rows[-1]["key"]}) if has_more else None
    return {"items": items, "has_more": has_more, "next_cursor": next_cursor}
