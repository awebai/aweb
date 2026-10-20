"""Principal-attestation verification: the frozen vector cases, then real AWID routes.

The vector cases give the verifier the registry state each case declares. The
integration tests read the same records from real AWID routes on PostgreSQL.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from aweb_naapp.runtime.attestation import (
    AWIDAttestationRecords,
    AttestationRefused,
    SignedRecord,
    read_member_person,
    verify_principal_attestation,
)
from awid.attestation_records import sign_record
from awid.signing import canonical_json_bytes
from tests.runtime.conftest import REGISTRY_URL

VECTORS = json.loads(
    (Path(__file__).parents[3] / "docs" / "vectors" / "principal-attestation-v1.json").read_text()
)


def _at(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _bytes(value: str | None) -> bytes | None:
    if value is None:
        return None
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class DeclaredRecords:
    """The registry state a vector case declares, served by key."""

    def __init__(self, registry: dict) -> None:
        self._registry = registry

    async def member_custody(self, team_id: str, certificate_id: str) -> SignedRecord | None:
        return self._registry.get("member_custody")

    async def team_custodian(self, team_id: str, custodian_id: str) -> SignedRecord | None:
        found = self._registry.get("team_custodian")
        return found if found and found["record"]["custodian_id"] == custodian_id else None

    async def member_person(self, team_id: str, certificate_id: str) -> SignedRecord | None:
        return self._registry.get("member_person")


async def _verify_case(case):
    certificate = case["certificate"]
    return await verify_principal_attestation(
        header=case["header"],
        signed_payload=_bytes(case["request"]["signed_payload_b64url"]),
        team_id=certificate["team_id"],
        certificate_id=certificate["certificate_id"],
        member_did_key=certificate["member_did_key"],
        current_team_did_key=case["registry"]["current_team_did_key"],
        records=DeclaredRecords(case["registry"]),
        now=_at(case["now"]),
    )


@pytest.mark.parametrize("case", VECTORS["verification_cases"], ids=lambda case: case["name"])
async def test_verification_vector_cases(case):
    expected = case["expected"]
    if "error" in expected:
        with pytest.raises(AttestationRefused) as refused:
            await _verify_case(case)
        assert refused.value.code == expected["error"]
        return
    result = await _verify_case(case)
    if expected["result"] == "none":
        assert result is None
        return
    assert result.custodian_id == expected["custodian_id"]
    assert result.channel == expected["channel"]
    assert result.human_principal == expected["human_principal"]
    assert result.session_id == expected["session_id"]


async def test_a_forged_attestation_never_reads_the_registry():
    case = next(c for c in VECTORS["verification_cases"] if c["name"] == "forged-signature")

    class Unreachable:
        async def member_custody(self, *args):
            raise AssertionError("registry read before the signature check")

        team_custodian = member_person = member_custody

    certificate = case["certificate"]
    with pytest.raises(AttestationRefused) as refused:
        await verify_principal_attestation(
            header=case["header"], signed_payload=_bytes(case["request"]["signed_payload_b64url"]),
            team_id=certificate["team_id"], certificate_id=certificate["certificate_id"],
            member_did_key=certificate["member_did_key"],
            current_team_did_key=case["registry"]["current_team_did_key"],
            records=Unreachable(), now=_at(case["now"]),
        )
    assert refused.value.code == "attestation_invalid"


KEYS = VECTORS["keys"]
TEAM_ID = "backend:acme.com"
VALID = next(c for c in VECTORS["verification_cases"] if c["name"] == "valid")


async def _publish_vector_state(registry):
    await registry.add_team(TEAM_ID, KEYS["team"]["did_key"], visibility="private")
    certificate = VALID["certificate"]
    await registry.add_certificate({
        "team_id": TEAM_ID, "certificate_id": certificate["certificate_id"],
        "member_did_key": certificate["member_did_key"], "alias": "alice",
    })
    for table, key_column, signed in (
        ("team_custodians", "custodian_id", VALID["registry"]["team_custodian"]),
        ("member_custody", "certificate_id", VALID["registry"]["member_custody"]),
    ):
        record = signed["record"]
        extra = ", custodian_id" if table == "member_custody" else ""
        extra_value = ", $7" if table == "member_custody" else ""
        await registry.db.execute(
            f"INSERT INTO {{{{tables.{table}}}}} (team_uuid, {key_column}, record_json, signature, team_did_key, issued_at{extra}) "
            f"SELECT team_uuid, $1, $2, $3, $4, $5::timestamptz{extra_value} FROM {{{{tables.teams}}}} WHERE name = $6",
            record[key_column], canonical_json_bytes(record).decode(), signed["signature"],
            record["team_did_key"], _at(record["issued_at"]), "backend",
            *([record["custodian_id"]] if table == "member_custody" else []),
        )


def _records(registry, ttl_seconds=60):
    return AWIDAttestationRecords(registry_url=REGISTRY_URL, ttl_seconds=ttl_seconds, transport=registry.transport)


async def _verify_valid(records, now=None):
    certificate = VALID["certificate"]
    return await verify_principal_attestation(
        header=VALID["header"], signed_payload=_bytes(VALID["request"]["signed_payload_b64url"]),
        team_id=certificate["team_id"], certificate_id=certificate["certificate_id"],
        member_did_key=certificate["member_did_key"], current_team_did_key=KEYS["team"]["did_key"],
        records=records, now=now or _at(VALID["now"]),
    )


async def test_real_awid_records_verify_and_are_cached(registry):
    await _publish_vector_state(registry)
    records = _records(registry)
    result = await _verify_valid(records)
    assert result.channel == "mcp_l2"
    reads = len(registry.transport.calls)
    assert reads == 2
    await _verify_valid(records)
    assert len(registry.transport.calls) == reads


async def test_a_registry_failure_after_expiry_is_authority_unavailable(registry):
    await _publish_vector_state(registry)
    records = _records(registry, ttl_seconds=0)

    def fail(request: httpx.Request, response: httpx.Response) -> None:
        response.status_code = 503

    registry.transport.fault = fail
    with pytest.raises(AttestationRefused) as refused:
        await _verify_valid(records)
    assert refused.value.code == "authority_unavailable"


async def test_the_cache_lifetime_is_clamped_to_sixty_seconds(registry):
    assert _records(registry, ttl_seconds=600).ttl_seconds == 60


async def test_an_absent_custody_record_on_real_awid_is_unregistered(registry):
    await registry.add_team(TEAM_ID, KEYS["team"]["did_key"])
    with pytest.raises(AttestationRefused) as refused:
        await _verify_valid(_records(registry))
    assert refused.value.code == "attestation_issuer_unregistered"


def _person(single_person: bool, team_key: str, *, issued_at="2026-10-20T12:00:00Z"):
    certificate = VALID["certificate"]
    return {
        "v": 1, "type": "aweb.member-person", "team_id": TEAM_ID, "team_did_key": KEYS[team_key]["did_key"],
        "certificate_id": certificate["certificate_id"], "member_did_key": certificate["member_did_key"],
        "single_person": single_person, "issued_at": issued_at,
    }


async def _read_person(signed, current="team"):
    certificate = VALID["certificate"]
    return await read_member_person(
        team_id=TEAM_ID, certificate_id=certificate["certificate_id"],
        member_did_key=certificate["member_did_key"], current_team_did_key=KEYS[current]["did_key"],
        records=DeclaredRecords({"member_person": signed}),
    )


def _signed(record, key):
    return {"record": record, "signature": sign_record(bytes.fromhex(KEYS[key]["seed_hex"]), record)}


async def test_member_person_is_true_only_when_present_valid_and_declared():
    assert await _read_person(_signed(_person(True, "team"), "team")) is True
    assert await _read_person(_signed(_person(False, "team"), "team")) is False
    assert await _read_person(None) is False


async def test_member_person_refusals():
    with pytest.raises(AttestationRefused) as stale:
        await _read_person(_signed(_person(True, "team"), "team"), current="new_team")
    assert stale.value.code == "member_person_record_stale"
    with pytest.raises(AttestationRefused) as forged:
        await _read_person(_signed(_person(True, "team"), "other"))
    assert forged.value.code == "member_person_invalid"
    other_member = dict(_person(True, "team"), member_did_key=KEYS["other"]["did_key"])
    with pytest.raises(AttestationRefused) as mismatch:
        await _read_person(_signed(other_member, "team"))
    assert mismatch.value.code == "member_person_invalid"
