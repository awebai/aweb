"""Principal attestation and member person verification for relying naapps.

Contracts: docs/principal-attestation.md §4 and docs/member-person.md. Both run
after team-auth v2 verification, which supplies the verified certificate and the
current team key. Every refusal raises :class:`AttestationRefused` with the
contract's code; nothing here infers self-custody, a default channel or a person
declaration from absence.

:func:`request_attestation` verifies a request's attestation once, and
:func:`caller_context` turns it into the invocation context the app's manifest
tools are checked against.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol, TypedDict
from urllib.parse import quote

import httpx
from awid.attestation_records import (
    ATTESTATION_HEADER,
    ATTESTATION_MAX_LIFETIME_SECONDS,
    AttestationError,
    RecordError,
    decode_attestation_header,
    parse_attestation_time,
    verify_attestation_signature,
    verify_record,
)
from awid.team_ids import parse_team_id
from fastapi import Request

from aweb_naapp.manifest import Attestation, ManifestError
from aweb_naapp.manifest import caller_context as manifest_caller_context
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.team_auth import Principal, signed_payload_bytes

__all__ = [
    "ATTESTATION_HEADER",
    "AWIDAttestationRecords",
    "AttestationRecordSource",
    "AttestationRefused",
    "SignedRecord",
    "VerifiedAttestation",
    "caller_context",
    "read_member_person",
    "request_attestation",
    "verify_principal_attestation",
]

MAX_RECORD_TTL_SECONDS = 60
MAX_IAT_AHEAD = timedelta(seconds=60)


class SignedRecord(TypedDict):
    record: dict[str, Any]
    signature: str


class AttestationRefused(Exception):
    """A refusal with one of the contract's codes."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class VerifiedAttestation:
    custodian_id: str
    channel: str
    human_principal: str | None
    session_id: str


class AttestationRecordSource(Protocol):
    """Team-key-signed records of one registry; ``None`` means a verified absence."""

    async def member_custody(self, team_id: str, certificate_id: str) -> SignedRecord | None: ...

    async def team_custodian(self, team_id: str, custodian_id: str) -> SignedRecord | None: ...

    async def member_person(self, team_id: str, certificate_id: str) -> SignedRecord | None: ...


class AWIDAttestationRecords:
    """Reads the records from AWID's anonymous routes, caching each for at most 60 s.

    A failed, timed-out or unexpected response is ``authority_unavailable``; an
    expired entry is never served.
    """

    def __init__(
        self,
        *,
        registry_url: str,
        ttl_seconds: int = MAX_RECORD_TTL_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.registry_url = registry_url.rstrip("/")
        self.ttl_seconds = max(0, min(int(ttl_seconds), MAX_RECORD_TTL_SECONDS))
        self._transport = transport
        self._timeout = timeout_seconds
        self._cache: dict[str, tuple[int, SignedRecord | None]] = {}

    async def _get(self, path: str) -> SignedRecord | None:
        cached = self._cache.get(path)
        if cached is not None and time.monotonic_ns() < cached[0]:
            return cached[1]
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self._timeout) as client:
                response = await client.get(self.registry_url + path)
        except httpx.HTTPError as exc:
            raise AttestationRefused("authority_unavailable", "registry read failed") from exc
        if response.status_code == 404:
            value: SignedRecord | None = None
        elif response.status_code == 200:
            try:
                body = response.json()
            except ValueError as exc:
                raise AttestationRefused("authority_unavailable", "registry returned invalid JSON") from exc
            if not isinstance(body, dict) or not isinstance(body.get("record"), dict) or not isinstance(body.get("signature"), str):
                raise AttestationRefused("authority_unavailable", "registry returned an unexpected record shape")
            value = {"record": body["record"], "signature": body["signature"]}
        else:
            raise AttestationRefused("authority_unavailable", f"registry answered {response.status_code}")
        self._cache[path] = (time.monotonic_ns() + seconds_to_ns(self.ttl_seconds), value)
        return value

    @staticmethod
    def _team_path(team_id: str) -> str:
        domain, name = parse_team_id(team_id)
        return f"/v1/namespaces/{quote(domain, safe='')}/teams/{quote(name, safe='')}"

    async def member_custody(self, team_id: str, certificate_id: str) -> SignedRecord | None:
        return await self._get(f"{self._team_path(team_id)}/certificates/{quote(certificate_id, safe='')}/custody")

    async def team_custodian(self, team_id: str, custodian_id: str) -> SignedRecord | None:
        return await self._get(f"{self._team_path(team_id)}/custodians/{quote(custodian_id, safe='')}")

    async def member_person(self, team_id: str, certificate_id: str) -> SignedRecord | None:
        return await self._get(f"{self._team_path(team_id)}/certificates/{quote(certificate_id, safe='')}/person")


def _registered(
    signed: SignedRecord | None, *, current_team_did_key: str, expected: dict[str, Any],
    absent_code: str, invalid_code: str, stale_code: str,
) -> dict[str, Any]:
    """Check one stored record against the current team key and the expected fields."""
    if signed is None:
        raise AttestationRefused(absent_code, "record is absent")
    record, signature = signed["record"], signed["signature"]
    stored_key = record.get("team_did_key") if isinstance(record, dict) else None
    if isinstance(stored_key, str) and stored_key != current_team_did_key:
        try:
            verify_record(record, signature, team_did_key=stored_key)
        except RecordError as exc:
            raise AttestationRefused(invalid_code, "record does not verify") from exc
        raise AttestationRefused(stale_code, "record is signed with an earlier team key")
    try:
        verify_record(record, signature, team_did_key=current_team_did_key)
    except RecordError as exc:
        raise AttestationRefused(invalid_code, "record does not verify") from exc
    if any(record.get(field) != value for field, value in expected.items()):
        raise AttestationRefused(invalid_code, "record does not match")
    return record


async def verify_principal_attestation(
    *,
    header: str | None,
    signed_payload: bytes | None,
    team_id: str,
    certificate_id: str,
    member_did_key: str,
    current_team_did_key: str,
    records: AttestationRecordSource,
    now: datetime,
) -> VerifiedAttestation | None:
    """Verify an ``X-AWEB-Principal-Attestation`` value; ``None`` when there is none.

    The inputs other than ``header`` come from a successful team-auth v2
    verification of the same request: its signed-payload bytes (``None`` for a
    compact v1 request), the verified certificate and the current team key.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if header is None:
        return None
    try:
        payload, signature = decode_attestation_header(header)
    except AttestationError as exc:
        raise AttestationRefused("attestation_invalid", str(exc)) from exc
    if signed_payload is None:
        raise AttestationRefused("attestation_binding_mismatch", "attestations apply to team-auth v2 requests only")
    if (
        payload["team_id"] != team_id
        or payload["certificate_id"] != certificate_id
        or payload["member_did_key"] != member_did_key
        or payload["request_binding"] != hashlib.sha256(signed_payload).hexdigest()
    ):
        raise AttestationRefused("attestation_binding_mismatch", "attestation is for another request")
    iat = parse_attestation_time(payload["iat"])
    exp = parse_attestation_time(payload["exp"])
    lifetime = (exp - iat).total_seconds()
    if lifetime <= 0 or lifetime > ATTESTATION_MAX_LIFETIME_SECONDS:
        raise AttestationRefused("attestation_expired", "exp must be after iat and at most 300 s later")
    if iat > now + MAX_IAT_AHEAD or exp <= now:
        raise AttestationRefused("attestation_expired", "attestation is outside its validity window")
    try:
        verify_attestation_signature(payload, signature)
    except AttestationError as exc:
        raise AttestationRefused("attestation_invalid", "signature does not verify") from exc

    codes = {
        "absent_code": "attestation_issuer_unregistered",
        "invalid_code": "attestation_issuer_unregistered",
        "stale_code": "attestation_record_stale",
    }
    _registered(
        await records.member_custody(team_id, certificate_id),
        current_team_did_key=current_team_did_key,
        expected={
            "team_id": team_id, "certificate_id": certificate_id,
            "member_did_key": member_did_key, "custodian_id": payload["custodian_id"],
        },
        **codes,
    )
    custodian = _registered(
        await records.team_custodian(team_id, payload["custodian_id"]),
        current_team_did_key=current_team_did_key,
        expected={"team_id": team_id, "custodian_id": payload["custodian_id"]},
        **codes,
    )
    if payload["issuer_did_key"] not in custodian["issuer_did_keys"]:
        raise AttestationRefused("attestation_issuer_unregistered", "issuer key is not registered")
    return VerifiedAttestation(
        custodian_id=payload["custodian_id"],
        channel=payload["channel"],
        human_principal=payload.get("human_principal"),
        session_id=payload["session_id"],
    )


async def read_member_person(
    *,
    team_id: str,
    certificate_id: str,
    member_did_key: str,
    current_team_did_key: str,
    records: AttestationRecordSource,
) -> bool:
    """True only when the controller declares this certificate's member one person."""
    signed = await records.member_person(team_id, certificate_id)
    if signed is None:
        return False
    record = _registered(
        signed,
        current_team_did_key=current_team_did_key,
        expected={"team_id": team_id, "certificate_id": certificate_id, "member_did_key": member_did_key},
        absent_code="member_person_invalid",
        invalid_code="member_person_invalid",
        stale_code="member_person_record_stale",
    )
    return record["single_person"] is True


async def request_attestation(
    request: Request, principal: Principal, *, records: AttestationRecordSource, now: datetime
) -> VerifiedAttestation | None:
    """The verified principal attestation of a request ``principal`` signed, or
    ``None`` when it carries none. An attestation that is present must verify,
    or :class:`AttestationRefused` is raised with its code."""
    return await verify_principal_attestation(
        header=request.headers.get(ATTESTATION_HEADER),
        signed_payload=signed_payload_bytes(request),
        team_id=principal.team_id,
        certificate_id=principal.certificate_id,
        member_did_key=principal.did_key,
        current_team_did_key=principal.team_did_key,
        records=records,
        now=now,
    )


def caller_context(verified: VerifiedAttestation | None) -> str:
    """The invocation context of a request with this verified attestation:
    ``agent`` without one, ``surface`` for the dashboard channel. No request
    calls in the ``hook`` context through team-auth."""
    attestation = None if verified is None else Attestation(verified=True, payload={"channel": verified.channel})
    try:
        return manifest_caller_context(attestation)
    except ManifestError as exc:
        raise AttestationRefused(exc.code, str(exc)) from None
