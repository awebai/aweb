"""Signed bytes, strict parsing and signatures of the principal-attestation records."""

from __future__ import annotations

import base64
import json

import pytest

from awid.attestation_records import (
    ATTESTATION_HEADER_MAX_BYTES,
    AttestationError,
    RecordError,
    decode_attestation_header,
    encode_attestation_header,
    sign_record,
    signing_bytes,
    validate_attestation,
    validate_member_custody,
    validate_member_person,
    validate_team_custodian,
    verify_record,
)
from awid.did import did_from_public_key, generate_keypair
from awid.signing import canonical_json_bytes


def _keypair():
    private, public = generate_keypair()
    return private, did_from_public_key(public)


TEAM_KEY, TEAM_DID = _keypair()
ISSUER_KEY, ISSUER_DID = _keypair()
_, MEMBER_DID = _keypair()


def _custodian(**overrides):
    record = {
        "v": 1,
        "type": "aweb.team-custodian",
        "team_id": "backend:acme.com",
        "team_did_key": TEAM_DID,
        "custodian_id": "custodian.example",
        "issuer_did_keys": [ISSUER_DID],
        "issued_at": "2026-10-20T12:00:00Z",
    }
    record.update(overrides)
    return record


def _custody(**overrides):
    record = {
        "v": 1,
        "type": "aweb.member-custody",
        "team_id": "backend:acme.com",
        "team_did_key": TEAM_DID,
        "certificate_id": "11111111-1111-4111-8111-111111111111",
        "member_did_key": MEMBER_DID,
        "custodian_id": "custodian.example",
        "issued_at": "2026-10-20T12:00:00Z",
    }
    record.update(overrides)
    return record


def _person(**overrides):
    record = {
        "v": 1,
        "type": "aweb.member-person",
        "team_id": "backend:acme.com",
        "team_did_key": TEAM_DID,
        "certificate_id": "11111111-1111-4111-8111-111111111111",
        "member_did_key": MEMBER_DID,
        "single_person": True,
        "issued_at": "2026-10-20T12:00:00Z",
    }
    record.update(overrides)
    return record


def _attestation(**overrides):
    payload = {
        "v": 1,
        "type": "aweb.principal-attestation",
        "team_id": "backend:acme.com",
        "certificate_id": "11111111-1111-4111-8111-111111111111",
        "member_did_key": MEMBER_DID,
        "custody": "custodial",
        "custodian_id": "custodian.example",
        "issuer_did_key": ISSUER_DID,
        "channel": "mcp_l2",
        "human_principal": "subject-1",
        "session_id": "session-1",
        "iat": "2026-10-20T12:00:00Z",
        "exp": "2026-10-20T12:05:00Z",
        "request_binding": "a" * 64,
    }
    payload.update(overrides)
    return payload


def test_signing_bytes_are_the_type_prefix_and_newline_then_canonical_json():
    record = _custodian()
    assert signing_bytes(record) == b"aweb.team-custodian/1\n" + canonical_json_bytes(record)
    assert signing_bytes(_custody()).startswith(b"aweb.member-custody/1\n")
    assert signing_bytes(_person()).startswith(b"aweb.member-person/1\n")
    assert signing_bytes(_attestation()).startswith(b"aweb.principal-attestation/1\n")


@pytest.mark.parametrize("make", [_custodian, _custody, _person])
def test_a_record_signed_by_the_team_key_verifies_and_another_key_does_not(make):
    record = make()
    signature = sign_record(TEAM_KEY, record)
    verify_record(record, signature, team_did_key=TEAM_DID)
    other_key, _ = _keypair()
    with pytest.raises(RecordError):
        verify_record(record, sign_record(other_key, record), team_did_key=TEAM_DID)


def test_a_signature_over_one_record_type_does_not_verify_as_another():
    custody = _custody()
    signature = sign_record(TEAM_KEY, custody)
    person_shaped = dict(custody, type="aweb.member-person")
    with pytest.raises(RecordError):
        verify_record(person_shaped, signature, team_did_key=TEAM_DID)


def test_a_record_naming_another_team_key_is_refused_even_if_signed():
    record = _custody(team_did_key=ISSUER_DID)
    with pytest.raises(RecordError):
        verify_record(record, sign_record(TEAM_KEY, record), team_did_key=TEAM_DID)


@pytest.mark.parametrize(
    "validate, record",
    [
        (validate_team_custodian, _custodian(extra="x")),
        (validate_team_custodian, _custodian(custodian_id="Upper.Case")),
        (validate_team_custodian, _custodian(issuer_did_keys=[ISSUER_DID, ISSUER_DID])),
        (validate_team_custodian, _custodian(issuer_did_keys=[ISSUER_DID, TEAM_DID, MEMBER_DID])),
        (validate_team_custodian, _custodian(issued_at="2026-10-20T12:00:00+00:00")),
        (validate_team_custodian, _custodian(v=2)),
        (validate_member_custody, _custody(certificate_id="")),
        (validate_member_custody, _custody(member_did_key="did:aw:x")),
        (validate_member_person, _person(single_person="yes")),
        (validate_member_person, {k: v for k, v in _person().items() if k != "single_person"}),
    ],
)
def test_malformed_records_are_refused(validate, record):
    with pytest.raises(RecordError):
        validate(record)


def test_an_empty_issuer_list_is_a_valid_deregistration():
    validate_team_custodian(_custodian(issuer_did_keys=[]))


def test_an_attestation_round_trips_through_its_header():
    payload = _attestation()
    header = encode_attestation_header(ISSUER_KEY, payload)
    decoded, signature = decode_attestation_header(header)
    assert decoded == payload
    assert isinstance(signature, bytes) and len(signature) == 64


def _header(raw: bytes, signature: bytes = b"\0" * 64) -> str:
    encode = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    return f"{encode(raw)}.{encode(signature)}"


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps(_attestation(), sort_keys=True, indent=1).encode(),
        canonical_json_bytes(_attestation())[:-1] + b',"channel":"api"}',
        canonical_json_bytes(_attestation(iat=1.5)),
        b"[]",
        b"not json",
    ],
    ids=["non-canonical", "duplicate-key", "float", "not-object", "not-json"],
)
def test_attestation_header_bytes_must_be_canonical_json(raw):
    with pytest.raises(AttestationError):
        decode_attestation_header(_header(raw))


def test_attestation_header_has_a_size_bound_and_no_padding():
    big = _attestation(session_id="s" * 128, human_principal="h" * 128)
    header = _header(canonical_json_bytes(big) * 30)
    assert len(header) > ATTESTATION_HEADER_MAX_BYTES
    with pytest.raises(AttestationError):
        decode_attestation_header(header)
    good = encode_attestation_header(ISSUER_KEY, _attestation())
    payload_part, sig_part = good.split(".")
    with pytest.raises(AttestationError):
        decode_attestation_header(payload_part + "=." + sig_part)


@pytest.mark.parametrize(
    "overrides",
    [
        {"channel": "browser"},
        {"custody": "self"},
        {"human_principal": "alice@example.com"},
        {"session_id": ""},
        {"exp": "2026-10-20T12:05:01Z"},
        {"exp": "2026-10-20T11:59:59Z"},
        {"request_binding": "A" * 64},
        {"unknown": "x"},
    ],
)
def test_attestation_fields_are_checked(overrides):
    with pytest.raises(AttestationError):
        validate_attestation(_attestation(**overrides))


def test_human_principal_is_optional():
    payload = _attestation()
    del payload["human_principal"]
    validate_attestation(payload)
