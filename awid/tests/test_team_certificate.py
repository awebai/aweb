"""The shared team-certificate helper: one reason per way a certificate fails."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes
from awid.team_certificate import (
    TeamCertificateError,
    TeamCertificateStanding,
    decode_team_certificate,
    evaluate_team_certificate_standing,
    verify_team_certificate_signature,
)
from nacl.signing import SigningKey

TEAM_KEY = SigningKey(bytes(range(32)))
TEAM_DID_KEY = did_from_public_key(bytes(TEAM_KEY.verify_key))


def certificate(**fields) -> dict:
    cert = {
        "version": 1,
        "certificate_id": "c_41",
        "team_id": "demo:example.com",
        "team_did_key": TEAM_DID_KEY,
        "member_did_key": did_from_public_key(
            bytes(SigningKey(bytes(range(32, 64))).verify_key)
        ),
        "alias": "bond",
        "identity_scope": "local",
        "issued_at": "2026-10-01T09:00:00Z",
        **fields,
    }
    signature = TEAM_KEY.sign(canonical_json_bytes(cert)).signature
    cert["signature"] = base64.b64encode(signature).decode().rstrip("=")
    return cert


def header(cert: dict) -> str:
    return base64.b64encode(json.dumps(cert).encode()).decode()


def test_a_certificate_signed_by_the_team_key_verifies() -> None:
    verify_team_certificate_signature(
        decode_team_certificate(header(certificate())), TEAM_DID_KEY
    )


@pytest.mark.parametrize("registered", [True, False, None])
def test_revocation_overrides_registration(registered: bool | None) -> None:
    assert (
        evaluate_team_certificate_standing(revoked=True, registered=registered)
        is TeamCertificateStanding.REVOKED
    )


def test_unrequired_registration_allows_an_unrevoked_certificate() -> None:
    assert (
        evaluate_team_certificate_standing(revoked=False, registered=None)
        is TeamCertificateStanding.ACTIVE
    )


@pytest.mark.parametrize(
    "encoded",
    [
        "not base64!",
        base64.b64encode(b"not json").decode(),
        base64.b64encode(b"[1, 2]").decode(),
        base64.b64encode(b"\xff\xfe").decode(),
    ],
    ids=["not-base64", "not-json", "not-an-object", "not-utf8"],
)
def test_an_unreadable_certificate_is_malformed(encoded: str) -> None:
    with pytest.raises(TeamCertificateError) as refused:
        decode_team_certificate(encoded)
    assert refused.value.reason == "malformed"


def test_a_certificate_without_a_signature() -> None:
    cert = certificate()
    del cert["signature"]
    with pytest.raises(TeamCertificateError) as refused:
        verify_team_certificate_signature(cert, TEAM_DID_KEY)
    assert refused.value.reason == "missing_signature"


def test_a_team_key_that_does_not_decode() -> None:
    with pytest.raises(TeamCertificateError) as refused:
        verify_team_certificate_signature(certificate(), "did:key:zNotAKey")
    assert refused.value.reason == "invalid_team_key"


def test_a_certificate_signed_by_another_key() -> None:
    other = did_from_public_key(bytes(SigningKey(bytes(range(64, 96))).verify_key))
    with pytest.raises(TeamCertificateError) as refused:
        verify_team_certificate_signature(certificate(), other)
    assert refused.value.reason == "bad_signature"


def test_an_altered_certificate() -> None:
    cert = dict(certificate(), alias="mallory")
    with pytest.raises(TeamCertificateError) as refused:
        verify_team_certificate_signature(cert, TEAM_DID_KEY)
    assert refused.value.reason == "bad_signature"


def test_a_lone_surrogate_is_a_bad_signature_not_a_crash() -> None:
    cert = certificate()
    encoded = base64.b64encode(
        json.dumps(cert).replace('"bond"', '"\\ud800"').encode()
    ).decode()
    decoded = decode_team_certificate(encoded)
    with pytest.raises(TeamCertificateError) as refused:
        verify_team_certificate_signature(decoded, TEAM_DID_KEY)
    assert refused.value.reason == "bad_signature"


def test_the_helper_imports_only_identity_primitives() -> None:
    src = Path(__file__).resolve().parents[1] / "src"
    heavy = (
        "fastapi",
        "starlette",
        "pydantic",
        "httpx",
        "pgdbm",
        "redis",
        "dns",
        "typer",
    )
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {str(src)!r})\n"
        "import awid.team_certificate\n"
        f"print(','.join(m for m in {heavy!r} if m in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == ""


def test_a_header_over_the_cap_is_malformed_before_decoding() -> None:
    from awid.team_certificate import MAX_HEADER_BYTES

    nested = base64.b64encode(b"[" * 100000).decode()
    for encoded in (nested, "A" * (MAX_HEADER_BYTES + 1)):
        with pytest.raises(TeamCertificateError) as refused:
            decode_team_certificate(encoded)
        assert refused.value.reason == "malformed"


def test_deep_nesting_under_the_cap_is_malformed_not_a_crash() -> None:
    from awid.team_certificate import MAX_HEADER_BYTES

    depth = MAX_HEADER_BYTES // 4 * 3
    encoded = base64.b64encode(b"[" * depth).decode()
    assert len(encoded) <= MAX_HEADER_BYTES
    with pytest.raises(TeamCertificateError) as refused:
        decode_team_certificate(encoded)
    assert refused.value.reason == "malformed"


def test_a_team_key_of_the_wrong_type_is_an_invalid_team_key() -> None:
    with pytest.raises(TeamCertificateError) as refused:
        verify_team_certificate_signature(certificate(), None)  # type: ignore[arg-type]
    assert refused.value.reason == "invalid_team_key"


def test_checked_certificate_retains_immutable_artifact_and_fingerprint(monkeypatch):
    import hashlib

    from awid import team_certificate

    issued = certificate(extra={"nested": ["original"]})
    checked = team_certificate.verify_team_certificate_claims(
        header(issued),
        subject_did_key=issued["member_did_key"],
        team_did_key=TEAM_DID_KEY,
    )
    assert checked.canonical_artifact == canonical_json_bytes(issued)
    assert (
        checked.fingerprint == hashlib.sha256(canonical_json_bytes(issued)).hexdigest()
    )
    assert checked.team_did_key == TEAM_DID_KEY
    with pytest.raises(TypeError):
        checked.claims["alias"] = "changed"
    with pytest.raises(TypeError):
        checked.claims["extra"]["nested"][0] = "changed"

    def unexpected_crypto(*args, **kwargs):
        raise AssertionError("evidence re-ran cryptographic verification")

    # The first phase used a real signature. Standing consumes the already
    # verified immutable artifact and cannot perform a second crypto check.
    monkeypatch.setattr(
        team_certificate, "verify_team_certificate_signature", unexpected_crypto
    )
    with pytest.raises(TeamCertificateError) as refusal:
        team_certificate.check_team_certificate_evidence(
            checked,
            revoked_certificate_ids={issued["certificate_id"]},
            registered_certificate_ids=None,
        )
    assert refusal.value.reason == "revoked"
    result = team_certificate.check_team_certificate_evidence(
        checked,
        revoked_certificate_ids=set(),
        registered_certificate_ids={issued["certificate_id"]},
    )
    result["extra"]["nested"][0] = "detached copy"
    assert checked.claims["extra"]["nested"] == ("original",)


_SENDER_STANDING = json.loads(
    (Path(__file__).resolve().parents[2] / "test-vectors/trust/sender-standing-v1.json").read_text()
)


@pytest.mark.parametrize("case", _SENDER_STANDING["cases"], ids=lambda case: case["id"])
def test_checked_certificate_standing_matches_the_shared_evidence(case):
    from awid.team_certificate import check_team_certificate_evidence, verify_team_certificate_claims

    issued = certificate()
    cert_id = issued["certificate_id"]
    checked = verify_team_certificate_claims(
        header(issued), subject_did_key=issued["member_did_key"], team_did_key=TEAM_DID_KEY,
    )
    evidence = {
        "revoked_certificate_ids": {cert_id} if case["revoked"] else set(),
        "registered_certificate_ids": {cert_id} if case["registered"] else set(),
    }
    if case["certificate_refusal"] is None:
        assert check_team_certificate_evidence(checked, **evidence)["certificate_id"] == cert_id
    else:
        with pytest.raises(TeamCertificateError) as refused:
            check_team_certificate_evidence(checked, **evidence)
        assert refused.value.reason == case["certificate_refusal"]
