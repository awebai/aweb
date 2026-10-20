"""The shared team-certificate helper: one reason per way a certificate fails."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes
from awid.team_certificate import (
    TeamCertificateError,
    decode_team_certificate,
    verify_team_certificate_signature,
)

TEAM_KEY = SigningKey(bytes(range(32)))
TEAM_DID_KEY = did_from_public_key(bytes(TEAM_KEY.verify_key))


def certificate(**fields) -> dict:
    cert = {
        "version": 1,
        "certificate_id": "c_41",
        "team_id": "demo:example.com",
        "team_did_key": TEAM_DID_KEY,
        "member_did_key": did_from_public_key(bytes(SigningKey(bytes(range(32, 64))).verify_key)),
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
    verify_team_certificate_signature(decode_team_certificate(header(certificate())), TEAM_DID_KEY)


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
    encoded = base64.b64encode(json.dumps(cert).replace('"bond"', '"\\ud800"').encode()).decode()
    decoded = decode_team_certificate(encoded)
    with pytest.raises(TeamCertificateError) as refused:
        verify_team_certificate_signature(decoded, TEAM_DID_KEY)
    assert refused.value.reason == "bad_signature"


def test_the_helper_imports_only_identity_primitives() -> None:
    src = Path(__file__).resolve().parents[1] / "src"
    heavy = ("fastapi", "starlette", "pydantic", "httpx", "pgdbm", "redis", "dns", "typer")
    probe = (
        "import sys\n"
        f"sys.path.insert(0, {str(src)!r})\n"
        "import awid.team_certificate\n"
        f"print(','.join(m for m in {heavy!r} if m in sys.modules))\n"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == ""
