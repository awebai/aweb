"""The app credential signer against the app-read-credential-v1 vector.

The vector is the server verifier's own (server/tests/test_app_grant_status.py
sends every case through the real route), so byte-parity here means this signer
produces exactly what the server accepts, and nothing it refuses.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb_naapp.runtime.app_credentials import (
    APP_EVENT,
    APP_GRANT_READ,
    HOOK_RESOLVE,
    PURPOSES,
    AppCredentialSigner,
)
from aweb_naapp.runtime.app_emit import sign_app_emit_credential
from aweb_naapp.runtime.app_keys import AppKey

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTOR = json.loads(
    (AWEB_ROOT / "test-vectors" / "app-read-credential-v1.json").read_text(encoding="utf-8")
)
ONE_ENCODING_SIGNATURE = re.compile(r"[A-Za-z0-9+/]{85}[AQgw]")


def _key(seed_hex: str, kid: str) -> AppKey:
    signing_key = SigningKey(bytes.fromhex(seed_hex))
    return AppKey(
        kid=kid, did_key=did_from_public_key(bytes(signing_key.verify_key)), signing_key=signing_key
    )


def _signer(case: dict, purpose: str) -> AppCredentialSigner:
    payload = case["payload"]
    return AppCredentialSigner(
        app_id=payload["app_id"],
        key=_key(VECTOR["seed_hex"], payload["kid"]),
        purpose=purpose,
    )


def _sign(case: dict, purpose: str):
    payload = case["payload"]
    return _signer(case, purpose).sign(
        method=case["method"],
        target=f"{payload['aud']}{case['path']}",
        team_id=payload["team_id"],
        body=case["body"].encode(),
        timestamp=payload["timestamp"],
    )


def _purpose_of(case: dict) -> str | None:
    """The purpose a case's prefix and signed auth both name, if they agree."""
    authorization = case["headers"]["Authorization"]
    for purpose, spec in PURPOSES.items():
        if authorization.startswith(spec.prefix) and case["payload"]["auth"] == spec.auth:
            return purpose
    return None


def test_the_signers_purpose_table_equals_the_vectors():
    # The vector is the one list of app credential purposes; the server and this
    # signer each assert equality with it, so neither can add one alone.
    assert {
        purpose: {"prefix": spec.prefix, "auth": spec.auth} for purpose, spec in PURPOSES.items()
    } == VECTOR["purposes"]


@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda case: case["name"])
def test_grant_read_credentials_are_byte_identical_to_the_vector(case):
    credential = _sign(case, case["purpose"])

    assert credential.canonical_payload == case["canonical_payload"]
    assert credential.signed_payload_b64url == case["signed_payload_b64url"]
    assert credential.signature_b64 == case["signature_b64"]
    assert {
        name: value for name, value in credential.headers.items() if name != "Content-Type"
    } == {name: value for name, value in case["headers"].items() if name != "Content-Type"}


@pytest.mark.parametrize("case", VECTOR["negative_cases"], ids=lambda case: case["name"])
def test_a_refused_credential_is_only_ever_a_correct_one_sent_to_the_wrong_route(case):
    authorization = case["headers"]["Authorization"]
    produced = {_sign(case, purpose).headers["Authorization"] for purpose in PURPOSES}
    purpose = _purpose_of(case)
    canonically_signed = authorization.endswith(" " + case["signature_b64"])

    if purpose is not None and canonically_signed:
        # Prefix and signed auth agree and the signature is canonical: the route
        # refuses it because it serves another purpose, and the signer for that
        # purpose produces exactly these bytes.
        assert _sign(case, purpose).headers["Authorization"] == authorization
    else:
        # A prefix/auth mismatch or a re-encoded signature: no signer produces it.
        assert authorization not in produced


@pytest.mark.parametrize("purpose", sorted(PURPOSES))
def test_every_signature_has_the_one_accepted_encoding(purpose):
    case = VECTOR["cases"][0]
    for second in range(50):
        credential = _signer(case, purpose).sign(
            method="GET",
            target=f"https://app.aweb.ai/v1/apps/self/grant?n={second}",
            team_id="backend:acme.com",
            body=b"",
            timestamp=f"2026-10-20T12:00:{second:02d}Z",
        )
        assert ONE_ENCODING_SIGNATURE.fullmatch(credential.signature_b64), credential.signature_b64


def test_the_app_event_purpose_signs_exactly_as_the_released_emit_signer():
    case = VECTOR["cases"][0]
    key = _key(VECTOR["seed_hex"], "emit-1")
    body = b'{"type":"folio/doc.changed","resource_ref":"pitch","payload":{}}'

    credential = AppCredentialSigner(app_id="folio", key=key, purpose=APP_EVENT).sign(
        method="POST",
        target="https://app.aweb.ai/v1/events/app",
        team_id="backend:acme.com",
        body=body,
        timestamp=case["payload"]["timestamp"],
    )
    released = sign_app_emit_credential(
        private_key=bytes(key.signing_key),
        method="POST",
        target="https://app.aweb.ai/v1/events/app",
        team_id="backend:acme.com",
        app_id="folio",
        key_id="emit-1",
        body=body,
        timestamp=case["payload"]["timestamp"],
    )

    assert credential.headers == released.headers


def test_the_default_timestamp_is_now_in_utc_seconds():
    case = VECTOR["cases"][0]
    before = datetime.now(UTC).replace(microsecond=0)

    credential = _signer(case, APP_GRANT_READ).sign(
        method="GET", target="https://app.aweb.ai/v1/apps/self/grant", team_id="backend:acme.com"
    )

    stamped = datetime.strptime(credential.headers["X-AWEB-Timestamp"], "%Y-%m-%dT%H:%M:%SZ")
    assert before <= stamped.replace(tzinfo=UTC) <= datetime.now(UTC)
    assert (
        json.loads(credential.canonical_payload)["timestamp"]
        == credential.headers["X-AWEB-Timestamp"]
    )


def test_an_unknown_purpose_is_refused():
    case = VECTOR["cases"][0]
    with pytest.raises(ValueError):
        _signer(case, "app-usage")


def test_a_key_whose_did_key_is_not_its_public_key_is_refused():
    real = _key(VECTOR["seed_hex"], "read-1")
    other = _key("22" * 32, "read-1")
    mismatched = AppKey(kid="read-1", did_key=other.did_key, signing_key=real.signing_key)

    with pytest.raises(ValueError):
        AppCredentialSigner(app_id="folio", key=mismatched, purpose=HOOK_RESOLVE)


def test_key_material_never_appears_in_the_signers_repr():
    case = VECTOR["cases"][0]
    signer = _signer(case, APP_GRANT_READ)

    assert VECTOR["seed_hex"] not in repr(signer)
    assert VECTOR["seed_hex"] not in str(signer)
