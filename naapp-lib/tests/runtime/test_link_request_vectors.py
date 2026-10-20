"""The frozen capability-link request vectors (docs/page-links.md §2-§3)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from aweb_naapp.runtime.link_requests import (
    LinkRequestRefused,
    link_request_signing_bytes,
    secret_verifier,
    sign_link_request,
    verify_link_request,
)

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((AWEB_ROOT / "docs" / "vectors" / "link-request-v1.json").read_text())


def at(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def session_key() -> SigningKey:
    return SigningKey(bytes.fromhex(VECTORS["keys"]["session"]["seed_hex"]))


@pytest.mark.parametrize("case", VECTORS["secrets"], ids=lambda case: case["name"])
def test_secret_verifier(case):
    assert secret_verifier(case["secret"]) == case["verifier_sha256"]


@pytest.mark.parametrize("case", VECTORS["valid"], ids=lambda case: case["name"])
def test_signing_bytes_and_signature(case):
    assert link_request_signing_bytes(case["payload"]) == case["signing_bytes"].encode("utf-8")
    assert sign_link_request(case["payload"], session_key()) == case["signature"]


@pytest.mark.parametrize("case", VECTORS["valid"], ids=lambda case: case["name"])
def test_valid_requests_verify(case):
    expected = {key: case["payload"][key] for key in VECTORS["bindings"]}
    verify_link_request(
        case["payload"],
        case["signature"],
        session_did_key=VECTORS["keys"]["session"]["did_key"],
        expected=expected,
        now=at(case["payload"]["issued_at"]),
    )


@pytest.mark.parametrize("case", VECTORS["verification_cases"], ids=lambda case: case["name"])
def test_verification_cases(case):
    def verify():
        verify_link_request(
            case["payload"],
            case["signature"],
            session_did_key=VECTORS["keys"]["session"]["did_key"],
            expected=case["expected"],
            now=at(case["now"]),
        )

    if case["expect"] is None:
        verify()
        return
    with pytest.raises(LinkRequestRefused) as refused:
        verify()
    assert refused.value.code == case["expect"]


@pytest.mark.parametrize("missing", VECTORS["bindings"])
def test_incomplete_bindings_raise(missing):
    case = VECTORS["valid"][0]
    expected = {key: case["payload"][key] for key in VECTORS["bindings"] if key != missing}
    with pytest.raises(ValueError, match="bindings"):
        verify_link_request(
            case["payload"],
            case["signature"],
            session_did_key=VECTORS["keys"]["session"]["did_key"],
            expected=expected,
            now=at(case["payload"]["issued_at"]),
        )
