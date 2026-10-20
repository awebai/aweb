"""The Python delivery credential against the public delivery vector."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aweb_naapp.hooks.delivery import ReceiveOptions, sign_delivery, verify_delivery
from aweb_naapp.hooks.envelope import Refused

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTOR = json.loads(
    (AWEB_ROOT / "docs" / "vectors" / "hook-delivery-credential-v1.json").read_bytes()
)


def _b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _time(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _options(receive: dict) -> ReceiveOptions:
    return ReceiveOptions(
        audience=receive["audience"],
        binding_id=receive["binding_id"],
        team_key_did=receive.get("team_key_did", ""),
        now=_time(receive["now"]),
    )


@pytest.mark.parametrize("case", VECTOR["positive_cases"], ids=lambda c: c["name"])
def test_positive_case_regenerates_and_verifies(case) -> None:
    delivery = sign_delivery(
        bytes.fromhex(case["seed_hex"]),
        "POST",
        case["target"],
        case["binding_id"],
        _b64url(case["event_signing_bytes_b64url"]),
        case["event_signature_b64"],
        case.get("certificate"),
        _time(case["timestamp"]),
    )
    assert delivery.body == case["body"].encode()
    assert delivery.signed_payload == case["canonical_signed_payload"].encode()
    assert delivery.headers == case["headers"]
    received = verify_delivery(
        "POST", delivery.path, delivery.headers, delivery.body, _options(case["receive"])
    )
    assert received.envelope.team_id == "demo:example.com"


@pytest.mark.parametrize("case", VECTOR["negative_cases"], ids=lambda c: c["name"])
def test_negative_case_is_refused_with_its_code(case) -> None:
    with pytest.raises(Refused) as refused:
        verify_delivery(
            case["method"],
            case["path"],
            case["headers"],
            case["body"].encode(),
            _options(case["receive"]),
        )
    assert refused.value.code == case["error"]


def test_verify_delivery_requires_the_targets_own_facts() -> None:
    case = VECTOR["positive_cases"][0]
    body = case["body"].encode()
    for receive in (
        dict(case["receive"], audience=""),
        dict(case["receive"], binding_id=""),
    ):
        with pytest.raises(Refused) as refused:
            verify_delivery("POST", "/hooks/ingest", case["headers"], body, _options(receive))
        assert refused.value.code == "verifier_misconfigured"


def test_a_naive_clock_or_timestamp_is_refused() -> None:
    case = VECTOR["positive_cases"][0]
    naive = datetime.strptime(case["receive"]["now"], "%Y-%m-%dT%H:%M:%SZ")
    options = ReceiveOptions(
        audience=case["receive"]["audience"],
        binding_id=case["receive"]["binding_id"],
        team_key_did=case["receive"]["team_key_did"],
        now=naive,
    )
    with pytest.raises(Refused) as refused:
        verify_delivery("POST", "/hooks/ingest", case["headers"], case["body"].encode(), options)
    assert refused.value.code == "verifier_misconfigured"
    with pytest.raises(Refused) as refused:
        sign_delivery(
            bytes.fromhex(case["seed_hex"]),
            "POST",
            case["target"],
            case["binding_id"],
            _b64url(case["event_signing_bytes_b64url"]),
            case["event_signature_b64"],
            None,
            datetime.strptime(case["timestamp"], "%Y-%m-%dT%H:%M:%SZ"),
        )
    assert refused.value.code == "verifier_misconfigured"


def test_a_lone_surrogate_in_a_client_certificate_is_refused_not_a_crash() -> None:
    case = next(c for c in VECTOR["positive_cases"] if "certificate" in c)
    certificate = base64.b64decode(case["certificate"]).decode()
    poisoned = certificate.replace('"alias":"bond"', '"alias":"bond","note":"\\ud800"')
    assert poisoned != certificate
    headers = dict(
        case["headers"], **{"X-AWID-Team-Certificate": base64.b64encode(poisoned.encode()).decode()}
    )
    with pytest.raises(Refused) as refused:
        verify_delivery(
            "POST", "/hooks/ingest", headers, case["body"].encode(), _options(case["receive"])
        )
    assert refused.value.code == "certificate_invalid"
