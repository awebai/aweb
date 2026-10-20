"""The Python owner-act verifier against the public owner-act vector."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aweb_naapp.hooks.owner_act import Refused
from aweb_naapp.hooks.owner_act import _verify_owner_act as verify_owner_act

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTOR = json.loads((AWEB_ROOT / "docs" / "vectors" / "owner-act-v1.json").read_bytes())


def _b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _verify(case: dict):
    options = case["verify"]
    return verify_owner_act(
        _b64url(case["signing_bytes_b64url"]),
        case["signature_b64"],
        team_id=options["team_id"],
        current_team_key_did=options["current_team_key_did"],
        audience=options["audience"],
        acts=options["acts"],
        now=datetime.strptime(options["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        expected_subject=options["expected_subject"],
        nonce_used=lambda nonce: options["nonce_used"],
    )


@pytest.mark.parametrize("case", VECTOR["positive_cases"], ids=lambda c: c["name"])
def test_positive_case_verifies(case) -> None:
    act = _verify(case)
    assert act.act == case["act"]["act"]
    assert act.subject == case["act"]["subject"]


@pytest.mark.parametrize("case", VECTOR["negative_cases"], ids=lambda c: c["name"])
def test_negative_case_is_refused_with_its_code(case) -> None:
    with pytest.raises(Refused) as refused:
        _verify(case)
    assert refused.value.code == case["error"]


def test_vocabularies_match_the_vector() -> None:
    from aweb_naapp.hooks.owner_act import APP_ACTS, CORE_ACTS, LOGS_ACTS

    vocabularies = VECTOR["scheme"]["vocabularies"]
    assert (list(CORE_ACTS), list(APP_ACTS), list(LOGS_ACTS)) == (
        vocabularies["core"],
        vocabularies["app"],
        vocabularies["logs"],
    )


@pytest.mark.parametrize(
    "missing",
    [
        "team_id",
        "current_team_key_did",
        "audience",
        "acts",
        "now",
        "expected_subject",
        "nonce_used",
    ],
)
def test_every_option_is_required(missing) -> None:
    case = VECTOR["positive_cases"][0]
    options = case["verify"]
    kwargs = {
        "team_id": options["team_id"],
        "current_team_key_did": options["current_team_key_did"],
        "audience": options["audience"],
        "acts": options["acts"],
        "now": datetime.strptime(options["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        "expected_subject": options["expected_subject"],
        "nonce_used": lambda nonce: False,
    }
    kwargs[missing] = (
        None if missing in ("now", "expected_subject", "nonce_used") else type(kwargs[missing])()
    )
    with pytest.raises(Refused) as refused:
        verify_owner_act(_b64url(case["signing_bytes_b64url"]), case["signature_b64"], **kwargs)
    assert refused.value.code == "verifier_misconfigured"


def test_a_naive_clock_is_refused() -> None:
    case = VECTOR["positive_cases"][0]
    options = case["verify"]
    with pytest.raises(Refused) as refused:
        verify_owner_act(
            _b64url(case["signing_bytes_b64url"]),
            case["signature_b64"],
            team_id=options["team_id"],
            current_team_key_did=options["current_team_key_did"],
            audience=options["audience"],
            acts=options["acts"],
            now=datetime.strptime(options["now"], "%Y-%m-%dT%H:%M:%SZ"),
            expected_subject=options["expected_subject"],
            nonce_used=lambda nonce: False,
        )
    assert refused.value.code == "verifier_misconfigured"


def test_only_the_verified_type_and_constants_are_public() -> None:
    import aweb_naapp.hooks.owner_act as owner_act

    assert set(owner_act.__all__) == {
        "APP_ACTS",
        "CORE_ACTS",
        "LOGS_ACTS",
        "PREFIX",
        "Refused",
        "VerifiedOwnerAct",
    }
    for private in ("check_owner_act", "require_subject", "verify_owner_act", "OwnerAct"):
        assert not hasattr(owner_act, private)
