"""The Python envelope reader and signer against the public envelope vector."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from aweb_naapp.hooks.envelope import Refused, sign, signing_bytes, verify

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTOR = json.loads((AWEB_ROOT / "docs" / "vectors" / "hook-event-envelope-v1.json").read_bytes())


def _b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@pytest.mark.parametrize("case", VECTOR["positive_cases"], ids=lambda c: c["name"])
def test_positive_case_regenerates_and_verifies(case) -> None:
    seed = bytes.fromhex(case["seed_hex"])
    signing, signature = sign(seed, case["envelope"])
    assert signing == _b64url(case["signing_bytes_b64url"])
    assert signature == case["signature_b64"]
    envelope = verify(signing, signature, team_id=case["envelope"]["team_id"])
    assert envelope.event_id == case["envelope"]["event_id"]


@pytest.mark.parametrize("case", VECTOR["negative_cases"], ids=lambda c: c["name"])
def test_negative_case_is_refused_at_its_layer(case) -> None:
    signing = _b64url(case["signing_bytes_b64url"])
    if case["layer"] == "catalog":
        verify(signing, case["signature_b64"], team_id=case["verify_team_id"])
        return
    with pytest.raises(Refused) as refused:
        verify(signing, case["signature_b64"], team_id=case["verify_team_id"])
    assert refused.value.code == case["error"]


def test_verify_requires_an_expected_team() -> None:
    case = VECTOR["positive_cases"][0]
    with pytest.raises(Refused) as refused:
        verify(_b64url(case["signing_bytes_b64url"]), case["signature_b64"], team_id="")
    assert refused.value.code == "verifier_misconfigured"


def test_sign_refuses_a_key_that_is_not_the_producer() -> None:
    case = VECTOR["positive_cases"][0]
    with pytest.raises(Refused) as refused:
        sign(bytes(32), case["envelope"])
    assert refused.value.code == "signer_mismatch"


def test_signing_bytes_refuse_an_invalid_envelope() -> None:
    envelope = dict(VECTOR["positive_cases"][0]["envelope"], note="x")
    with pytest.raises(Refused) as refused:
        signing_bytes(envelope)
    assert refused.value.code == "unknown_field"


def test_deep_nesting_is_refused_before_parsing() -> None:
    hostile = b"aweb.hook-event/1\n" + b"[" * 1_000_000
    with pytest.raises(Refused) as refused:
        verify(hostile, "A" * 86, team_id="demo:example.com")
    assert refused.value.code == "too_deep"


def test_hook_table_matches_the_catalog_vector() -> None:
    from aweb_naapp.hooks.catalog import load_catalog
    from aweb_naapp.hooks.envelope import HOOKS

    catalog = load_catalog((AWEB_ROOT / "docs" / "vectors" / "hook-catalog-v1.json").read_bytes())
    assert HOOKS == {
        name: (hook.hook_class, hook.producer_kinds) for name, hook in catalog.hooks.items()
    }


def test_an_integer_too_long_for_int_is_refused_before_parsing_it() -> None:
    from aweb_naapp.hooks.strictjson import parse_strict

    for text in (b'{"a":' + b"1" * 5000 + b"}", b'{"a":-' + b"9" * 17 + b"}"):
        with pytest.raises(Refused) as refused:
            parse_strict(text)
        assert refused.value.code == "invalid_value"
    assert parse_strict(b'{"a":9007199254740991}') == {"a": 9007199254740991}
