"""Building owner-act signing bytes in Python, against the public owner-act
vector: a signer gets the vector's exact bytes for every act, and is refused,
with the verifier's own code, for an act whose fields are wrong."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from aweb_naapp.hooks.owner_act import (
    PREFIX,
    Refused,
    hook_binding_subject,
    owner_act_signing_bytes,
)

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTOR = json.loads((AWEB_ROOT / "docs" / "vectors" / "owner-act-v1.json").read_bytes())

# Refusals that come from the act itself, which a signer must refuse too.
FIELD_REFUSALS = {
    "unknown_act",
    "unknown_field",
    "missing_field",
    "invalid_value",
    "lifetime_too_long",
}
# Refusals of bytes a dict cannot express (or of a different artifact).
BYTE_REFUSALS = {
    "duplicate_key",
    "float_value",
    "null_value",
    "string_not_ascii",
    "not_canonical",
    "wrong_prefix",
}


def _b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _act(case: dict) -> dict:
    return json.loads(_b64url(case["signing_bytes_b64url"])[len(PREFIX) :])


@pytest.mark.parametrize("case", VECTOR["positive_cases"], ids=lambda c: c["name"])
def test_a_valid_act_gives_the_vector_bytes(case) -> None:
    assert owner_act_signing_bytes(case["act"]) == _b64url(case["signing_bytes_b64url"])


@pytest.mark.parametrize(
    "case",
    [c for c in VECTOR["negative_cases"] if c["error"] in FIELD_REFUSALS],
    ids=lambda c: c["name"],
)
def test_an_act_with_wrong_fields_is_refused_with_the_verifiers_code(case) -> None:
    with pytest.raises(Refused) as refused:
        owner_act_signing_bytes(_act(case))
    assert refused.value.code == case["error"]


@pytest.mark.parametrize(
    "case",
    [
        c
        for c in VECTOR["negative_cases"]
        if c["error"] not in FIELD_REFUSALS and c["error"] not in BYTE_REFUSALS
    ],
    ids=lambda c: c["name"],
)
def test_the_verifiers_own_facts_do_not_change_the_bytes(case) -> None:
    assert owner_act_signing_bytes(_act(case)) == _b64url(case["signing_bytes_b64url"])


def test_a_value_json_cannot_carry_is_refused() -> None:
    act = VECTOR["positive_cases"][0]["act"]
    with pytest.raises(Refused) as refused:
        owner_act_signing_bytes({**act, "v": 1.0})
    assert refused.value.code == "invalid_value"


def _binding(case_name: str) -> dict:
    return next(c for c in VECTOR["positive_cases"] if c["name"] == case_name)["act"]["subject"]


def test_the_binding_builder_gives_the_vector_registration_subject() -> None:
    expected = _binding("activate_registration_sorted_scopes")
    built = hook_binding_subject(
        **{k: v for k, v in expected.items() if k != "scopes"},
        scopes=["logs:read", "logs:ingest", "logs:read"],
    )
    assert built == expected


def test_the_binding_builder_gives_the_vector_production_subject() -> None:
    expected = _binding("activate_production")
    assert hook_binding_subject(**expected) == expected


def test_the_binding_builder_sorts_and_dedupes_reads() -> None:
    expected = _binding("activate_production")
    built = hook_binding_subject(**{**expected, "reads": ["list", "get", "list"]})
    assert built["reads"] == ["get", "list"]


def test_a_built_subject_signs_like_the_vector() -> None:
    case = next(
        c for c in VECTOR["positive_cases"] if c["name"] == "activate_registration_sorted_scopes"
    )
    subject = case["act"]["subject"]
    act = {**case["act"], "subject": hook_binding_subject(**subject)}
    assert owner_act_signing_bytes(act) == _b64url(case["signing_bytes_b64url"])


@pytest.mark.parametrize("name", ["scopes", "reads"])
def test_the_binding_builder_refuses_a_string_for_a_list(name) -> None:
    kind = "activate_registration_sorted_scopes" if name == "scopes" else "activate_production"
    with pytest.raises(TypeError, match=name):
        hook_binding_subject(**{**_binding(kind), name: "ingest"})
