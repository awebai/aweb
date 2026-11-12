"""What the server's certificate check answers for each shared case."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from awid.team_certificate import TeamCertificateError

from aweb.team_auth import certificate_refusal, parse_and_verify_certificate

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "docs/vectors/team-certificate-verification-v1.json").read_text()
)


def _verdict(case: dict, *, registered: bool) -> dict | None:
    try:
        parse_and_verify_certificate(
            case["certificate_header"],
            request_did_key=case["request_did_key"],
            team_did_key=case["team_did_key"],
            revoked_certificate_ids=case["revoked_certificate_ids"],
            registered_certificate_ids=case["registered_certificate_ids"] if registered else None,
        )
    except TeamCertificateError as refused:
        return {"reason": refused.reason, **({"field": refused.field} if refused.field else {})}
    return None


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_with_the_registered_set_the_server_gives_each_case_its_expected_verdict(case: dict) -> None:
    assert _verdict(case, registered=True) == case["expected"]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_without_the_registered_set_the_server_answers_as_recorded(case: dict) -> None:
    answered = "accepted" if _verdict(case, registered=False) is None else "refused"
    assert answered == case["today"]["server"]
    # The one staged difference: registration is not checked while its requirement is off.
    if answered == "accepted":
        assert case["expected"] is None or case["expected"] == {"reason": "unregistered"}


def test_every_refusal_is_an_invalid_credential_and_says_only_its_reason() -> None:
    for case in VECTORS["cases"]:
        if case["expected"] is None:
            continue
        with pytest.raises(TeamCertificateError) as refused:
            parse_and_verify_certificate(
                case["certificate_header"],
                request_did_key=case["request_did_key"],
                team_did_key=case["team_did_key"],
                revoked_certificate_ids=case["revoked_certificate_ids"],
                registered_certificate_ids=case["registered_certificate_ids"],
            )
        answer = certificate_refusal(refused.value)
        expected = case["expected"]
        detail = expected["reason"] if "field" not in expected else f"{expected['reason']}: {expected['field']}"
        assert (answer.status_code, answer.detail) == (401, detail), case["name"]


def test_a_registry_key_that_does_not_decode_is_the_registrys_fault() -> None:
    answer = certificate_refusal(TeamCertificateError("invalid_team_key"))
    assert (answer.status_code, answer.detail) == (503, "authority_unavailable")
