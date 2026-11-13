"""What awid's team-certificate primitive answers for each shared case.

The primitive decodes the header and checks the signature; the certificate's
fields, its signer and its standing at the registry are its callers' to check.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from awid.team_certificate import (
    REASONS,
    TeamCertificateError,
    check_team_certificate,
    decode_team_certificate,
    refusal_answer,
    verify_team_certificate_signature,
)

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "docs/vectors/team-certificate-verification-v1.json").read_text()
)


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_the_primitive_answers_each_case_as_recorded(case: dict) -> None:
    try:
        certificate = decode_team_certificate(case["certificate_header"])
        verify_team_certificate_signature(certificate, case["team_did_key"])
        answered = "accepted"
    except TeamCertificateError as refused:
        answered = refused.reason
    assert answered == case["today"]["awid"]


def test_every_case_names_a_known_verdict() -> None:
    assert VECTORS["version"] == 1
    names = [case["name"] for case in VECTORS["cases"]]
    assert len(names) == len(set(names))
    for case in VECTORS["cases"]:
        expected = case["expected"]
        assert expected is None or expected["reason"] in VECTORS["reasons"], case["name"]
        assert expected is None or ("field" in expected) == (expected["reason"] == "invalid_field"), case["name"]
        assert set(case["today"]) == set(VECTORS["today_verifiers"]), case["name"]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_the_shared_check_gives_each_case_its_expected_verdict(case: dict) -> None:
    try:
        certificate = check_team_certificate(
            case["certificate_header"],
            subject_did_key=case["request_did_key"],
            team_did_key=case["team_did_key"],
            revoked_certificate_ids=case["revoked_certificate_ids"],
            registered_certificate_ids=case["registered_certificate_ids"],
        )
        verdict = None
        assert certificate["certificate_id"] == "cert-001"
    except TeamCertificateError as refused:
        verdict = {"reason": refused.reason, **({"field": refused.field} if refused.field else {})}
    assert verdict == case["expected"]


def test_the_reasons_are_the_vector_files_and_a_refusal_echoes_nothing_presented() -> None:
    assert list(REASONS) == VECTORS["reasons"]
    for case in VECTORS["cases"]:
        if case["expected"] is None:
            continue
        with pytest.raises(TeamCertificateError) as refused:
            check_team_certificate(
                case["certificate_header"],
                subject_did_key=case["request_did_key"],
                team_did_key=case["team_did_key"],
                revoked_certificate_ids=case["revoked_certificate_ids"],
                registered_certificate_ids=case["registered_certificate_ids"],
            )
        said = str(refused.value)
        assert said in {refused.value.reason, f"{refused.value.reason}: {refused.value.field}"}, case["name"]


def test_a_caller_without_a_registered_set_says_so_and_only_registration_goes_unchecked() -> None:
    by_name = {case["name"]: case for case in VECTORS["cases"]}

    def check(case: dict) -> None:
        check_team_certificate(
            case["certificate_header"],
            subject_did_key=case["request_did_key"],
            team_did_key=case["team_did_key"],
            revoked_certificate_ids=case["revoked_certificate_ids"],
            registered_certificate_ids=None,
        )

    check(by_name["unregistered"])
    for case in VECTORS["cases"]:
        if case["expected"] is None or case["expected"]["reason"] == "unregistered":
            continue
        with pytest.raises(TeamCertificateError) as refused:
            check(case)
        assert refused.value.reason == case["expected"]["reason"], case["name"]


def test_the_registered_and_revoked_sets_are_not_optional() -> None:
    valid = next(case for case in VECTORS["cases"] if case["name"] == "valid")
    with pytest.raises(TypeError):
        check_team_certificate(  # type: ignore[call-arg]
            valid["certificate_header"],
            subject_did_key=valid["request_did_key"],
            team_did_key=valid["team_did_key"],
        )


def test_a_team_key_that_does_not_decode_is_the_callers_fault_not_the_certificates() -> None:
    valid = next(case for case in VECTORS["cases"] if case["name"] == "valid")
    with pytest.raises(TeamCertificateError) as refused:
        check_team_certificate(
            valid["certificate_header"],
            subject_did_key=valid["request_did_key"],
            team_did_key="did:key:not-a-key",
            revoked_certificate_ids=[],
            registered_certificate_ids=["cert-001"],
        )
    assert refused.value.reason == "invalid_team_key"


def test_every_reason_is_an_invalid_credential_and_only_the_registrys_key_is_a_503() -> None:
    for reason in REASONS:
        field = "alias" if reason == "invalid_field" else None
        detail = reason if field is None else f"{reason}: {field}"
        assert refusal_answer(TeamCertificateError(reason, field)) == (401, detail)
    assert refusal_answer(TeamCertificateError("invalid_team_key")) == (503, "authority_unavailable")
