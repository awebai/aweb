"""What the server's certificate check answers for each shared case."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from awid.team_certificate import (
    TeamCertificateError,
    TeamCertificateReason,
    check_team_certificate_evidence,
    verify_team_certificate_claims,
)
from httpx import ASGITransport, AsyncClient

from aweb.api import create_app
from aweb.team_auth import certificate_refusal

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "docs/vectors/team-certificate-verification-v1.json").read_text()
)


def _check(case: dict, *, registered: bool) -> None:
    claims = verify_team_certificate_claims(
        case["certificate_header"],
        subject_did_key=case["request_did_key"],
        team_did_key=case["team_did_key"],
    )
    check_team_certificate_evidence(
        claims,
        revoked_certificate_ids=case["revoked_certificate_ids"],
        registered_certificate_ids=case["registered_certificate_ids"] if registered else None,
    )


def _verdict(case: dict, *, registered: bool) -> dict | None:
    try:
        _check(case, registered=registered)
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


def test_every_refusal_is_an_invalid_credential_with_a_diagnostic() -> None:
    for case in VECTORS["cases"]:
        if case["expected"] is None:
            continue
        with pytest.raises(TeamCertificateError) as refused:
            _check(case, registered=True)
        answer = certificate_refusal(refused.value)
        assert answer.status_code == 401, case["name"]
        assert answer.certificate_error is refused.value
        expected = case["expected"]
        if expected["reason"] == "revoked":
            assert answer.certificate_error.reason is TeamCertificateReason.REVOKED
            assert answer.detail["code"] == "certificate_revoked"
        else:
            detail = expected["reason"] if "field" not in expected else f"{expected['reason']}: {expected['field']}"
            assert answer.detail == detail, case["name"]


def test_a_registry_key_that_does_not_decode_is_the_registrys_fault() -> None:
    answer = certificate_refusal(TeamCertificateError("invalid_team_key"))
    assert (answer.status_code, answer.detail) == (503, "authority_unavailable")


@pytest.mark.asyncio
async def test_verified_revoked_certificate_has_named_http_refusal() -> None:
    case = next(case for case in VECTORS["cases"] if case["name"] == "revoked")
    app = create_app()

    @app.post("/certificate")
    async def authorize() -> None:
        try:
            _check(case, registered=True)
        except TeamCertificateError as exc:
            raise certificate_refusal(exc) from None
        pytest.fail("revoked certificate was accepted")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://native.test"
    ) as client:
        response = await client.post("/certificate")

    assert response.status_code == 401
    assert response.json() == {
        "detail": {
            "code": "certificate_revoked",
            "message": (
                "This team certificate has been revoked. "
                "Ask the team's owner for a new certificate."
            ),
        }
    }
