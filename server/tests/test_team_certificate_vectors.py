"""What the server's certificate check answers for each shared case."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from aweb.team_auth import parse_and_verify_certificate

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "docs/vectors/team-certificate-verification-v1.json").read_text()
)


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_the_server_answers_each_case_as_recorded(case: dict) -> None:
    revoked = set(case["revoked_certificate_ids"])
    try:
        parse_and_verify_certificate(
            case["certificate_header"],
            request_did_key=case["request_did_key"],
            team_public_key_resolver=lambda _team_id: case["team_did_key"],
            revocation_checker=lambda _team_id, certificate_id: certificate_id in revoked,
        )
        answered = "accepted"
    except ValueError:
        answered = "refused"
    assert answered == case["today"]["server"]
