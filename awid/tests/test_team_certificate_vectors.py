"""What awid's team-certificate primitive answers for each shared case.

The primitive decodes the header and checks the signature; the certificate's
fields, its signer and its standing at the registry are its callers' to check.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from awid.team_certificate import (
    TeamCertificateError,
    decode_team_certificate,
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
        assert case["expected"] is None or case["expected"] in VECTORS["reasons"], case["name"]
        assert set(case["today"]) == set(VECTORS["today_verifiers"]), case["name"]
