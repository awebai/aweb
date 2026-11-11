"""What the delivery receiver answers for each shared certificate case.

The receiver checks that a client delivery's certificate names its producer and
is signed under the team's current key. Revocation is its caller's to check.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aweb_naapp.hooks.delivery import _verify_client_certificate
from aweb_naapp.hooks.envelope import Envelope, Refused

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "docs/vectors/team-certificate-verification-v1.json").read_text()
)


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_the_receiver_answers_each_case_as_recorded(case: dict) -> None:
    delivery = Envelope(
        fields={"producer": {"certificate_id": "cert-001"}},
        hook="example.hook",
        event_id="event-1",
        team_id=VECTORS["team_id"],
        producer_kind="client",
        producer_did_key=case["request_did_key"],
        producer_kid="member",
        producer="client:cert-001",
    )
    try:
        _verify_client_certificate(case["certificate_header"], delivery, case["team_did_key"])
        answered = "accepted"
    except Refused as refused:
        answered = refused.code
    assert answered == case["today"]["hooks"]
