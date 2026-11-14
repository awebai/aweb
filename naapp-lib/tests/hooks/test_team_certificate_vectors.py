"""What the delivery receiver answers for each shared certificate case.

The receiver checks that a client delivery's certificate names its producer,
and then calls the one check with what the registry says about the team.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

import pytest
from awid.protected_membership import TeamProtectionObservation

from aweb_naapp.hooks.delivery import ReceiveOptions, _verify_client_certificate
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
        _verify_client_certificate(
            case["certificate_header"],
            delivery,
            ReceiveOptions(
                protection_observation=TeamProtectionObservation(VECTORS["team_id"], case["team_did_key"], {"mode": "legacy"}, monotonic()+60),
                audience="https://logs.example.com",
                binding_id="binding",
                now=datetime(2026, 11, 2, tzinfo=UTC),
                team_key_did=case["team_did_key"],
                revoked_certificate_ids=case["revoked_certificate_ids"],
                registered_certificate_ids=case["registered_certificate_ids"],
            ),
        )
        answered = "accepted"
    except Refused as refused:
        answered = refused.code
    assert answered == case["today"]["hooks"]
