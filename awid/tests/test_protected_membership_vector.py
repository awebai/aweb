"""Frozen protected presentation reasons, without altering legacy cert vectors."""

import json
from pathlib import Path

import pytest

from awid import protected_membership
from awid.protected_effect import EffectRefused
from awid.team_certificate import TeamCertificateError

FIXTURE = Path(__file__).resolve().parents[2] / "docs/vectors/protected-membership-v1.json"
VECTOR = json.loads(FIXTURE.read_bytes())


@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda case: case["name"])
def test_protected_membership_reason_vector(monkeypatch, case):
    monkeypatch.setattr(protected_membership, "monotonic", lambda: 99.0)
    registered = VECTOR["registered"]
    observation = protected_membership.TeamProtectionObservation(
        VECTOR["team_id"], VECTOR["controller_did_key"], VECTOR["binding"], 100.0,
        registered["certificate_id"],
        case.get("certificate_sha256", registered["certificate_sha256"]),
        registered["status"],
    )
    if case["expected"] == "accepted":
        assert protected_membership.check_presented_membership(observation, case["certificate"]) == case["certificate"]
    else:
        with pytest.raises((TeamCertificateError, EffectRefused)) as refused:
            protected_membership.check_presented_membership(observation, case["certificate"])
        reason = refused.value.reason if isinstance(refused.value, TeamCertificateError) else refused.value.code
        assert reason == case["expected"]
