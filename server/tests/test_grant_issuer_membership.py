"""Pure stored issuer equality; route and presence regressions are separate."""

import pytest
from aweb.member_team_key import grant_issuer_current


@pytest.mark.parametrize(
    ("issuer", "current", "expected"),
    [
        ("issued", "issued", True),
        ("issued", "replacement", False),
        ("issued", None, False),
        ("issued", "", False),
        (None, None, True),
        (None, "replacement", True),
    ],
    ids=[
        "current",
        "superseded",
        "no-current-certificate",
        "empty-current-certificate",
        "issuer-less",
        "issuer-less-with-current",
    ],
)
def test_issuer_bound_grant_requires_its_exact_current_certificate(issuer, current, expected):
    # Deliberate unit inputs. No row or cache is represented as admission proof.
    row = {
        "identity_scope": "local",
        "accepted_team_did_key": "unit-controller",
        "current_team_did_key": "unit-controller",
        "issued_by_certificate_id": issuer,
        "certificate_id": current,
    }
    assert grant_issuer_current(row) is expected
