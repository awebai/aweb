"""secrets policies: immutable, digest-addressed records (secrets.md §4.4)."""

from __future__ import annotations

import copy
from datetime import UTC, datetime

import pytest

from aweb_secrets.policy import AttestationFacts, Policy, PolicyInvalid

OPERATION_DIGEST = "24252d809f32328585e0e05fa02bf474df2cab5ba52b840eba6941f80c1c7fe1"

BODY = {
    "approval": "per_use",
    "approvers": ["apr_1", "apr_2"],
    "approval_ttl_s": 900,
    "rate": [
        {"per": "principal_secret", "capacity": 30, "window_s": 3600},
        {"per": "secret", "capacity": 100, "window_s": 3600},
    ],
    "windows": {
        "time_zone": "Europe/Madrid",
        "ranges": [{"days": ["mon", "tue", "wed", "thu", "fri"], "from": "09:00", "to": "18:00"}],
    },
    "operations": [{"operation_id": "refund", "digest": OPERATION_DIGEST}],
    "open_request": False,
    "request": {"max_bytes": 1048576},
    "result": {"max_bytes": 65536},
    "requires_attestation": None,
    "distinct_approver": "required",
}


def _body(**changes):
    body = copy.deepcopy(BODY)
    body.update(changes)
    return body


def test_a_policy_is_addressed_by_the_digest_of_its_canonical_form() -> None:
    reordered = dict(reversed(list(copy.deepcopy(BODY).items())))
    assert Policy.from_body(BODY).digest == Policy.from_body(reordered).digest
    assert len(Policy.from_body(BODY).digest) == 64


@pytest.mark.parametrize(
    "change",
    [
        {"approval": "none"},
        {"approval_ttl_s": 600},
        {"open_request": True},
        {"distinct_approver": "not_required"},
        {"operations": []},
    ],
)
def test_any_change_gives_a_new_digest(change) -> None:
    assert Policy.from_body(_body(**change)).digest != Policy.from_body(BODY).digest


def test_the_canonical_body_round_trips_to_the_same_digest() -> None:
    policy = Policy.from_body(BODY)
    assert Policy.from_body(policy.body).digest == policy.digest


@pytest.mark.parametrize(
    "change",
    [
        {"approval": "sometimes"},
        {"approval_ttl_s": 0},
        {"approval_ttl_s": 900.5},
        {"approval_ttl_s": True},
        {"rate": [{"per": "team", "capacity": 1, "window_s": 60}]},
        {"rate": [{"per": "secret", "capacity": 0, "window_s": 60}]},
        {"rate": [{"per": "secret", "capacity": 1, "window_s": 60, "burst": 2}]},
        {"windows": {"time_zone": "Mars/Olympus", "ranges": []}},
        {
            "windows": {
                "time_zone": "UTC",
                "ranges": [{"days": ["sun"], "from": "18:00", "to": "09:00"}],
            }
        },
        {
            "windows": {
                "time_zone": "UTC",
                "ranges": [{"days": ["someday"], "from": "09:00", "to": "18:00"}],
            }
        },
        {
            "windows": {
                "time_zone": "UTC",
                "ranges": [{"days": ["mon"], "from": "9:00", "to": "18:00"}],
            }
        },
        {"operations": [{"operation_id": "refund", "digest": "sha256:" + OPERATION_DIGEST}]},
        {"operations": [{"operation_id": "Refund Now", "digest": OPERATION_DIGEST}]},
        {"open_request": "yes"},
        {"distinct_approver": "maybe"},
        {"requires_attestation": {"channels": ["fax"]}},
        {"requires_attestation": {}},
        {"result": {"max_bytes": 0}},
        {"request": {"max_bytes": 1048577}},
        {"request": {"max_bytes": 0}},
        {"request": {}},
        {"surprise": 1},
    ],
)
def test_a_malformed_policy_is_refused(change) -> None:
    with pytest.raises(PolicyInvalid):
        Policy.from_body(_body(**change))


@pytest.mark.parametrize("missing", sorted(BODY))
def test_every_field_is_required(missing) -> None:
    body = copy.deepcopy(BODY)
    del body[missing]
    with pytest.raises(PolicyInvalid):
        Policy.from_body(body)


def test_per_use_approval_needs_an_approver() -> None:
    with pytest.raises(PolicyInvalid):
        Policy.from_body(_body(approvers=[]))
    Policy.from_body(_body(approval="none", approvers=[]))


# 2026-10-20 is a Tuesday; Madrid is UTC+2 until 2026-10-25.
@pytest.mark.parametrize(
    ("instant", "open_"),
    [
        (datetime(2026, 10, 20, 7, 0, tzinfo=UTC), True),
        (datetime(2026, 10, 20, 6, 59, tzinfo=UTC), False),
        (datetime(2026, 10, 20, 16, 0, tzinfo=UTC), False),
        (datetime(2026, 10, 18, 10, 0, tzinfo=UTC), False),
        # After the change to UTC+1, 08:30 UTC is 09:30 in Madrid.
        (datetime(2026, 10, 26, 8, 30, tzinfo=UTC), True),
    ],
)
def test_windows_are_evaluated_in_the_owner_time_zone(instant, open_) -> None:
    assert Policy.from_body(BODY).window_open(instant) is open_


def test_a_policy_without_windows_is_always_open() -> None:
    policy = Policy.from_body(_body(windows=None))
    assert policy.window_open(datetime(2026, 10, 18, 3, 0, tzinfo=UTC))


def test_window_evaluation_needs_an_aware_instant() -> None:
    with pytest.raises(ValueError):
        Policy.from_body(BODY).window_open(datetime(2026, 10, 20, 9, 0))


ATTESTED = AttestationFacts(custodian_id="cust_hosted", channel="dashboard", human_principal="h_1")


@pytest.mark.parametrize(
    ("predicate", "facts", "satisfied"),
    [
        ({"custodial_via": "cust_hosted"}, ATTESTED, True),
        ({"custodial_via": "cust_other"}, ATTESTED, False),
        ({"channels": ["dashboard", "api"]}, ATTESTED, True),
        ({"channels": ["api"]}, ATTESTED, False),
        ({"human_principal": True}, ATTESTED, True),
        (
            {"human_principal": True},
            AttestationFacts(custodian_id="cust_hosted", channel="api", human_principal=None),
            False,
        ),
        ({"channels": ["dashboard"]}, None, False),
    ],
)
def test_attestation_predicates(predicate, facts, satisfied) -> None:
    policy = Policy.from_body(_body(requires_attestation=predicate))
    assert policy.requires_attestation
    assert policy.attestation_satisfied(facts) is satisfied


def test_a_policy_without_attestation_predicates_needs_no_attestation() -> None:
    policy = Policy.from_body(BODY)
    assert not policy.requires_attestation
    assert policy.attestation_satisfied(None)
