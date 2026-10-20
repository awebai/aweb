"""The grant record v1 (§4.3): who may use or run a secret, under which policy."""

from __future__ import annotations

import copy

import pytest

from aweb_secrets.grant import GrantInvalid, GrantRecord, mint_grant_id

OPERATION = {"operation_id": "refund", "digest": "a" * 64}
JOB = {"job_id": "nightly-backup", "digest": "b" * 64}
POLICY = "c" * 64

USE = {
    "v": 1,
    "grant_id": "grt_77c1aa",
    "secret_id": "sec_19ab42",
    "subject": {"principal": "did:aw:2rMeyRyvQbWUZYjT8Jx6Kq"},
    "capability": "use",
    "operations": [OPERATION],
    "open_request": False,
    "jobs": [],
    "policy_digest": POLICY,
}


def _grant(**changes):
    grant = copy.deepcopy(USE)
    grant.update(changes)
    return grant


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"subject": {"principal": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"}},
        {"subject": {"role": "secrets.role.deployers"}},
        {"subject": {"role": "secrets.owner"}},
        {"operations": [], "open_request": True},
        {"capability": "run", "operations": [], "jobs": [JOB]},
    ],
)
def test_well_formed_grants_round_trip(change) -> None:
    grant = _grant(**change)
    assert GrantRecord.from_after(grant).after == grant


@pytest.mark.parametrize(
    "change",
    [
        {"v": 2},
        {"grant_id": "77c1"},
        {"subject": {"principal": "alice"}},
        {"subject": {"role": "deployers"}},
        {"subject": {"role": "logs.reader"}},
        {"subject": {"role": "secrets.role.Deployers"}},
        {"subject": {"principal": "did:aw:x", "role": "secrets.owner"}},
        {"subject": {}},
        {"capability": "read"},
        {"operations": [], "open_request": False},
        {"operations": [OPERATION], "open_request": True},
        {"operations": [OPERATION, OPERATION]},
        {"operations": [{"operation_id": "refund", "digest": "A" * 64}]},
        {"jobs": [JOB]},
        {"capability": "run", "operations": [], "jobs": []},
        {"capability": "run", "operations": [OPERATION], "jobs": [JOB]},
        {"capability": "run", "operations": [], "open_request": True, "jobs": [JOB]},
        {"policy_digest": "sha256:" + POLICY},
        {"surprise": 1},
    ],
)
def test_a_malformed_grant_is_refused(change) -> None:
    with pytest.raises(GrantInvalid):
        GrantRecord.from_after(_grant(**change))


@pytest.mark.parametrize("missing", sorted(USE))
def test_every_field_is_required(missing) -> None:
    grant = copy.deepcopy(USE)
    del grant[missing]
    with pytest.raises(GrantInvalid):
        GrantRecord.from_after(grant)


def test_a_grant_covers_exactly_its_operation_digests() -> None:
    grant = GrantRecord.from_after(USE)
    assert grant.covers_operation("refund", "a" * 64)
    assert not grant.covers_operation("refund", "d" * 64)
    assert not grant.covers_operation("charge", "a" * 64)


def test_minted_grant_ids_are_valid() -> None:
    grant_id = mint_grant_id()
    assert GrantRecord.from_after(_grant(grant_id=grant_id)).grant_id == grant_id
