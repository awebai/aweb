"""The grant record v1 (§4.3): who may use or run a secret, under which policy."""

from __future__ import annotations

import copy

import pytest
from awid.did import did_from_public_key, stable_id_from_public_key
from nacl.signing import SigningKey

from aweb_secrets.grant import GrantInvalid, GrantRecord, GrantTemplate, mint_grant_id

_KEY = bytes(SigningKey(b"\x01" * 32).verify_key)
DID_AW = stable_id_from_public_key(_KEY)
DID_KEY = did_from_public_key(_KEY)

OPERATION = {"operation_id": "refund", "digest": "a" * 64}
JOB = {"job_id": "nightly-backup", "digest": "b" * 64}
POLICY = "c" * 64

USE = {
    "v": 1,
    "grant_id": "grt_77c1aa",
    "secret_id": "sec_19ab42",
    "subject": {"principal": DID_AW},
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
        {"subject": {"principal": DID_KEY}},
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
        {"subject": {"principal": "did:aw:2rMeyRyvQbWUZYjT8Jx6Kq"}},
        {"subject": {"principal": DID_KEY[:-1]}},
        {"subject": {"role": "deployers"}},
        {"subject": {"role": "logs.reader"}},
        {"subject": {"role": "secrets.role.Deployers"}},
        {"subject": {"principal": DID_AW, "role": "secrets.owner"}},
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


TEMPLATE = {
    "v": 1,
    "grant_template_id": "gtp_sts-derived",
    "subject": {"role": "secrets.role.deployers"},
    "capability": "use",
    "operations": [OPERATION],
    "open_request": False,
    "jobs": [],
    "policy_digest": POLICY,
}


def test_a_grant_template_round_trips() -> None:
    assert GrantTemplate.from_after(TEMPLATE).after == TEMPLATE


@pytest.mark.parametrize(
    "change",
    [
        {"grant_template_id": "sts-derived"},
        {"grant_id": "grt_77c1aa"},
        {"secret_id": "sec_19ab42"},
        {"operations": [], "open_request": False},
        {"subject": {"role": "deployers"}},
    ],
)
def test_a_malformed_grant_template_is_refused(change) -> None:
    template = copy.deepcopy(TEMPLATE)
    template.update(change)
    with pytest.raises(GrantInvalid):
        GrantTemplate.from_after(template)


def test_a_template_makes_the_grant_it_describes_for_a_secret() -> None:
    grant = GrantTemplate.from_after(TEMPLATE).grant_for("sec_derived01", grant_id="grt_derived01")
    expected = {k: v for k, v in TEMPLATE.items() if k != "grant_template_id"}
    assert grant.after == {**expected, "grant_id": "grt_derived01", "secret_id": "sec_derived01"}
