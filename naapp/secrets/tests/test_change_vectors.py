"""aweb.secrets.change/1 (secrets §6.3) against its frozen vector and B2.

The positive cases are change sets whose bytes a B2 approval must cover exactly:
B2's public canonical form reproduces them, and B2's real mint on PostgreSQL
records the same request_sha256. The negative cases never reach those bytes,
and the confirmation cases fix when a change set may be confirmed.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    Approvals,
    Approver,
    Assurance,
    DeliveryStatus,
    PgApprovalStore,
    canonical_request,
)
from aweb_naapp.runtime.approvals.request import DOMAIN_PREFIX, parse_request_json
from pgdbm.core import TransactionManager

from aweb_secrets.change import (
    AFTER_SHAPES,
    KINDS,
    REENABLE_TARGETS,
    ChangeRefused,
    check_confirmable,
    covered_bytes,
    parse_change,
    validate_change,
)

VECTOR = json.loads((Path(__file__).parents[1] / "vectors" / "change-v1.json").read_text())
POSITIVE = VECTOR["positive_cases"]
NEGATIVE = VECTOR["negative_cases"]
CONFIRMATIONS = VECTOR["confirmation_cases"]


def _bytes(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _case(name: str) -> dict:
    return next(case for case in POSITIVE if case["name"] == name)


def test_the_vector_uses_b2s_single_prefix() -> None:
    assert VECTOR["prefix"].encode() == DOMAIN_PREFIX


def test_the_vector_freezes_the_kinds_ops_and_shapes_in_force() -> None:
    assert VECTOR["kinds"] == {kind: sorted(ops) for kind, ops in KINDS.items()}
    assert VECTOR["reenable_targets"] == sorted(REENABLE_TARGETS)
    assert VECTOR["after_shapes"] == {
        f"{kind}/{v}": list(shape.fields) for (kind, v), shape in AFTER_SHAPES.items()
    }


@pytest.mark.parametrize("case", POSITIVE, ids=lambda case: case["name"])
def test_b2_canonical_form_reproduces_the_covered_bytes(case: dict) -> None:
    covered = canonical_request({"policy": case["policy"], "request": case["request"]})
    assert covered == _bytes(case["covered_bytes_b64url"])
    assert hashlib.sha256(covered).hexdigest() == case["request_sha256"]
    assert covered_bytes(case["request"], case["policy"]) == covered


@pytest.mark.parametrize("case", POSITIVE, ids=lambda case: case["name"])
def test_positive_change_sets_are_accepted_with_exactly_the_frozen_fields(case: dict) -> None:
    fields = VECTOR["fields"]
    change = case["request"]
    validate_change(change)
    assert list(change) == fields["request"]
    drafter = set(change["drafter"])
    if change["drafter"]["via"] == "console":
        assert drafter == set(fields["drafter_console"])
    else:
        required = set(fields["drafter_team_auth"])
        assert required <= drafter <= required | set(fields["drafter_team_auth_optional"])
    for item in change["changes"]:
        assert list(item) == fields["change"]


def test_positive_cases_cover_both_drafters_and_every_shape_in_force() -> None:
    drafters = {
        (c["request"]["drafter"]["via"], "did_aw" in c["request"]["drafter"]) for c in POSITIVE
    }
    assert drafters == {("console", False), ("team_auth", True), ("team_auth", False)}
    kinds = {item["kind"] for c in POSITIVE for item in c["request"]["changes"]}
    assert kinds == {kind for kind, _ in AFTER_SHAPES}


@pytest.mark.parametrize("case", NEGATIVE, ids=lambda case: case["name"])
def test_negative_cases_never_reach_the_covered_bytes(case: dict) -> None:
    reference = _case(case["of"])
    expected = case["expected"]
    if expected == "refused":
        with pytest.raises(ChangeRefused):
            parse_change(case["raw_json"].encode())
        return
    if expected == "digest_differs":
        digest = hashlib.sha256(_bytes(case["bytes_b64url"])).hexdigest()
        assert digest != reference["request_sha256"]
        return
    assert expected == "recanonicalized"
    raw = case["raw_json"].encode()
    canonical = canonical_request(parse_request_json(raw))
    assert canonical == _bytes(reference["covered_bytes_b64url"])
    assert DOMAIN_PREFIX + raw != canonical


@pytest.mark.parametrize("case", CONFIRMATIONS, ids=lambda case: case["name"])
def test_confirmation_cases(case: dict) -> None:
    change = _case(case["of"])["request"]
    now = datetime.fromisoformat(case["now"].replace("Z", "+00:00"))
    current = {**case["current"], "current_revision": case["current_revision"], "now": now}
    if case["expected"] == "confirmable":
        check_confirmable(change, **current)
        return
    with pytest.raises(ChangeRefused) as refused:
        check_confirmable(change, **current)
    assert refused.value.code == case["expected"]


class _Policies:
    def __init__(self, policy: ActionPolicy) -> None:
        self._policy = policy

    async def current(self, policy_ref: str) -> ActionPolicy | None:
        return self._policy if policy_ref == self._policy.policy_ref else None


class _Directory:
    approver = Approver(subject="owner-1", subject_type="app_local", contact="owner@example.com")

    async def designated_approver(self, policy: ActionPolicy) -> Approver | None:
        return self.approver

    async def is_current(self, approver_subject: str, policy: ActionPolicy) -> bool:
        return approver_subject == self.approver.subject


class _Mailbox:
    async def deliver_approval_link(self, approver, link_token, approval) -> DeliveryStatus:
        return DeliveryStatus.DELIVERED


class _Audit:
    def __init__(self, db) -> None:
        self.db = db

    async def emit(self, event, transaction) -> None:
        await TransactionManager(transaction.connection, self.db).execute(
            "INSERT INTO {{tables.audit_events}} (kind, approval_id) VALUES ($1, $2)",
            event.kind.value,
            event.approval_id,
        )


async def test_b2_mint_records_the_vector_digest(test_db_factory) -> None:
    db = await test_db_factory.create_db(suffix="change_vectors", schema="secrets")
    store = PgApprovalStore(db)
    await store.migrate()
    await db.execute("CREATE TABLE {{tables.audit_events}} (kind TEXT NOT NULL, approval_id TEXT)")
    policy = POSITIVE[0]["policy"]
    approvals = Approvals(
        store=store,
        policies=_Policies(
            ActionPolicy(
                policy_ref=policy["ref"],
                version=policy["version"],
                min_assurance=Assurance.PASSKEY,
                ttl=timedelta(minutes=15),
                approver_scope="secrets.owner.fixture",
            )
        ),
        approvers=_Directory(),
        delivery=_Mailbox(),
        authenticators=[],
        audit=_Audit(db),
    )
    for case in POSITIVE:
        view = await approvals.mint(
            request=case["request"],
            policy_ref=case["policy"]["ref"],
            requested_by=case["request"]["change_id"],
        )
        approval = await store.get_by_request(view.request_id)
        assert approval is not None
        assert approval.request_sha256 == case["request_sha256"], case["name"]
