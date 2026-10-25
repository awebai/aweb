"""aweb.secrets.use-approval/1 (secrets §10.4) against B2's frozen request.

The positive cases are approval requests whose bytes B2 must cover exactly:
B2's public canonical form reproduces them, and B2's real mint on PostgreSQL
records the same request_sha256. The negative cases are encodings that never
reach those bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import timedelta
from pathlib import Path

import pytest
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    ApprovalRefused,
    Approvals,
    Approver,
    Assurance,
    DeliveryStatus,
    PgApprovalStore,
    Refusal,
    RequestNotCanonical,
    canonical_request,
)
from aweb_naapp.runtime.approvals.request import DOMAIN_PREFIX, parse_request_json
from pgdbm.core import TransactionManager

VECTOR = json.loads((Path(__file__).parents[1] / "vectors" / "use-approval-v1.json").read_text())
POSITIVE = VECTOR["positive_cases"]
NEGATIVE = VECTOR["negative_cases"]
DESIGN = Path(__file__).resolve().parents[3] / "docs" / "design" / "secrets.md"


def _auth_schemes() -> set[str]:
    """The kinds in the secrets §7.5 table, the closed v1 set (decision 36)."""
    section = DESIGN.read_text().split("### 7.5 Auth schemes", 1)[1].split("\n### ", 1)[0]
    return set(re.findall(r"^\| `([a-z0-9-]+)` \|", section, flags=re.MULTILINE))


def _bytes(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _covered(case: dict) -> dict:
    return {"policy": case["policy"], "request": case["request"]}


def test_the_vector_uses_b2s_single_prefix():
    assert VECTOR["prefix"].encode() == DOMAIN_PREFIX


def test_secret_kinds_are_the_auth_schemes():
    assert VECTOR["secret_kinds"] == sorted(_auth_schemes())
    assert set(VECTOR["secret_kinds"]) == {
        "bearer",
        "basic",
        "header",
        "query",
        "oauth2-client-credentials",
        "aws-sigv4",
    }
    assert {case["request"]["secret"]["kind"] for case in POSITIVE} <= set(VECTOR["secret_kinds"])


@pytest.mark.parametrize("case", POSITIVE, ids=lambda case: case["name"])
def test_use_policy_reference_binds_the_installation_team_grant_and_digest(case):
    request = case["request"]
    parts = (
        "secrets.use",
        request["installation_id"],
        request["team_id"],
        request["grant_id"],
        request["policy_digest"],
    )
    if "frozen_plan" in case:
        assert request["action"] == "run_job"
        parts = ("secrets.run", *parts[1:], "-", "-", "-")
    assert case["policy"] == {"ref": "|".join(parts), "version": 1}


@pytest.mark.parametrize("case", POSITIVE, ids=lambda case: case["name"])
def test_b2_canonical_form_reproduces_the_covered_bytes(case):
    covered = canonical_request(_covered(case))
    assert covered == _bytes(case["covered_bytes_b64url"])
    assert hashlib.sha256(covered).hexdigest() == case["request_sha256"]


@pytest.mark.parametrize("case", POSITIVE, ids=lambda case: case["name"])
def test_positive_requests_have_exactly_the_frozen_fields(case):
    fields = VECTOR["fields"]
    request = case["request"]
    assert request["type"] == "aweb.secrets.use-approval" and request["v"] == 1
    assert set(request) == set(fields["request"]) | {request["action"]}
    requester = set(request["requester"])
    assert (
        set(fields["requester"])
        <= requester
        <= set(fields["requester"]) | set(fields["requester_optional"])
    )
    assert set(request["secret"]) == set(fields["secret"])
    if request["action"] == "run_job":
        assert set(request["run_job"]) == set(fields["run_job"])
    else:
        broker = set(request["broker"])
        assert broker in (set(fields["broker_operation"]), set(fields["broker_open"]))


def test_positive_cases_cover_every_action_and_an_integer_amount():
    actions = {
        (c["request"]["action"], "canonical_url" in c["request"].get("broker", {}))
        for c in POSITIVE
    }
    assert actions == {("broker", False), ("broker", True), ("run_job", False)}
    amounts = [
        value
        for case in POSITIVE
        for key, value in case["request"]
        .get("broker", case["request"].get("run_job", {}))
        .get("params", {})
        .items()
        if key.endswith("_minor_units")
    ]
    assert amounts and all(isinstance(value, int) for value in amounts)


@pytest.mark.parametrize("case", NEGATIVE, ids=lambda case: case["name"])
def test_negative_cases_never_reach_the_covered_bytes(case):
    expected = case["expected"]
    reference = next(c for c in POSITIVE if c["name"] == case["of"])
    if expected == "refused":
        with pytest.raises(RequestNotCanonical):
            canonical_request(parse_request_json(case["raw_json"].encode()))
        return
    if expected == "digest_differs":
        assert (
            hashlib.sha256(_bytes(case["bytes_b64url"])).hexdigest() != reference["request_sha256"]
        )
        return
    assert expected == "recanonicalized"
    raw = case["raw_json"].encode()
    canonical = canonical_request(parse_request_json(raw))
    assert canonical == _bytes(reference["covered_bytes_b64url"])
    assert DOMAIN_PREFIX + raw != canonical


def test_a_float_has_no_canonical_form():
    request = json.loads(json.dumps(POSITIVE[0]["request"]))
    request["broker"]["params"]["amount_minor_units"] = 12.5
    with pytest.raises(RequestNotCanonical):
        canonical_request({"policy": POSITIVE[0]["policy"], "request": request})


class _Policies:
    def __init__(self, policies: list[ActionPolicy]) -> None:
        self._by_ref = {p.policy_ref: p for p in policies}

    async def current(self, policy_ref: str) -> ActionPolicy | None:
        return self._by_ref.get(policy_ref)


class _Directory:
    approver = Approver(
        scope="installation",
        subject="approver-1",
        subject_type="app_local",
        contact="owner@example.com",
    )

    async def candidates(self, policy: ActionPolicy, request) -> list[Approver]:
        return [self.approver]

    async def is_current(self, scope: str, subject: str) -> bool:
        return (scope, subject) == (self.approver.scope, self.approver.subject)


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


async def test_b2_mint_records_the_vector_digest(test_db_factory):
    db = await test_db_factory.create_db(suffix="use_approval", schema="secrets")
    store = PgApprovalStore(db)
    await store.migrate()
    await db.execute("CREATE TABLE {{tables.audit_events}} (kind TEXT NOT NULL, approval_id TEXT)")
    policies = [
        ActionPolicy(
            policy_ref=case["policy"]["ref"],
            version=case["policy"]["version"],
            min_assurance=Assurance.PASSKEY,
            ttl=timedelta(minutes=15),
            approver_scopes=("installation",),
        )
        for case in POSITIVE
    ]
    approvals = Approvals(
        store=store,
        policies=_Policies(policies),
        approvers=_Directory(),
        delivery=_Mailbox(),
        authenticators=[],
        audit=_Audit(db),
    )
    for case in POSITIVE:
        view = await approvals.mint(
            request=case["request"],
            policy_ref=case["policy"]["ref"],
            requested_by=case["request"]["requester"]["principal"],
        )
        approval = await store.get_by_request(view.request_id)
        assert approval is not None
        assert approval.request_sha256 == case["request_sha256"], case["name"]
        if case["name"] == "run-job-durable-ordinary-child":
            changed = next(
                case for case in NEGATIVE if case["name"] == "changed-ordinary-child-binding"
            )
            covered = _bytes(changed["bytes_b64url"])
            assert covered.startswith(DOMAIN_PREFIX)
            changed_request = parse_request_json(covered[len(DOMAIN_PREFIX) :])["request"]
            before = await store.get(approval.approval_id)
            with pytest.raises(ApprovalRefused) as refused:
                await approvals.admit(approval.approval_id, changed_request, "changed-child")
            assert refused.value.reason is Refusal.REQUEST_MISMATCH
            assert await store.get(approval.approval_id) == before
