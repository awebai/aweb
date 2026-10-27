"""POST /v1/id-certificates/register (docs/id-certificates.md §3).

Frozen operation cases are consumed BY NAME: every case in the vector file is
either consumed here or in a later S2 checkpoint, or is named as owned by
another slice, so a renamed or dropped case fails this module.
"""

from __future__ import annotations

import asyncio
import copy
import json
from datetime import timedelta

import pytest
import pytest_asyncio

from awid import dns_auth
from awid import ratelimit as ratelimit_module
from awid.ratelimit import MemoryFixedWindowRateLimiter

from conftest import build_signed_headers

from id_tree_support import (
    DOMAIN,
    REGISTER_PATH,
    VECTORS,
    Tree,
    at,
    certificate,
    certificate_id,
    chain_header,
    covering_headers,
    did_aw,
    did_key,
    operation_case,
    seed,
    sign,
    wire_time,
)
from lock_waits import wait_until_blocked_on_lock

CONSUMED: set[str] = set()

# S2 cases whose effects land in a later S2 checkpoint (3 revoke, 4 status,
# 5 races and lost-key replacement). This set must be empty when S2 closes.
S2_LATER = {
    "registration-after-sign-then-parent-revoke",
    "directly-revoked-subject-cannot-reopen-head",
    "signed-issued-at-cannot-backdate",
    "accepted-human-invite-retry-after-inviter-revoke",
    "concurrent-registration-cas",
    "reparent-register-race",
    "root-revokes-with-compromise-cutoff",
    "self-revokes-now",
    "live-parent-revokes-now",
    "unrelated-human-cannot-revoke",
    "revoked-parent-cannot-revoke",
    "parent-cannot-backdate",
    "subject-cannot-backdate",
    "future-cutoff-refuses",
    "loss-replacement-is-a-new-human-id",
    "address-replacement-does-not-transfer-contact-trust",
    "public-chain-not-private-team-read-authority",
    "status-rate-limit",
    "post-lock-revocation-time-is-not-transaction-start",
    "status-prefix-enumeration-refuses",
    "status-never-discloses-private-team-data",
}

# Cases whose effects belong to another slice's component.
OWNED_ELSEWHERE = {
    "resign-after-revoke-refuses": "S3 local signer",
    "resign-mismatched-id": "S3 local signer",
    "resign-mismatched-kind": "S3 local signer",
    "resign-unchanged-child": "S3 local signer",
    "resign-forged-old-key-refuses": "S3 local signer",
    "local-reparent-same-key-refuses": "S3 local re-parent",
    "local-reparent-new-key-and-member-cert": "S3 local re-parent",
    "chainless-local-adoption-keeps-key-and-team-cert": "S3/S7 adoption",
    "existing-human-org-join-is-membership-only": "S6 org membership",
    "org-membership-completes-before-registration": "S6 invitations",
    "org-registration-fails-membership-stays": "S6 invitations",
    "registry-success-cloud-completion-retry": "S6 invitations",
    "membership-removal-does-not-revoke-shared-human": "S6 offboarding",
    "partial-reparent-then-offboard": "S6/S7 offboarding",
    "key-export-import-preserves-human": "S3 keychain",
    "key-import-wrong-key-refuses": "S3 keychain",
    "same-human-two-machines-no-second-id": "S3 keychain",
    "token-holder-not-recipient": "S6 invitations",
    "fixed-recipient-deferred-human-signing": "S6 invitations",
    "key-import-below-kdf-floor-refuses": "S3 keychain",
}


def consumes(name: str):
    case = operation_case(name)
    CONSUMED.add(name)

    def decorate(test):
        return pytest.mark.asyncio(pytest.mark.parametrize("case", [case], ids=[name])(test))

    return decorate


def test_every_frozen_operation_case_is_accounted_for_by_name():
    names = [case["name"] for case in VECTORS["operation_cases"]]
    assert len(names) == len(set(names))
    groups = [CONSUMED, S2_LATER, set(OWNED_ELSEWHERE)]
    assert sum(len(group) for group in groups) == len(set().union(*groups))
    assert set(names) == set().union(*groups)


@pytest_asyncio.fixture
async def tree(clocked_client, manual_clock):
    tree = Tree(clocked_client, manual_clock)
    await tree.root()
    for key_name in ("alice", "bob", "other_human", "global_agent", "global_from_local"):
        await tree.did(key_name)
    return tree


async def _revisions(awid_db_infra, id_=None):
    db = awid_db_infra.get_manager("aweb")
    return await db.fetch_all(
        """
        SELECT certificate_id, id, registered_at, superseded_at, issuer_key_seq, invitation_id
        FROM {{tables.id_certificates}}
        WHERE $1::text IS NULL OR id = $1
        ORDER BY registered_at
        """,
        id_,
    )


def _code(resp):
    return resp.json()["detail"]["code"]


# ---------------------------------------------------------------------------
# Frozen operation cases
# ---------------------------------------------------------------------------


@consumes("first-exact-invitation-registration")
async def test_first_exact_invitation_registration(case, tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))

    resp = await tree.register(
        [certificate("alice"), certificate("bob")],
        invitation_id=case["input"]["invitation_id"],
        when=at(case["input"]["registered_at"]),
    )

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"certificate_id": certificate_id("bob"), "registered_at": case["expected"]["registered_at"]}
    assert len(await _revisions(awid_db_infra, did_aw("bob"))) == case["expected"]["writes"]


@consumes("exact-invitation-retry-keeps-time")
async def test_exact_invitation_retry_keeps_time(case, tree, awid_db_infra):
    invitation = operation_case("first-exact-invitation-registration")["input"]["invitation_id"]
    chain = [certificate("alice"), certificate("bob")]
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    first = await tree.register(chain, invitation_id=invitation, when=at(case["input"]["original_registered_at"]))
    assert first.status_code == 200, first.text
    before = await _revisions(awid_db_infra)

    retry = await tree.register(chain, invitation_id=invitation, when=at(case["input"]["retry_at"]))

    assert retry.status_code == 200, retry.text
    assert retry.json() == {"certificate_id": certificate_id("bob"), "registered_at": case["expected"]["registered_at"]}
    assert await _revisions(awid_db_infra) == before


async def _invitation_conflict(case, tree, awid_db_infra, conflicting_chain, *, signer=None):
    invitation = operation_case("first-exact-invitation-registration")["input"]["invitation_id"]
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    first = await tree.register(
        [certificate("alice"), certificate("bob")], invitation_id=invitation, when=at("2026-10-26T00:03:00Z"),
    )
    assert first.status_code == 200, first.text
    before = await _revisions(awid_db_infra)

    resp = await tree.register(conflicting_chain, invitation_id=invitation, signer=signer)

    assert resp.status_code == 409, resp.text
    assert _code(resp) == case["expected"]["reason"]
    assert await _revisions(awid_db_infra) == before


def _bob_variant(**changes):
    fields = copy.deepcopy(certificate("bob")["certificate"])
    fields.update(changes)
    return fields


@consumes("invitation-conflict-child")
async def test_invitation_conflict_child(case, tree, awid_db_infra):
    await _invitation_conflict(case, tree, awid_db_infra, [certificate("alice"), certificate("global-agent")])


@consumes("invitation-conflict-parent")
async def test_invitation_conflict_parent(case, tree, awid_db_infra):
    under_root = _bob_variant(parent={"kind": "namespace", "id": DOMAIN}, issuer_key=did_key("root"))
    await _invitation_conflict(case, tree, awid_db_infra, [sign(under_root, "root")])


@consumes("invitation-conflict-domain")
async def test_invitation_conflict_domain(case, tree, awid_db_infra):
    elsewhere = _bob_variant(
        domain="other.example", parent={"kind": "namespace", "id": "other.example"}, issuer_key=did_key("root"),
    )
    await _invitation_conflict(case, tree, awid_db_infra, [sign(elsewhere, "root")])


@consumes("invitation-conflict-certificate")
async def test_invitation_conflict_certificate(case, tree, awid_db_infra):
    reissued = _bob_variant(issued_at="2026-10-26T00:09:00Z")
    await _invitation_conflict(case, tree, awid_db_infra, [certificate("alice"), sign(reissued, "alice")])


@consumes("same-certificate-retry-does-not-reactivate-old-head")
async def test_same_certificate_retry_does_not_reactivate_old_head(case, tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    await tree.enroll("alice", "bob", when=at("2026-10-26T00:02:00Z"))
    await tree.enroll("alice", "global-agent", when=at(case["expected"]["registered_at"]))
    reparent = await tree.register(
        [certificate("alice"), certificate("bob"), certificate("global-agent-reparented")],
        expected_head=certificate_id("global-agent"), when=at("2026-10-26T00:14:00Z"),
    )
    assert reparent.status_code == 200, reparent.text

    retry = await tree.register([certificate("alice"), certificate("global-agent")], when=at("2026-10-26T00:20:00Z"))

    assert retry.status_code == 200, retry.text
    assert retry.json() == {"certificate_id": certificate_id("global-agent"), "registered_at": case["expected"]["registered_at"]}
    heads = [r["certificate_id"] for r in await _revisions(awid_db_infra, did_aw("global_agent")) if r["superseded_at"] is None]
    assert heads == [certificate_id("global-agent-reparented")]


@consumes("registration-after-parent-rotate-refuses-old-key")
async def test_registration_after_parent_rotate_refuses_old_key(case, tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    tree.clock.now = at(case["input"]["parent_rotated_at"])
    await tree.rotate_did("alice", "alice_rotated")
    before = await _revisions(awid_db_infra)

    resp = await tree.register([certificate("alice"), certificate("bob")], when=at(case["input"]["registered_at"]))

    assert resp.status_code == 422, resp.text
    assert _code(resp) == case["expected"]["reason"]
    assert await _revisions(awid_db_infra) == before


@consumes("registered-kind-change-refuses")
async def test_registered_kind_change_refuses(case, tree, awid_db_infra):
    assert case["input"]["id"] == did_aw("alice")
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    as_agent = copy.deepcopy(certificate("alice")["certificate"])
    as_agent.update(kind=case["input"]["requested_kind"], issued_at="2026-10-26T00:05:00Z")
    before = await _revisions(awid_db_infra)

    resp = await tree.register([sign(as_agent, "root")], expected_head=certificate_id("alice"))

    assert resp.status_code == 422, resp.text
    assert _code(resp) == case["expected"]["reason"]
    assert await _revisions(awid_db_infra) == before


@consumes("registered-domain-change-refuses")
async def test_registered_domain_change_refuses(case, tree, awid_db_infra):
    assert case["input"]["id"] == did_aw("alice")
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    moved = copy.deepcopy(certificate("alice")["certificate"])
    domain = case["input"]["requested_domain"]
    moved.update(domain=domain, parent={"kind": "namespace", "id": domain}, issued_at="2026-10-26T00:05:00Z")
    before = await _revisions(awid_db_infra)

    resp = await tree.register([sign(moved, "root")], expected_head=certificate_id("alice"))

    assert resp.status_code == 422, resp.text
    assert _code(resp) == case["expected"]["reason"]
    assert await _revisions(awid_db_infra) == before


@consumes("registered-child-under-local-parent-refuses")
async def test_registered_child_under_local_parent_refuses(case, tree, awid_db_infra):
    leaf = certificate("global-from-local")["certificate"]
    assert (leaf["id"], leaf["kind"], leaf["parent"]["id"]) == (
        case["input"]["child_id"], case["input"]["child_kind"], case["input"]["parent"],
    )
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    before = await _revisions(awid_db_infra)

    resp = await tree.register([certificate("alice"), certificate("coordinator"), certificate("global-from-local")])

    assert resp.status_code == 422, resp.text
    assert _code(resp) == case["expected"]["reason"]
    assert await _revisions(awid_db_infra) == before


@consumes("registered-reparent-keeps-key-and-team-cert")
async def test_registered_reparent_keeps_key_and_team_cert(case, tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    await tree.enroll("alice", "bob", when=at("2026-10-26T00:02:00Z"))
    await tree.enroll("alice", "global-agent", when=at("2026-10-26T00:04:00Z"))
    db = awid_db_infra.get_manager("aweb")
    team_certificates = await db.fetch_value("SELECT COUNT(*) FROM {{tables.team_certificates}}")

    resp = await tree.register(
        [certificate("alice"), certificate("bob"), certificate(case["input"]["new_certificate"])],
        expected_head=certificate_id(case["input"]["old_certificate"]), when=at("2026-10-26T00:14:00Z"),
    )

    assert resp.status_code == 200, resp.text
    key = await tree.client.get(f"/v1/did/{did_aw('global_agent')}/key")
    assert key.json()["current_did_key"] == did_key("global_agent")
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.team_certificates}}") == team_certificates
    old, new = await _revisions(awid_db_infra, did_aw("global_agent"))
    assert (old["certificate_id"], old["superseded_at"]) == (certificate_id("global-agent"), at("2026-10-26T00:14:00Z"))
    assert (new["certificate_id"], new["superseded_at"]) == (certificate_id("global-agent-reparented"), None)


@consumes("post-lock-registration-time-is-monotone")
async def test_post_lock_registration_time_is_monotone(case, tree, awid_db_infra):
    await tree.enroll("alice", when=at(case["input"]["last_authority_serialization_at"]))
    db = awid_db_infra.get_manager("aweb")
    tree.clock.now = at(case["input"]["transaction_started_at"])
    async with db.transaction() as holder:
        await holder.fetch_one(
            "SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain = $1 FOR UPDATE", DOMAIN,
        )
        registration = asyncio.create_task(tree.register([certificate("alice"), certificate("bob")]))
        await wait_until_blocked_on_lock(db, registration)
        tree.clock.now = at(case["input"]["last_lock_acquired_at"])
    resp = await registration

    assert resp.status_code == 200, resp.text
    assert resp.json()["registered_at"] == case["expected"]["registered_at"]


# ---------------------------------------------------------------------------
# Wire and gate refusals beyond the operation cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_frozen_registration_example_is_accepted_byte_for_byte(tree, monkeypatch):
    example = VECTORS["registration_example"]
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    tree.clock.now = at(example["response"]["registered_at"])
    monkeypatch.setattr(dns_auth, "_utc_now", lambda: at(example["payload"]["timestamp"]))

    resp = await tree.client.post(
        REGISTER_PATH, content=example["body_utf8"].encode(),
        headers={**example["headers"], "Content-Type": "application/json"},
    )

    assert resp.status_code == 200, resp.text
    assert resp.json() == example["response"]
    assert example["expected_certificate_id"] == example["response"]["certificate_id"]


@pytest.mark.asyncio
async def test_root_child_records_the_exact_epoch_it_was_issued_under(tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))

    [revision] = await _revisions(awid_db_infra, did_aw("alice"))
    assert (revision["issuer_key_seq"], revision["registered_at"]) == (1, at("2026-10-26T00:01:00Z"))


@pytest.mark.asyncio
async def test_identity_child_records_its_parents_current_key_version(tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    tree.clock.now = at("2026-10-26T00:02:00Z")
    await tree.rotate_did("alice", "alice_rotated")
    reissued = _bob_variant(issuer_key=did_key("alice_rotated"))

    resp = await tree.register([certificate("alice"), sign(reissued, "alice_rotated")], when=at("2026-10-26T00:03:00Z"))

    assert resp.status_code == 200, resp.text
    [revision] = await _revisions(awid_db_infra, did_aw("bob"))
    assert revision["issuer_key_seq"] == 2


@pytest.mark.asyncio
async def test_root_children_require_an_exact_dns_epoch(clocked_client, manual_clock, monkeypatch):
    tree = Tree(clocked_client, manual_clock)
    monkeypatch.setenv("AWID_SKIP_DNS_VERIFY", "1")
    await tree.root()
    await tree.did("alice")

    resp = await tree.register([certificate("alice")], when=at("2026-10-26T00:01:00Z"))

    assert resp.status_code == 422, resp.text
    assert _code(resp) == "evidence_unavailable"


@pytest.mark.asyncio
async def test_root_children_must_be_signed_by_the_open_epoch_key(tree, awid_db_infra):
    tree.clock.now = at("2026-10-26T00:00:30Z")
    await tree.rotate_root("root_rotated")

    resp = await tree.register([certificate("alice")], when=at("2026-10-26T00:01:00Z"))

    assert resp.status_code == 422, resp.text
    assert _code(resp) == "issuer_key_not_current"
    assert await _revisions(awid_db_infra) == []


@pytest.mark.asyncio
async def test_a_human_cannot_be_registered_under_an_agent(tree, awid_db_infra):
    resp = await tree.register(
        [certificate("alice"), certificate("coordinator"), certificate("human-issued-by-agent")],
    )

    assert resp.status_code == 422, resp.text
    assert _code(resp) == "human_issuer_is_agent"
    assert await _revisions(awid_db_infra) == []


@pytest.mark.asyncio
async def test_the_request_must_be_signed_by_the_subjects_current_key(tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))

    resp = await tree.register([certificate("alice"), certificate("bob")], signer="alice")

    assert resp.status_code == 403, resp.text
    assert _code(resp) == "subject_mismatch"


@pytest.mark.asyncio
async def test_a_rotated_subject_proves_its_current_key(tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    await tree.rotate_did("bob", "bob_agent")

    stale = await tree.register([certificate("alice"), certificate("bob")], signer="bob")
    current = await tree.register([certificate("alice"), certificate("bob")], signer="bob_agent")

    assert (stale.status_code, _code(stale)) == (403, "subject_mismatch")
    assert current.status_code == 200, current.text


@pytest.mark.asyncio
async def test_head_cas_refuses_a_stale_or_missing_expected_head(tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    await tree.enroll("alice", "bob", when=at("2026-10-26T00:02:00Z"))
    await tree.enroll("alice", "global-agent", when=at("2026-10-26T00:04:00Z"))
    reparented = [certificate("alice"), certificate("bob"), certificate("global-agent-reparented")]

    missing = await tree.register(reparented)
    stale = await tree.register(reparented, expected_head=certificate_id("bob"))
    first_with_head = await tree.register(
        [certificate("other-human")], expected_head=certificate_id("alice"),
    )

    for resp in (missing, stale, first_with_head):
        assert (resp.status_code, _code(resp)) == (409, "head_conflict"), resp.text


@pytest.mark.asyncio
async def test_a_reparent_under_its_own_descendant_is_a_cycle(tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    await tree.enroll("alice", "global-agent", when=at("2026-10-26T00:04:00Z"))
    child = {
        "v": 1, "type": "aweb.id-certificate", "id": did_aw("global_from_local"), "domain": DOMAIN,
        "parent": {"kind": "identity", "id": did_aw("global_agent")}, "kind": "agent",
        "issuer_key": did_key("global_agent"), "issued_at": "2026-10-26T00:05:00Z",
    }
    child_signed = sign(child, "global_agent")
    created = await tree.register([certificate("alice"), certificate("global-agent"), child_signed])
    assert created.status_code == 200, created.text
    loop = copy.deepcopy(certificate("global-agent")["certificate"])
    loop.update(
        parent={"kind": "identity", "id": did_aw("global_from_local")},
        issuer_key=did_key("global_from_local"), issued_at="2026-10-26T00:06:00Z",
    )

    resp = await tree.register(
        [certificate("alice"), certificate("global-agent"), child_signed, sign(loop, "global_from_local")],
        expected_head=certificate_id("global-agent"),
    )

    assert (resp.status_code, _code(resp)) == (422, "cycle"), resp.text


@pytest.mark.asyncio
async def test_the_supporting_chain_must_be_the_registered_ancestry(tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    reissued_alice = copy.deepcopy(certificate("alice")["certificate"])
    reissued_alice["issued_at"] = "2026-10-26T00:00:30Z"

    resp = await tree.register([sign(reissued_alice, "root"), certificate("bob")])

    assert (resp.status_code, _code(resp)) == (422, "superseded_certificate"), resp.text


@pytest.mark.asyncio
async def test_the_chain_leaf_must_be_the_body_certificate(tree):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))

    resp = await tree.register(
        [certificate("alice"), certificate("bob")], header_chain=[certificate("alice"), certificate("global-agent")],
    )

    assert (resp.status_code, _code(resp)) == (400, "invalid_shape"), resp.text


@pytest.mark.asyncio
async def test_a_missing_chain_header_refuses(tree):
    body = json.dumps({"certificate": certificate("alice"), "expected_head": None, "invitation_id": None}).encode()
    headers = covering_headers(
        "alice", method="POST", path=REGISTER_PATH, body=body, domain=DOMAIN, operation="register_id_certificate",
    )

    resp = await tree.client.post(REGISTER_PATH, content=body, headers=headers)

    assert (resp.status_code, _code(resp)) == (400, "invalid_shape"), resp.text


@pytest.mark.parametrize(
    "body",
    [
        {"certificate": None, "expected_head": None},
        {"certificate": None, "expected_head": None, "invitation_id": None, "extra": 1},
        {"certificate": None, "expected_head": "sha256:XYZ", "invitation_id": None},
        {"certificate": None, "expected_head": None, "invitation_id": "00000000-0000-4000-8000-00000000000A"},
    ],
)
@pytest.mark.asyncio
async def test_the_body_has_exactly_the_contract_fields(tree, body):
    body = {**body, "certificate": certificate("alice")} if "certificate" in body else body
    raw = json.dumps(body).encode()
    headers = covering_headers(
        "alice", method="POST", path=REGISTER_PATH, body=raw, domain=DOMAIN, operation="register_id_certificate",
    )

    resp = await tree.client.post(REGISTER_PATH, content=raw, headers=headers)

    assert (resp.status_code, _code(resp)) == (400, "invalid_shape"), resp.text


@pytest.mark.asyncio
async def test_a_validly_signed_legacy_envelope_is_never_accepted(tree, awid_db_infra):
    chain = [certificate("alice")]
    body = json.dumps({"certificate": chain[0], "expected_head": None, "invitation_id": None}).encode()
    headers = build_signed_headers(seed("alice"), did_key("alice"), domain=DOMAIN, operation="register_id_certificate")
    headers.update({"Content-Type": "application/json", "X-AWID-ID-Chain": chain_header(chain)})

    resp = await tree.client.post(REGISTER_PATH, content=body, headers=headers)

    assert resp.status_code == 401, resp.text
    assert await _revisions(awid_db_infra) == []


@pytest.mark.asyncio
async def test_a_did_key_subject_is_not_registered(tree):
    resp = await tree.register(
        [certificate("alice"), certificate("coordinator")], signer="coordinator",
    )

    assert (resp.status_code, _code(resp)) == (400, "invalid_shape"), resp.text


@pytest.mark.asyncio
async def test_a_receipt_is_returned_only_for_the_exact_invitation(tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    chain = [certificate("alice"), certificate("bob")]
    first = await tree.register(chain, when=at("2026-10-26T00:03:00Z"))
    assert first.status_code == 200, first.text

    resp = await tree.register(chain, invitation_id="00000000-0000-4000-8000-000000000009")

    assert (resp.status_code, _code(resp)) == (409, "invitation_conflict"), resp.text


@pytest.mark.asyncio
async def test_witness_times_never_precede_the_key_epochs_they_select(tree, awid_db_infra):
    tree.clock.now = at("2026-10-26T00:10:00Z")
    await tree.rotate_did("alice", "alice_rotated")
    resp = await tree.register([certificate("alice")], signer="alice_rotated", when=at("2026-10-26T00:01:00Z"))
    assert resp.status_code == 200, resp.text

    [revision] = await _revisions(awid_db_infra, did_aw("alice"))
    assert revision["registered_at"] == at("2026-10-26T00:10:00Z") + timedelta(microseconds=1)
    assert wire_time(revision["registered_at"]) == "2026-10-26T00:10:00.000001Z"


# ---------------------------------------------------------------------------
# Serialization with did:aw rotation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("held", ["alice", "bob"], ids=["parent-mapping", "subject-mapping"])
@pytest.mark.asyncio
async def test_registration_waits_for_a_rotation_holding_a_selected_key(held, tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    db = awid_db_infra.get_manager("aweb")
    async with db.transaction() as rotation:
        await rotation.fetch_one(
            "SELECT did_aw FROM {{tables.did_aw_mappings}} WHERE did_aw = $1 FOR UPDATE", did_aw(held),
        )
        registration = asyncio.create_task(tree.register([certificate("alice"), certificate("bob")]))
        await wait_until_blocked_on_lock(db, registration)
    resp = await registration

    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_a_parent_rotation_committed_during_the_wait_is_seen(tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    db = awid_db_infra.get_manager("aweb")
    async with db.transaction() as holder:
        await holder.fetch_one(
            "SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain = $1 FOR UPDATE", DOMAIN,
        )
        registration = asyncio.create_task(tree.register([certificate("alice"), certificate("bob")]))
        await wait_until_blocked_on_lock(db, registration)
        await tree.rotate_did("alice", "alice_rotated")
    resp = await registration

    assert (resp.status_code, _code(resp)) == (422, "issuer_key_not_current"), resp.text
    assert await _revisions(awid_db_infra, did_aw("bob")) == []


# ---------------------------------------------------------------------------
# Rate limit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("credential", ["configured", "missing", "wrong", "unconfigured"])
@pytest.mark.asyncio
async def test_only_the_configured_service_token_exempts_registration_from_its_bucket(
    credential, clocked_client, monkeypatch,
):
    token = "s" * 40
    app = clocked_client.app
    monkeypatch.setattr(app.state, "awid_service_token", None if credential == "unconfigured" else token)
    monkeypatch.setattr(app.state, "rate_limiter", MemoryFixedWindowRateLimiter())
    monkeypatch.setitem(ratelimit_module._BUCKET_DEFAULTS, "id_certificate_register", (2, 3600))
    headers = {} if credential == "missing" else {"X-AWID-Service-Token": "w" * 40 if credential == "wrong" else token}

    statuses = [
        (await clocked_client.post(REGISTER_PATH, content=b"{}", headers=headers)).status_code for _ in range(3)
    ]

    assert statuses == ([400, 400, 400] if credential == "configured" else [400, 400, 429])
