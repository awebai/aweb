"""POST /v1/id-certificates/status (docs/id-certificates.md §4).

One coherent snapshot of a domain's namespace epochs and of exact requested
registered IDs with their bounded proof closure. Nothing else about the
domain is listed or disclosed, and the endpoint is rate limited per caller.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
from datetime import datetime, timezone

import pytest
import pytest_asyncio

from awid.did import did_from_public_key, generate_keypair
from awid.signing import canonical_json_bytes, sign_message
from awid.id_certificates import id_certificate_id
from awid.ratelimit import NoOpRateLimiter
from awid_service import id_status
from awid_service.deps import get_domain_verifier

from conftest import build_signed_headers
from identity_support import request_rotation
from lock_waits import wait_until_blocked_on_lock
from id_tree_support import (
    DOMAIN,
    ORIGIN,
    MixedOrderController,
    VECTORS,
    Tree,
    at,
    certificate,
    certificate_id,
    chain_header,
    consumes,
    covering_headers,
    did_aw,
    did_key,
    seed,
    sign,
)

STATUS_PATH = "/v1/id-certificates/status"
OBSERVED_AT = at("2026-10-26T00:30:00Z")


@pytest_asyncio.fixture
async def tree(clocked_client, manual_clock):
    """The frozen "normal" tree, built through the real routes at the fixture's times."""
    tree = Tree(clocked_client, manual_clock)
    tree.clock.now = at("2026-10-26T00:00:00Z")
    await tree.root()
    for key_name in ("alice", "bob", "global_agent", "other_human", "replacement_human"):
        await tree.vector_did(key_name)
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    await tree.enroll("other-human", when=at("2026-10-26T00:02:00Z"))
    await tree.enroll("alice", "bob", when=at("2026-10-26T00:03:00Z"))
    await tree.enroll("alice", "global-agent", when=at("2026-10-26T00:04:00Z"))
    return tree


async def _status(tree, body, *, signer=None, when=OBSERVED_AT, headers=None):
    tree.clock.now = when
    raw = json.dumps(body, separators=(",", ":")).encode()
    sent = {"Content-Type": "application/json"}
    if signer is not None:
        sent = covering_headers(
            signer, method="POST", path=STATUS_PATH, body=raw, domain=DOMAIN, operation="read_id_certificate_status",
        )
    return await tree.client.post(STATUS_PATH, content=raw, headers={**sent, **(headers or {})})


def _request(*ids):
    return {"v": 1, "domain": DOMAIN, "ids": [did_aw(key_name) for key_name in ids]}


def _code(resp):
    return resp.json()["detail"]["code"]


def _ids(resp):
    return [identity["id"] for identity in resp.json()["identities"]]


# ---------------------------------------------------------------------------
# Frozen evidence and cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_frozen_batch_example_is_answered_with_its_fixture(tree):
    example = VECTORS["batch_example"]

    resp = await _status(tree, example["request"])

    assert resp.status_code == 200, resp.text
    assert resp.json() == VECTORS["status_fixtures"][example["response_fixture"]]


@consumes("status-never-discloses-private-team-data")
async def test_status_never_discloses_private_team_data(case, tree):
    resp = await _status(tree, {"v": 1, "domain": DOMAIN, "ids": case["input"]["ids"]})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {"v", "domain", "observed_at", "namespace", "identities", "missing"}
    assert set(body["namespace"]) == {"epochs"}
    for epoch in body["namespace"]["epochs"]:
        assert set(epoch) == {"seq", "did_key", "registered_at", "retired_at", "continuity"}
    for identity in body["identities"]:
        assert set(identity) == {
            "id", "current_certificate_id", "current_key_seq", "key_history", "certificates", "revocation",
        }
        for revision in identity["certificates"]:
            assert set(revision) == {"signed", "registered_at", "superseded_at", "issuer_key_seq"}
    assert "invitation" not in resp.text
    assert case["expected"]["accepted"] is True
    assert not any(value for flag, value in case["expected"].items() if flag.startswith("contains_"))


@consumes("status-prefix-enumeration-refuses")
async def test_status_prefix_enumeration_refuses(case, tree):
    resp = await _status(tree, case["input"]["request"])

    assert (resp.status_code, _code(resp)) == (case["expected"]["http_status"], case["expected"]["reason"]), resp.text


@consumes("status-rate-limit")
async def test_status_rate_limit(case, tree):
    statuses = [(await _status(tree, _request("alice"))).status_code for _ in range(case["input"]["requests_in_minute"])]

    assert statuses[:-1] == [200] * (case["input"]["requests_in_minute"] - 1)
    assert statuses[-1] == case["expected"]["http_status"]


def _from_ip(monkeypatch, address: str) -> dict:
    """Headers that make a trusted edge attribute the request to ``address``."""
    monkeypatch.setenv("AWEB_TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
    monkeypatch.setenv("AWEB_CF_EDGE_CIDRS", "203.0.113.0/24")
    return {"X-Forwarded-For": f"{address}, 203.0.113.1"}


async def _signed_by_fresh_key(tree, body, headers):
    signing_key, public = generate_keypair()
    caller = did_from_public_key(public)
    raw = json.dumps(body, separators=(",", ":")).encode()
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    payload = canonical_json_bytes({
        "v": 2, "type": "aweb.awid-controller-request", "aud": ORIGIN, "method": "POST", "path": STATUS_PATH,
        "body_sha256": hashlib.sha256(raw).hexdigest(), "timestamp": timestamp,
        "domain": DOMAIN, "operation": "read_id_certificate_status",
    })
    return await tree.client.post(STATUS_PATH, content=raw, headers={
        "Authorization": f"DIDKey {caller} {sign_message(signing_key, payload)}",
        "X-AWEB-Timestamp": timestamp,
        "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload).rstrip(b"=").decode(),
        "Content-Type": "application/json",
        **headers,
    })


@pytest.mark.asyncio
async def test_fresh_caller_keys_from_one_ip_share_its_budget(tree, monkeypatch):
    headers = _from_ip(monkeypatch, "198.51.100.7")
    tree.clock.now = OBSERVED_AT

    statuses = [(await _signed_by_fresh_key(tree, _request("alice"), headers)).status_code for _ in range(61)]

    assert statuses == [200] * 60 + [429]


@pytest.mark.asyncio
async def test_a_rate_limited_request_does_no_dns_lookup(tree):
    for _ in range(60):
        assert (await _status(tree, _request("alice"))).status_code == 200
    answer = tree.client.app.dependency_overrides[get_domain_verifier]()
    lookups = []

    async def counted(domain: str):
        lookups.append(domain)
        return await answer(domain)

    tree.client.app.dependency_overrides[get_domain_verifier] = lambda: counted

    resp = await _status(tree, _request("alice"))

    assert resp.status_code == 429
    assert lookups == []


@pytest.mark.asyncio
async def test_one_caller_key_from_many_ips_has_one_budget(tree, monkeypatch):
    statuses = []
    for n in range(61):
        resp = await _status(tree, _request("alice"), signer="bob", headers=_from_ip(monkeypatch, f"198.51.100.{n + 1}"))
        statuses.append(resp.status_code)

    assert statuses == [200] * 60 + [429]


@pytest.mark.asyncio
async def test_an_invalid_caller_envelope_is_refused_not_anonymous(tree):
    raw = json.dumps(_request("alice")).encode()
    headers = covering_headers(
        "bob", method="POST", path=STATUS_PATH, body=b"{}", domain=DOMAIN, operation="read_id_certificate_status",
    )

    resp = await tree.client.post(STATUS_PATH, content=raw, headers=headers)

    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_a_legacy_caller_envelope_is_refused(tree):
    raw = json.dumps(_request("alice")).encode()
    headers = {**build_signed_headers(seed("bob"), did_key("bob"), domain=DOMAIN, operation="read_id_certificate_status"),
               "Content-Type": "application/json"}

    resp = await tree.client.post(STATUS_PATH, content=raw, headers=headers)

    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_a_caller_key_outside_the_prime_order_subgroup_is_refused(tree):
    raw = json.dumps(_request("alice")).encode()
    caller = MixedOrderController()
    headers = caller.covering_headers(
        method="POST", path=STATUS_PATH, body=raw, domain=DOMAIN, operation="read_id_certificate_status",
    )

    resp = await tree.client.post(STATUS_PATH, content=raw, headers=headers)

    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_a_revoked_identity_is_reported_as_in_its_fixture(tree):
    revoked = await tree.revoke("alice", "alice", expected_head=certificate_id("alice"), when=at("2026-10-26T00:20:00Z"))
    assert revoked.status_code == 200, revoked.text

    resp = await _status(tree, VECTORS["batch_example"]["request"])

    assert resp.status_code == 200, resp.text
    assert resp.json() == VECTORS["status_fixtures"]["alice-revoked-now"]


@consumes("public-chain-not-private-team-read-authority")
async def test_public_chain_not_private_team_read_authority(case, tree):
    assert case["input"]["membership_in_private_team"] is False
    team_key, team_public = generate_keypair()
    created = await tree.client.post(
        f"/v1/namespaces/{DOMAIN}/teams",
        json={"name": "ops", "team_did_key": did_from_public_key(team_public), "visibility": "private"},
        headers=build_signed_headers(seed("root"), did_key("root"), domain=DOMAIN, operation="create_team", name="ops"),
    )
    assert created.status_code == 200, created.text
    chain = [certificate(name) for name in case["input"]["chain"]]
    reader = case["input"]["chain"][-1]

    for path in (
        f"/v1/namespaces/{DOMAIN}/teams/ops",
        f"/v1/namespaces/{DOMAIN}/teams/ops/certificates",
        f"/v1/namespaces/{DOMAIN}/teams/ops/revocations",
    ):
        timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        signature = sign_message(seed(reader), f"{timestamp}\nGET\n{path}".encode())
        resp = await tree.client.get(path, headers={
            "Authorization": f"DIDKey {did_key(reader)} {signature}",
            "X-AWEB-Timestamp": timestamp,
            "X-AWID-ID-Chain": chain_header(chain),
        })

        assert (resp.status_code, _code(resp)) == (case["expected"]["http_status"], case["expected"]["reason"]), resp.text


# ---------------------------------------------------------------------------
# Exact IDs, closure and missing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_requested_child_brings_its_parent_and_nothing_else(tree):
    resp = await _status(tree, _request("bob"))

    assert resp.status_code == 200, resp.text
    assert _ids(resp) == [did_aw("bob"), did_aw("alice")]
    assert resp.json()["missing"] == []


@pytest.mark.asyncio
async def test_unregistered_and_other_domain_ids_are_missing(tree):
    request = {"v": 1, "domain": DOMAIN, "ids": [did_aw("depth1"), did_aw("alice")]}

    resp = await _status(tree, request)

    assert resp.status_code == 200, resp.text
    assert _ids(resp) == [did_aw("alice")]
    assert resp.json()["missing"] == [did_aw("depth1")]


@pytest.mark.asyncio
async def test_the_closure_carries_the_parent_revision_in_force_at_registration(tree):
    await tree.register(
        [certificate("alice"), certificate("post-replacement-child-of-old-owner")], when=at("2026-10-26T00:05:00Z"),
    )
    tree.clock.now = at("2026-10-26T00:10:00Z")
    await tree.replace_root("root_rotated")
    readmitted = await tree.register(
        [certificate("alice-readmitted")], expected_head=certificate_id("alice"), when=at("2026-10-26T00:14:00Z"),
    )
    assert readmitted.status_code == 200, readmitted.text

    resp = await _status(tree, _request("replacement_human"))

    assert resp.status_code == 200, resp.text
    [alice] = [identity for identity in resp.json()["identities"] if identity["id"] == did_aw("alice")]
    assert [(revision["registered_at"], revision["superseded_at"]) for revision in alice["certificates"]] == [
        ("2026-10-26T00:01:00.000000Z", "2026-10-26T00:14:00.000000Z"),
        ("2026-10-26T00:14:00.000000Z", None),
    ]


def _human(subject: str, parent: dict, issuer: str) -> dict:
    fields = copy.deepcopy(certificate("alice")["certificate"])
    fields.update(id=did_aw(subject), parent=parent, issuer_key=did_key(issuer), issued_at="2026-10-26T00:05:00Z")
    return sign(fields, issuer)


@pytest.mark.asyncio
async def test_neighbouring_reparents_whose_union_cycles_are_returned(tree):
    root_parent = {"kind": "namespace", "id": DOMAIN}
    b_under_alice = _human("replacement_human", {"kind": "identity", "id": did_aw("alice")}, "alice")
    b_under_root = _human("replacement_human", root_parent, "root")
    a_under_b = _human("alice", {"kind": "identity", "id": did_aw("replacement_human")}, "replacement_human")
    steps = [
        ([certificate("alice"), b_under_alice], None, "2026-10-26T00:05:00Z"),
        ([b_under_root], b_under_alice, "2026-10-26T00:06:00Z"),
        ([b_under_root, a_under_b], certificate("alice"), "2026-10-26T00:07:00Z"),
    ]
    for chain, previous, when in steps:
        expected_head = None if previous is None else certificate_id_of(previous)
        resp = await tree.register(chain, expected_head=expected_head, when=at(when))
        assert resp.status_code == 200, resp.text

    resp = await _status(tree, _request("alice"))

    assert resp.status_code == 200, resp.text
    assert _ids(resp) == [did_aw("alice"), did_aw("replacement_human")]


def certificate_id_of(signed: dict) -> str:
    return id_certificate_id(signed["certificate"])


@pytest.mark.asyncio
async def test_an_id_registered_in_another_domain_is_missing_here(tree):
    other = "other.example"
    tree.dns("depth2", domain=other)
    assert (await tree.register_namespace("depth2", domain=other)).status_code == 200
    await tree.did("depth1")
    fields = copy.deepcopy(certificate("alice")["certificate"])
    fields.update(id=did_aw("depth1"), domain=other, parent={"kind": "namespace", "id": other},
                  issuer_key=did_key("depth2"))
    registered = await tree.register([sign(fields, "depth2")], when=at("2026-10-26T00:06:00Z"))
    assert registered.status_code == 200, registered.text
    tree.exact_dns("root")

    resp = await _status(tree, {"v": 1, "domain": DOMAIN, "ids": [did_aw("depth1")]})

    assert resp.status_code == 200, resp.text
    assert (resp.json()["identities"], resp.json()["missing"]) == ([], [did_aw("depth1")])
    assert resp.json()["namespace"] == VECTORS["status_fixtures"]["normal"]["namespace"]


@pytest.mark.asyncio
async def test_the_snapshot_is_coherent_while_a_revocation_commits(tree, awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    async with db.transaction() as holder:
        # The status snapshot reads each identity's key history after its
        # other rows, so holding that table pauses it part-way through.
        await holder.execute("LOCK TABLE {{tables.did_aw_log}} IN ACCESS EXCLUSIVE MODE")
        status = asyncio.create_task(_status(tree, VECTORS["batch_example"]["request"]))
        await wait_until_blocked_on_lock(db, status)
        revoked = await tree.revoke(
            "root", "other_human", expected_head=certificate_id("other-human"), when=at("2026-10-26T00:20:00Z"),
        )
        assert revoked.status_code == 200, revoked.text
        tree.clock.now = OBSERVED_AT
    resp = await status

    assert resp.status_code == 200, resp.text
    assert resp.json() == VECTORS["status_fixtures"]["normal"]


@pytest.mark.parametrize(
    "body",
    [
        {"v": 1, "domain": DOMAIN},
        {"v": 2, "domain": DOMAIN, "ids": []},
        {"v": 1, "domain": DOMAIN, "ids": [], "extra": 1},
        {"v": 1, "domain": DOMAIN, "ids": ["alice"]},
        {"v": 1, "domain": DOMAIN, "ids": [did_key("alice")]},
        {"v": 1, "domain": DOMAIN, "ids": [did_aw("alice"), did_aw("alice")]},
        {"v": 1, "domain": DOMAIN, "ids": [did_aw(name) for name in (
            "alice", "bob", "global_agent", "other_human", "depth1", "depth2", "depth3", "depth4", "depth5",
        )]},
        {"v": 1, "domain": 7, "ids": []},
    ],
)
@pytest.mark.asyncio
async def test_the_status_body_has_exactly_the_contract_fields(tree, body):
    resp = await _status(tree, body)

    assert (resp.status_code, _code(resp)) == (400, "invalid_shape"), resp.text


@pytest.mark.asyncio
async def test_the_domain_is_canonicalized_before_lookup(tree):
    resp = await _status(tree, {"v": 1, "domain": "Example.COM.", "ids": [did_aw("alice")]})

    assert resp.status_code == 200, resp.text
    assert (resp.json()["domain"], _ids(resp)) == (DOMAIN, [did_aw("alice")])


@pytest.mark.parametrize("domain", ["", "exa mple.com", "-example.com", "example..com", "a" * 64 + ".com"])
@pytest.mark.asyncio
async def test_an_invalid_domain_name_refuses(tree, domain):
    resp = await _status(tree, {"v": 1, "domain": domain, "ids": []})

    assert (resp.status_code, _code(resp)) == (400, "invalid_shape"), resp.text


@pytest.mark.asyncio
async def test_an_empty_request_returns_only_namespace_evidence(tree):
    resp = await _status(tree, {"v": 1, "domain": DOMAIN, "ids": []})

    assert resp.status_code == 200, resp.text
    assert (resp.json()["identities"], resp.json()["missing"]) == ([], [])
    assert [epoch["seq"] for epoch in resp.json()["namespace"]["epochs"]] == [1]


# ---------------------------------------------------------------------------
# Current root authority and time
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("dns", ["other-key", "inherited", "failed"])
@pytest.mark.asyncio
async def test_no_status_is_issued_while_root_authority_is_unavailable(dns, tree):
    if dns == "other-key":
        tree.exact_dns("root_rotated")
    elif dns == "inherited":
        tree.dns("root", inherited=True)
    else:
        tree.dns(None)

    resp = await _status(tree, _request("alice"))

    assert (resp.status_code, _code(resp)) == (503, "evidence_unavailable"), resp.text


@pytest.mark.asyncio
async def test_evidence_over_the_byte_limit_is_unavailable_not_partial(tree):
    signing_key, current = seed("alice"), did_key("alice")
    # Setting up a long key history is not what this test measures, so the
    # rotations run with the deployment's disabled limiter.
    limiter = tree.client.app.state.rate_limiter
    tree.client.app.state.rate_limiter = NoOpRateLimiter()
    for _ in range(200):
        next_key, next_public = generate_keypair()
        next_did = did_from_public_key(next_public)
        resp = await request_rotation(tree.client, signing_key, did_aw("alice"), current, next_did)
        assert resp.status_code == 200, resp.text
        signing_key, current = next_key, next_did
    tree.client.app.state.rate_limiter = limiter

    resp = await _status(tree, _request("alice"))

    assert (resp.status_code, _code(resp)) == (503, "evidence_unavailable"), resp.text


@pytest.mark.asyncio
async def test_the_snapshot_transaction_cannot_write(tree, awid_db_infra, monkeypatch):
    """Defence in depth: a write slipped into the snapshot is refused by the database."""
    real_identity = id_status._identity

    async def identity_that_writes(tx, id_):
        await tx.execute("UPDATE {{tables.id_identities}} SET revoked_at = NULL WHERE id = $1", id_)
        return await real_identity(tx, id_)

    monkeypatch.setattr(id_status, "_identity", identity_that_writes)

    with pytest.raises(Exception, match="read-only transaction"):
        await _status(tree, _request("alice"))


@pytest.mark.asyncio
async def test_observed_at_never_precedes_the_snapshot(tree):
    resp = await _status(tree, _request("alice"), when=at("2026-10-25T00:00:00Z"))

    assert resp.status_code == 200, resp.text
    assert resp.json()["observed_at"] > "2026-10-26T00:04:00.000000Z"
