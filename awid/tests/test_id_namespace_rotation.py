"""POST /v1/namespaces/{domain}/rotate (docs/id-certificates.md
"Continuity-preserving namespace rotation").

The previous and the new controller keys both sign the same covering-v2
request. Under the namespace lock the open epoch must still be the one the
request names; the rotation retires it and opens its successor, `rotated`,
at one witness time, so registrations under the previous key stay valid.
"""

from __future__ import annotations

import asyncio
import json

import pytest
import pytest_asyncio

from awid import dns_auth
from awid.signing import canonical_json_bytes, sign_message

from conftest import build_signed_headers
from lock_waits import wait_until_blocked_on_lock
from id_tree_support import (
    DOMAIN,
    VECTORS,
    Tree,
    at,
    certificate,
    consumes,
    covering_headers,
    did_key,
    ed25519_vector_key,
    seed,
)

ROTATE_PATH = f"/v1/namespaces/{DOMAIN}/rotate"
REQUESTS = VECTORS["namespace_rotation_requests"]
SIGNED_AT = at("2026-10-26T00:10:00Z")


@pytest_asyncio.fixture
async def tree(clocked_client, manual_clock):
    tree = Tree(clocked_client, manual_clock)
    await tree.root()
    for key_name in ("alice", "bob", "other_human"):
        await tree.did(key_name)
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    return tree


# The envelope clock while a frozen request is checked: the vectors' "now".
ENVELOPE_NOW = {"now": at("2026-10-26T00:10:01Z")}


async def _post_frozen(tree, name, *, when=SIGNED_AT):
    """POST a frozen rotation request byte for byte, judged at the vectors' time."""
    request = REQUESTS[name]
    tree.clock.now = when
    real_now = dns_auth._utc_now
    dns_auth._utc_now = lambda: ENVELOPE_NOW["now"]
    try:
        return await tree.client.post(
            ROTATE_PATH, content=request["body_utf8"].encode(),
            headers={**request["headers"], "Content-Type": "application/json"},
        )
    finally:
        dns_auth._utc_now = real_now


async def _post(tree, body, *, signer="root", new_key_signer="root_rotated", path=ROTATE_PATH):
    raw = json.dumps(body, separators=(",", ":")).encode()
    claims = {key: value for key, value in body.items() if key not in ("domain", "operation")}
    headers = covering_headers(
        signer, method="POST", path=path, body=raw, domain=DOMAIN, operation="rotate_namespace_controller",
        new_key_signer=new_key_signer, **claims,
    )
    return await tree.client.post(path, content=raw, headers=headers)


def _body(**changes):
    return {**REQUESTS["valid"]["body"], **changes}


async def _state(tree, awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    epochs = await db.fetch_all(
        "SELECT seq, did_key, continuity, registered_at, retired_at FROM {{tables.id_namespace_epochs}} ORDER BY seq",
    )
    controller = await db.fetch_value(
        "SELECT controller_did FROM {{tables.dns_namespaces}} WHERE domain = $1 AND deleted_at IS NULL", DOMAIN,
    )
    return [dict(row) for row in epochs], controller


def _code(resp):
    return resp.json()["detail"]["code"]


@consumes("namespace-signed-rotation-preserves-tree")
async def test_namespace_signed_rotation_preserves_tree(case, tree, awid_db_infra):
    tree.exact_dns("root_rotated")

    resp = await _post_frozen(tree, case["input"]["request"], when=at(case["input"]["registered_at"]))

    assert resp.status_code == 200, resp.text
    epochs, controller = await _state(tree, awid_db_infra)
    rotated_at = at(case["input"]["registered_at"])
    assert [(epoch["seq"], epoch["did_key"], epoch["continuity"]) for epoch in epochs] == [
        (1, did_key("root"), "replaced"), (2, did_key("root_rotated"), case["expected"]["continuity"]),
    ]
    assert epochs[0]["retired_at"] == epochs[1]["registered_at"] == rotated_at
    assert controller == did_key("root_rotated")
    child = await tree.register([certificate("alice"), certificate("bob")], when=at("2026-10-26T00:12:00Z"))
    assert (child.status_code == 200) is case["expected"]["old_registered_ids_still_valid"], child.text


@consumes(
    "namespace-rotation-wrong-from-seq", "namespace-rotation-new-key-only-refuses",
    "namespace-rotation-swapped-roles-refuses",
)
async def test_a_rotation_against_the_first_epoch_refuses(case, tree, awid_db_infra):
    tree.exact_dns("root_rotated")
    before = await _state(tree, awid_db_infra)

    resp = await _post_frozen(tree, case["input"]["request"])

    expected_status = 409 if case["expected"]["reason"] == "head_conflict" else 401
    assert (resp.status_code, _code(resp)) == (expected_status, case["expected"]["reason"]), resp.text
    assert await _state(tree, awid_db_infra) == before


@consumes("namespace-rotation-replay", "namespace-rotation-stale-old-key")
async def test_a_rotation_against_a_later_epoch_refuses(case, tree, awid_db_infra):
    tree.exact_dns("root_rotated")
    assert (await _post_frozen(tree, "valid")).status_code == 200
    tree.exact_dns("other_human" if case["input"]["request"] == "stale-old-key" else "root_rotated")
    assert did_key("other_human" if case["input"]["request"] == "stale-old-key" else "root_rotated") == (
        case["input"]["exact_dns_key"]
    )
    before = await _state(tree, awid_db_infra)

    resp = await _post_frozen(tree, case["input"]["request"], when=at("2026-10-26T00:10:01Z"))

    assert (resp.status_code, _code(resp)) == (409, case["expected"]["reason"]), resp.text
    assert await _state(tree, awid_db_infra) == before


@pytest.mark.parametrize(
    "body",
    [
        _body(extra=1),
        _body(domain="other.example"),
        _body(operation="rotate_controller"),
        _body(from_seq=0),
        _body(from_seq=True),
        _body(from_seq="1"),
        _body(new_did_key=REQUESTS["valid"]["body"]["previous_did_key"]),
        _body(new_did_key="did:key:z6Mkexample"),
        _body(previous_did_key=None),
        _body(previous_did_key=ed25519_vector_key("small-order-A-1")),
        _body(new_did_key=ed25519_vector_key("mixed-order-A-k-div-8")),
    ],
)
@pytest.mark.asyncio
async def test_the_rotation_body_has_exactly_the_contract_fields(body, tree, awid_db_infra):
    tree.exact_dns("root_rotated")
    before = await _state(tree, awid_db_infra)

    resp = await _post(tree, body)

    assert (resp.status_code, _code(resp)) == (400, "invalid_shape"), resp.text
    assert await _state(tree, awid_db_infra) == before


@pytest.mark.asyncio
async def test_the_new_key_proof_is_required(tree, awid_db_infra):
    tree.exact_dns("root_rotated")

    resp = await _post(tree, _body(), new_key_signer=None)

    assert (resp.status_code, _code(resp)) == (401, "invalid_signature"), resp.text


@pytest.mark.asyncio
async def test_the_new_key_proof_must_be_by_the_new_key(tree, awid_db_infra):
    tree.exact_dns("root_rotated")
    before = await _state(tree, awid_db_infra)

    resp = await _post(tree, _body(), new_key_signer="other_human")

    assert (resp.status_code, _code(resp)) == (401, "invalid_signature"), resp.text
    assert await _state(tree, awid_db_infra) == before


@pytest.mark.asyncio
async def test_a_validly_signed_legacy_pair_never_rotates(tree, awid_db_infra):
    tree.exact_dns("root_rotated")
    before = await _state(tree, awid_db_infra)
    body = _body()
    claims = {key: value for key, value in body.items() if key not in ("domain", "operation")}
    headers = build_signed_headers(
        seed("root"), did_key("root"), domain=DOMAIN, operation="rotate_namespace_controller", **claims,
    )
    payload = {
        "domain": DOMAIN, "operation": "rotate_namespace_controller",
        "timestamp": headers["X-AWEB-Timestamp"], **claims,
    }
    headers["X-AWEB-New-Key-Authorization"] = (
        f"DIDKey {did_key('root_rotated')} {sign_message(seed('root_rotated'), canonical_json_bytes(payload))}"
    )

    resp = await tree.client.post(ROTATE_PATH, content=json.dumps(body).encode(), headers=headers)

    assert resp.status_code == 401, resp.text
    assert await _state(tree, awid_db_infra) == before


@pytest.mark.parametrize("dns", ["inherited", "other-key", "failed"])
@pytest.mark.asyncio
async def test_the_new_key_needs_exact_dns(dns, tree, awid_db_infra):
    if dns == "inherited":
        tree.dns("root_rotated", inherited=True)
    elif dns == "other-key":
        tree.exact_dns("other_human")
    else:
        tree.dns(None)
    before = await _state(tree, awid_db_infra)

    resp = await _post(tree, _body())

    assert (resp.status_code, _code(resp)) == (503, "evidence_unavailable"), resp.text
    assert await _state(tree, awid_db_infra) == before


@pytest.mark.asyncio
async def test_the_timestamp_is_rechecked_after_the_lock_wait(tree, awid_db_infra):
    tree.exact_dns("root_rotated")
    db = awid_db_infra.get_manager("aweb")
    before = await _state(tree, awid_db_infra)
    async with db.transaction() as holder:
        await holder.fetch_one(
            "SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain = $1 FOR UPDATE", DOMAIN,
        )
        rotation = asyncio.create_task(_post_frozen(tree, "valid"))
        await wait_until_blocked_on_lock(db, rotation)
        ENVELOPE_NOW["now"] = at("2026-10-26T00:20:00Z")
    try:
        resp = await rotation
    finally:
        ENVELOPE_NOW["now"] = at("2026-10-26T00:10:01Z")

    assert (resp.status_code, _code(resp)) == (401, "invalid_signature"), resp.text
    assert await _state(tree, awid_db_infra) == before
