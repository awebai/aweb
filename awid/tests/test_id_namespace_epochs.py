"""Namespace controller epochs (docs/id-certificates.md "Namespace continuity and replacement").

An epoch opens only on an explicit first namespace registration with exact
DNS proof, on re-registration after deletion, or on an explicit exact
controller-key change. The new-key-only PUT and every DNS-only establishment
open a `replaced` epoch. Same-key observations (reverify, inherited, failed
or unverified DNS) never open, replace or retire one.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from id_tree_support import (
    DOMAIN,
    Tree,
    at,
    certificate,
    consumes,
    did_key,
    seed,
)
from conftest import build_signed_headers
from lock_waits import wait_until_blocked_on_lock


@pytest_asyncio.fixture
async def tree(clocked_client, manual_clock):
    tree = Tree(clocked_client, manual_clock)
    tree.clock.now = at("2026-10-26T00:00:00Z")
    await tree.root()
    for key_name in ("alice", "bob", "other_human"):
        await tree.did(key_name)
    return tree


@pytest_asyncio.fixture
async def pre_upgrade(clocked_client, manual_clock, monkeypatch, awid_db_infra):
    """A namespace registered before epoch history existed: a row, no epoch."""
    tree = Tree(clocked_client, manual_clock)
    tree.clock.now = at("2026-10-26T00:00:00Z")
    monkeypatch.setenv("AWID_SKIP_DNS_VERIFY", "1")
    resp = await tree.register_namespace("root")
    assert resp.status_code == 200, resp.text
    monkeypatch.delenv("AWID_SKIP_DNS_VERIFY")
    assert await _epochs(awid_db_infra) == []
    await tree.did("alice")
    return tree


async def _epochs(awid_db_infra, domain=DOMAIN):
    db = awid_db_infra.get_manager("aweb")
    rows = await db.fetch_all(
        """
        SELECT seq, did_key, continuity, registered_at, retired_at
        FROM {{tables.id_namespace_epochs}}
        WHERE domain = $1
        ORDER BY seq
        """,
        domain,
    )
    return [dict(row) for row in rows]


async def _root_authority(tree, child="alice"):
    """Probe current root authority by registering a root child: available or unavailable."""
    resp = await tree.register([certificate(child)])
    if resp.status_code == 200:
        return "available"
    assert (resp.status_code, resp.json()["detail"]["code"]) == (503, "evidence_unavailable"), resp.text
    return "unavailable"


async def _namespace(tree):
    resp = await tree.client.get(f"/v1/namespaces/{DOMAIN}")
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _namespace_data(awid_db_infra):
    """Namespace, address and team rows, which epoch work must never touch."""
    db = awid_db_infra.get_manager("aweb")
    return [
        [dict(row) for row in await db.fetch_all(f"SELECT * FROM {{{{tables.{table}}}}} ORDER BY 1")]
        for table in ("dns_namespaces", "public_addresses", "teams")
    ]


# ---------------------------------------------------------------------------
# First registration, deletion and re-registration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_exact_first_registration_opens_a_replaced_epoch(tree, awid_db_infra):
    assert await _epochs(awid_db_infra) == [
        {"seq": 1, "did_key": did_key("root"), "continuity": "replaced",
         "registered_at": at("2026-10-26T00:00:00Z"), "retired_at": None},
    ]


@pytest.mark.parametrize("lane", ["inherited", "skip_dns"])
@pytest.mark.asyncio
async def test_a_first_registration_without_exact_proof_opens_no_epoch(
    lane, clocked_client, manual_clock, monkeypatch, awid_db_infra,
):
    tree = Tree(clocked_client, manual_clock)
    if lane == "inherited":
        tree.dns("root", inherited=True)
    else:
        monkeypatch.setenv("AWID_SKIP_DNS_VERIFY", "1")

    resp = await tree.register_namespace("root")

    assert resp.status_code == 200, resp.text
    assert await _epochs(awid_db_infra) == []


@consumes("namespace-delete-with-live-ids-preserves-history")
async def test_namespace_delete_with_live_ids_preserves_history(case, tree, awid_db_infra):
    await tree.enroll("alice", when=at("2026-10-26T00:01:00Z"))
    await tree.enroll("alice", "bob", when=at("2026-10-26T00:02:00Z"))
    db = awid_db_infra.get_manager("aweb")
    revisions = await db.fetch_all("SELECT * FROM {{tables.id_certificates}} ORDER BY registered_at")
    tree.clock.now = at(case["expected"]["epoch_retired_at"])

    resp = await tree.delete_namespace()

    assert resp.status_code == 200, resp.text
    [epoch] = await _epochs(awid_db_infra)
    assert epoch["retired_at"] == at(case["expected"]["epoch_retired_at"])
    assert await db.fetch_all("SELECT * FROM {{tables.id_certificates}} ORDER BY registered_at") == revisions


@consumes("namespace-delete-reregister-cuts-old-tree", "namespace-delete-reregister-same-key-cuts-old-tree")
async def test_namespace_delete_then_reregister_opens_replaced(case, tree, awid_db_infra):
    tree.clock.now = at(case["input"]["deleted_at"])
    assert (await tree.delete_namespace()).status_code == 200
    controller = "root" if case["input"]["reuse_same_key"] else "root_rotated"
    tree.exact_dns(controller)
    tree.clock.now = at(case["input"]["registered_at"])

    resp = await tree.register_namespace(controller)

    assert resp.status_code == 200, resp.text
    first, second = await _epochs(awid_db_infra)
    assert first["retired_at"] == at(case["input"]["deleted_at"])
    assert (second["seq"], second["did_key"], second["continuity"], second["registered_at"]) == (
        2, did_key(controller), case["expected"]["continuity"], at(case["input"]["registered_at"]),
    )


# ---------------------------------------------------------------------------
# Pre-upgrade namespaces: the authenticated POST opens epoch 1 once
# ---------------------------------------------------------------------------


@consumes("pre-upgrade-namespace-authenticated-post-opens-first-epoch")
async def test_pre_upgrade_authenticated_post_opens_first_epoch(case, pre_upgrade, awid_db_infra):
    tree = pre_upgrade
    data = await _namespace_data(awid_db_infra)
    tree.exact_dns("root")
    tree.clock.now = at(case["input"]["registered_at"])

    resp = await tree.register_namespace("root")

    assert resp.status_code == 200, resp.text
    assert await _epochs(awid_db_infra) == [
        {"seq": case["expected"]["epoch_seq"], "did_key": did_key("root"),
         "continuity": case["expected"]["continuity"],
         "registered_at": at(case["expected"]["registered_at"]), "retired_at": None},
    ]
    assert await _namespace_data(awid_db_infra) == data


@consumes("namespace-repeat-authenticated-post-is-epoch-noop")
async def test_repeat_authenticated_post_is_epoch_noop(case, tree, awid_db_infra):
    epochs, data = await _epochs(awid_db_infra), await _namespace_data(awid_db_infra)
    tree.clock.now = at("2026-10-26T00:10:00Z")

    resp = await tree.register_namespace("root")

    assert resp.status_code == 200, resp.text
    assert await _epochs(awid_db_infra) == epochs
    assert await _namespace_data(awid_db_infra) == data


@consumes("pre-upgrade-post-dns-caller-differs-from-stored-controller")
async def test_pre_upgrade_post_by_another_dns_key_opens_nothing(case, pre_upgrade, awid_db_infra):
    tree = pre_upgrade
    data = await _namespace_data(awid_db_infra)
    tree.exact_dns("root_rotated")

    resp = await tree.register_namespace("root_rotated")

    assert resp.status_code == 200, resp.text
    assert await _epochs(awid_db_infra) == []
    assert await _namespace_data(awid_db_infra) == data


@consumes("pre-upgrade-parent-authorized-post-no-epoch")
async def test_pre_upgrade_parent_authorized_post_opens_nothing(case, pre_upgrade, awid_db_infra):
    tree = pre_upgrade
    data = await _namespace_data(awid_db_infra)
    tree.exact_dns("root")
    parent = build_signed_headers(
        seed("other_human"), did_key("other_human"), domain=DOMAIN,
        operation="authorize_subdomain_registration", child_domain=DOMAIN, controller_did=did_key("root"),
    )

    resp = await tree.register_namespace(
        "root",
        headers={
            "X-AWEB-Parent-Authorization": parent["Authorization"],
            "X-AWEB-Parent-Timestamp": parent["X-AWEB-Timestamp"],
        },
    )

    assert resp.status_code == 200, resp.text
    assert await _epochs(awid_db_infra) == []
    assert await _namespace_data(awid_db_infra) == data


@consumes("pre-upgrade-namespace-unauthenticated-reverify-no-epoch")
async def test_pre_upgrade_reverify_opens_nothing(case, pre_upgrade, awid_db_infra):
    pre_upgrade.exact_dns("root")

    resp = await pre_upgrade.reverify()

    assert resp.status_code == 200, resp.text
    assert await _epochs(awid_db_infra) == []
    assert await _root_authority(pre_upgrade) == case["expected"]["tree_authority"]


@consumes("pre-upgrade-concurrent-authenticated-posts-open-once")
async def test_pre_upgrade_concurrent_authenticated_posts_open_once(case, pre_upgrade, awid_db_infra):
    tree = pre_upgrade
    tree.exact_dns("root")
    db = awid_db_infra.get_manager("aweb")
    first_wait_ends = at(case["input"]["last_lock_wait_ends"][0])
    async with db.transaction() as holder:
        await holder.fetch_one(
            "SELECT namespace_id FROM {{tables.dns_namespaces}} WHERE domain = $1 FOR UPDATE", DOMAIN,
        )
        first = asyncio.create_task(tree.register_namespace("root"))
        second = asyncio.create_task(tree.register_namespace("root"))
        await wait_until_blocked_on_lock(db, first, waiters=2)
        tree.clock.now = first_wait_ends
    responses = await asyncio.gather(first, second)

    assert [resp.status_code for resp in responses] == [200, 200]
    assert await _epochs(awid_db_infra) == [
        {"seq": case["expected"]["epoch_seq"], "did_key": did_key("root"),
         "continuity": case["expected"]["continuity"],
         "registered_at": at(case["expected"]["registered_at"]), "retired_at": None},
    ]


# ---------------------------------------------------------------------------
# PUT: new-key-only recovery
# ---------------------------------------------------------------------------


@consumes("namespace-dns-replacement-cuts-tree", "lost-root-key-dns-replacement")
async def test_exact_put_to_a_new_key_opens_replaced(case, tree, awid_db_infra):
    tree.exact_dns("root_rotated")
    tree.clock.now = at(case["input"]["registered_at"])

    resp = await tree.replace_controller("root_rotated")

    assert resp.status_code == 200, resp.text
    first, second = await _epochs(awid_db_infra)
    assert first["retired_at"] == at(case["input"]["registered_at"])
    assert (second["seq"], second["did_key"], second["continuity"], second["registered_at"]) == (
        2, case["input"]["exact_dns_key"], case["expected"]["continuity"], at(case["input"]["registered_at"]),
    )


@pytest.mark.asyncio
async def test_exact_put_of_the_epoch_key_is_an_epoch_noop(tree, awid_db_infra):
    epochs = await _epochs(awid_db_infra)

    resp = await tree.replace_controller("root")

    assert resp.status_code == 200, resp.text
    assert await _epochs(awid_db_infra) == epochs


@pytest.mark.asyncio
async def test_exact_put_without_an_epoch_opens_the_first_one(pre_upgrade, awid_db_infra):
    pre_upgrade.exact_dns("root")
    pre_upgrade.clock.now = at("2026-10-26T00:10:00Z")

    resp = await pre_upgrade.replace_controller("root")

    assert resp.status_code == 200, resp.text
    assert await _epochs(awid_db_infra) == [
        {"seq": 1, "did_key": did_key("root"), "continuity": "replaced",
         "registered_at": at("2026-10-26T00:10:00Z"), "retired_at": None},
    ]


@consumes("namespace-put-skip-dns-no-epoch")
async def test_put_skip_dns_writes_no_epoch(case, tree, awid_db_infra, monkeypatch):
    epochs = await _epochs(awid_db_infra)
    monkeypatch.setenv("AWID_SKIP_DNS_VERIFY", "1")

    resp = await tree.replace_controller("root_rotated")
    monkeypatch.delenv("AWID_SKIP_DNS_VERIFY")

    assert resp.status_code == 200, resp.text
    assert (await _namespace(tree))["controller_did"] == case["expected"]["stored_controller"]
    assert await _epochs(awid_db_infra) == epochs
    assert await _root_authority(tree) == case["expected"]["current_authority"]


@consumes("namespace-put-parent-authorization-no-epoch")
async def test_put_parent_authorization_writes_no_epoch(case, clocked_client, manual_clock, awid_db_infra):
    tree = Tree(clocked_client, manual_clock)
    tree.dns("depth1", domain="com")
    assert (await tree.register_namespace("depth1", domain="com")).status_code == 200
    await tree.root()
    epochs = await _epochs(awid_db_infra)
    parent = build_signed_headers(
        seed("depth1"), did_key("depth1"), domain=DOMAIN, operation="authorize_subdomain_rotation",
        child_domain=DOMAIN, new_controller_did=did_key("root_rotated"),
    )

    resp = await tree.replace_controller(
        "root_rotated",
        headers={
            "X-AWEB-Parent-Authorization": parent["Authorization"],
            "X-AWEB-Parent-Timestamp": parent["X-AWEB-Timestamp"],
        },
    )

    assert resp.status_code == 200, resp.text
    assert (await _namespace(tree))["controller_did"] == case["expected"]["stored_controller"]
    assert await _epochs(awid_db_infra) == epochs
    await tree.did("alice")
    assert await _root_authority(tree) == case["expected"]["current_authority"]


@consumes("namespace-reverify-row-change-then-exact-put-opens-replaced")
async def test_reverify_row_change_then_exact_put_opens_replaced(case, tree, awid_db_infra):
    tree.exact_dns("root_rotated")
    assert (await tree.reverify()).status_code == 200
    assert (await _namespace(tree))["controller_did"] == case["input"]["stored_controller_after_reverify"]
    assert len(await _epochs(awid_db_infra)) == 1
    tree.clock.now = at("2026-10-26T00:10:00Z")

    resp = await tree.replace_controller("root_rotated")

    assert resp.status_code == 200, resp.text
    first, second = await _epochs(awid_db_infra)
    assert first["retired_at"] is not None
    assert (second["seq"], second["did_key"], second["continuity"]) == (
        case["expected"]["epoch_seq"], case["expected"]["stored_controller"], case["expected"]["continuity"],
    )


# ---------------------------------------------------------------------------
# Observations never touch epochs
# ---------------------------------------------------------------------------


@consumes("namespace-same-key-reverify-no-epoch")
async def test_same_key_reverify_writes_no_epoch(case, tree, awid_db_infra):
    epochs = await _epochs(awid_db_infra)

    resp = await tree.reverify()

    assert resp.status_code == 200, resp.text
    assert await _epochs(awid_db_infra) == epochs
    assert case["expected"]["tree_valid"] is True
    assert await _root_authority(tree) == "available"


@consumes("namespace-unauthenticated-reverify-cannot-replace")
async def test_reverify_to_another_key_writes_no_epoch(case, tree, awid_db_infra):
    epochs = await _epochs(awid_db_infra)
    tree.exact_dns("root_rotated")

    resp = await tree.reverify()

    assert resp.status_code == 200, resp.text
    assert await _epochs(awid_db_infra) == epochs
    assert await _root_authority(tree) == case["expected"]["current_authority"]


@consumes("namespace-failed-dns-observation-no-epoch", "namespace-unverified-dns-observation-no-epoch")
async def test_failed_or_unverified_dns_writes_no_epoch(case, tree, awid_db_infra, monkeypatch):
    epochs = await _epochs(awid_db_infra)
    if case["input"]["observed_dns"] == "failed":
        tree.dns(None)
    else:
        monkeypatch.setenv("AWID_SKIP_DNS_VERIFY", "1")

    await tree.reverify()
    await tree.register_namespace("root")

    assert await _epochs(awid_db_infra) == epochs
    assert await _root_authority(tree) == case["expected"]["current_authority"]


@consumes("namespace-exact-inherited-exact-same-key")
async def test_exact_inherited_exact_observations_write_no_epoch(case, tree, awid_db_infra):
    epochs = await _epochs(awid_db_infra)

    outcomes = []
    for observation, child in zip(case["input"]["observations"], ["alice", "other-human", "other-human"]):
        tree.dns("root", inherited=observation["authority"] == "inherited")
        assert (await tree.reverify()).status_code == 200
        assert (await tree.register_namespace("root")).status_code == 200
        assert (await tree.replace_controller("root")).status_code == 200
        outcomes.append(await _root_authority(tree, child))

    assert outcomes == case["expected"]["authority_outcomes"]
    assert await _epochs(awid_db_infra) == epochs


@pytest.mark.asyncio
async def test_epoch_times_stay_monotone_when_the_clock_goes_back(tree, awid_db_infra):
    tree.exact_dns("root_rotated")
    tree.clock.now = at("2026-10-25T00:00:00Z")

    resp = await tree.replace_controller("root_rotated")

    assert resp.status_code == 200, resp.text
    first, second = await _epochs(awid_db_infra)
    assert first["retired_at"] == second["registered_at"] > first["registered_at"]
