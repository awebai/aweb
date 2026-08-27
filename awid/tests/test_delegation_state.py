from __future__ import annotations

import asyncio

import pytest
from nacl.signing import SigningKey

from awid.delegation import (
    DELEGATION_VERSION,
    DelegationPayload,
    canonical_delegation_payload,
    delegation_entry_hash,
)
from awid.did import did_from_public_key, generate_keypair
from awid.signing import sign_message
from awid_service.delegation_state import (
    DelegationStateError,
    append_transition,
    stored_delegation_chain,
)
from awid_service.routes.dns_namespaces import _validated_rollover_children


def assertion(*, operation, parent, child, controller, sequence, previous, key, signer):
    payload = DelegationPayload(
        version=DELEGATION_VERSION,
        operation=operation,
        parent_domain=parent,
        child_domain=child,
        child_controller_did=controller,
        sequence=sequence,
        previous_delegation_hash=previous,
    )
    canonical = canonical_delegation_payload(payload)
    return {
        "payload": payload.model_dump(mode="json"),
        "entry_hash": delegation_entry_hash(canonical),
        "signatures": [{"controller_did": signer, "signature": sign_message(key, canonical)}],
    }


@pytest.mark.asyncio
async def test_retry_is_submitted_subset_and_returns_rollover_signature_superset(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    parent_signing_key = SigningKey(bytes([3]) * 32)
    parent_key = bytes(parent_signing_key)
    parent_did = did_from_public_key(bytes(parent_signing_key.verify_key))
    next_parent_signing_key = SigningKey(bytes([230]) * 32)
    next_parent_key = bytes(next_parent_signing_key)
    next_parent_did = did_from_public_key(bytes(next_parent_signing_key.verify_key))
    assert parent_did == "did:key:z6MkvRXNYcE7MMduynWTgeKbDaT1iijDSC8pZqXZc8rHPrf2"
    assert next_parent_did == "did:key:z6MkvRjjH6wfER2xTYDatCEECjdWFpKTC5w1PPFUnMCVdx7W"
    child_key, child_public = generate_keypair()
    child_did = did_from_public_key(child_public)
    item = assertion(
        operation="delegate", parent="retry.example", child="child.retry.example",
        controller=child_did, sequence=1, previous=None, key=parent_key, signer=parent_did,
    )
    async with db.transaction() as tx:
        await append_transition(
            tx, item, authority_did=parent_did,
            expected_child_domain="child.retry.example",
            expected_child_controller_did=child_did,
            expected_operation="delegate",
        )
        canonical = canonical_delegation_payload(DelegationPayload.model_validate(item["payload"]))
        await tx.execute(
            """
            INSERT INTO {{tables.namespace_delegation_signatures}}
                (child_domain,sequence,controller_did,signature)
            VALUES ('child.retry.example',1,$1,$2)
            """,
            next_parent_did,
            sign_message(next_parent_key, canonical),
        )
    async with db.transaction() as tx:
        retried = await append_transition(
            tx, item, authority_did=parent_did,
            expected_child_domain="child.retry.example",
            expected_child_controller_did=child_did,
            expected_operation="delegate",
        )
    assert [value["controller_did"] for value in retried["signatures"]] == sorted(
        [parent_did, next_parent_did]
    )

    same_controller_rotation = assertion(
        operation="rotate", parent="retry.example", child="child.retry.example",
        controller=child_did, sequence=2, previous=item["entry_hash"],
        key=parent_key, signer=parent_did,
    )
    async with db.transaction() as tx:
        with pytest.raises(DelegationStateError, match="does not extend"):
            await append_transition(
                tx, same_controller_rotation, authority_did=parent_did,
                expected_child_domain="child.retry.example",
                expected_child_controller_did=child_did,
                expected_operation="rotate",
            )

    unknown_key, unknown_public = generate_keypair()
    unknown_did = did_from_public_key(unknown_public)
    unknown = dict(item)
    unknown["signatures"] = [
        {"controller_did": unknown_did, "signature": sign_message(unknown_key, canonical)}
    ]
    async with db.transaction() as tx:
        with pytest.raises(DelegationStateError, match="cannot add or replace"):
            await append_transition(
                tx, unknown, authority_did=parent_did,
                expected_child_domain="child.retry.example",
                expected_child_controller_did=child_did,
                expected_operation="delegate",
            )


@pytest.mark.asyncio
async def test_concurrent_successor_fork_has_one_atomic_winner(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    parent_key, parent_public = generate_keypair()
    parent_did = did_from_public_key(parent_public)
    child_key, child_public = generate_keypair()
    child_did = did_from_public_key(child_public)
    genesis = assertion(
        operation="delegate", parent="race.example", child="child.race.example",
        controller=child_did, sequence=1, previous=None, key=parent_key, signer=parent_did,
    )
    async with db.transaction() as tx:
        await append_transition(
            tx, genesis, authority_did=parent_did,
            expected_child_domain="child.race.example",
            expected_child_controller_did=child_did,
            expected_operation="delegate",
        )
    candidates = []
    for _ in range(2):
        _, public = generate_keypair()
        candidate_did = did_from_public_key(public)
        candidates.append(
            assertion(
                operation="rotate", parent="race.example", child="child.race.example",
                controller=candidate_did, sequence=2, previous=genesis["entry_hash"],
                key=parent_key, signer=parent_did,
            )
        )

    async def apply(item):
        try:
            async with db.transaction() as tx:
                await append_transition(
                    tx, item, authority_did=parent_did,
                    expected_child_domain="child.race.example",
                    expected_child_controller_did=item["payload"]["child_controller_did"],
                    expected_operation="rotate",
                )
            return "ok"
        except DelegationStateError:
            return "conflict"

    assert sorted(await asyncio.gather(*(apply(item) for item in candidates))) == [
        "conflict",
        "ok",
    ]
    assert await db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.namespace_delegation_entries}} WHERE child_domain='child.race.example' AND sequence=2"
    ) == 1


@pytest.mark.asyncio
async def test_nested_chain_stops_at_direct_marker_and_fails_inconsistent_marker(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    root_key, root_public = generate_keypair()
    root_did = did_from_public_key(root_public)
    parent_key, parent_public = generate_keypair()
    parent_did = did_from_public_key(parent_public)
    leaf_key, leaf_public = generate_keypair()
    leaf_did = did_from_public_key(leaf_public)
    await db.execute(
        """
        INSERT INTO {{tables.dns_namespaces}}
            (domain,controller_did,verification_status)
        VALUES ('root.example',$1,'verified'),('parent.root.example',$2,'verified'),
               ('leaf.parent.root.example',$3,'verified')
        """,
        root_did,
        parent_did,
        leaf_did,
    )
    parent_assertion = assertion(
        operation="delegate", parent="root.example", child="parent.root.example",
        controller=parent_did, sequence=1, previous=None, key=root_key, signer=root_did,
    )
    leaf_assertion = assertion(
        operation="delegate", parent="parent.root.example", child="leaf.parent.root.example",
        controller=leaf_did, sequence=1, previous=None, key=parent_key, signer=parent_did,
    )
    async with db.transaction() as tx:
        await append_transition(
            tx, parent_assertion, authority_did=root_did,
            expected_child_domain="parent.root.example",
            expected_child_controller_did=parent_did,
            expected_operation="delegate",
        )
        await append_transition(
            tx, leaf_assertion, authority_did=parent_did,
            expected_child_domain="leaf.parent.root.example",
            expected_child_controller_did=leaf_did,
            expected_operation="delegate",
        )
        await tx.execute(
            "UPDATE {{tables.dns_namespaces}} SET active_delegation_hash=$2 WHERE domain=$1",
            "parent.root.example",
            parent_assertion["entry_hash"],
        )
        await tx.execute(
            "UPDATE {{tables.dns_namespaces}} SET active_delegation_hash=$2 WHERE domain=$1",
            "leaf.parent.root.example",
            leaf_assertion["entry_hash"],
        )
    assert [item["entry_hash"] for item in await stored_delegation_chain(db, "leaf.parent.root.example")] == [
        parent_assertion["entry_hash"],
        leaf_assertion["entry_hash"],
    ]
    async with db.transaction() as tx:
        root_children = await _validated_rollover_children(tx, "root.example")
    assert [row["child_domain"] for row in root_children] == ["parent.root.example"]

    await db.execute(
        "UPDATE {{tables.dns_namespaces}} SET active_delegation_hash=NULL WHERE domain='parent.root.example'"
    )
    assert [item["entry_hash"] for item in await stored_delegation_chain(db, "leaf.parent.root.example")] == [
        leaf_assertion["entry_hash"]
    ]
    await db.execute(
        "UPDATE {{tables.dns_namespaces}} SET active_delegation_hash=$1 WHERE domain='parent.root.example'",
        "sha256:" + "f" * 64,
    )
    with pytest.raises(DelegationStateError, match="inconsistent"):
        await stored_delegation_chain(db, "leaf.parent.root.example")
