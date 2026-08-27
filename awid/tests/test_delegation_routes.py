from __future__ import annotations

import asyncio
import hashlib
from uuid import uuid4

import pytest

from awid.delegation import (
    DELEGATION_VERSION,
    DelegationPayload,
    canonical_delegation_payload,
    delegation_entry_hash,
)
from awid.did import did_from_public_key, generate_keypair
from awid.dns_verify import DomainAuthority
from awid.signing import canonical_json_bytes, sign_message
from awid_service.delegation_state import append_transition
from awid_service.deps import get_domain_verifier
from conftest import build_signed_headers


def _assertion(*, operation, parent_domain, child_domain, child_did, sequence, previous_hash, signer_key, signer_did):
    payload = DelegationPayload(
        version=DELEGATION_VERSION,
        operation=operation,
        parent_domain=parent_domain,
        child_domain=child_domain,
        child_controller_did=child_did,
        sequence=sequence,
        previous_delegation_hash=previous_hash,
    )
    canonical = canonical_delegation_payload(payload)
    entry_hash = delegation_entry_hash(canonical)
    return {
        "payload": payload.model_dump(mode="json"),
        "entry_hash": entry_hash,
        "signatures": [
            {"controller_did": signer_did, "signature": sign_message(signer_key, canonical)}
        ],
    }


def _parent_headers(key, did, *, domain, operation, **extra):
    headers = build_signed_headers(key, did, domain=domain, operation=operation, **extra)
    return {
        "X-AWEB-Parent-Authorization": headers["Authorization"],
        "X-AWEB-Parent-Timestamp": headers["X-AWEB-Timestamp"],
    }


async def _register_parent(client, parent_key, parent_did, domain):
    headers = build_signed_headers(parent_key, parent_did, domain=domain, operation="register")
    response = await client.post("/v1/namespaces", json={"domain": domain}, headers=headers)
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_delegated_create_rotate_delete_persists_public_history(
    client, controller_identity, awid_db_infra,
):
    parent_key, parent_did = controller_identity
    parent_domain = "delegation.example"
    child_domain = "child.delegation.example"
    await _register_parent(client, parent_key, parent_did, parent_domain)

    child_key, child_public = generate_keypair()
    child_did = did_from_public_key(child_public)
    genesis = _assertion(
        operation="delegate",
        parent_domain=parent_domain,
        child_domain=child_domain,
        child_did=child_did,
        sequence=1,
        previous_hash=None,
        signer_key=parent_key,
        signer_did=parent_did,
    )
    create_headers = build_signed_headers(
        child_key,
        child_did,
        domain=child_domain,
        operation="register",
        controller_did=child_did,
        delegation_entry_hash=genesis["entry_hash"],
    )
    create_headers.update(
        _parent_headers(
            parent_key,
            parent_did,
            domain=child_domain,
            operation="authorize_subdomain_registration",
            child_domain=child_domain,
            controller_did=child_did,
            delegation_entry_hash=genesis["entry_hash"],
        )
    )
    created = await client.post(
        "/v1/namespaces",
        json={
            "domain": child_domain,
            "controller_did": child_did,
            "delegation_assertion": genesis,
        },
        headers=create_headers,
    )
    assert created.status_code == 200, created.text
    assert created.json()["delegation_chain"] == [genesis]

    other_key, other_public = generate_keypair()
    other_did = did_from_public_key(other_public)
    conflicting_create = _assertion(
        operation="delegate", parent_domain=parent_domain, child_domain=child_domain,
        child_did=other_did, sequence=1, previous_hash=None,
        signer_key=parent_key, signer_did=parent_did,
    )
    conflict_headers = build_signed_headers(
        other_key, other_did, domain=child_domain, operation="register",
        controller_did=other_did,
        delegation_entry_hash=conflicting_create["entry_hash"],
    )
    conflict_headers.update(_parent_headers(
        parent_key, parent_did, domain=child_domain,
        operation="authorize_subdomain_registration", child_domain=child_domain,
        controller_did=other_did,
        delegation_entry_hash=conflicting_create["entry_hash"],
    ))
    conflict = await client.post(
        "/v1/namespaces",
        json={
            "domain": child_domain, "controller_did": other_did,
            "delegation_assertion": conflicting_create,
        },
        headers=conflict_headers,
    )
    assert conflict.status_code == 409
    db = awid_db_infra.get_manager("aweb")
    unchanged = await db.fetch_one(
        """
        SELECT ns.controller_did,ns.active_delegation_hash,h.head_hash,
               (SELECT COUNT(*) FROM {{tables.namespace_delegation_entries}} e WHERE e.child_domain=ns.domain)::int AS entries
        FROM {{tables.dns_namespaces}} ns
        JOIN {{tables.namespace_delegation_heads}} h ON h.child_domain=ns.domain
        WHERE ns.domain=$1 AND ns.deleted_at IS NULL
        """,
        child_domain,
    )
    assert unchanged["controller_did"] == child_did
    assert unchanged["active_delegation_hash"] == genesis["entry_hash"]
    assert unchanged["head_hash"] == genesis["entry_hash"]
    assert unchanged["entries"] == 1

    parent_delete_headers = build_signed_headers(
        parent_key, parent_did, domain=parent_domain, operation="delete_namespace",
    )
    parent_delete = await client.request(
        "DELETE", f"/v1/namespaces/{parent_domain}", headers=parent_delete_headers,
    )
    assert parent_delete.status_code == 409
    assert parent_delete.json()["detail"]["code"] == "namespace_has_nonrevoked_child_delegations"

    new_key, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    legacy_rotate_headers = build_signed_headers(
        new_key,
        new_did,
        domain=child_domain,
        operation="rotate_controller",
        new_controller_did=new_did,
    )
    legacy_rotate_headers.update(
        _parent_headers(
            parent_key,
            parent_did,
            domain=child_domain,
            operation="authorize_subdomain_rotation",
            child_domain=child_domain,
            new_controller_did=new_did,
        )
    )
    legacy_rotate = await client.put(
        f"/v1/namespaces/{child_domain}",
        json={"new_controller_did": new_did},
        headers=legacy_rotate_headers,
    )
    assert legacy_rotate.status_code == 409
    assert legacy_rotate.json()["detail"]["code"] == "namespace_delegation_required"

    rotation = _assertion(
        operation="rotate",
        parent_domain=parent_domain,
        child_domain=child_domain,
        child_did=new_did,
        sequence=2,
        previous_hash=genesis["entry_hash"],
        signer_key=parent_key,
        signer_did=parent_did,
    )
    rotate_headers = build_signed_headers(
        new_key,
        new_did,
        domain=child_domain,
        operation="rotate_controller",
        new_controller_did=new_did,
        delegation_entry_hash=rotation["entry_hash"],
    )
    rotate_headers.update(
        _parent_headers(
            parent_key,
            parent_did,
            domain=child_domain,
            operation="authorize_subdomain_rotation",
            child_domain=child_domain,
            new_controller_did=new_did,
            delegation_entry_hash=rotation["entry_hash"],
        )
    )
    rotated = await client.put(
        f"/v1/namespaces/{child_domain}",
        json={"new_controller_did": new_did, "delegation_assertion": rotation},
        headers=rotate_headers,
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["controller_did"] == new_did
    stale_page = await client.get(
        f"/v1/namespaces/{child_domain}/delegation-log",
        params={"after_sequence": 0, "limit": 1},
    )
    assert stale_page.status_code == 200, stale_page.text
    stale_cursor = stale_page.json()["next_cursor"]

    tombstone = _assertion(
        operation="revoke",
        parent_domain=parent_domain,
        child_domain=child_domain,
        child_did=new_did,
        sequence=3,
        previous_hash=rotation["entry_hash"],
        signer_key=new_key,
        signer_did=new_did,
    )
    delete_headers = build_signed_headers(
        new_key,
        new_did,
        domain=child_domain,
        operation="delete_namespace",
        delegation_entry_hash=tombstone["entry_hash"],
    )
    deleted = await client.request(
        "DELETE",
        f"/v1/namespaces/{child_domain}",
        json={"delegation_assertion": tombstone},
        headers=delete_headers,
    )
    assert deleted.status_code == 200, deleted.text

    assert (await client.get(f"/v1/namespaces/{child_domain}")).status_code == 404
    changed_snapshot = await client.get(
        f"/v1/namespaces/{child_domain}/delegation-log",
        params={"cursor": stale_cursor},
    )
    assert changed_snapshot.status_code == 409
    assert changed_snapshot.json()["detail"]["code"] == "delegation_log_snapshot_changed"
    history = await client.get(
        f"/v1/namespaces/{child_domain}/delegation-log",
        params={"after_sequence": 0, "limit": 100},
    )
    assert history.status_code == 200, history.text
    body = history.json()
    assert [entry["entry_hash"] for entry in body["entries"]] == [
        genesis["entry_hash"],
        rotation["entry_hash"],
        tombstone["entry_hash"],
    ]
    assert body["head_hash"] == tombstone["entry_hash"]
    assert body["has_more"] is False

    first_page, first_retry = await asyncio.gather(
        client.get(
            f"/v1/namespaces/{child_domain}/delegation-log",
            params={"after_sequence": 0, "limit": 1},
        ),
        client.get(
            f"/v1/namespaces/{child_domain}/delegation-log",
            params={"after_sequence": 0, "limit": 1},
        ),
    )
    assert first_page.status_code == 200, first_page.text
    first = first_page.json()
    assert [entry["entry_hash"] for entry in first["entries"]] == [genesis["entry_hash"]]
    assert first["next_cursor"]
    assert first_retry.json() == first
    forged = await client.get(
        f"/v1/namespaces/{child_domain}/delegation-log",
        params={"cursor": first["next_cursor"] + "x"},
    )
    assert forged.status_code == 400
    assert forged.json()["detail"]["code"] == "delegation_cursor_invalid"

    second_page = await client.get(
        f"/v1/namespaces/{child_domain}/delegation-log",
        params={"cursor": first["next_cursor"]},
    )
    second_retry = await client.get(
        f"/v1/namespaces/{child_domain}/delegation-log",
        params={"cursor": first["next_cursor"]},
    )
    assert second_page.status_code == 200, second_page.text
    assert second_retry.json() == second_page.json()
    second = second_page.json()
    assert [entry["entry_hash"] for entry in second["entries"]] == [rotation["entry_hash"]]
    assert second["next_cursor"]

    final_page = await client.get(
        f"/v1/namespaces/{child_domain}/delegation-log",
        params={"cursor": second["next_cursor"]},
    )
    assert final_page.status_code == 200, final_page.text
    assert [entry["entry_hash"] for entry in final_page.json()["entries"]] == [
        tombstone["entry_hash"]
    ]
    assert final_page.json()["next_cursor"] is None


@pytest.mark.asyncio
async def test_rollover_start_serializes_with_child_rotation(
    client, controller_identity, awid_db_infra,
):
    parent_key, parent_did = controller_identity
    parent_domain = "start-race.example"
    child_domain = "child.start-race.example"
    await _register_parent(client, parent_key, parent_did, parent_domain)
    child_key, child_public = generate_keypair()
    child_did = did_from_public_key(child_public)
    genesis = _assertion(
        operation="delegate", parent_domain=parent_domain, child_domain=child_domain,
        child_did=child_did, sequence=1, previous_hash=None,
        signer_key=parent_key, signer_did=parent_did,
    )
    async with awid_db_infra.get_manager("aweb").transaction() as tx:
        await append_transition(
            tx, genesis, authority_did=parent_did,
            expected_child_domain=child_domain,
            expected_child_controller_did=child_did, expected_operation="delegate",
        )
        await tx.execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status,active_delegation_hash) VALUES ($1,$2,'verified',$3)",
            child_domain, child_did, genesis["entry_hash"],
        )
    replacement_key, replacement_public = generate_keypair()
    replacement_did = did_from_public_key(replacement_public)
    successor = _assertion(
        operation="rotate", parent_domain=parent_domain, child_domain=child_domain,
        child_did=replacement_did, sequence=2, previous_hash=genesis["entry_hash"],
        signer_key=parent_key, signer_did=parent_did,
    )
    rotate_headers = build_signed_headers(
        replacement_key, replacement_did, domain=child_domain,
        operation="rotate_controller", new_controller_did=replacement_did,
        delegation_entry_hash=successor["entry_hash"],
    )
    rotate_headers.update(_parent_headers(
        parent_key, parent_did, domain=child_domain,
        operation="authorize_subdomain_rotation", child_domain=child_domain,
        new_controller_did=replacement_did, delegation_entry_hash=successor["entry_hash"],
    ))
    new_parent_key, new_parent_public = generate_keypair()
    new_parent_did = did_from_public_key(new_parent_public)
    start_headers = build_signed_headers(
        parent_key, parent_did, domain=parent_domain,
        operation="start_controller_rollover", new_controller_did=new_parent_did,
        recovery_mode="none",
    )
    proof = build_signed_headers(
        new_parent_key, new_parent_did, domain=parent_domain,
        operation="prove_controller_rollover_key", new_controller_did=new_parent_did,
        recovery_mode="none",
    )
    start_headers["X-AWEB-New-Controller-Authorization"] = proof["Authorization"]
    start_headers["X-AWEB-New-Controller-Timestamp"] = proof["X-AWEB-Timestamp"]
    started, rotated = await asyncio.gather(
        client.post(
            f"/v1/namespaces/{parent_domain}/controller-rollovers",
            json={"new_controller_did": new_parent_did, "recovery_mode": "none"},
            headers=start_headers,
        ),
        client.put(
            f"/v1/namespaces/{child_domain}",
            json={"new_controller_did": replacement_did, "delegation_assertion": successor},
            headers=rotate_headers,
        ),
    )
    assert started.status_code == 200, started.text
    assert rotated.status_code in {200, 409}, rotated.text
    db = awid_db_infra.get_manager("aweb")
    row = await db.fetch_one(
        """
        SELECT c.head_hash AS snapshot_hash,h.head_hash AS live_hash
        FROM {{tables.namespace_controller_rollover_children}} c
        JOIN {{tables.namespace_delegation_heads}} h ON h.child_domain=c.child_domain
        WHERE c.rollover_id=$1::uuid AND c.child_domain=$2
        """,
        started.json()["rollover_id"], child_domain,
    )
    assert row["snapshot_hash"] == row["live_hash"]


@pytest.mark.asyncio
async def test_rollover_snapshots_signs_and_fences_child_mutation(
    client, controller_identity, awid_db_infra,
):
    parent_key, parent_did = controller_identity
    parent_domain = "rollover.example"
    child_domain = "child.rollover.example"
    await _register_parent(client, parent_key, parent_did, parent_domain)

    child_key, child_public = generate_keypair()
    child_did = did_from_public_key(child_public)
    genesis = _assertion(
        operation="delegate",
        parent_domain=parent_domain,
        child_domain=child_domain,
        child_did=child_did,
        sequence=1,
        previous_hash=None,
        signer_key=parent_key,
        signer_did=parent_did,
    )
    child_headers = build_signed_headers(
        child_key,
        child_did,
        domain=child_domain,
        operation="register",
        controller_did=child_did,
        delegation_entry_hash=genesis["entry_hash"],
    )
    child_headers.update(
        _parent_headers(
            parent_key,
            parent_did,
            domain=child_domain,
            operation="authorize_subdomain_registration",
            child_domain=child_domain,
            controller_did=child_did,
            delegation_entry_hash=genesis["entry_hash"],
        )
    )
    response = await client.post(
        "/v1/namespaces",
        json={"domain": child_domain, "controller_did": child_did, "delegation_assertion": genesis},
        headers=child_headers,
    )
    assert response.status_code == 200, response.text

    new_parent_key, new_parent_public = generate_keypair()
    new_parent_did = did_from_public_key(new_parent_public)
    start_headers = build_signed_headers(
        parent_key,
        parent_did,
        domain=parent_domain,
        operation="start_controller_rollover",
        new_controller_did=new_parent_did,
        recovery_mode="none",
    )
    new_proof = build_signed_headers(
        new_parent_key,
        new_parent_did,
        domain=parent_domain,
        operation="prove_controller_rollover_key",
        new_controller_did=new_parent_did,
        recovery_mode="none",
    )
    start_headers["X-AWEB-New-Controller-Authorization"] = new_proof["Authorization"]
    start_headers["X-AWEB-New-Controller-Timestamp"] = new_proof["X-AWEB-Timestamp"]
    started = await client.post(
        f"/v1/namespaces/{parent_domain}/controller-rollovers",
        json={"new_controller_did": new_parent_did, "recovery_mode": "none"},
        headers=start_headers,
    )
    assert started.status_code == 200, started.text
    rollover = started.json()
    assert rollover["state"] == "preparing"
    assert rollover["total_children"] == 1
    assert await awid_db_infra.get_manager("aweb").fetch_value(
        "SELECT previous_dns_ttl_seconds FROM {{tables.namespace_controller_rollovers}} WHERE rollover_id=$1::uuid",
        rollover["rollover_id"],
    ) == 300

    replay_register_headers = build_signed_headers(
        child_key, child_did, domain=child_domain, operation="register",
    )
    replay_register_headers.update(_parent_headers(
        parent_key, parent_did, domain=child_domain,
        operation="authorize_subdomain_registration", child_domain=child_domain,
        controller_did=child_did,
    ))
    replay_register = await client.post(
        "/v1/namespaces",
        json={"domain": child_domain, "controller_did": child_did},
        headers=replay_register_headers,
    )
    assert replay_register.status_code == 409
    assert replay_register.json()["detail"]["code"] == "namespace_delegation_fenced"
    fenced_delete_headers = build_signed_headers(
        child_key, child_did, domain=child_domain, operation="delete_namespace",
    )
    fenced_delete = await client.request(
        "DELETE", f"/v1/namespaces/{child_domain}", headers=fenced_delete_headers,
    )
    assert fenced_delete.status_code == 409
    assert fenced_delete.json()["detail"]["code"] == "namespace_delegation_fenced"

    children = await client.get(
        f"/v1/namespaces/{parent_domain}/controller-rollovers/{rollover['rollover_id']}/children"
    )
    assert children.status_code == 200, children.text
    child = children.json()["children"][0]
    signature = sign_message(new_parent_key, canonical_json_bytes(child["payload"]))
    batch = {
        "signatures": [
            {
                "child_domain": child_domain,
                "head_hash": genesis["entry_hash"],
                "signature": signature,
            }
        ]
    }
    batch_hash = "sha256:" + hashlib.sha256(canonical_json_bytes(batch)).hexdigest()
    batch_headers = build_signed_headers(
        new_parent_key,
        new_parent_did,
        domain=parent_domain,
        operation="attach_controller_rollover_signatures",
        rollover_id=rollover["rollover_id"],
        batch_hash=batch_hash,
    )
    attached = await client.put(
        f"/v1/namespaces/{parent_domain}/controller-rollovers/{rollover['rollover_id']}/signatures",
        json=batch,
        headers=batch_headers,
    )
    assert attached.status_code == 200, attached.text
    assert attached.json()["state"] == "ready"
    assert attached.json()["signed_children"] == 1
    attached_retry = await client.put(
        f"/v1/namespaces/{parent_domain}/controller-rollovers/{rollover['rollover_id']}/signatures",
        json=batch,
        headers=batch_headers,
    )
    assert attached_retry.status_code == 200, attached_retry.text
    assert attached_retry.json()["signed_children"] == 1

    replacement_key, replacement_public = generate_keypair()
    replacement_did = did_from_public_key(replacement_public)
    successor = _assertion(
        operation="rotate",
        parent_domain=parent_domain,
        child_domain=child_domain,
        child_did=replacement_did,
        sequence=2,
        previous_hash=genesis["entry_hash"],
        signer_key=parent_key,
        signer_did=parent_did,
    )
    rotate_headers = build_signed_headers(
        replacement_key,
        replacement_did,
        domain=child_domain,
        operation="rotate_controller",
        new_controller_did=replacement_did,
        delegation_entry_hash=successor["entry_hash"],
    )
    rotate_headers.update(
        _parent_headers(
            parent_key,
            parent_did,
            domain=child_domain,
            operation="authorize_subdomain_rotation",
            child_domain=child_domain,
            new_controller_did=replacement_did,
            delegation_entry_hash=successor["entry_hash"],
        )
    )
    fenced = await client.put(
        f"/v1/namespaces/{child_domain}",
        json={"new_controller_did": replacement_did, "delegation_assertion": successor},
        headers=rotate_headers,
    )
    assert fenced.status_code == 409
    assert fenced.json()["detail"]["code"] == "namespace_delegation_fenced"

    cancel_headers = build_signed_headers(
        parent_key,
        parent_did,
        domain=parent_domain,
        operation="cancel_controller_rollover",
        rollover_id=rollover["rollover_id"],
    )
    canceled = await client.request(
        "DELETE",
        f"/v1/namespaces/{parent_domain}/controller-rollovers/{rollover['rollover_id']}",
        headers=cancel_headers,
    )
    assert canceled.status_code == 200, canceled.text
    assert canceled.json()["state"] == "canceled"

    retried = await client.put(
        f"/v1/namespaces/{child_domain}",
        json={"new_controller_did": replacement_did, "delegation_assertion": successor},
        headers=rotate_headers,
    )
    assert retried.status_code == 200, retried.text


@pytest.mark.asyncio
async def test_direct_rotation_requires_parent_sync_before_revoke(client, controller_identity):
    parent_key, parent_did = controller_identity
    parent_domain = "dormant.example"
    child_domain = "child.dormant.example"
    await _register_parent(client, parent_key, parent_did, parent_domain)
    child_key, child_public = generate_keypair()
    child_did = did_from_public_key(child_public)
    genesis = _assertion(
        operation="delegate", parent_domain=parent_domain, child_domain=child_domain,
        child_did=child_did, sequence=1, previous_hash=None,
        signer_key=parent_key, signer_did=parent_did,
    )
    headers = build_signed_headers(
        child_key, child_did, domain=child_domain, operation="register",
        controller_did=child_did, delegation_entry_hash=genesis["entry_hash"],
    )
    headers.update(_parent_headers(
        parent_key, parent_did, domain=child_domain,
        operation="authorize_subdomain_registration", child_domain=child_domain,
        controller_did=child_did, delegation_entry_hash=genesis["entry_hash"],
    ))
    assert (await client.post(
        "/v1/namespaces",
        json={"domain": child_domain, "controller_did": child_did, "delegation_assertion": genesis},
        headers=headers,
    )).status_code == 200

    new_key, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)

    async def exact_child_verifier(domain):
        return DomainAuthority(
            controller_did=new_did,
            registry_url="https://api.awid.ai",
            dns_name=f"_awid.{domain}",
            inherited=False,
            ttl_seconds=300,
        )

    app = client._transport.app
    previous_override = app.dependency_overrides[get_domain_verifier]
    app.dependency_overrides[get_domain_verifier] = lambda: exact_child_verifier
    try:
        direct_headers = build_signed_headers(
            new_key, new_did, domain=child_domain, operation="rotate_controller",
            new_controller_did=new_did,
        )
        direct = await client.put(
            f"/v1/namespaces/{child_domain}",
            json={"new_controller_did": new_did},
            headers=direct_headers,
        )
        assert direct.status_code == 200, direct.text
        assert direct.json()["delegation_chain"] == [genesis]

        invalid_revoke = _assertion(
            operation="revoke", parent_domain=parent_domain, child_domain=child_domain,
            child_did=new_did, sequence=2, previous_hash=genesis["entry_hash"],
            signer_key=new_key, signer_did=new_did,
        )
        delete_headers = build_signed_headers(
            new_key, new_did, domain=child_domain, operation="delete_namespace",
            delegation_entry_hash=invalid_revoke["entry_hash"],
        )
        refused = await client.request(
            "DELETE", f"/v1/namespaces/{child_domain}",
            json={"delegation_assertion": invalid_revoke}, headers=delete_headers,
        )
        assert refused.status_code == 409
        assert refused.json()["detail"]["code"] == "namespace_delegation_sync_required"

        sync = _assertion(
            operation="rotate", parent_domain=parent_domain, child_domain=child_domain,
            child_did=new_did, sequence=2, previous_hash=genesis["entry_hash"],
            signer_key=parent_key, signer_did=parent_did,
        )
        sync_headers = build_signed_headers(
            new_key, new_did, domain=child_domain, operation="rotate_controller",
            new_controller_did=new_did, delegation_entry_hash=sync["entry_hash"],
        )
        sync_headers.update(_parent_headers(
            parent_key, parent_did, domain=child_domain,
            operation="authorize_subdomain_rotation", child_domain=child_domain,
            new_controller_did=new_did, delegation_entry_hash=sync["entry_hash"],
        ))
        synchronized = await client.put(
            f"/v1/namespaces/{child_domain}",
            json={"new_controller_did": new_did, "delegation_assertion": sync},
            headers=sync_headers,
        )
        assert synchronized.status_code == 200, synchronized.text
        tombstone = _assertion(
            operation="revoke", parent_domain=parent_domain, child_domain=child_domain,
            child_did=new_did, sequence=3, previous_hash=sync["entry_hash"],
            signer_key=new_key, signer_did=new_did,
        )
        final_headers = build_signed_headers(
            new_key, new_did, domain=child_domain, operation="delete_namespace",
            delegation_entry_hash=tombstone["entry_hash"],
        )
        deleted = await client.request(
            "DELETE", f"/v1/namespaces/{child_domain}",
            json={"delegation_assertion": tombstone}, headers=final_headers,
        )
        assert deleted.status_code == 200, deleted.text

        reuse_headers = build_signed_headers(
            new_key, new_did, domain=child_domain, operation="register",
        )
        reused = await client.post(
            "/v1/namespaces",
            json={"domain": child_domain, "controller_did": new_did},
            headers=reuse_headers,
        )
        assert reused.status_code == 200, reused.text
        assert reused.json()["delegation_chain"][-1]["entry_hash"] == tombstone["entry_hash"]
        refused_reuse_delete = await client.request(
            "DELETE", f"/v1/namespaces/{child_domain}",
            json={"delegation_assertion": tombstone}, headers=final_headers,
        )
        assert refused_reuse_delete.status_code == 409
        assert refused_reuse_delete.json()["detail"]["code"] == "namespace_delegation_sync_required"

        reactivation = _assertion(
            operation="delegate", parent_domain=parent_domain, child_domain=child_domain,
            child_did=new_did, sequence=4, previous_hash=tombstone["entry_hash"],
            signer_key=parent_key, signer_did=parent_did,
        )
        reactivate_headers = build_signed_headers(
            new_key, new_did, domain=child_domain, operation="rotate_controller",
            new_controller_did=new_did, delegation_entry_hash=reactivation["entry_hash"],
        )
        reactivate_headers.update(_parent_headers(
            parent_key, parent_did, domain=child_domain,
            operation="authorize_subdomain_rotation", child_domain=child_domain,
            new_controller_did=new_did, delegation_entry_hash=reactivation["entry_hash"],
        ))
        reactivated = await client.put(
            f"/v1/namespaces/{child_domain}",
            json={"new_controller_did": new_did, "delegation_assertion": reactivation},
            headers=reactivate_headers,
        )
        assert reactivated.status_code == 200, reactivated.text
        final_tombstone = _assertion(
            operation="revoke", parent_domain=parent_domain, child_domain=child_domain,
            child_did=new_did, sequence=5, previous_hash=reactivation["entry_hash"],
            signer_key=new_key, signer_did=new_did,
        )
        final_delete_headers = build_signed_headers(
            new_key, new_did, domain=child_domain, operation="delete_namespace",
            delegation_entry_hash=final_tombstone["entry_hash"],
        )
        final_delete = await client.request(
            "DELETE", f"/v1/namespaces/{child_domain}",
            json={"delegation_assertion": final_tombstone}, headers=final_delete_headers,
        )
        assert final_delete.status_code == 200, final_delete.text
    finally:
        app.dependency_overrides[get_domain_verifier] = previous_override


@pytest.mark.asyncio
async def test_registry_cutover_fences_nested_controller_rollover(
    client, controller_identity, awid_db_infra,
):
    old_key, old_did = controller_identity
    domain = "rollover-blocked.ancestor.example"
    await _register_parent(client, old_key, old_did, domain)
    db = awid_db_infra.get_manager("aweb")
    state = await db.fetch_one(
        "SELECT registry_instance_id,current_generation FROM {{tables.registry_state}} WHERE singleton=TRUE"
    )
    cutover_id = str(uuid4())
    await db.execute(
        """
        INSERT INTO {{tables.registry_migration_cutovers}}
            (cutover_id,role,source_registry_id,destination_registry_id,
             expected_destination_origin,root_domain,source_generation,
             snapshot_digest,manifest_digest,state)
        VALUES ($1::uuid,'source',$2,$3,'https://destination.example',
                'ancestor.example',$4,$5,$5,'frozen')
        """,
        cutover_id, state["registry_instance_id"], uuid4(), state["current_generation"],
        "sha256:" + "a" * 64,
    )
    new_key, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    headers = build_signed_headers(
        old_key, old_did, domain=domain, operation="start_controller_rollover",
        new_controller_did=new_did, recovery_mode="none",
    )
    proof = build_signed_headers(
        new_key, new_did, domain=domain, operation="prove_controller_rollover_key",
        new_controller_did=new_did, recovery_mode="none",
    )
    headers["X-AWEB-New-Controller-Authorization"] = proof["Authorization"]
    headers["X-AWEB-New-Controller-Timestamp"] = proof["X-AWEB-Timestamp"]
    response = await client.post(
        f"/v1/namespaces/{domain}/controller-rollovers",
        json={"new_controller_did": new_did, "recovery_mode": "none"},
        headers=headers,
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "registry_migration_fenced"


@pytest.mark.asyncio
async def test_cancel_and_cutover_race_has_one_consistent_winner(
    client, controller_identity, awid_db_infra,
):
    old_key, old_did = controller_identity
    new_key, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    domain = "cutover-race.example"
    await _register_parent(client, old_key, old_did, domain)
    rollover_id = str(uuid4())
    db = awid_db_infra.get_manager("aweb")
    await db.execute(
        """
        INSERT INTO {{tables.namespace_controller_rollovers}}
            (rollover_id,parent_domain,old_controller_did,new_controller_did,
             state,recovery_mode,previous_dns_ttl_seconds)
        VALUES ($1::uuid,$2,$3,$4,'ready','none',300)
        """,
        rollover_id, domain, old_did, new_did,
    )

    async def new_dns(_domain):
        return DomainAuthority(
            controller_did=new_did, registry_url="https://api.awid.ai",
            dns_name=f"_awid.{domain}", inherited=False, ttl_seconds=300,
        )

    app = client._transport.app
    prior = app.dependency_overrides[get_domain_verifier]
    app.dependency_overrides[get_domain_verifier] = lambda: new_dns
    try:
        rotate_headers = build_signed_headers(
            new_key, new_did, domain=domain, operation="rotate_controller",
            new_controller_did=new_did, rollover_id=rollover_id,
        )
        cancel_headers = build_signed_headers(
            old_key, old_did, domain=domain, operation="cancel_controller_rollover",
            rollover_id=rollover_id,
        )
        cutover, cancel = await asyncio.gather(
            client.put(
                f"/v1/namespaces/{domain}",
                json={"new_controller_did": new_did, "rollover_id": rollover_id},
                headers=rotate_headers,
            ),
            client.request(
                "DELETE", f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}",
                headers=cancel_headers,
            ),
        )
        assert sorted([cutover.status_code, cancel.status_code]) == [200, 409]
        row = await db.fetch_one(
            """
            SELECT r.state,ns.controller_did
            FROM {{tables.namespace_controller_rollovers}} r
            JOIN {{tables.dns_namespaces}} ns ON ns.domain=r.parent_domain AND ns.deleted_at IS NULL
            WHERE r.rollover_id=$1::uuid
            """,
            rollover_id,
        )
        assert (row["state"], row["controller_did"]) in {
            ("canceled", old_did), ("overlap", new_did),
        }
    finally:
        app.dependency_overrides[get_domain_verifier] = prior


@pytest.mark.asyncio
async def test_zero_child_direct_rollover_is_consumed_and_completes(
    client, controller_identity, awid_db_infra,
):
    old_key, old_did = controller_identity
    domain = "zero-direct.example"
    await _register_parent(client, old_key, old_did, domain)
    new_key, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    headers = build_signed_headers(
        old_key, old_did, domain=domain, operation="start_controller_rollover",
        new_controller_did=new_did, recovery_mode="none",
    )
    proof = build_signed_headers(
        new_key, new_did, domain=domain, operation="prove_controller_rollover_key",
        new_controller_did=new_did, recovery_mode="none",
    )
    headers["X-AWEB-New-Controller-Authorization"] = proof["Authorization"]
    headers["X-AWEB-New-Controller-Timestamp"] = proof["X-AWEB-Timestamp"]
    started = await client.post(
        f"/v1/namespaces/{domain}/controller-rollovers",
        json={"new_controller_did": new_did, "recovery_mode": "none"},
        headers=headers,
    )
    assert started.status_code == 200, started.text
    assert started.json()["state"] == "ready"
    rollover_id = started.json()["rollover_id"]

    async def new_dns(_domain):
        return DomainAuthority(
            controller_did=new_did, registry_url="https://api.awid.ai",
            dns_name=f"_awid.{domain}", inherited=False, ttl_seconds=300,
        )

    app = client._transport.app
    prior = app.dependency_overrides[get_domain_verifier]
    app.dependency_overrides[get_domain_verifier] = lambda: new_dns
    try:
        rotate_headers = build_signed_headers(
            new_key, new_did, domain=domain, operation="rotate_controller",
            new_controller_did=new_did, rollover_id=rollover_id,
        )
        cutover = await client.put(
            f"/v1/namespaces/{domain}",
            json={"new_controller_did": new_did, "rollover_id": rollover_id},
            headers=rotate_headers,
        )
        assert cutover.status_code == 200, cutover.text
        state = await client.get(
            f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}"
        )
        assert state.json()["state"] == "overlap"
        db = awid_db_infra.get_manager("aweb")
        await db.execute(
            "UPDATE {{tables.namespace_controller_rollovers}} SET complete_after=NOW()-INTERVAL '1 second' WHERE rollover_id=$1::uuid",
            rollover_id,
        )
        complete_headers = build_signed_headers(
            new_key, new_did, domain=domain, operation="complete_controller_rollover",
            rollover_id=rollover_id,
        )
        completed = await client.post(
            f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}/complete",
            headers=complete_headers,
        )
        assert completed.status_code == 200, completed.text
        assert completed.json()["state"] == "completed"
    finally:
        app.dependency_overrides[get_domain_verifier] = prior


@pytest.mark.asyncio
async def test_zero_child_delegated_recovery_is_consumed_and_completes(
    client, awid_db_infra,
):
    db = awid_db_infra.get_manager("aweb")
    grand_key, grand_public = generate_keypair()
    grand_did = did_from_public_key(grand_public)
    parent_key, parent_public = generate_keypair()
    parent_did = did_from_public_key(parent_public)
    await db.execute(
        "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('zero-grand.example',$1,'verified')",
        grand_did,
    )
    genesis = _assertion(
        operation="delegate", parent_domain="zero-grand.example",
        child_domain="parent.zero-grand.example", child_did=parent_did,
        sequence=1, previous_hash=None, signer_key=grand_key, signer_did=grand_did,
    )
    async with db.transaction() as tx:
        await append_transition(
            tx, genesis, authority_did=grand_did,
            expected_child_domain="parent.zero-grand.example",
            expected_child_controller_did=parent_did, expected_operation="delegate",
        )
        await tx.execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status,active_delegation_hash) VALUES ('parent.zero-grand.example',$1,'verified',$2)",
            parent_did, genesis["entry_hash"],
        )
    new_key, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    recovery = _assertion(
        operation="rotate", parent_domain="zero-grand.example",
        child_domain="parent.zero-grand.example", child_did=new_did,
        sequence=2, previous_hash=genesis["entry_hash"],
        signer_key=grand_key, signer_did=grand_did,
    )
    extra = {
        "new_controller_did": new_did, "recovery_mode": "delegated",
        "recovery_entry_hash": recovery["entry_hash"],
    }
    headers = build_signed_headers(
        new_key, new_did, domain="parent.zero-grand.example",
        operation="recover_controller_rollover", **extra,
    )
    proof = build_signed_headers(
        new_key, new_did, domain="parent.zero-grand.example",
        operation="prove_controller_rollover_key", **extra,
    )
    headers["X-AWEB-New-Controller-Authorization"] = proof["Authorization"]
    headers["X-AWEB-New-Controller-Timestamp"] = proof["X-AWEB-Timestamp"]
    started = await client.post(
        "/v1/namespaces/parent.zero-grand.example/controller-rollovers",
        json={
            "new_controller_did": new_did, "recovery_mode": "delegated",
            "recovery_assertion": recovery,
        },
        headers=headers,
    )
    assert started.status_code == 200, started.text
    assert started.json()["state"] == "ready"
    rollover_id = started.json()["rollover_id"]
    rotate_headers = build_signed_headers(
        new_key, new_did, domain="parent.zero-grand.example",
        operation="rotate_controller", new_controller_did=new_did,
        delegation_entry_hash=recovery["entry_hash"], rollover_id=rollover_id,
    )
    cutover = await client.put(
        "/v1/namespaces/parent.zero-grand.example",
        json={
            "new_controller_did": new_did, "delegation_assertion": recovery,
            "rollover_id": rollover_id,
        },
        headers=rotate_headers,
    )
    assert cutover.status_code == 200, cutover.text
    await db.execute(
        "UPDATE {{tables.namespace_controller_rollovers}} SET complete_after=NOW()-INTERVAL '1 second' WHERE rollover_id=$1::uuid",
        rollover_id,
    )
    complete_headers = build_signed_headers(
        new_key, new_did, domain="parent.zero-grand.example",
        operation="complete_controller_rollover", rollover_id=rollover_id,
    )
    completed = await client.post(
        f"/v1/namespaces/parent.zero-grand.example/controller-rollovers/{rollover_id}/complete",
        headers=complete_headers,
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["state"] == "completed"


@pytest.mark.asyncio
async def test_delegated_parent_key_loss_consumes_grandparent_successor(
    client, awid_db_infra,
):
    db = awid_db_infra.get_manager("aweb")
    grand_key, grand_public = generate_keypair()
    grand_did = did_from_public_key(grand_public)
    parent_key, parent_public = generate_keypair()
    parent_did = did_from_public_key(parent_public)
    child_key, child_public = generate_keypair()
    child_did = did_from_public_key(child_public)
    await db.execute(
        "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('grand.example',$1,'verified')",
        grand_did,
    )
    parent_genesis = _assertion(
        operation="delegate", parent_domain="grand.example", child_domain="parent.grand.example",
        child_did=parent_did, sequence=1, previous_hash=None,
        signer_key=grand_key, signer_did=grand_did,
    )
    child_genesis = _assertion(
        operation="delegate", parent_domain="parent.grand.example",
        child_domain="child.parent.grand.example", child_did=child_did,
        sequence=1, previous_hash=None, signer_key=parent_key, signer_did=parent_did,
    )
    async with db.transaction() as tx:
        await append_transition(
            tx, parent_genesis, authority_did=grand_did,
            expected_child_domain="parent.grand.example",
            expected_child_controller_did=parent_did, expected_operation="delegate",
        )
        await tx.execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status,active_delegation_hash) VALUES ('parent.grand.example',$1,'verified',$2)",
            parent_did, parent_genesis["entry_hash"],
        )
        await append_transition(
            tx, child_genesis, authority_did=parent_did,
            expected_child_domain="child.parent.grand.example",
            expected_child_controller_did=child_did, expected_operation="delegate",
        )
        await tx.execute(
            "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status,active_delegation_hash) VALUES ('child.parent.grand.example',$1,'verified',$2)",
            child_did, child_genesis["entry_hash"],
        )

    new_parent_key, new_parent_public = generate_keypair()
    new_parent_did = did_from_public_key(new_parent_public)
    recovery = _assertion(
        operation="rotate", parent_domain="grand.example", child_domain="parent.grand.example",
        child_did=new_parent_did, sequence=2, previous_hash=parent_genesis["entry_hash"],
        signer_key=grand_key, signer_did=grand_did,
    )
    extra = {
        "new_controller_did": new_parent_did,
        "recovery_mode": "delegated",
        "recovery_entry_hash": recovery["entry_hash"],
    }
    headers = build_signed_headers(
        new_parent_key, new_parent_did, domain="parent.grand.example",
        operation="recover_controller_rollover", **extra,
    )
    proof = build_signed_headers(
        new_parent_key, new_parent_did, domain="parent.grand.example",
        operation="prove_controller_rollover_key", **extra,
    )
    headers["X-AWEB-New-Controller-Authorization"] = proof["Authorization"]
    headers["X-AWEB-New-Controller-Timestamp"] = proof["X-AWEB-Timestamp"]
    wrong_grand_key, wrong_grand_public = generate_keypair()
    wrong_grand_did = did_from_public_key(wrong_grand_public)
    wrong_recovery = dict(recovery)
    wrong_recovery["signatures"] = [{
        "controller_did": wrong_grand_did,
        "signature": sign_message(
            wrong_grand_key, canonical_json_bytes(recovery["payload"])
        ),
    }]
    wrong_start = await client.post(
        "/v1/namespaces/parent.grand.example/controller-rollovers",
        json={
            "new_controller_did": new_parent_did,
            "recovery_mode": "delegated",
            "recovery_assertion": wrong_recovery,
        },
        headers=headers,
    )
    assert wrong_start.status_code == 403
    assert wrong_start.json()["detail"]["code"] == "controller_rollover_recovery_invalid"
    stale_recovery = _assertion(
        operation="rotate", parent_domain="grand.example", child_domain="parent.grand.example",
        child_did=new_parent_did, sequence=3, previous_hash="sha256:" + "a" * 64,
        signer_key=grand_key, signer_did=grand_did,
    )
    stale_extra = {
        "new_controller_did": new_parent_did,
        "recovery_mode": "delegated",
        "recovery_entry_hash": stale_recovery["entry_hash"],
    }
    stale_headers = build_signed_headers(
        new_parent_key, new_parent_did, domain="parent.grand.example",
        operation="recover_controller_rollover", **stale_extra,
    )
    stale_proof = build_signed_headers(
        new_parent_key, new_parent_did, domain="parent.grand.example",
        operation="prove_controller_rollover_key", **stale_extra,
    )
    stale_headers["X-AWEB-New-Controller-Authorization"] = stale_proof["Authorization"]
    stale_headers["X-AWEB-New-Controller-Timestamp"] = stale_proof["X-AWEB-Timestamp"]
    stale_start = await client.post(
        "/v1/namespaces/parent.grand.example/controller-rollovers",
        json={
            "new_controller_did": new_parent_did,
            "recovery_mode": "delegated",
            "recovery_assertion": stale_recovery,
        },
        headers=stale_headers,
    )
    assert stale_start.status_code == 403
    assert stale_start.json()["detail"]["code"] == "controller_rollover_recovery_invalid"
    started = await client.post(
        "/v1/namespaces/parent.grand.example/controller-rollovers",
        json={
            "new_controller_did": new_parent_did,
            "recovery_mode": "delegated",
            "recovery_assertion": recovery,
        },
        headers=headers,
    )
    assert started.status_code == 200, started.text
    rollover = started.json()
    assert rollover["state"] == "preparing"
    start_retry = await client.post(
        "/v1/namespaces/parent.grand.example/controller-rollovers",
        json={
            "new_controller_did": new_parent_did,
            "recovery_mode": "delegated",
            "recovery_assertion": recovery,
        },
        headers=headers,
    )
    assert start_retry.status_code == 200, start_retry.text
    assert start_retry.json()["rollover_id"] == rollover["rollover_id"]
    child_signature = sign_message(
        new_parent_key, canonical_json_bytes(child_genesis["payload"])
    )
    batch = {"signatures": [{
        "child_domain": "child.parent.grand.example",
        "head_hash": child_genesis["entry_hash"],
        "signature": child_signature,
    }]}
    batch_headers = build_signed_headers(
        new_parent_key, new_parent_did, domain="parent.grand.example",
        operation="attach_controller_rollover_signatures",
        rollover_id=rollover["rollover_id"],
        batch_hash="sha256:" + hashlib.sha256(canonical_json_bytes(batch)).hexdigest(),
    )
    ready = await client.put(
        f"/v1/namespaces/parent.grand.example/controller-rollovers/{rollover['rollover_id']}/signatures",
        json=batch, headers=batch_headers,
    )
    assert ready.status_code == 200, ready.text
    rotate_headers = build_signed_headers(
        new_parent_key, new_parent_did, domain="parent.grand.example",
        operation="rotate_controller", new_controller_did=new_parent_did,
        delegation_entry_hash=recovery["entry_hash"], rollover_id=rollover["rollover_id"],
    )
    cutover = await client.put(
        "/v1/namespaces/parent.grand.example",
        json={
            "new_controller_did": new_parent_did,
            "delegation_assertion": recovery,
            "rollover_id": rollover["rollover_id"],
        },
        headers=rotate_headers,
    )
    assert cutover.status_code == 200, cutover.text
    assert cutover.json()["controller_did"] == new_parent_did
    state = await client.get(
        f"/v1/namespaces/parent.grand.example/controller-rollovers/{rollover['rollover_id']}"
    )
    assert state.json()["state"] == "overlap"
    assert state.json()["recovery_mode"] == "delegated"
    assert state.json()["recovery_assertion"] == recovery


@pytest.mark.asyncio
async def test_genesis_parent_domain_must_equal_selected_parent(client, controller_identity):
    parent_key, parent_did = controller_identity
    await _register_parent(client, parent_key, parent_did, "nearest.example")
    child_key, child_public = generate_keypair()
    child_did = did_from_public_key(child_public)
    domain = "child.nearest.example"
    wrong = _assertion(
        operation="delegate", parent_domain="example", child_domain=domain,
        child_did=child_did, sequence=1, previous_hash=None,
        signer_key=parent_key, signer_did=parent_did,
    )
    headers = build_signed_headers(
        child_key, child_did, domain=domain, operation="register",
        controller_did=child_did, delegation_entry_hash=wrong["entry_hash"],
    )
    headers.update(_parent_headers(
        parent_key, parent_did, domain=domain,
        operation="authorize_subdomain_registration", child_domain=domain,
        controller_did=child_did, delegation_entry_hash=wrong["entry_hash"],
    ))
    response = await client.post(
        "/v1/namespaces",
        json={"domain": domain, "controller_did": child_did, "delegation_assertion": wrong},
        headers=headers,
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "namespace_delegation_transition_invalid"

    legacy_domain = "legacy.nearest.example"
    legacy_key, legacy_public = generate_keypair()
    legacy_did = did_from_public_key(legacy_public)
    legacy_headers = build_signed_headers(
        legacy_key, legacy_did, domain=legacy_domain, operation="register",
    )
    legacy_headers.update(_parent_headers(
        parent_key, parent_did, domain=legacy_domain,
        operation="authorize_subdomain_registration", child_domain=legacy_domain,
        controller_did=legacy_did,
    ))
    assert (await client.post(
        "/v1/namespaces",
        json={"domain": legacy_domain, "controller_did": legacy_did},
        headers=legacy_headers,
    )).status_code == 200
    wrong_backfill = _assertion(
        operation="delegate", parent_domain="example", child_domain=legacy_domain,
        child_did=legacy_did, sequence=1, previous_hash=None,
        signer_key=parent_key, signer_did=parent_did,
    )
    backfill_headers = build_signed_headers(
        legacy_key, legacy_did, domain=legacy_domain,
        operation="backfill_namespace_delegation",
        delegation_entry_hash=wrong_backfill["entry_hash"],
    )
    backfill_headers.update(_parent_headers(
        parent_key, parent_did, domain=legacy_domain,
        operation="authorize_subdomain_backfill", child_domain=legacy_domain,
        controller_did=legacy_did,
        delegation_entry_hash=wrong_backfill["entry_hash"],
    ))
    backfill = await client.post(
        f"/v1/namespaces/{legacy_domain}/delegation/backfill",
        json={"delegation_assertion": wrong_backfill}, headers=backfill_headers,
    )
    assert backfill.status_code == 409
    assert backfill.json()["detail"]["code"] == "namespace_delegation_transition_invalid"


@pytest.mark.asyncio
async def test_global_enforcement_rejects_new_legacy_inherited_write(
    client, controller_identity, monkeypatch,
):
    parent_key, parent_did = controller_identity
    await _register_parent(client, parent_key, parent_did, "enforced.example")
    child_key, child_public = generate_keypair()
    child_did = did_from_public_key(child_public)
    domain = "child.enforced.example"
    headers = build_signed_headers(child_key, child_did, domain=domain, operation="register")
    headers.update(_parent_headers(
        parent_key, parent_did, domain=domain,
        operation="authorize_subdomain_registration", child_domain=domain,
        controller_did=child_did,
    ))
    monkeypatch.setenv("AWID_REQUIRE_DELEGATION_ASSERTION", "1")
    response = await client.post(
        "/v1/namespaces", json={"domain": domain, "controller_did": child_did}, headers=headers,
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "namespace_delegation_required"


@pytest.mark.asyncio
async def test_ready_rollover_fences_reverify_cuts_over_and_completes(
    client, controller_identity, awid_db_infra,
):
    old_key, old_did = controller_identity
    domain = "cutover.example"
    await _register_parent(client, old_key, old_did, domain)
    child_key, child_public = generate_keypair()
    child_did = did_from_public_key(child_public)
    child_domain = "child.cutover.example"
    delegated = _assertion(
        operation="delegate", parent_domain=domain, child_domain=child_domain,
        child_did=child_did, sequence=1, previous_hash=None,
        signer_key=old_key, signer_did=old_did,
    )
    db = awid_db_infra.get_manager("aweb")
    async with db.transaction() as tx:
        await append_transition(
            tx, delegated, authority_did=old_did,
            expected_child_domain=child_domain,
            expected_child_controller_did=child_did,
            expected_operation="delegate",
        )
        await tx.execute(
            """
            INSERT INTO {{tables.dns_namespaces}}
                (domain,controller_did,verification_status,active_delegation_hash)
            VALUES ($1,$2,'verified',$3)
            """,
            child_domain, child_did, delegated["entry_hash"],
        )
    new_key, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    rollover_id = str(uuid4())
    canonical = canonical_json_bytes(delegated["payload"])
    new_signature = sign_message(new_key, canonical)
    await db.execute(
        """
        INSERT INTO {{tables.namespace_controller_rollovers}}
            (rollover_id,parent_domain,old_controller_did,new_controller_did,
             state,recovery_mode,previous_dns_ttl_seconds)
        VALUES ($1::uuid,$2,$3,$4,'ready','none',1)
        """,
        rollover_id, domain, old_did, new_did,
    )
    await db.execute(
        """
        INSERT INTO {{tables.namespace_controller_rollover_children}}
            (rollover_id,child_domain,head_hash,canonical_payload,new_signature,ordinal)
        VALUES ($1::uuid,$2,$3,$4,$5,0),
               ($1::uuid,'dormant.cutover.example',$6,$7,$8,1),
               ($1::uuid,'third.cutover.example',$9,$10,$11,2)
        """,
        rollover_id, child_domain, delegated["entry_hash"], canonical, new_signature,
        "sha256:" + "d" * 64, canonical_json_bytes(delegated["payload"]), new_signature,
        "sha256:" + "e" * 64, canonical_json_bytes(delegated["payload"]), new_signature,
    )
    first_children, first_children_retry = await asyncio.gather(
        client.get(
            f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}/children",
            params={"limit": 1},
        ),
        client.get(
            f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}/children",
            params={"limit": 1},
        ),
    )
    assert first_children.status_code == 200, first_children.text
    assert first_children.json()["next_cursor"]
    assert first_children_retry.json() == first_children.json()
    cursor = first_children.json()["next_cursor"]
    forged_children = await client.get(
        f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}/children",
        params={"cursor": cursor + "x"},
    )
    assert forged_children.status_code == 400
    wrong_rollover = await client.get(
        f"/v1/namespaces/{domain}/controller-rollovers/{uuid4()}/children",
        params={"cursor": cursor},
    )
    assert wrong_rollover.status_code == 400
    wrong_domain = await client.get(
        f"/v1/namespaces/wrong.example/controller-rollovers/{rollover_id}/children",
        params={"cursor": cursor},
    )
    assert wrong_domain.status_code == 400
    second_children = await client.get(
        f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}/children",
        params={"cursor": cursor},
    )
    second_retry = await client.get(
        f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}/children",
        params={"cursor": cursor},
    )
    assert second_children.status_code == 200, second_children.text
    assert second_retry.json() == second_children.json()
    assert second_children.json()["children"][0]["child_domain"] == "dormant.cutover.example"
    await db.execute(
        "UPDATE {{tables.namespace_controller_rollover_read_pages}} SET expires_at=NOW()-INTERVAL '1 second' WHERE rollover_id=$1::uuid AND page_start_ordinal=1",
        rollover_id,
    )
    expired = await client.get(
        f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}/children",
        params={"cursor": cursor},
    )
    assert expired.status_code == 400

    async def new_dns(_domain):
        return DomainAuthority(
            controller_did=new_did, registry_url="https://api.awid.ai",
            dns_name=f"_awid.{domain}", inherited=False, ttl_seconds=1,
        )

    app = client._transport.app
    prior = app.dependency_overrides[get_domain_verifier]
    app.dependency_overrides[get_domain_verifier] = lambda: new_dns
    try:
        bypass = await client.post(f"/v1/namespaces/{domain}/reverify")
        assert bypass.status_code == 409
        assert bypass.json()["detail"]["code"] == "controller_rollover_not_ready"

        rotate_headers = build_signed_headers(
            new_key, new_did, domain=domain, operation="rotate_controller",
            new_controller_did=new_did, rollover_id=rollover_id,
        )
        rotated = await client.put(
            f"/v1/namespaces/{domain}",
            json={"new_controller_did": new_did, "rollover_id": rollover_id},
            headers=rotate_headers,
        )
        assert rotated.status_code == 200, rotated.text
        state = await client.get(
            f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}"
        )
        assert state.json()["state"] == "overlap"
        complete_headers = build_signed_headers(
            new_key, new_did, domain=domain, operation="complete_controller_rollover",
            rollover_id=rollover_id,
        )
        early = await client.post(
            f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}/complete",
            headers=complete_headers,
        )
        assert early.status_code == 409
        assert early.json()["detail"]["code"] == "controller_rollover_overlap_pending"
        await db.execute(
            "UPDATE {{tables.namespace_controller_rollovers}} SET complete_after=NOW()-INTERVAL '1 second' WHERE rollover_id=$1::uuid",
            rollover_id,
        )
        completed = await client.post(
            f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}/complete",
            headers=complete_headers,
        )
        assert completed.status_code == 200, completed.text
        assert completed.json()["state"] == "completed"
        completed_retry = await client.post(
            f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}/complete",
            headers=complete_headers,
        )
        assert completed_retry.status_code == 200, completed_retry.text
        assert completed_retry.json() == completed.json()
        old_complete_headers = build_signed_headers(
            old_key, old_did, domain=domain, operation="complete_controller_rollover",
            rollover_id=rollover_id,
        )
        old_complete = await client.post(
            f"/v1/namespaces/{domain}/controller-rollovers/{rollover_id}/complete",
            headers=old_complete_headers,
        )
        assert old_complete.status_code == 403
    finally:
        app.dependency_overrides[get_domain_verifier] = prior


@pytest.mark.asyncio
async def test_signature_batch_conflict_rolls_back_every_child(client, awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    parent_key, parent_public = generate_keypair()
    parent_did = did_from_public_key(parent_public)
    new_key, new_public = generate_keypair()
    new_did = did_from_public_key(new_public)
    await db.execute(
        "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status) VALUES ('batch.example',$1,'verified')",
        parent_did,
    )
    items = []
    async with db.transaction() as tx:
        for index in range(2):
            _, child_public = generate_keypair()
            child_did = did_from_public_key(child_public)
            domain = f"child-{index}.batch.example"
            item = _assertion(
                operation="delegate", parent_domain="batch.example", child_domain=domain,
                child_did=child_did, sequence=1, previous_hash=None,
                signer_key=parent_key, signer_did=parent_did,
            )
            await append_transition(
                tx, item, authority_did=parent_did,
                expected_child_domain=domain,
                expected_child_controller_did=child_did, expected_operation="delegate",
            )
            await tx.execute(
                "INSERT INTO {{tables.dns_namespaces}} (domain,controller_did,verification_status,active_delegation_hash) VALUES ($1,$2,'verified',$3)",
                domain, child_did, item["entry_hash"],
            )
            items.append(item)
    rollover_id = str(uuid4())
    await db.execute(
        """
        INSERT INTO {{tables.namespace_controller_rollovers}}
            (rollover_id,parent_domain,old_controller_did,new_controller_did,state,recovery_mode)
        VALUES ($1::uuid,'batch.example',$2,$3,'preparing','none')
        """,
        rollover_id, parent_did, new_did,
    )
    for ordinal, item in enumerate(items):
        await db.execute(
            "INSERT INTO {{tables.namespace_controller_rollover_children}} (rollover_id,child_domain,head_hash,canonical_payload,ordinal) VALUES ($1::uuid,$2,$3,$4,$5)",
            rollover_id, item["payload"]["child_domain"], item["entry_hash"],
            canonical_json_bytes(item["payload"]), ordinal,
        )
    conflicting = sign_message(parent_key, canonical_json_bytes(items[1]["payload"]))
    await db.execute(
        "INSERT INTO {{tables.namespace_delegation_signatures}} (child_domain,sequence,controller_did,signature) VALUES ($1,1,$2,$3)",
        items[1]["payload"]["child_domain"], new_did, conflicting,
    )
    signatures = [
        {
            "child_domain": item["payload"]["child_domain"],
            "head_hash": item["entry_hash"],
            "signature": sign_message(new_key, canonical_json_bytes(item["payload"])),
        }
        for item in items
    ]
    batch = {"signatures": signatures}
    headers = build_signed_headers(
        new_key, new_did, domain="batch.example",
        operation="attach_controller_rollover_signatures", rollover_id=rollover_id,
        batch_hash="sha256:" + hashlib.sha256(canonical_json_bytes(batch)).hexdigest(),
    )
    response = await client.put(
        f"/v1/namespaces/batch.example/controller-rollovers/{rollover_id}/signatures",
        json=batch, headers=headers,
    )
    assert response.status_code == 409
    assert await db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.namespace_delegation_signatures}} WHERE child_domain=$1 AND controller_did=$2",
        items[0]["payload"]["child_domain"], new_did,
    ) == 0
    assert await db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.namespace_controller_rollover_children}} WHERE rollover_id=$1::uuid AND new_signature IS NOT NULL",
        rollover_id,
    ) == 0


@pytest.mark.asyncio
async def test_backfill_atomically_sets_inherited_marker(client, controller_identity, awid_db_infra):
    parent_key, parent_did = controller_identity
    parent_domain = "backfill.example"
    child_domain = "child.backfill.example"
    await _register_parent(client, parent_key, parent_did, parent_domain)

    child_key, child_public = generate_keypair()
    child_did = did_from_public_key(child_public)
    child_headers = build_signed_headers(
        child_key, child_did, domain=child_domain, operation="register",
    )
    child_headers.update(
        _parent_headers(
            parent_key,
            parent_did,
            domain=child_domain,
            operation="authorize_subdomain_registration",
            child_domain=child_domain,
            controller_did=child_did,
        )
    )
    legacy = await client.post(
        "/v1/namespaces",
        json={"domain": child_domain, "controller_did": child_did},
        headers=child_headers,
    )
    assert legacy.status_code == 200, legacy.text
    assert legacy.json()["delegation_chain"] == []

    genesis = _assertion(
        operation="delegate",
        parent_domain=parent_domain,
        child_domain=child_domain,
        child_did=child_did,
        sequence=1,
        previous_hash=None,
        signer_key=parent_key,
        signer_did=parent_did,
    )
    headers = build_signed_headers(
        child_key,
        child_did,
        domain=child_domain,
        operation="backfill_namespace_delegation",
        delegation_entry_hash=genesis["entry_hash"],
    )
    headers.update(
        _parent_headers(
            parent_key,
            parent_did,
            domain=child_domain,
            operation="authorize_subdomain_backfill",
            child_domain=child_domain,
            controller_did=child_did,
            delegation_entry_hash=genesis["entry_hash"],
        )
    )
    rollover_key, rollover_public = generate_keypair()
    rollover_did = did_from_public_key(rollover_public)
    start_headers = build_signed_headers(
        parent_key, parent_did, domain=parent_domain,
        operation="start_controller_rollover", new_controller_did=rollover_did,
        recovery_mode="none",
    )
    proof = build_signed_headers(
        rollover_key, rollover_did, domain=parent_domain,
        operation="prove_controller_rollover_key", new_controller_did=rollover_did,
        recovery_mode="none",
    )
    start_headers["X-AWEB-New-Controller-Authorization"] = proof["Authorization"]
    start_headers["X-AWEB-New-Controller-Timestamp"] = proof["X-AWEB-Timestamp"]
    started = await client.post(
        f"/v1/namespaces/{parent_domain}/controller-rollovers",
        json={"new_controller_did": rollover_did, "recovery_mode": "none"},
        headers=start_headers,
    )
    assert started.status_code == 200, started.text
    fenced = await client.post(
        f"/v1/namespaces/{child_domain}/delegation/backfill",
        json={"delegation_assertion": genesis}, headers=headers,
    )
    assert fenced.status_code == 409
    assert fenced.json()["detail"]["code"] == "namespace_delegation_fenced"
    rollover_id = started.json()["rollover_id"]
    cancel_headers = build_signed_headers(
        parent_key, parent_did, domain=parent_domain,
        operation="cancel_controller_rollover", rollover_id=rollover_id,
    )
    canceled = await client.request(
        "DELETE", f"/v1/namespaces/{parent_domain}/controller-rollovers/{rollover_id}",
        headers=cancel_headers,
    )
    assert canceled.status_code == 200, canceled.text
    response = await client.post(
        f"/v1/namespaces/{child_domain}/delegation/backfill",
        json={"delegation_assertion": genesis},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["delegation_chain"] == [genesis]

    db = awid_db_infra.get_manager("aweb")
    row = await db.fetch_one(
        """
        SELECT ns.controller_did, ns.active_delegation_hash, h.head_hash,
               h.head_controller_did
        FROM {{tables.dns_namespaces}} ns
        JOIN {{tables.namespace_delegation_heads}} h ON h.child_domain = ns.domain
        WHERE ns.domain = $1 AND ns.deleted_at IS NULL
        """,
        child_domain,
    )
    assert row["active_delegation_hash"] == genesis["entry_hash"] == row["head_hash"]
    assert row["controller_did"] == child_did == row["head_controller_did"]
