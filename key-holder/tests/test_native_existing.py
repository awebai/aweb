"""Operator issuance followed by own-key later enrollment on the real registry."""

import json

import httpx
import pytest
from approval_service.statements import verify_enrollment_evidence
from aweb_key_holder.auth import Caller
from policy_inputs import policy_file
from aweb_key_holder.http import create_app
from aweb_key_holder.keys import Refused
from awid.controller_signing import parse_controller_request
from test_native_holder import (
    call,
    commit_identity,
    creation_receipt,
    material_for,
    register_identity,
)


@pytest.mark.asyncio
async def test_existing_person_self_enrolls_and_controller_cannot_carry_it(
    native_holder,
):
    holder, registry = native_holder.holder, native_holder.registry
    root = holder.store.descriptor()
    await registry.controller_request(
        parse_controller_request(
            {
                "operation": "namespace_register",
                "domain": root.domain,
                "controller_did": root.did_key,
            }
        ),
        controllers={"controller": root},
        signer=lambda ctx: holder.store.sign_controller(ctx, actor="operator"),
    )
    seed, key, person = await register_identity(registry)
    policy_file(holder.human_approval_config, root.domain, None)
    issued = await holder.issue_person(person, key)
    assert "evidence" not in issued
    chain = [issued["certificate"]]
    await commit_identity(registry, {"id_chain": chain}, seed, key)
    own = {"seed": seed, "key": key, "identity": person, "chain": chain}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        start = await call(
            client,
            "/v1/enrollments/" + person,
            {"requester": {"kind": "identity", "id": person, "key": key}},
            **own,
        )
        assert start.status_code == 200, start.text
        intent = start.json()["intent"]
        assert intent["intent"]["purpose"] == "enroll_existing_person"
        assert intent["intent"]["pending_certificate"] == issued["certificate"]
        # The organisation's own key is not the person's carrier.
        controller = Caller(root.did_key, root.did_key, "", b"")
        with pytest.raises(Refused, match="requester_mismatch"):
            await holder.enroll_existing(controller, person=person, chain=[])
        device, material = material_for(holder, intent)
        response = await call(
            client,
            f"/v1/enrollments/{person}/binding",
            {"material": material, "registration_count": 1},
            **own,
        )
        assert response.status_code == 200, response.text
        bound = response.json()
        repeated = await call(
            client,
            f"/v1/enrollments/{person}/binding",
            {"material": material, "registration_count": 1},
            **own,
        )
        assert repeated.status_code == 200, repeated.text
        assert repeated.json() == bound
        proof = creation_receipt(bound, device)
        response = await call(client, f"/v1/enrollments/{person}/finish", proof, **own)
        assert response.status_code == 200, response.text
        activation = response.json()
        assert (
            activation["version"] == 2
            and "creation" not in activation["evidence"]["evidence"]
        )
        trust = await holder.public.person(
            chain, person=person, identity_key=key, organisation=root.domain
        )
        assert (
            verify_enrollment_evidence(
                activation["evidence"], receipt=proof, trust=trust
            )["proof_status"]
            == "checked"
        )
        with holder.store._connection() as db:
            assert not db.execute(
                "SELECT credential FROM active_attestation_inventory"
            ).fetchall()
        response = await call(client, f"/v1/enrollments/{person}/activate", {}, **own)
        assert response.status_code == 200, response.text
        assert holder.active_person(person)["active"] == 1
    with holder.store._connection() as db:
        inventoried = db.execute(
            "SELECT credential FROM active_attestation_inventory WHERE namespace=? AND person=?",
            (root.domain, person),
        ).fetchone()
        assert inventoried["credential"] == proof["assertion"]["id"]
    holder.store.retire_person(person)
    with holder.store._connection() as db:
        assert not db.execute("SELECT credential FROM attestation_inventory").fetchall()
        saved = db.execute(
            "SELECT creation_receipt FROM enrollments WHERE person=?", (person,)
        ).fetchone()
        assert json.loads(saved["creation_receipt"]) == proof
