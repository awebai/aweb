"""Operator issuance followed by own-key later enrollment on the real registry."""

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
    # Another issued person of the same organisation, with a valid chain of
    # its own: only being the enrollment's requester distinguishes them.
    other_seed, other_key, other = await register_identity(registry)
    other_chain = [(await holder.issue_person(other, other_key))["certificate"]]
    await commit_identity(registry, {"id_chain": other_chain}, other_seed, other_key)
    stranger = {
        "seed": other_seed,
        "key": other_key,
        "identity": other,
        "chain": other_chain,
    }

    async def refused_to_stranger(client, path, body):
        before = holder.store.audit()
        response = await call(client, path, body, **stranger)
        assert response.status_code == 401, response.text
        assert response.json()["error"]["code"] == "requester_mismatch"
        assert holder.store.audit() == before

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
        binding = {"material": material, "registration_count": 1}
        await refused_to_stranger(client, f"/v1/enrollments/{person}/binding", binding)
        response = await call(
            client,
            f"/v1/enrollments/{person}/binding",
            {"material": material, "registration_count": 1},
            **own,
        )
        assert response.status_code == 200, response.text
        proof = creation_receipt(response.json(), device)
        await refused_to_stranger(client, f"/v1/enrollments/{person}/finish", proof)
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
        await refused_to_stranger(client, f"/v1/enrollments/{person}/activate", {})
        response = await call(client, f"/v1/enrollments/{person}/activate", {}, **own)
        assert response.status_code == 200, response.text
        assert holder.active_person(person)["active"] == 1
