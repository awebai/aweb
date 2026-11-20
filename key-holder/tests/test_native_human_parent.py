"""A currently valid person need not have the namespace as their direct parent."""

from datetime import UTC, datetime

import httpx
import pytest
from approval_service.canonical import parse
from approval_service.encoding import decode
from awid.id_certificates import id_certificate_id, sign_id_certificate
from test_native_holder import (
    call,
    commit_identity,
    creation_receipt,
    material_for,
    register_identity,
    signature,
)
from test_native_review import first_person

from aweb_key_holder.http import create_app


@pytest.mark.asyncio
async def test_human_parented_person_enrolls_approves_and_refreshes_a_reissued_certificate(
    native_holder,
    tmp_path,
):
    holder, registry = native_holder.holder, native_holder.registry
    parent, _, _, _ = await first_person(native_holder, activate=True)
    seed, key, person = await register_identity(registry)
    certificate = await sign_id_certificate(
        {
            "v": 1,
            "type": "aweb.id-certificate",
            "id": person,
            "domain": holder.store.descriptor().domain,
            "parent": {"kind": "identity", "id": parent["identity"]},
            "kind": "human",
            "issuer_key": parent["key"],
            "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        signer=lambda payload: (parent["key"], signature(parent["seed"], payload)),
    )
    chain = [*parent["chain"], certificate]
    await commit_identity(registry, {"id_chain": chain}, seed, key)
    own = {"seed": seed, "key": key, "identity": person, "chain": chain}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        response = await call(
            client,
            "/v1/enrollments/" + person,
            {"requester": {"kind": "identity", "id": person, "key": key}},
            **own,
        )
        assert response.status_code == 200, response.text
        device, material = material_for(holder, response.json()["intent"])
        response = await call(
            client,
            f"/v1/enrollments/{person}/binding",
            {"material": material, "registration_count": 1},
            **own,
        )
        assert response.status_code == 200, response.text
        proof = creation_receipt(response.json(), device)
        proof["id_chain"] = chain
        response = await call(client, f"/v1/enrollments/{person}/finish", proof, **own)
        assert response.status_code == 200, response.text
        activation = response.json()
        response = await call(client, f"/v1/enrollments/{person}/activate", {}, **own)
        assert response.status_code == 200, response.text
        trust = await holder.public.person(
            chain,
            person=person,
            identity_key=key,
            organisation=holder.store.descriptor().domain,
        )
        assert trust.issuer == parent["key"]
        assert trust.namespace_issuer == holder.store.descriptor().did_key
        _, target_key, target = await register_identity(registry)
        response = await call(
            client,
            "/v1/humans",
            {"person": target, "identity_key": target_key, "approver": person},
            **own,
        )
        assert response.status_code == 428, response.text
        packet = response.json()
        receipt = {
            "version": 1,
            "request_bytes": packet["request_bytes"],
            "binding": activation["binding"],
            "id_chain": chain,
            "assertion": device.assert_request(parse(decode(packet["request_bytes"]))),
        }
        response = await call(
            client,
            "/v1/humans",
            {
                "version": 1,
                "request_bytes": packet["request_bytes"],
                "receipt": receipt,
            },
            **own,
        )
        assert response.status_code == 200, response.text
        assert response.json()["intent"]["intent"]["person"] == target

    # The operator reissues a real namespace-parented certificate for the same
    # ID/key, using the normal private certificate effect and explicit off policy.
    from approval_service.seams import commitment
    from policy_inputs import policy_file

    from aweb_key_holder.enrollment import Holder

    operator = Holder(
        holder.store,
        registry=registry,
        origin=holder.origin,
        approval_origin=holder.approval_origin,
        rp_id=holder.rp_id,
        grading=holder.grading,
        human_approval_config=policy_file(
            tmp_path / "operator-policy.json", holder.store.descriptor().domain, None
        ),
    )
    issued = operator.issue_person_certificate(person, key)["certificate"]
    assert id_certificate_id(issued["certificate"]) != id_certificate_id(
        certificate["certificate"]
    )
    await registry.register_id_certificate(
        {"v": 1, "type": "aweb.id-chain", "certificates": [issued]},
        signer=lambda payload: (key, signature(seed, payload)),
        expected_head=id_certificate_id(certificate["certificate"]),
        invitation_id=None,
    )
    original = holder.active_person(person)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(operator)),
        base_url=operator.origin,
    ) as client:
        response = await call(
            client,
            f"/v1/enrollments/{person}/refresh-binding",
            {
                "previous_binding_commitment": commitment(
                    "binding_commitment", activation["binding"]
                )
            },
            **{**own, "chain": [issued]},
        )
    assert response.status_code == 200, response.text
    refreshed = response.json()["binding"]
    assert refreshed["binding"]["certificate"] == id_certificate_id(
        issued["certificate"]
    )
    assert commitment("binding_commitment", refreshed) != commitment(
        "binding_commitment", activation["binding"]
    )
    assert (
        refreshed["binding"]["credentials"]
        == activation["binding"]["binding"]["credentials"]
    )
    assert holder.active_person(person) == original
