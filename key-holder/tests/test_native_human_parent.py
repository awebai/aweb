"""A currently valid person need not have the namespace as their direct parent."""

from datetime import datetime, timezone

import httpx
import pytest
from approval_service.canonical import parse
from approval_service.encoding import decode
from awid.id_certificates import sign_id_certificate
from aweb_key_holder.http import create_app
from test_native_holder import (
    call,
    commit_identity,
    creation_receipt,
    material_for,
    register_identity,
    signature,
)
from test_native_review import first_person


@pytest.mark.asyncio
async def test_human_parented_person_enrolls_and_approves_at_namespace_holder(
    native_holder,
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
            "parent": {"kind": "human", "id": parent["identity"]},
            "kind": "human",
            "issuer_key": parent["key"],
            "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
