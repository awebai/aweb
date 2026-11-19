"""A real person asks the issuer to re-sign its stored active credential set."""

import json
from datetime import UTC, datetime

import httpx
import pytest
from approval_service.binding_refresh import check_refresh_replacement
from approval_service.seams import commitment
from awid.id_certificates import sign_id_certificate
from test_native_holder import call, commit_identity, register_identity, signature
from test_native_review import first_person

from aweb_key_holder.http import create_app


@pytest.mark.asyncio
async def test_own_person_refreshes_only_the_held_active_binding(native_holder):
    holder, registry = native_holder.holder, native_holder.registry
    own, _device, confirmation, evidence = await first_person(
        native_holder, activate=True
    )
    original = holder.active_person(own["identity"])
    binding = confirmation["binding"]
    packet = {"previous_binding_commitment": commitment("binding_commitment", binding)}
    path = f"/v1/enrollments/{own['identity']}/refresh-binding"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        response = await call(client, path, packet, **own)
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["requester"] == {
            "kind": "identity",
            "id": own["identity"],
            "key": own["key"],
        }
        assert (
            result["previous_binding_commitment"]
            == packet["previous_binding_commitment"]
        )
        assert result["id_chain"] == own["chain"]
        trust = await holder.public.person(
            own["chain"],
            person=own["identity"],
            identity_key=own["key"],
            organisation=holder.store.descriptor().domain,
        )
        check_refresh_replacement(binding, result["binding"], trust=trust)
        assert holder.active_person(own["identity"]) == original
        assert json.loads(original["evidence"]) == evidence["evidence"]
        other_seed, other_key, other_id = await register_identity(registry)
        certificate = await sign_id_certificate(
            {
                "v": 1,
                "type": "aweb.id-certificate",
                "id": other_id,
                "domain": holder.store.descriptor().domain,
                "parent": {"kind": "human", "id": own["identity"]},
                "kind": "human",
                "issuer_key": own["key"],
                "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            signer=lambda payload: (own["key"], signature(own["seed"], payload)),
        )
        other_chain = [*own["chain"], certificate]
        await commit_identity(
            registry, {"id_chain": other_chain}, other_seed, other_key
        )
        # A second currently valid person is not authority over this enrollment.
        other = await call(
            client,
            path,
            packet,
            seed=other_seed,
            key=other_key,
            identity=other_id,
            chain=other_chain,
        )
        assert other.status_code in (401, 403), other.text
        assert holder.active_person(own["identity"]) == original
        audit = holder.store.audit()
        assert audit[-1]["actor"] == own["key"]
        assert audit[-1]["operation"] == "binding_refresh"


@pytest.mark.asyncio
async def test_current_rotated_person_key_gets_enrollment_recovery_advice(
    native_holder,
):
    from awid.did import did_from_public_key, generate_keypair

    holder, registry = native_holder.holder, native_holder.registry
    own, _, confirmation, _ = await first_person(native_holder, activate=True)
    original = holder.active_person(own["identity"])
    audit_before = holder.store.audit()
    seed, public = generate_keypair()
    key = did_from_public_key(public)
    mapping = await registry.rotate_key(own["identity"], key, own["seed"], seed)
    assert mapping.current_did_key == key
    path = f"/v1/enrollments/{own['identity']}/refresh-binding"
    packet = {
        "previous_binding_commitment": commitment(
            "binding_commitment", confirmation["binding"]
        )
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        response = await call(client, path, packet, **{**own, "seed": seed, "key": key})
    assert response.status_code == 409, response.text
    error = response.json()["error"]
    assert error["code"] == "binding_refresh_identity_key_changed"
    assert "enrolment or recovery" in error["message"]
    assert (
        "operator must revoke the old ID, issue a new ID and enrol again"
        in error["message"]
    )
    assert holder.active_person(own["identity"]) == original
    assert holder.store.audit() == audit_before
