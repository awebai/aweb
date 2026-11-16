"""Real public authority and holder effects; software UV is not the browser journey.

No registry/DNS/receipt verifier is replaced and limits remain enabled. The
separate adcl.6 joined journey supplies real service HTTP and Chromium's device.
"""

import base64
from datetime import datetime, timezone
import hashlib

import httpx
import pytest

from awid.controller_signing import (
    parse_controller_request,
    parse_controller_object,
    sign_controller_object,
)
from awid.did import generate_keypair, did_from_public_key, stable_id_from_did_key
from awid.id_certificates import encode_id_chain_header
from awid.signing import sign_message
from approval_service.canonical import canonical, parse
from approval_service.encoding import encode, decode
from approval_service.seams import commitment

from aweb_key_holder.http import create_app
from authenticator import Passkey


def signature(seed, payload):
    return base64.b64decode(sign_message(seed, payload) + "==", validate=True)


async def register_identity(registry):
    seed, public = generate_keypair()
    key = did_from_public_key(public)
    await registry.register_did(key, seed)
    return seed, key, stable_id_from_did_key(key)


def material_for(holder, intent):
    device = Passkey(holder.approval_origin, holder.rp_id)
    material = {
        "version": 1,
        "state": "pending",
        "locator": commitment("enrollment_locator", intent),
        "deadline": intent["intent"]["deadline"],
        "registrations": [
            {
                "registration": device.register(decode(intent["intent"]["challenge"])),
                "client_extension_results": {"credProps": {"rk": True}},
            }
        ],
    }
    return device, material


def creation_receipt(confirmation, device):
    request = parse(decode(confirmation["request_bytes"]))
    return {
        "version": 1,
        "request_bytes": confirmation["request_bytes"],
        "binding": confirmation["binding"],
        "id_chain": [confirmation["intent"]["intent"]["pending_certificate"]],
        "assertion": device.assert_request(request),
    }


async def commit_identity(registry, activation, seed, key):
    await registry.register_id_certificate(
        {"v": 1, "type": "aweb.id-chain", "certificates": activation["id_chain"]},
        signer=lambda payload: (key, signature(seed, payload)),
        expected_head=None,
        invitation_id=None,
    )


async def call(client, path, body, *, seed, key, identity, chain):
    raw = canonical(body)
    timestamp = datetime.now(timezone.utc).isoformat()
    packet = canonical(
        {
            "v": 2,
            "did_aw": identity,
            "aud": "https://holder.example",
            "method": "POST",
            "path": path,
            "timestamp": timestamp,
            "body_sha256": hashlib.sha256(raw).hexdigest(),
        }
    )
    return await client.post(
        path,
        content=raw,
        headers={
            "Authorization": f"DIDKey {key} {sign_message(seed, packet)}",
            "X-AWEB-Timestamp": timestamp,
            "X-AWEB-DID-AW": identity,
            "X-AWEB-Signed-Payload": encode(packet),
            "Content-Type": "application/json",
            "X-AWID-ID-Chain": encode_id_chain_header(
                {"v": 1, "type": "aweb.id-chain", "certificates": chain}
            ),
        },
    )


@pytest.mark.asyncio
async def test_real_authority_first_bootstrap_then_second_requires_exact_approval(
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
    first_seed, first_key, first = await register_identity(registry)
    intent = (await holder.bootstrap(first, first_key))["intent"]
    first_device, material = material_for(holder, intent)
    confirmation = holder.bind_registration(first, material, registration_count=1)
    activation = await holder.finish(
        first, creation_receipt(confirmation, first_device)
    )
    await commit_identity(registry, activation, first_seed, first_key)
    assert (await holder.activate(first))["state"] == "active"
    first_caller = dict(
        seed=first_seed, key=first_key, identity=first, chain=activation["id_chain"]
    )

    # A second valid caller in the same namespace is not this request's presenter.
    agent_seed, agent_key, agent = await register_identity(registry)
    agent_certificate = {
        "v": 1,
        "type": "aweb.id-certificate",
        "id": agent,
        "domain": root.domain,
        "parent": {"kind": "namespace", "id": root.domain},
        "kind": "agent",
        "issuer_key": root.did_key,
        "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    signed_agent = await sign_controller_object(
        parse_controller_object(
            {
                "operation": "namespace_id_issue",
                "domain": root.domain,
                "kind": "agent",
                "certificate": agent_certificate,
            }
        ),
        controller=root,
        signer=lambda ctx: holder.store.sign_controller(ctx, actor="operator"),
    )
    await commit_identity(registry, {"id_chain": [signed_agent]}, agent_seed, agent_key)
    agent_caller = dict(
        seed=agent_seed, key=agent_key, identity=agent, chain=[signed_agent]
    )

    second_seed, second_key, second = await register_identity(registry)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        response = await call(
            client,
            "/v1/humans",
            {"person": second, "identity_key": second_key, "approver": first},
            **first_caller,
        )
        assert response.status_code == 428, response.text
        raw = response.json()["request_bytes"]
        request = parse(decode(raw))
        assert request["requester"]["key"] == first_key
        receipt = {
            "version": 1,
            "request_bytes": raw,
            "binding": activation["binding"],
            "id_chain": activation["id_chain"],
            "assertion": first_device.assert_request(request),
        }
        presentation = {"version": 1, "request_bytes": raw, "receipt": receipt}
        before = holder.store.audit()
        refused = await call(client, "/v1/humans", presentation, **agent_caller)
        assert (
            refused.status_code == 401
            and refused.json()["error"]["code"] == "requester_mismatch"
        )
        assert holder.store.audit() == before

        # Even a genuine UV assertion cannot manufacture the holder's own nonce.
        invented = {**request, "nonce": {"kid": "holder-1", "value": encode(bytes(32))}}
        forged_receipt = {
            **receipt,
            "request_bytes": encode(canonical(invented)),
            "assertion": first_device.assert_request(invented),
        }
        refused = await call(
            client,
            "/v1/humans",
            {
                "version": 1,
                "request_bytes": encode(canonical(invented)),
                "receipt": forged_receipt,
            },
            **first_caller,
        )
        assert (
            refused.status_code == 401
            and refused.json()["error"]["code"] == "nonce_invalid"
        )
        assert holder.store.audit() == before

        approved = await call(client, "/v1/humans", presentation, **first_caller)
        assert approved.status_code == 200, approved.text
        after = holder.store.audit()
        duplicate = await call(client, "/v1/humans", presentation, **first_caller)
        assert duplicate.json() == approved.json()
        assert holder.store.audit() == after

        second_intent = approved.json()["intent"]
        second_device, second_material = material_for(holder, second_intent)
        base = "/v1/enrollments/" + second
        bound = await call(
            client,
            base + "/binding",
            {"material": second_material, "registration_count": 1},
            **first_caller,
        )
        assert bound.status_code == 200, bound.text
        creation = creation_receipt(bound.json(), second_device)
        finished = await call(client, base + "/finish", creation, **first_caller)
        assert finished.status_code == 200, finished.text
        await commit_identity(registry, finished.json(), second_seed, second_key)
        activated = await call(client, base + "/activate", {}, **first_caller)
        assert activated.status_code == 200 and activated.json()["state"] == "active", (
            activated.text
        )
        assert holder.active_person(second)["identity_key"] == second_key
