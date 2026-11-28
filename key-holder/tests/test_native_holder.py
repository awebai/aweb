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
from pending import expire_pending


def signature(seed, payload):
    return base64.b64decode(sign_message(seed, payload) + "==", validate=True)


async def register_identity(registry):
    seed, public = generate_keypair()
    key = did_from_public_key(public)
    await registry.register_did(key, seed)
    return seed, key, stable_id_from_did_key(key)


def material_for(holder, intent, *, device=None):
    if device is None:
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
            **(
                {
                    "X-AWID-ID-Chain": encode_id_chain_header(
                        {"v": 1, "type": "aweb.id-chain", "certificates": chain}
                    )
                }
                if chain
                else {}
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
    first_pending = dict(seed=first_seed, key=first_key, identity=first, chain=[])
    assert intent["intent"]["requester"] == {
        "kind": "identity",
        "id": first,
        "key": first_key,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        bound = await call(
            client,
            f"/v1/enrollments/{first}/binding",
            {"material": material, "registration_count": 1},
            **first_pending,
        )
        assert bound.status_code == 200, bound.text
        proof = creation_receipt(bound.json(), first_device)
        finished = await call(
            client, f"/v1/enrollments/{first}/finish", proof, **first_pending
        )
        assert finished.status_code == 200, finished.text
        activation = finished.json()
        await commit_identity(registry, activation, first_seed, first_key)
        response = await call(
            client,
            f"/v1/enrollments/{first}/activate",
            {},
            **{**first_pending, "chain": activation["id_chain"]},
        )
        assert response.status_code == 200, response.text
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

        # Known local enrollment conflicts must not ask the person to approve.
        async def already_exists(expected="person_already_exists"):
            before = holder.store.audit()
            response = await call(
                client,
                "/v1/humans",
                {"person": second, "identity_key": second_key, "approver": first},
                **first_caller,
            )
            assert response.status_code == 409, response.text
            assert response.json()["error"]["code"] == expected
            assert holder.store.audit() == before

        await already_exists()
        expired = expire_pending(holder, second)
        old_audit = holder.store.audit()
        retried = await call(
            client,
            "/v1/humans",
            {"person": second, "identity_key": second_key, "approver": first},
            **first_caller,
        )
        assert retried.status_code == 428, retried.text
        new_raw = retried.json()["request_bytes"]
        new_request = parse(decode(new_raw))
        new_receipt = {
            "version": 1,
            "request_bytes": new_raw,
            "binding": activation["binding"],
            "id_chain": activation["id_chain"],
            "assertion": first_device.assert_request(new_request),
        }
        renewed = await call(
            client,
            "/v1/humans",
            {"version": 1, "request_bytes": new_raw, "receipt": new_receipt},
            **first_caller,
        )
        assert renewed.status_code == 200, renewed.text
        second_intent = renewed.json()["intent"]
        assert second_intent != expired
        assert (
            second_intent["intent"]["deadline"] - second_intent["intent"]["not_before"]
            == 24 * 60 * 60
        )
        assert holder.store.audit()[: len(old_audit)] == old_audit
        # A previously consumed request must not disclose the replacement intent.
        old_replay = await call(client, "/v1/humans", presentation, **first_caller)
        assert old_replay.status_code == 409
        second_device, second_material = material_for(holder, second_intent)
        base = "/v1/enrollments/" + second
        second_caller = dict(
            seed=second_seed, key=second_key, identity=second, chain=[]
        )
        bound = await call(
            client,
            base + "/binding",
            {"material": second_material, "registration_count": 1},
            **second_caller,
        )
        assert bound.status_code == 200, bound.text
        creation = creation_receipt(bound.json(), second_device)
        finished = await call(client, base + "/finish", creation, **second_caller)
        assert finished.status_code == 200, finished.text
        await already_exists()
        await commit_identity(registry, finished.json(), second_seed, second_key)
        activated = await call(
            client,
            base + "/activate",
            {},
            **{**second_caller, "chain": finished.json()["id_chain"]},
        )
        assert activated.status_code == 200 and activated.json()["state"] == "active", (
            activated.text
        )
        assert holder.active_person(second)["identity_key"] == second_key
        await already_exists("enrollment_replacement_unavailable")

        # Physical SQLite order is not bootstrap authority. Keep the logical
        # first-person row unchanged while placing it after the second person.
        with holder.store._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            saved = dict(holder._row(db, first))
            db.execute("DELETE FROM enrollments WHERE person=?", (first,))
            columns = ",".join(saved)
            placeholders = ",".join("?" for _ in saved)
            db.execute(
                f"INSERT INTO enrollments({columns}) VALUES ({placeholders})",
                tuple(saved.values()),
            )
        assert (await holder.bootstrap(first, first_key))["intent"] == intent
