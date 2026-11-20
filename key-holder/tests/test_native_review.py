"""Review regressions through the real DNS/registry/holder, never SQL authority."""

import json
import subprocess
import sys

import httpx
import pytest
from policy_inputs import policy_file
from approval_service.canonical import parse
from approval_service.encoding import decode
from aweb_key_holder.http import create_app
from awid.controller_signing import parse_controller_request
from awid.id_certificates import id_certificate_id
from test_native_holder import (
    call,
    commit_identity,
    creation_receipt,
    material_for,
    register_identity,
    signature,
)


def retire(holder, person):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aweb_key_holder.cli",
            "--state",
            str(holder.store.directory),
            "retire-person",
            "--person",
            person,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"person": person, "state": "retired"}


async def first_person(native, *, activate):
    holder, registry = native.holder, native.registry
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
    intent = (await holder.bootstrap(person, key))["intent"]
    device, material = material_for(holder, intent)
    own = {"seed": seed, "key": key, "identity": person, "chain": []}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        answer = await call(
            client,
            f"/v1/enrollments/{person}/binding",
            {"material": material, "registration_count": 1},
            **own,
        )
        assert answer.status_code == 200, answer.text
        confirmation = answer.json()
        proof = creation_receipt(confirmation, device)
        answer = await call(client, f"/v1/enrollments/{person}/finish", proof, **own)
        assert answer.status_code == 200, answer.text
        evidence = answer.json()
        await commit_identity(registry, evidence, seed, key)
        own["chain"] = evidence["id_chain"]
        if activate:
            answer = await call(client, f"/v1/enrollments/{person}/activate", {}, **own)
            assert answer.status_code == 200, answer.text
    return own, device, confirmation, evidence


async def revoke(registry, holder, own):
    await registry.revoke_id_certificate(
        holder.store.descriptor().domain,
        own["identity"],
        signer=lambda payload: (own["key"], signature(own["seed"], payload)),
        expected_head=id_certificate_id(own["chain"][-1]["certificate"]),
    )


@pytest.mark.asyncio
async def test_retire_unactivated_evidence_after_public_certificate_revocation(
    native_holder,
):
    holder, registry = native_holder.holder, native_holder.registry
    own, _, _, _ = await first_person(native_holder, activate=False)
    await revoke(registry, holder, own)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        answer = await call(
            client, f"/v1/enrollments/{own['identity']}/activate", {}, **own
        )
        assert answer.status_code != 200
    with holder.store._connection() as db:
        evidence = db.execute(
            "SELECT evidence FROM enrollments WHERE person=?", (own["identity"],)
        ).fetchone()[0]
    retire(holder, own["identity"])
    _, key, person = await register_identity(registry)
    assert (await holder.bootstrap(person, key))["state"] == "enrollment_pending"
    with holder.store._connection() as db:
        assert (
            db.execute(
                "SELECT evidence FROM enrollments WHERE person=?", (own["identity"],)
            ).fetchone()[0]
            == evidence
        )


@pytest.mark.asyncio
async def test_active_person_gets_replacement_advice_then_operator_fresh_id_exit(
    native_holder,
):
    holder, registry = native_holder.holder, native_holder.registry
    own, _, _, _ = await first_person(native_holder, activate=True)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        answer = await call(
            client,
            f"/v1/enrollments/{own['identity']}",
            {
                "requester": {
                    "kind": "identity",
                    "id": own["identity"],
                    "key": own["key"],
                }
            },
            **own,
        )
        assert answer.status_code == 409
        assert answer.json()["error"]["code"] == "enrollment_replacement_unavailable"
        assert "new ID" in answer.json()["error"]["message"]
        retire(holder, own["identity"])
        await revoke(registry, holder, own)
        seed, key, person = await register_identity(registry)
        policy_file(
            holder.human_approval_config, holder.store.descriptor().domain, None
        )
        issued = await holder.issue_person(person, key)
        chain = [issued["certificate"]]
        await commit_identity(registry, {"id_chain": chain}, seed, key)
        answer = await call(
            client,
            f"/v1/enrollments/{person}",
            {"requester": {"kind": "identity", "id": person, "key": key}},
            seed=seed,
            key=key,
            identity=person,
            chain=chain,
        )
        assert answer.status_code == 200, answer.text
        assert answer.json()["intent"]["intent"]["purpose"] == "enroll_existing_person"


@pytest.mark.asyncio
async def test_two_targets_prepared_together_do_not_invalidate_one_another(
    native_holder,
):
    holder, registry = native_holder.holder, native_holder.registry
    own, device, confirmation, _ = await first_person(native_holder, activate=True)
    pending = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        for _ in range(2):
            _, key, person = await register_identity(registry)
            answer = await call(
                client,
                "/v1/humans",
                {"person": person, "identity_key": key, "approver": own["identity"]},
                **own,
            )
            assert answer.status_code == 428, answer.text
            needs = answer.json()
            request = parse(decode(needs["request_bytes"]))
            receipt = {
                "version": 1,
                "request_bytes": needs["request_bytes"],
                "binding": confirmation["binding"],
                "id_chain": own["chain"],
                "assertion": device.assert_request(request),
            }
            pending.append(
                {
                    "version": 1,
                    "request_bytes": needs["request_bytes"],
                    "receipt": receipt,
                }
            )
        for presentation in pending:
            answer = await call(client, "/v1/humans", presentation, **own)
            assert answer.status_code == 200, answer.text
