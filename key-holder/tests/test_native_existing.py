"""Operator issuance followed by own-key later enrollment on the real registry."""

import asyncio
import json
import sys
from datetime import UTC, datetime

import httpx
import pytest
from approval_service.grading import EnrollmentGrading
from approval_service.statements import verify_enrollment_evidence
from attestation_inventory_migration import (
    lose_passkey_inventory,
    upgraded_pre_inventory_store,
)
from authenticator import packed_device
from aweb_key_holder import cli
from aweb_key_holder.auth import Caller
from aweb_key_holder.http import create_app
from aweb_key_holder.keys import Refused
from awid.controller_signing import parse_controller_request
from policy_inputs import policy_file
from test_native_holder import (
    call,
    commit_identity,
    creation_receipt,
    material_for,
    register_identity,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("binding_kind", ["passkey", "hardware", "mixed"])
async def test_existing_person_self_enrolls_and_controller_cannot_carry_it(
    native_holder, binding_kind, monkeypatch, capsys
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
        if binding_kind == "passkey":
            device, material = material_for(holder, intent)
        else:
            hardware, snapshot, _attestation = packed_device(
                holder.approval_origin, holder.rp_id
            )
            holder.grading = EnrollmentGrading("hardware", snapshot)
            device, material = material_for(holder, intent, device=hardware)
        if binding_kind == "mixed":
            _, passkey = material_for(holder, intent)
            material["registrations"].extend(passkey["registrations"])
        binding_request = {
            "material": material,
            "registration_count": len(material["registrations"]),
        }
        response = await call(
            client,
            f"/v1/enrollments/{person}/binding",
            binding_request,
            **own,
        )
        assert response.status_code == 200, response.text
        bound = response.json()
        repeated = await call(
            client,
            f"/v1/enrollments/{person}/binding",
            binding_request,
            **own,
        )
        assert repeated.status_code == 200, repeated.text
        assert repeated.json() == bound
        proof = creation_receipt(bound, device)
        credentials = proof["binding"]["binding"]["credentials"]
        assert [entry["grade"] for entry in credentials] == {
            "passkey": ["passkey_uv"],
            "hardware": ["certified_hardware"],
            "mixed": ["certified_hardware", "passkey_uv"],
        }[binding_kind]
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
        if binding_kind == "hardware":
            with holder.store._connection() as db:
                stored = db.execute(
                    "SELECT namespace FROM attestation_inventory WHERE person=? AND credential=?",
                    (person, credentials[0]["id"]),
                ).fetchone()
                assert stored["namespace"] == root.domain
            with upgraded_pre_inventory_store(holder.store):
                await check_missing_inventory_refusal(
                    holder, client, own, binding_request, monkeypatch, capsys
                )
        if binding_kind == "mixed":
            lose_passkey_inventory(holder.store, person, credentials[1]["id"])
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


async def check_missing_inventory_refusal(
    holder, client, own, binding_request, monkeypatch, capsys
):
    person = own["identity"]
    audit = holder.store.audit()
    repeated = await call(
        client, f"/v1/enrollments/{person}/binding", binding_request, **own
    )
    assert repeated.status_code == 200
    with holder.store._connection() as db:
        assert not db.execute(
            "SELECT credential FROM attestation_inventory WHERE person=?", (person,)
        ).fetchall()
    path = f"/v1/enrollments/{person}/activate"
    message = (
        "The pending enrolment predates the attestation inventory. "
        "Let it expire or remove it and start the enrolment again."
    )
    response = await call(client, path, {}, **own)
    assert response.status_code == 409
    assert response.json() == {
        "error": {"code": "attestation_assessment_unavailable", "message": message}
    }

    caller = Caller(person, own["key"], datetime.now(UTC).isoformat(), b"")
    with pytest.raises(Refused, match="attestation_assessment_unavailable") as refused:
        await holder.activate(person, caller=caller, chain=own["chain"])

    async def report_activation_refusal(_args, _parser):
        # The CLI has no activate subcommand. Exercise its real refusal writer.
        raise refused.value

    with monkeypatch.context() as patch:
        patch.setattr(cli, "operate", report_activation_refusal)
        patch.setattr(
            sys,
            "argv",
            ["aweb-key-holder", "--state", str(holder.store.directory), "serve"],
        )
        capsys.readouterr()
        with pytest.raises(SystemExit) as exited:
            await asyncio.to_thread(cli.main)
    assert exited.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "error": "attestation_assessment_unavailable",
        "message": message,
    }
    assert holder.store.audit() == audit
    with holder.store._connection() as db:
        assert (
            db.execute(
                "SELECT active FROM enrollments WHERE person=?", (person,)
            ).fetchone()["active"]
            == 0
        )
