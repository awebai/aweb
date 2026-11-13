"""Real isolated-custody executor proofs accepted by real protected AWID."""

import base64
import json
from datetime import timedelta

import pytest
from nacl.signing import SigningKey

from aweb.protected_signing.custody import ProtectedControllerCustody
from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.protected_effect import HEADER
from awid.registry_types import RegistryError
from awid_service.protected_teams import provision_team_protection
from tests.test_independent_protected_signer import DOMAIN, TEAM, did
from tests.test_protected_admission_native import admit_operation, endorse, execute, prepare
from tests.test_protected_removal_native import removal

pytest_plugins = ("tests.test_protected_admission_native",)


async def activate(a, tmp_path):
    w = a.w
    service = SigningKey.generate()
    directory = tmp_path / "retention-custody"
    directory.mkdir(mode=0o700)
    controller_file, service_file = directory / "controller", directory / "service"
    for path, key in ((controller_file, w.controller), (service_file, service)):
        path.write_text(bytes(key).hex())
        path.chmod(0o400)
    custody = ProtectedControllerCustody(
        service_id=w.context.service_id, team_id=TEAM, domain=DOMAIN,
        key_file=controller_file, service_key_file=service_file, worker_uids=frozenset({65534}),
    )
    w.app.authority.custody = w.app.signer.custody = custody
    custody.configure_effects(registry=w.registry, clients={w.registry.registry_url: w.registry._http_client},
        clock=lambda: w.app.signer.clock())
    async with w.host.db.transaction() as tx:
        await provision_team_protection(tx, domain=DOMAIN, name="engineering", service_id=w.context.service_id,
            service_did_key=did(service), expected_generation=0, approval_ref="native-explicit-provisioning")
    return custody


@pytest.mark.asyncio
@pytest.mark.parametrize("lost_answer", [False, True, "purged"])
async def test_genuine_retained_admission_and_exact_confirmation(admissions, tmp_path, monkeypatch, lost_answer):
    a = admissions
    await endorse(a)  # Actual B3/UV endorsement authorizes the bounded root.
    custody = await activate(a, tmp_path)
    sends = []
    deliver = custody.deliver_retained

    async def release(operation, retained):
        sends.append(retained.fields())
        await deliver(operation, retained)
        if lost_answer:
            raise SignerRefused("receipt_unavailable")  # Lose only the applied answer.

    monkeypatch.setattr(custody, "deliver_retained", release)
    operation = admit_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    response = await execute(a, operation)
    if lost_answer:
        assert response.status_code == 503, response.text
        if lost_answer == "purged":
            await a.w.host.db.execute("DELETE FROM {{tables.protected_effect_receipts}} WHERE operation_id=$1::uuid", operation.operation_id)
        else:
            async with a.w.host.db.transaction() as tx:
                await provision_team_protection(tx, domain=DOMAIN, name="engineering", service_id=a.w.context.service_id,
                    service_did_key=did(SigningKey.generate()), expected_generation=1, approval_ref="native-service-key-transition")
        original_clock = a.w.app.signer.clock
        monkeypatch.setattr(a.w.app.signer, "clock", lambda: original_clock() + timedelta(hours=2))
        response = await execute(a, operation)
    assert response.status_code == 200, response.text
    if lost_answer == "purged":
        assert response.json()["state"] == "unknown"
        assert response.json()["code"] == "external_effect_unresolved"
        assert len(sends) == 1
        return
    result = response.json()["result"]
    assert result["v"] == 2 and result["delivery"]["state"] == "applied"
    assert set(result) == {"v", "type", "artifact", "delivery"}
    assert HEADER not in json.dumps(result)
    artifact = json.loads(base64.b64decode(result["artifact"]["signing"]))
    certificate = {**artifact, "signature": base64.b64encode(base64.b64decode(result["artifact"]["signature"])).rstrip(b"=").decode()}
    records = await a.w.registry.list_team_certificates_fresh(DOMAIN, "engineering", active_only=False)
    assert len([r for r in records if r.certificate_id == artifact["certificate_id"] and r.revoked_at is None]) == 1
    assert len(sends) == 1
    row = await a.w.db.fetch_one(
        "SELECT signed_result,retained_effect,delivery_claim FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
        operation.operation_id,
    )
    assert row["delivery_claim"] is not None and json.loads(row["retained_effect"]) == sends[0]
    assert json.loads(row["signed_result"]) == result["artifact"]
    if lost_answer:
        assert (await execute(a, operation)).json() == response.json()
        assert len(sends) == 1
        return
    # The original typed artifact/controller signature alone is still refused.
    with pytest.raises(RegistryError) as refused:
        await custody.register_admission(a.w.registry, operation, artifact, result["artifact"])
    assert refused.value.status_code == 403
    removed = removal(a, certificate)
    assert (await prepare(a, removed)).status_code == 200
    removed_response = await execute(a, removed)
    assert removed_response.status_code == 200, removed_response.text
    assert removed_response.json()["result"]["v"] == 2
    assert len(sends) == 2
    status = await a.w.registry.get_team_certificate_status_fresh(DOMAIN, "engineering", artifact["certificate_id"])
    assert status["status"] == "revoked"


@pytest.mark.asyncio
@pytest.mark.parametrize("unconfirmed", [False, True])
async def test_genuine_b3_owner_act_reaches_protected_sql_consumer(world, tmp_path, test_db_factory, monkeypatch, unconfirmed):
    import httpx
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from types import SimpleNamespace

    from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS, Refused
    from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier, apply_owner_act_migrations
    from aweb_naapp.runtime.protected_effect_receipts import receipt_router
    from awid.protected_effect import http_consumer
    from awid.protected_membership import observe_team_protection
    from tests.test_independent_protected_signer import prepare as prepare_owner

    w = world
    custody = await activate(SimpleNamespace(w=w), tmp_path)
    db = await test_db_factory.create_db(suffix="actual_owner_consumer")
    await apply_owner_act_migrations(db)
    await db.execute("CREATE TABLE holding (app_id text,installation_id text,role text,principal text)")
    await db.execute("INSERT INTO holding VALUES($1,$2,$3,$4)", w.operation.app_id,
        w.operation.installation_id, w.operation.role, w.operation.principal)
    async def key(team):
        return (await observe_team_protection(w.registry, team)).controller_did_key
    async def authority(team):
        return await observe_team_protection(w.registry, team)
    verifier = OwnerActVerifier(scope=w.operation.app_id, audience=w.operation.audience, acts=HUMAN_ROLE_ACTS,
        team_key_for=key, team_authority_for=authority)
    app = FastAPI()
    app.include_router(receipt_router(lambda request: db))

    @app.post("/.well-known/aweb-owner-act")
    async def effect(request: Request):
        body = await request.body()
        payload = json.loads(body)
        try:
            prepared = await verifier.prepare(base64.b64decode(payload["signing"]), payload["signature"], team_id=TEAM,
                protected_delivery=(request.headers.get(HEADER), http_consumer(audience=w.operation.audience,
                    method="POST", path=request.url.path, body=body)))
            async with db.transaction() as tx:
                row = await tx.fetch_one("SELECT * FROM holding FOR UPDATE")
                await verifier.consume_in(tx, prepared, expected_subject=dict(row))
                await tx.execute("DELETE FROM holding")
                await prepared.record_applied(tx)
                prepared.require_fresh()
        except Refused as exc:
            return JSONResponse({"detail": exc.code}, status_code=503 if exc.code == "protected_state_unavailable" else 403)
        return {"applied": True}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), follow_redirects=False) as client:
        custody.configure_effects(registry=w.registry, clients={w.operation.audience: client}, clock=lambda: w.app.signer.clock())
        prepared = await prepare_owner(w)
        candidate_row = await w.db.fetch_one(
            "SELECT candidate_links FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", prepared.operation_id)
        token = next(iter(json.loads(candidate_row["candidate_links"]).values()))
        if unconfirmed:
            async def unreadable(*args):
                return None  # Hide only confirmation; the actual consumer still applies.
            monkeypatch.setattr(custody, "confirm_retained", unreadable)
        options = await w.app.signer.approval_options(prepared.operation_id, human=w.human)
        proof = w.device.get(dict(options))
        original_clock = w.app.signer.clock
        if unconfirmed:
            # The candidate and authorized unsigned snapshot precede a real
            # B3-authorized signature, retained delivery and consumer commit.
            authorized = w.app.signer._authorized
            interleaved = False
            results = []
            async def sign_after_authorized(operation_id, actor, purpose, **kwargs):
                nonlocal interleaved
                snapshot = await authorized(operation_id, actor, purpose, **kwargs)
                if purpose == "approval" and not interleaved:
                    interleaved = True
                    results.append(await w.app.signer.execute(prepared.operation_id, proof, human=w.human))
                    monkeypatch.setattr(w.app.signer, "clock", lambda: original_clock() + timedelta(days=2))
                return snapshot
            monkeypatch.setattr(w.app.signer, "_authorized", sign_after_authorized)
            with pytest.raises(SignerRefused, match="scope_refused"):
                await w.app.signer.link_view(prepared.handoff_id, token)
            assert interleaved
            result = results[0]
            assert result.state == "pending" and result.code == "effect_in_progress"
        else:
            result = await w.app.signer.execute(prepared.operation_id, proof, human=w.human)
            assert result.state == "committed" and result.result["v"] == 2
        assert await db.fetch_value("SELECT count(*) FROM holding") == 0
        assert await db.fetch_value("SELECT count(*) FROM {{tables.owner_act_nonces}}") == 1
        assert await db.fetch_value("SELECT count(*) FROM {{tables.protected_effect_receipts}}") == 1
        row = await w.db.fetch_one("SELECT retained_effect FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", prepared.operation_id)
        retained = json.loads(row["retained_effect"])
        if unconfirmed:
            from aweb.protected_signing.owner import owner_view, owner_page_html
            async with w.db.transaction() as tx:
                scope = (await w.app.authority.binding(tx))["b3_scope"]
            for offset in (timedelta(), timedelta(days=2)):
                view = await owner_view(w.app, scope=scope, now=original_clock() + offset)
                assert view["pending"] == []
                assert [(item["operation_id"], item["state"]) for item in view["history"]] == [
                    (prepared.operation_id, "unresolved")]
                html = owner_page_html(view)
                assert "whether it took effect is not confirmed yet" in html
                assert "Expired, nobody decided" not in html and "by you" not in html
            historical = await w.app.signer.receipt(prepared.operation_id, reader=w.human)
            assert historical.state == "unknown" and historical.code == "external_effect_unresolved"
            reread = await w.db.fetch_one(
                "SELECT retained_effect FROM {{tables.protected_signer_operations}} WHERE operation_id=$1", prepared.operation_id)
            assert json.loads(reread["retained_effect"]) == retained
            assert await db.fetch_value("SELECT count(*) FROM {{tables.owner_act_nonces}}") == 1
            return
        body = base64.b64decode(retained["delivery"]["body"])
        url = w.operation.audience + retained["delivery"]["path"]
        missing = await client.post(url, content=body)
        assert (missing.status_code, missing.json()["detail"]) == (403, "protected_controller_required")
        altered = await client.post(url, content=body + b" ", headers=retained["delivery"]["headers"])
        assert (altered.status_code, altered.json()["detail"]) == (403, "protected_controller_required")



@pytest.mark.asyncio
async def test_cache_wait_expiry_keeps_original_bundle_claim_and_never_sends(admissions, tmp_path, monkeypatch):
    a = admissions
    await endorse(a)
    custody = await activate(a, tmp_path)
    operation = admit_operation(a)
    assert (await prepare(a, operation)).status_code == 200
    original_clock = a.w.app.signer.clock
    original_request = custody._request_effect
    original_invalidate = a.w.registry.invalidate_team_certificate_cache
    original_deliver = custody.deliver_retained
    refusals = []
    invalidations, sends = [], []

    async def invalidate(*args):
        invalidations.append(args)
        await original_invalidate(*args)
        monkeypatch.setattr(a.w.app.signer, "clock", lambda: original_clock() + timedelta(hours=2))

    async def request(delivery, **kwargs):
        if not kwargs.get("receipt"):
            sends.append(delivery)
        return await original_request(delivery, **kwargs)

    async def deliver(operation, retained):
        try:
            await original_deliver(operation, retained)
        except SignerRefused as exc:
            refusals.append(exc.code)
            raise

    monkeypatch.setattr(custody, "deliver_retained", deliver)
    monkeypatch.setattr(a.w.registry, "invalidate_team_certificate_cache", invalidate)
    monkeypatch.setattr(custody, "_request_effect", request)
    response = await execute(a, operation)
    assert response.status_code == 200 and response.json()["code"] == "external_effect_unresolved", response.text
    assert refusals == ["operation_expired"]
    assert sends == [] and len(invalidations) == 2
    before = await a.w.db.fetch_one(
        "SELECT signed_result,retained_effect,delivery_claim FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
        operation.operation_id)
    assert all(before[k] is not None for k in ("signed_result", "retained_effect", "delivery_claim"))
    recovered = await execute(a, operation)
    assert recovered.status_code == 200 and recovered.json()["code"] == "external_effect_unresolved"
    after = await a.w.db.fetch_one(
        "SELECT signed_result,retained_effect,delivery_claim FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
        operation.operation_id)
    assert dict(after) == dict(before) and sends == [] and len(invalidations) == 2
