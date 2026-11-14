"""Explicit native protection and a real human-role consumer context.

Calling these helpers opts the selected test world into protection. Ordinary
legacy admission/removal worlds stay unmarked. The context does not prepare,
approve or sign an operation on behalf of its caller.
"""

import base64
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

import httpx
from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS, Refused
from aweb_naapp.hooks.owner_act_nonces import OwnerActVerifier, apply_owner_act_migrations
from aweb_naapp.runtime.protected_effect_receipts import receipt_router
from awid.did import did_from_public_key
from awid.protected_effect import HEADER, http_consumer
from awid.protected_membership import observe_team_protection
from awid_service.protected_teams import provision_team_protection
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from nacl.signing import SigningKey

from aweb.protected_signing.custody import ProtectedControllerCustody


async def activate(a, tmp_path):
    """Provision the selected fixture team; this is not implicit global setup."""
    w = a.w
    name, domain = w.context.authority_id.split(":", 1)
    service = SigningKey.generate()
    directory = tmp_path / "retention-custody"
    directory.mkdir(mode=0o700)
    controller_file, service_file = directory / "controller", directory / "service"
    for path, key in ((controller_file, w.controller), (service_file, service)):
        path.write_text(bytes(key).hex())
        path.chmod(0o400)
    custody = ProtectedControllerCustody(service_id=w.context.service_id,
        team_id=w.context.authority_id, domain=domain, key_file=controller_file,
        service_key_file=service_file, worker_uids=frozenset({65534}))
    w.app.authority.custody = w.app.signer.custody = custody
    custody.configure_effects(registry=w.registry,
        clients={w.registry.registry_url: w.registry._http_client},
        receipt_origins=frozenset({w.registry.registry_url}), clock=lambda: w.app.signer.clock())
    async with w.host.db.transaction() as tx:
        await provision_team_protection(tx, domain=domain, name=name,
            service_id=w.context.service_id,
            service_did_key=did_from_public_key(bytes(service.verify_key)),
            expected_generation=0, approval_ref="native-explicit-provisioning")
    return custody


@asynccontextmanager
async def ready_owner_act_consumer(world, tmp_path, test_db_factory):
    """Real pinned human-role SQL consumer, including exact receipt readiness.

    The original operation fixes the consumer scope/subject. Changing the
    caller's operation afterward cannot silently change the resource ACL.
    Protection persists for this fixture world's lifetime after context exit.
    """
    w = world
    operation = w.operation
    subject = operation.intent()["subject"]
    team_id = operation.context.authority_id
    custody = await activate(SimpleNamespace(w=w), tmp_path)
    db = await test_db_factory.create_db(suffix="actual_owner_consumer", schema="owner_consumer")
    await apply_owner_act_migrations(db)
    assert db.schema == "owner_consumer"
    await db.execute("CREATE TABLE holding (app_id text,installation_id text,role text,principal text)")
    consumer_tables = {"schema_migrations", "owner_act_nonces", "protected_effect_receipts", "holding"}
    namespaces = await db.fetch_all(
        "SELECT n.nspname AS namespace,c.relname AS name FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "WHERE c.relkind='r' AND c.relname=ANY($1::text[])", list(consumer_tables))
    assert {(row["namespace"], row["name"]) for row in namespaces} == {
        ("owner_consumer", name) for name in consumer_tables}
    await db.execute("INSERT INTO holding VALUES($1,$2,$3,$4)", subject["app_id"],
        subject["installation_id"], subject["role"], subject["principal"])

    async def key(team):
        return (await observe_team_protection(w.registry, team)).controller_did_key

    async def authority(team):
        return await observe_team_protection(w.registry, team)

    verifier = OwnerActVerifier(scope=subject["app_id"], audience=operation.audience,
        acts=HUMAN_ROLE_ACTS, team_key_for=key, team_authority_for=authority)
    app = FastAPI()
    app.include_router(receipt_router(lambda request: db))

    @app.post("/.well-known/aweb-owner-act")
    async def effect(request: Request):
        body = await request.body()
        payload = json.loads(body)
        try:
            prepared = await verifier.prepare(base64.b64decode(payload["signing"]),
                payload["signature"], team_id=team_id,
                protected_delivery=(request.headers.get(HEADER), http_consumer(
                    audience=operation.audience, method="POST", path=request.url.path, body=body)))
            async with db.transaction() as tx:
                row = await tx.fetch_one("SELECT * FROM holding FOR UPDATE")
                await verifier.consume_in(tx, prepared, expected_subject=dict(row))
                await tx.execute("DELETE FROM holding")
                await prepared.record_applied(tx)
                prepared.require_fresh()
        except Refused as exc:
            return JSONResponse({"detail": exc.code},
                status_code=503 if exc.code == "protected_state_unavailable" else 403)
        return {"applied": True}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), follow_redirects=False) as client:
        custody.configure_effects(registry=w.registry, clients={operation.audience: client},
            receipt_origins=frozenset({operation.audience}), clock=lambda: w.app.signer.clock())
        yield SimpleNamespace(world=w, operation=operation, custody=custody, db=db, app=app, client=client,
            service_key_file=tmp_path / "retention-custody" / "service")
