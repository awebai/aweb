"""Event-key history survives real origin-fetched v1/v2 representation switches."""

import base64
import hashlib
import json
from datetime import datetime, timezone

import httpx
import pytest
import test_verified_installations as store_fixture
from aweb.app_credentials import APP_EVENT, verify_app_credential
from aweb.installations import install_verified_manifest_on
from aweb.service_errors import ConflictError
from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from fastapi import FastAPI, Request
from nacl.signing import SigningKey

TEAM = store_fixture.TEAM
origin = store_fixture.origin
db = store_fixture.db
pytestmark = pytest.mark.asyncio
KID = "history-event"


async def install_version(db, origin, version, did, expected=None):
    document = json.loads(origin.manifest(version))
    # Keep declarations from the shared vector while making the event key's
    # public identity the same on both sides of the version switch.
    if version == 1:
        document["event_emitters"] = [{"kid": KID, "did_key": did}]
    else:
        document["app_keys"] = [{"kid": KID, "did_key": did, "purposes": [APP_EVENT]}]
    data = json.dumps(document).encode()
    if version == 1:
        origin.routes["/.well-known/aweb-app-versions.json"] = (404, b"", [])
        origin.routes["/.well-known/aweb-app.json"] = (200, data, [])
    else:
        origin.publish(data)
    evidence = await origin.fetcher.fetch(origin.url)
    assert evidence.data == data and evidence.manifest.manifest_version == version
    async with db.transaction() as tx:
        return await install_verified_manifest_on(
            tx, team_id=TEAM, fetched=evidence, granted_scopes=["fixture:read"], expected_generation=expected,
        )


async def emit_probe(db, signing):
    app = FastAPI()
    app.state.public_origin = "http://test"

    @app.post("/probe")
    async def probe(request: Request):
        credential = await verify_app_credential(request, db, APP_EVENT)
        return {"kid": credential.kid, "digest": credential.digest}

    body = b"{}"
    did = did_from_public_key(bytes(signing.verify_key))
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = canonical_json_bytes({
        "v": 1, "auth": APP_EVENT, "aud": "http://test", "method": "POST", "path": "/probe",
        "team_id": TEAM, "app_id": "fixture", "kid": KID, "did_key": did,
        "body_sha256": hashlib.sha256(body).hexdigest(), "timestamp": timestamp,
    })
    headers = {
        "Authorization": f"AWEB-App DIDKey {did} {sign_message(bytes(signing), payload)}",
        "X-AWEB-App-ID": "fixture", "X-AWEB-App-Key-ID": KID, "X-AWEB-Team-ID": TEAM,
        "X-AWEB-Timestamp": timestamp, "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload).decode().rstrip("="),
    }
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.post("/probe", content=body, headers=headers)


async def revoke_old_representation(db, version):
    table = "team_app_emit_keys" if version == 1 else "team_app_keys"
    await db.execute(
        "UPDATE {{tables." + table + "}} SET revoked_at=clock_timestamp() WHERE team_id=$1 AND app_id='fixture' AND key_id=$2",
        TEAM, KID,
    )


@pytest.mark.parametrize("versions", [(1, 2), (2, 1)])
@pytest.mark.parametrize("revocation", ["before", "after", None])
async def test_version_switch_keeps_event_revocation_authoritative(db, origin, versions, revocation):
    signing = SigningKey.generate()
    did = did_from_public_key(bytes(signing.verify_key))
    first = await install_version(db, origin, versions[0], did)
    assert (await emit_probe(db, signing)).status_code == 200
    if revocation == "before":
        await revoke_old_representation(db, versions[0])
        assert (await emit_probe(db, signing)).status_code == 403
    second = await install_version(db, origin, versions[1], did, first["generation"])
    assert second["installation_id"] == first["installation_id"]
    assert second["generation"] > first["generation"]
    if revocation == "after":
        assert (await emit_probe(db, signing)).status_code == 200
        await revoke_old_representation(db, versions[0])
    result = await emit_probe(db, signing)
    assert result.status_code == (200 if revocation is None else 403), result.text
    if revocation is None:
        assert result.json()["digest"] == second["digest"]


@pytest.mark.parametrize("versions", [(1, 2), (2, 1)])
async def test_version_switch_cannot_rebind_an_existing_event_kid(db, origin, versions):
    original, replacement = SigningKey.generate(), SigningKey.generate()
    first = await install_version(db, origin, versions[0], did_from_public_key(bytes(original.verify_key)))
    with pytest.raises(ConflictError):
        await install_version(db, origin, versions[1], did_from_public_key(bytes(replacement.verify_key)), first["generation"])
    assert await store_fixture.current(db) == first
    assert await db.fetch_value("SELECT last_generation FROM {{tables.team_app_install_counters}}") == first["generation"]
    assert (await emit_probe(db, original)).status_code == 200


@pytest.mark.parametrize("revoked", [False, True])
async def test_verification_preserves_a_declared_v2_key_stored_as_a_legacy_emitter(db, origin, revoked):
    from aweb.app_registry import AppEmitKey
    from aweb.installations import verify_pending_installations
    from tests.installation_fixtures import seed_pending_installation

    signing = SigningKey.generate()
    did = did_from_public_key(bytes(signing.verify_key))
    document = json.loads(origin.manifest(2))
    document["app_keys"] = [{"kid": KID, "did_key": did, "purposes": [APP_EVENT]}]
    origin.publish(json.dumps(document).encode())
    evidence = await origin.fetcher.fetch(origin.url)
    # Released pre-F6 v2 clients registered app-event keys as emitters under
    # this same pin, without supplying manifest bytes. Migration keeps it pending.
    await seed_pending_installation(
        db, team_id=TEAM, app_id="fixture", origin=origin.url, app_version=document["app"]["version"],
        manifest_version=2, digest=evidence.digest, granted_scopes=["fixture:read"],
        emit_keys=[AppEmitKey(kid=KID, did_key=did)],
    )
    before = await store_fixture.current(db)
    if revoked:
        await revoke_old_representation(db, 1)
    reports = await verify_pending_installations(db, fetcher=origin.fetcher)
    assert reports[0]["outcome"] == "verified"
    after = await store_fixture.current(db)
    assert after["state"] == "active" and after["origin_verified"]
    assert (after["installation_id"], after["generation"], after["digest"], after["granted_scopes"]) == (
        before["installation_id"], before["generation"], before["digest"], before["granted_scopes"],
    )
    legacy_revoked = await db.fetch_value("SELECT revoked_at IS NOT NULL FROM {{tables.team_app_emit_keys}} WHERE key_id=$1", KID)
    assert legacy_revoked is revoked  # Verification must not invent a revocation.
    result = await emit_probe(db, signing)
    assert result.status_code == (403 if revoked else 200), result.text
