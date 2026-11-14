"""Native verifier controls using codec fixtures, not executor-issued effects."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from awid.protected_effect import (
    HEADER,
    artifact_digest,
    encode_proofs,
    http_consumer,
    issue_proof,
)
from awid.signing import canonical_json_bytes, sign_message
from awid.team_server_record import record_signing_bytes
from test_controller_request_v2_http import (
    ORIGIN,
    controller_app as controller_app,
    keypair,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("expire_after_write", [False, True])
@pytest.mark.parametrize(
    "audience,accepted",
    [(ORIGIN, True), ("https://second.registry.test", True),
     ("https://unpinned.registry.test", False)],
)
async def test_artifact_delivery_accepts_each_pinned_origin_only(
    controller_app, audience, accepted, monkeypatch, expire_after_write
):
    env = controller_app
    env.app.state.awid_public_origins = (ORIGIN, "https://second.registry.test")
    service_key, service_did = keypair()
    history_id = str(uuid4())
    await env.db.execute(
        "INSERT INTO {{tables.team_protection}} "
        "(domain,name,service_id,service_did_key,history_id,generation) "
        "VALUES ('local','base','test-service',$1,$2::uuid,1)",
        service_did, history_id,
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    current = now
    wrote = False
    from awid_service import protected_teams
    from pgdbm.core import TransactionManager

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return current.astimezone(tz)

    original_execute = TransactionManager.execute

    async def execute(tx, query, *args, **kwargs):
        nonlocal current, wrote
        result = await original_execute(tx, query, *args, **kwargs)
        if "INSERT INTO {{tables.team_server_records}}" in query:
            wrote = True
            if expire_after_write:
                current += timedelta(seconds=121)
        return result

    monkeypatch.setattr(protected_teams, "datetime", Clock)
    monkeypatch.setattr(TransactionManager, "execute", execute)
    record = {
        "v": 1, "type": "aweb.team-server", "team_id": "base:local",
        "team_did_key": env.team[1], "server_url": "https://coord.example/api",
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    signing = record_signing_bytes(record)
    signature = sign_message(env.team[0], signing)
    body = canonical_json_bytes({"record": record, "signature": signature})
    path = "/v1/namespaces/local/teams/base/server"
    operation_id = str(uuid4())
    proof = issue_proof({
        "v": 1, "type": "aweb.protected-effect", "service_id": "test-service",
        "team_id": "base:local", "history_id": history_id, "generation": 1,
        "controller_did_key": env.team[1], "operation": "team.server-record.publish",
        "variant": "default", "operation_id": operation_id,
        "artifact_type": "team-server-record",
        "artifact_sha256": artifact_digest(signing, signature),
        "consumer": http_consumer(audience=audience, method="PUT", path=path, body=body),
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }, service_key)
    response = await env.client.put(
        path, content=body,
        headers={HEADER: encode_proofs([proof]), "Content-Type": "application/json"},
    )
    applied = accepted and not expire_after_write
    assert response.status_code == (200 if applied else 403), response.text
    assert wrote == accepted
    if not applied:
        assert response.json()["detail"]["code"] == "protected_controller_required"
    assert await env.db.fetch_value(
        "SELECT count(*) FROM {{tables.team_server_records}}"
    ) == int(applied)
    receipt_path = "/.well-known/aweb-protected-effect-receipts/" + operation_id
    current += timedelta(hours=2)
    receipt = await env.client.get(receipt_path, headers={HEADER: encode_proofs([proof])})
    assert receipt.status_code == (200 if applied else 404), receipt.text
    if applied:
        assert receipt.json() == {"v": 1, "operation_id": operation_id,
            "artifact_sha256": artifact_digest(signing, signature)}
        assert (await env.client.get(receipt_path, headers={HEADER: "different"})).status_code == 404
