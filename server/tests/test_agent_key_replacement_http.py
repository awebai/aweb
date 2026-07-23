from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.routes.agents import router as agents_router


TEAM_ID = "backend:acme.com"


def _keypair() -> tuple[bytes, str]:
    signing_key = SigningKey.generate()
    return bytes(signing_key), did_from_public_key(bytes(signing_key.verify_key))


def _app(aweb_db) -> FastAPI:
    app = FastAPI()
    app.include_router(agents_router)

    class _DB:
        def get_manager(self, name="aweb"):
            return aweb_db

    app.state.db = _DB()
    app.state.redis = None
    app.state.rate_limiter = None
    return app


async def _seed_local_agent(aweb_db, *, team_did_key: str, did_key: str, alias: str = "alice") -> str:
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', $2)
        """,
        TEAM_ID,
        team_did_key,
    )
    agent_id = uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_id, did_key, alias, identity_scope, status)
        VALUES ($1, $2, $3, $4, 'local', 'active')
        """,
        agent_id,
        TEAM_ID,
        did_key,
        alias,
    )
    return str(agent_id)


def _payload(*, old_did_key: str, new_did_key: str) -> dict[str, str]:
    return {
        "team_id": TEAM_ID,
        "old_did_key": old_did_key,
        "new_did_key": new_did_key,
        "old_certificate_id": "cert-old",
        "new_certificate_id": "cert-new",
    }


def _controller_headers(
    signing_key: bytes,
    controller_did_key: str,
    *,
    alias: str,
    payload: dict[str, str],
) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).isoformat()
    canonical = canonical_json_bytes(
        {
            "agent_alias": alias,
            "new_certificate_id": payload["new_certificate_id"],
            "new_did_key": payload["new_did_key"],
            "old_certificate_id": payload["old_certificate_id"],
            "old_did_key": payload["old_did_key"],
            "operation": "replace_local_identity_key",
            "team_id": payload["team_id"],
            "timestamp": timestamp,
        }
    )
    return {
        "Authorization": f"DIDKey {controller_did_key} {sign_message(signing_key, canonical)}",
        "X-AWEB-Timestamp": timestamp,
    }


@pytest.mark.asyncio
async def test_controller_replaces_local_agent_key_and_writes_audit(aweb_cloud_db):
    controller_sk, controller_did = _keypair()
    _, old_did = _keypair()
    _, new_did = _keypair()
    agent_id = await _seed_local_agent(
        aweb_cloud_db.aweb_db,
        team_did_key=controller_did,
        did_key=old_did,
    )
    payload = _payload(old_did_key=old_did, new_did_key=new_did)

    async with AsyncClient(transport=ASGITransport(app=_app(aweb_cloud_db.aweb_db)), base_url="http://test") as client:
        response = await client.post(
            "/v1/agents/alice/replace-key",
            json=payload,
            headers=_controller_headers(controller_sk, controller_did, alias="alice", payload=payload),
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body == {
        "status": "replaced",
        "audit_id": body["audit_id"],
        "agent_id": agent_id,
        "team_id": TEAM_ID,
        "alias": "alice",
        "old_did_key": old_did,
        "new_did_key": new_did,
        "old_certificate_id": "cert-old",
        "new_certificate_id": "cert-new",
        "authorized_by": controller_did,
        "authorized_at": body["authorized_at"],
    }
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT did_key FROM {{tables.agents}} WHERE agent_id = $1::uuid",
        agent_id,
    )
    assert row["did_key"] == new_did
    audit = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT alias, event_type, resource, details, created_at
        FROM {{tables.audit_log}}
        WHERE id = $1::uuid
        """,
        body["audit_id"],
    )
    assert audit["alias"] == controller_did
    assert audit["event_type"] == "local_identity_key_replaced"
    assert audit["resource"] == f"agent:{agent_id}"
    assert json.loads(audit["details"]) == {
        "agent_id": agent_id,
        "agent_alias": "alice",
        "authorized_by": controller_did,
        "old_did_key": old_did,
        "new_did_key": new_did,
        "old_certificate_id": "cert-old",
        "new_certificate_id": "cert-new",
    }
    assert body["authorized_at"] == audit["created_at"].isoformat()


@pytest.mark.asyncio
async def test_exact_controller_replay_returns_the_original_audit_result(aweb_cloud_db):
    controller_sk, controller_did = _keypair()
    _, old_did = _keypair()
    _, new_did = _keypair()
    await _seed_local_agent(aweb_cloud_db.aweb_db, team_did_key=controller_did, did_key=old_did)
    payload = _payload(old_did_key=old_did, new_did_key=new_did)

    async with AsyncClient(transport=ASGITransport(app=_app(aweb_cloud_db.aweb_db)), base_url="http://test") as client:
        first = await client.post(
            "/v1/agents/alice/replace-key",
            json=payload,
            headers=_controller_headers(controller_sk, controller_did, alias="alice", payload=payload),
        )
        replay = await client.post(
            "/v1/agents/alice/replace-key",
            json=payload,
            headers=_controller_headers(controller_sk, controller_did, alias="alice", payload=payload),
        )

    assert first.status_code == 200
    assert replay.status_code == 200
    assert replay.json() == first.json()
    assert await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.audit_log}} WHERE team_id = $1",
        TEAM_ID,
    ) == 1


@pytest.mark.asyncio
async def test_new_key_with_different_certificate_ids_is_not_treated_as_replay(aweb_cloud_db):
    controller_sk, controller_did = _keypair()
    _, old_did = _keypair()
    _, new_did = _keypair()
    await _seed_local_agent(aweb_cloud_db.aweb_db, team_did_key=controller_did, did_key=old_did)
    payload = _payload(old_did_key=old_did, new_did_key=new_did)

    async with AsyncClient(transport=ASGITransport(app=_app(aweb_cloud_db.aweb_db)), base_url="http://test") as client:
        first = await client.post(
            "/v1/agents/alice/replace-key",
            json=payload,
            headers=_controller_headers(controller_sk, controller_did, alias="alice", payload=payload),
        )
        changed = dict(payload)
        changed["new_certificate_id"] = "different-cert"
        response = await client.post(
            "/v1/agents/alice/replace-key",
            json=changed,
            headers=_controller_headers(controller_sk, controller_did, alias="alice", payload=changed),
        )

    assert first.status_code == 200
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "identity_key_changed"
    assert await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.audit_log}} WHERE team_id = $1",
        TEAM_ID,
    ) == 1


@pytest.mark.asyncio
async def test_member_key_cannot_authorize_local_key_replacement(aweb_cloud_db):
    _, controller_did = _keypair()
    old_sk, old_did = _keypair()
    _, new_did = _keypair()
    await _seed_local_agent(aweb_cloud_db.aweb_db, team_did_key=controller_did, did_key=old_did)
    payload = _payload(old_did_key=old_did, new_did_key=new_did)

    async with AsyncClient(transport=ASGITransport(app=_app(aweb_cloud_db.aweb_db)), base_url="http://test") as client:
        response = await client.post(
            "/v1/agents/alice/replace-key",
            json=payload,
            headers=_controller_headers(old_sk, old_did, alias="alice", payload=payload),
        )

    assert response.status_code == 403
    assert "team controller" in response.text.lower()
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT did_key FROM {{tables.agents}} WHERE team_id = $1 AND alias = 'alice'",
        TEAM_ID,
    )
    assert row["did_key"] == old_did
    assert await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.audit_log}} WHERE team_id = $1",
        TEAM_ID,
    ) == 0


@pytest.mark.asyncio
async def test_controller_signature_binds_the_exact_replacement(aweb_cloud_db):
    controller_sk, controller_did = _keypair()
    _, old_did = _keypair()
    _, new_did = _keypair()
    await _seed_local_agent(aweb_cloud_db.aweb_db, team_did_key=controller_did, did_key=old_did)
    signed = _payload(old_did_key=old_did, new_did_key=new_did)
    headers = _controller_headers(controller_sk, controller_did, alias="alice", payload=signed)
    tampered = dict(signed)
    tampered["new_certificate_id"] = "attacker-certificate"

    async with AsyncClient(transport=ASGITransport(app=_app(aweb_cloud_db.aweb_db)), base_url="http://test") as client:
        response = await client.post(
            "/v1/agents/alice/replace-key",
            json=tampered,
            headers=headers,
        )

    assert response.status_code == 401
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT did_key FROM {{tables.agents}} WHERE team_id = $1 AND alias = 'alice'",
        TEAM_ID,
    )
    assert row["did_key"] == old_did
    assert await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.audit_log}} WHERE team_id = $1",
        TEAM_ID,
    ) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["stale_old_key", "global_identity", "new_key_collision"])
async def test_replacement_preconditions_fail_without_audit(aweb_cloud_db, case: str):
    controller_sk, controller_did = _keypair()
    _, old_did = _keypair()
    _, new_did = _keypair()
    await _seed_local_agent(aweb_cloud_db.aweb_db, team_did_key=controller_did, did_key=old_did)
    payload = _payload(old_did_key=old_did, new_did_key=new_did)
    expected_status = 409
    if case == "stale_old_key":
        _, payload["old_did_key"] = _keypair()
    elif case == "global_identity":
        await aweb_cloud_db.aweb_db.execute(
            """
            UPDATE {{tables.agents}}
            SET identity_scope = 'global', did_aw = 'did:aw:alice'
            WHERE team_id = $1 AND alias = 'alice'
            """,
            TEAM_ID,
        )
    else:
        await aweb_cloud_db.aweb_db.execute(
            """
            INSERT INTO {{tables.agents}} (team_id, did_key, alias, identity_scope, status)
            VALUES ($1, $2, 'bob', 'local', 'active')
            """,
            TEAM_ID,
            new_did,
        )

    async with AsyncClient(transport=ASGITransport(app=_app(aweb_cloud_db.aweb_db)), base_url="http://test") as client:
        response = await client.post(
            "/v1/agents/alice/replace-key",
            json=payload,
            headers=_controller_headers(controller_sk, controller_did, alias="alice", payload=payload),
        )

    assert response.status_code == expected_status, response.text
    assert await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.audit_log}} WHERE team_id = $1",
        TEAM_ID,
    ) == 0


@pytest.mark.asyncio
async def test_replacement_rejects_same_or_invalid_did_keys(aweb_cloud_db):
    controller_sk, controller_did = _keypair()
    _, old_did = _keypair()
    await _seed_local_agent(aweb_cloud_db.aweb_db, team_did_key=controller_did, did_key=old_did)

    async with AsyncClient(transport=ASGITransport(app=_app(aweb_cloud_db.aweb_db)), base_url="http://test") as client:
        same = _payload(old_did_key=old_did, new_did_key=old_did)
        response = await client.post(
            "/v1/agents/alice/replace-key",
            json=same,
            headers=_controller_headers(controller_sk, controller_did, alias="alice", payload=same),
        )
        assert response.status_code == 422

        invalid = _payload(old_did_key=old_did, new_did_key="not-a-did")
        response = await client.post(
            "/v1/agents/alice/replace-key",
            json=invalid,
            headers=_controller_headers(controller_sk, controller_did, alias="alice", payload=invalid),
        )
        assert response.status_code == 422
