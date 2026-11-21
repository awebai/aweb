from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message


from test_dashboard_privacy import TEAM as TEAM_ID
from test_agents_suggest_alias_http import privacy_app as privacy_app, _global_actor

__all__ = ["privacy_app"]


def _keypair() -> tuple[bytes, str]:
    signing_key = SigningKey.generate()
    return bytes(signing_key), did_from_public_key(bytes(signing_key.verify_key))


def _payload(*, old_did_key: str, new_did_key: str) -> dict[str, str]:
    return {
        "team_id": TEAM_ID,
        "old_did_key": old_did_key,
        "new_did_key": new_did_key,
        "old_certificate_id": "privacy-alice",
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
async def test_controller_replaces_local_agent_key_and_writes_audit(privacy_app):
    controller_sk, controller_did = privacy_app.team_sk, privacy_app.team_did
    old_did = privacy_app.actors["alice"].did
    _, new_did = _keypair()
    agent_id = str(privacy_app.actors["alice"].id)
    payload = _payload(old_did_key=old_did, new_did_key=new_did)

    client = privacy_app.client
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
        "old_certificate_id": "privacy-alice",
        "new_certificate_id": "cert-new",
        "authorized_by": controller_did,
        "authorized_at": body["authorized_at"],
    }
    row = await privacy_app.db.fetch_one(
        "SELECT did_key FROM {{tables.agents}} WHERE agent_id = $1::uuid",
        agent_id,
    )
    assert row["did_key"] == new_did
    audit = await privacy_app.db.fetch_one(
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
        "old_certificate_id": "privacy-alice",
        "new_certificate_id": "cert-new",
    }
    assert body["authorized_at"] == audit["created_at"].isoformat()


@pytest.mark.asyncio
async def test_exact_controller_replay_returns_the_original_audit_result(privacy_app):
    controller_sk, controller_did = privacy_app.team_sk, privacy_app.team_did
    old_did = privacy_app.actors["alice"].did
    _, new_did = _keypair()
    payload = _payload(old_did_key=old_did, new_did_key=new_did)

    client = privacy_app.client
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
    assert (
        await privacy_app.db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.audit_log}} WHERE team_id = $1",
            TEAM_ID,
        )
        == 1
    )


@pytest.mark.asyncio
async def test_new_key_with_different_certificate_ids_is_not_treated_as_replay(privacy_app):
    controller_sk, controller_did = privacy_app.team_sk, privacy_app.team_did
    old_did = privacy_app.actors["alice"].did
    _, new_did = _keypair()
    payload = _payload(old_did_key=old_did, new_did_key=new_did)

    client = privacy_app.client
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
    assert (
        await privacy_app.db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.audit_log}} WHERE team_id = $1",
            TEAM_ID,
        )
        == 1
    )


@pytest.mark.asyncio
async def test_member_key_cannot_authorize_local_key_replacement(privacy_app):
    old_sk, old_did = privacy_app.actors["alice"].sk, privacy_app.actors["alice"].did
    _, new_did = _keypair()
    payload = _payload(old_did_key=old_did, new_did_key=new_did)

    client = privacy_app.client
    response = await client.post(
        "/v1/agents/alice/replace-key",
        json=payload,
        headers=_controller_headers(old_sk, old_did, alias="alice", payload=payload),
    )

    assert response.status_code == 403
    assert "team controller" in response.text.lower()
    row = await privacy_app.db.fetch_one(
        "SELECT did_key FROM {{tables.agents}} WHERE team_id = $1 AND alias = 'alice'",
        TEAM_ID,
    )
    assert row["did_key"] == old_did
    assert (
        await privacy_app.db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.audit_log}} WHERE team_id = $1",
            TEAM_ID,
        )
        == 0
    )


@pytest.mark.asyncio
async def test_controller_signature_binds_the_exact_replacement(privacy_app):
    controller_sk, controller_did = privacy_app.team_sk, privacy_app.team_did
    old_did = privacy_app.actors["alice"].did
    _, new_did = _keypair()
    signed = _payload(old_did_key=old_did, new_did_key=new_did)
    headers = _controller_headers(controller_sk, controller_did, alias="alice", payload=signed)
    tampered = dict(signed)
    tampered["new_certificate_id"] = "attacker-certificate"

    client = privacy_app.client
    response = await client.post(
        "/v1/agents/alice/replace-key",
        json=tampered,
        headers=headers,
    )

    assert response.status_code == 401
    row = await privacy_app.db.fetch_one(
        "SELECT did_key FROM {{tables.agents}} WHERE team_id = $1 AND alias = 'alice'",
        TEAM_ID,
    )
    assert row["did_key"] == old_did
    assert (
        await privacy_app.db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.audit_log}} WHERE team_id = $1",
            TEAM_ID,
        )
        == 0
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["stale_old_key", "global_identity", "new_key_collision"])
async def test_replacement_preconditions_fail_without_audit(privacy_app, case: str):
    controller_sk, controller_did = privacy_app.team_sk, privacy_app.team_did
    old_did = privacy_app.actors["alice"].did
    _, new_did = _keypair()
    payload = _payload(old_did_key=old_did, new_did_key=new_did)
    expected_status = 409
    if case == "stale_old_key":
        _, payload["old_did_key"] = _keypair()
    elif case == "global_identity":
        await _global_actor(privacy_app)
    else:
        payload["new_did_key"] = privacy_app.actors["bob"].did

    client = privacy_app.client
    response = await client.post(
        "/v1/agents/alice/replace-key",
        json=payload,
        headers=_controller_headers(controller_sk, controller_did, alias="alice", payload=payload),
    )

    assert response.status_code == expected_status, response.text
    assert (
        await privacy_app.db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.audit_log}} WHERE team_id = $1",
            TEAM_ID,
        )
        == 0
    )


@pytest.mark.asyncio
async def test_replacement_rejects_same_or_invalid_did_keys(privacy_app):
    controller_sk, controller_did = privacy_app.team_sk, privacy_app.team_did
    old_did = privacy_app.actors["alice"].did

    client = privacy_app.client
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
