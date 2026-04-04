from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from aweb.address_scope import format_local_address
from aweb.awid import (
    RegistryError,
    canonical_payload,
    did_from_public_key,
    encode_public_key,
    generate_keypair,
    sign_message,
)
from aweb.db import get_db_infra
from aweb.deps import get_redis
from aweb.routes.chat import router as chat_router
from aweb.routes.init import bootstrap_router, router as init_router
from aweb.routes.messages import router as messages_router


class _FakeRedis:
    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._ttl: dict[str, int] = {}

    async def eval(self, _script: str, _num_keys: int, key: str, window_seconds: int) -> int:
        current = self._counts.get(key, 0) + 1
        self._counts[key] = current
        self._ttl[key] = int(window_seconds)
        return current

    async def ttl(self, key: str) -> int:
        return self._ttl.get(key, -1)

    async def delete(self, key: str) -> int:
        self._counts.pop(key, None)
        self._ttl.pop(key, None)
        return 1

    async def publish(self, _channel: str, _message: str) -> int:
        return 0

    async def ping(self) -> bool:
        return True


class _DbInfra:
    is_initialized = True

    def __init__(self, *, aweb_db, server_db) -> None:
        self.aweb_db = aweb_db
        self.server_db = server_db

    def get_manager(self, name: str = "aweb"):
        if name == "aweb":
            return self.aweb_db
        if name == "server":
            return self.server_db
        raise KeyError(name)


class _FakeRegistryClient:
    def __init__(
        self,
        *,
        did_keys_by_stable_id: dict[str, str] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.did_keys_by_stable_id = did_keys_by_stable_id or {}
        self.error = error
        self.calls: list[str] = []

    async def resolve_key(self, did_aw: str):
        self.calls.append(did_aw)
        if self.error is not None:
            raise self.error
        did_key = self.did_keys_by_stable_id[did_aw]
        return SimpleNamespace(current_did_key=did_key)


def _auth_headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _mail_payload_fields(
    *,
    sender_alias: str,
    sender_project_slug: str,
    recipient_project_slug: str,
    recipient_alias: str,
    message_id: str,
    timestamp: str,
    body: str,
    from_stable_id: str | None,
) -> dict[str, str]:
    fields: dict[str, str] = {
        "from": format_local_address(
            base_project_slug=recipient_project_slug,
            target_project_slug=sender_project_slug,
            alias=sender_alias,
        ),
        "from_did": "",
        "message_id": message_id,
        "to": recipient_alias,
        "to_did": "",
        "type": "mail",
        "subject": "",
        "body": body,
        "timestamp": timestamp,
    }
    if from_stable_id:
        fields["from_stable_id"] = from_stable_id
    return fields


def _chat_payload_fields(
    *,
    sender_alias: str,
    message_id: str,
    timestamp: str,
    body: str,
    from_stable_id: str | None,
) -> dict[str, str]:
    fields: dict[str, str] = {
        "from": sender_alias,
        "from_did": "",
        "message_id": message_id,
        "to": "bob",
        "to_did": "",
        "type": "chat",
        "subject": "",
        "body": body,
        "timestamp": timestamp,
    }
    if from_stable_id:
        fields["from_stable_id"] = from_stable_id
    return fields


def _sign_fields(signing_key: bytes, did_key: str, fields: dict[str, str]) -> tuple[str, str]:
    payload_bytes = canonical_payload(fields | {"from_did": did_key})
    return sign_message(signing_key, payload_bytes), payload_bytes.decode("utf-8")


def _build_test_app(*, aweb_db, server_db, registry_client) -> FastAPI:
    app = FastAPI(title="aweb signed verification test")
    app.include_router(bootstrap_router)
    app.include_router(init_router)
    app.include_router(messages_router)
    app.include_router(chat_router)
    app.state.db = _DbInfra(aweb_db=aweb_db, server_db=server_db)
    app.state.redis = _FakeRedis()
    app.state.awid_registry_client = registry_client
    app.dependency_overrides[get_db_infra] = lambda: app.state.db
    app.dependency_overrides[get_redis] = lambda: app.state.redis
    return app


async def _bootstrap_agents(*, app: FastAPI, project_slug: str, did_key: str, public_key: str):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bootstrap = await client.post(
            "/api/v1/create-project",
            json={
                "project_slug": project_slug,
                "namespace_slug": project_slug,
                "name": "alice",
                "lifetime": "persistent",
                "custody": "self",
                "did": did_key,
                "public_key": public_key,
            },
        )
        assert bootstrap.status_code == 200, bootstrap.text
        alice = bootstrap.json()

        second = await client.post(
            "/v1/workspaces/init",
            headers=_auth_headers(alice["api_key"]),
            json={"alias": "bob"},
        )
        assert second.status_code == 200, second.text
        bob = second.json()

    return alice, bob


@pytest.mark.asyncio
async def test_send_message_verifies_signature_against_registry_key(aweb_cloud_db, monkeypatch):
    monkeypatch.setenv("AWEB_MANAGED_DOMAIN", "example.test")
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    project_slug = f"signed-mail-{uuid.uuid4().hex[:8]}"
    registry_client = _FakeRegistryClient()
    app = _build_test_app(
        aweb_db=aweb_cloud_db.aweb_db,
        server_db=aweb_cloud_db.oss_db,
        registry_client=registry_client,
    )
    alice, bob = await _bootstrap_agents(
        app=app,
        project_slug=project_slug,
        did_key=did_key,
        public_key=encode_public_key(public_key),
    )
    registry_client.did_keys_by_stable_id[alice["stable_id"]] = did_key

    message_id = str(uuid.uuid4())
    timestamp = "2026-04-04T12:00:00Z"
    fields = _mail_payload_fields(
        sender_alias="alice",
        sender_project_slug=project_slug,
        recipient_project_slug=project_slug,
        recipient_alias="bob",
        message_id=message_id,
        timestamp=timestamp,
        body="signed hello",
        from_stable_id=alice["stable_id"],
    )
    signature, canonical_text = _sign_fields(signing_key, did_key, fields)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/messages",
            headers=_auth_headers(alice["api_key"]),
            json={
                "to_alias": "bob",
                "body": "signed hello",
                "message_id": message_id,
                "timestamp": timestamp,
                "from_did": did_key,
                "from_stable_id": alice["stable_id"],
                "signature": signature,
                "signing_key_id": "wrong-key-id",
                "signed_payload": "tampered",
            },
        )

    assert response.status_code == 200, response.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT signature, signing_key_id, signed_payload
        FROM {{tables.messages}}
        WHERE message_id = $1
        """,
        uuid.UUID(message_id),
    )
    assert row is not None
    assert row["signature"] == signature
    assert row["signing_key_id"] == did_key
    assert json.loads(row["signed_payload"]) == json.loads(canonical_text)
    assert registry_client.calls == [alice["stable_id"]]


@pytest.mark.asyncio
async def test_send_message_rejects_stale_cached_agent_key_when_registry_has_rotated(
    aweb_cloud_db, monkeypatch
):
    monkeypatch.setenv("AWEB_MANAGED_DOMAIN", "example.test")
    old_signing_key, old_public_key = generate_keypair()
    old_did_key = did_from_public_key(old_public_key)
    new_signing_key, new_public_key = generate_keypair()
    new_did_key = did_from_public_key(new_public_key)
    project_slug = f"stale-mail-{uuid.uuid4().hex[:8]}"
    registry_client = _FakeRegistryClient()
    app = _build_test_app(
        aweb_db=aweb_cloud_db.aweb_db,
        server_db=aweb_cloud_db.oss_db,
        registry_client=registry_client,
    )
    alice, _bob = await _bootstrap_agents(
        app=app,
        project_slug=project_slug,
        did_key=old_did_key,
        public_key=encode_public_key(old_public_key),
    )
    registry_client.did_keys_by_stable_id[alice["stable_id"]] = new_did_key

    message_id = str(uuid.uuid4())
    timestamp = "2026-04-04T12:00:00Z"
    fields = _mail_payload_fields(
        sender_alias="alice",
        sender_project_slug=project_slug,
        recipient_project_slug=project_slug,
        recipient_alias="bob",
        message_id=message_id,
        timestamp=timestamp,
        body="stale hello",
        from_stable_id=alice["stable_id"],
    )
    signature, _ = _sign_fields(old_signing_key, old_did_key, fields)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/messages",
            headers=_auth_headers(alice["api_key"]),
            json={
                "to_alias": "bob",
                "body": "stale hello",
                "message_id": message_id,
                "timestamp": timestamp,
                "from_did": old_did_key,
                "from_stable_id": alice["stable_id"],
                "signature": signature,
            },
        )

    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "from_did does not match current sender did:key"
    assert registry_client.calls == [alice["stable_id"]]
    assert new_signing_key != old_signing_key


@pytest.mark.asyncio
async def test_send_message_falls_back_to_cached_agent_key_when_registry_is_unavailable(
    aweb_cloud_db,
    monkeypatch,
):
    monkeypatch.setenv("AWEB_MANAGED_DOMAIN", "example.test")
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    project_slug = f"fallback-mail-{uuid.uuid4().hex[:8]}"
    registry_client = _FakeRegistryClient(
        error=RegistryError("registry unavailable", status_code=503, detail="registry unavailable")
    )
    app = _build_test_app(
        aweb_db=aweb_cloud_db.aweb_db,
        server_db=aweb_cloud_db.oss_db,
        registry_client=registry_client,
    )
    alice, _bob = await _bootstrap_agents(
        app=app,
        project_slug=project_slug,
        did_key=did_key,
        public_key=encode_public_key(public_key),
    )

    message_id = str(uuid.uuid4())
    timestamp = "2026-04-04T12:00:00Z"
    fields = _mail_payload_fields(
        sender_alias="alice",
        sender_project_slug=project_slug,
        recipient_project_slug=project_slug,
        recipient_alias="bob",
        message_id=message_id,
        timestamp=timestamp,
        body="fallback hello",
        from_stable_id=alice["stable_id"],
    )
    signature, _ = _sign_fields(signing_key, did_key, fields)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/messages",
            headers=_auth_headers(alice["api_key"]),
            json={
                "to_alias": "bob",
                "body": "fallback hello",
                "message_id": message_id,
                "timestamp": timestamp,
                "from_did": did_key,
                "from_stable_id": alice["stable_id"],
                "signature": signature,
            },
        )

    assert response.status_code == 200, response.text
    assert registry_client.calls == [alice["stable_id"]]


@pytest.mark.asyncio
async def test_create_chat_session_verifies_signature_against_registry_key(
    aweb_cloud_db, monkeypatch
):
    monkeypatch.setenv("AWEB_MANAGED_DOMAIN", "example.test")
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    project_slug = f"signed-chat-{uuid.uuid4().hex[:8]}"
    registry_client = _FakeRegistryClient()
    app = _build_test_app(
        aweb_db=aweb_cloud_db.aweb_db,
        server_db=aweb_cloud_db.oss_db,
        registry_client=registry_client,
    )
    alice, bob = await _bootstrap_agents(
        app=app,
        project_slug=project_slug,
        did_key=did_key,
        public_key=encode_public_key(public_key),
    )
    registry_client.did_keys_by_stable_id[alice["stable_id"]] = did_key

    message_id = str(uuid.uuid4())
    timestamp = "2026-04-04T12:00:00Z"
    fields = _chat_payload_fields(
        sender_alias="alice",
        message_id=message_id,
        timestamp=timestamp,
        body="signed chat hello",
        from_stable_id=alice["stable_id"],
    )
    signature, canonical_text = _sign_fields(signing_key, did_key, fields)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/v1/chat/sessions",
            headers=_auth_headers(alice["api_key"]),
            json={
                "to_aliases": ["bob"],
                "message": "signed chat hello",
                "message_id": message_id,
                "timestamp": timestamp,
                "from_did": did_key,
                "from_stable_id": alice["stable_id"],
                "signature": signature,
                "signed_payload": "tampered",
            },
        )

    assert response.status_code == 200, response.text
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT signature, signing_key_id, signed_payload
        FROM {{tables.chat_messages}}
        WHERE message_id = $1
        """,
        uuid.UUID(message_id),
    )
    assert row is not None
    assert row["signature"] == signature
    assert row["signing_key_id"] == did_key
    assert json.loads(row["signed_payload"]) == json.loads(canonical_text)
    assert registry_client.calls == [alice["stable_id"]]
    assert bob["agent_id"]


@pytest.mark.asyncio
async def test_send_chat_message_uses_registry_backed_verifier(aweb_cloud_db, monkeypatch):
    monkeypatch.setenv("AWEB_MANAGED_DOMAIN", "example.test")
    old_signing_key, old_public_key = generate_keypair()
    old_did_key = did_from_public_key(old_public_key)
    new_signing_key, new_public_key = generate_keypair()
    new_did_key = did_from_public_key(new_public_key)
    project_slug = f"signed-chat-session-{uuid.uuid4().hex[:8]}"
    registry_client = _FakeRegistryClient()
    app = _build_test_app(
        aweb_db=aweb_cloud_db.aweb_db,
        server_db=aweb_cloud_db.oss_db,
        registry_client=registry_client,
    )
    alice, _bob = await _bootstrap_agents(
        app=app,
        project_slug=project_slug,
        did_key=old_did_key,
        public_key=encode_public_key(old_public_key),
    )
    registry_client.did_keys_by_stable_id[alice["stable_id"]] = old_did_key

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        create_session = await client.post(
            "/v1/chat/sessions",
            headers=_auth_headers(alice["api_key"]),
            json={"to_aliases": ["bob"], "message": "bootstrap session"},
        )
        assert create_session.status_code == 200, create_session.text
        session_id = create_session.json()["session_id"]

        registry_client.did_keys_by_stable_id[alice["stable_id"]] = new_did_key
        message_id = str(uuid.uuid4())
        timestamp = "2026-04-04T12:00:00Z"
        fields = _chat_payload_fields(
            sender_alias="alice",
            message_id=message_id,
            timestamp=timestamp,
            body="session signed hello",
            from_stable_id=alice["stable_id"],
        )
        signature, _ = _sign_fields(old_signing_key, old_did_key, fields)
        response = await client.post(
            f"/v1/chat/sessions/{session_id}/messages",
            headers=_auth_headers(alice["api_key"]),
            json={
                "body": "session signed hello",
                "message_id": message_id,
                "timestamp": timestamp,
                "from_did": old_did_key,
                "from_stable_id": alice["stable_id"],
                "signature": signature,
            },
        )

    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "from_did does not match current sender did:key"
    assert registry_client.calls == [alice["stable_id"]]
    assert new_signing_key != old_signing_key
