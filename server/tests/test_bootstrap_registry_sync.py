from __future__ import annotations

import uuid

import pytest

from aweb.awid import AlreadyRegisteredError, did_from_public_key, encode_public_key, generate_keypair
from aweb.bootstrap import bootstrap_identity


class _DbInfra:
    is_initialized = True

    def __init__(self, aweb_db, server_db):
        self._aweb_db = aweb_db
        self._server_db = server_db

    def get_manager(self, name: str = "aweb"):
        if name == "aweb":
            return self._aweb_db
        if name == "server":
            return self._server_db
        raise KeyError(name)


class _FakeRegistryClient:
    def __init__(self) -> None:
        self.register_calls: list[tuple[str, bytes, str]] = []
        self.update_calls: list[tuple[str, str, bytes]] = []
        self.resolve_calls: list[str] = []
        self.full_calls: list[tuple[str, bytes]] = []
        self.current_did_key_by_did_aw: dict[str, str] = {}
        self.server_by_did_aw: dict[str, str] = {}

    async def register_did(self, did_key: str, signing_key: bytes, server_url: str):
        self.register_calls.append((did_key, signing_key, server_url))
        return None

    async def update_server(self, did_aw: str, server_url: str, signing_key: bytes):
        self.update_calls.append((did_aw, server_url, signing_key))
        return None

    async def resolve_key(self, did_aw: str):
        self.resolve_calls.append(did_aw)

        class _Resolution:
            def __init__(self, current_did_key: str) -> None:
                self.current_did_key = current_did_key

        return _Resolution(self.current_did_key_by_did_aw[did_aw])

    async def _get_did_full(self, did_aw: str, signing_key: bytes):
        self.full_calls.append((did_aw, signing_key))

        class _Mapping:
            def __init__(self, server: str) -> None:
                self.server = server

        return _Mapping(self.server_by_did_aw[did_aw])


class _AlreadyRegisteredRegistryClient(_FakeRegistryClient):
    def __init__(self, *, did_aw: str, did_key: str) -> None:
        super().__init__()
        self._did_aw = did_aw
        self._did_key = did_key
        self.current_did_key_by_did_aw[did_aw] = did_key
        self.server_by_did_aw[did_aw] = "https://old.example"

    async def register_did(self, did_key: str, signing_key: bytes, server_url: str):
        self.register_calls.append((did_key, signing_key, server_url))
        raise AlreadyRegisteredError(did_aw=self._did_aw, existing_did_key=self._did_key)


@pytest.mark.asyncio
async def test_bootstrap_identity_syncs_persistent_did_when_signing_key_available(aweb_cloud_db):
    db_infra = _DbInfra(aweb_cloud_db.aweb_db, aweb_cloud_db.oss_db)
    slug = f"registry-sync-{uuid.uuid4().hex[:8]}"
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    registry_client = _FakeRegistryClient()

    result = await bootstrap_identity(
        db_infra,
        project_slug=slug,
        alias="durable-test",
        human_name="Durable Test",
        agent_type="human",
        did=did_key,
        public_key=encode_public_key(public_key),
        custody="self",
        lifetime="persistent",
        mint_api_key=False,
        registry_client=registry_client,
        registry_server_url="https://aweb.example",
        registry_signing_key=signing_key,
    )

    assert result.stable_id is not None
    assert registry_client.register_calls == [(did_key, signing_key, "https://aweb.example")]
    assert registry_client.update_calls == []


@pytest.mark.asyncio
async def test_bootstrap_identity_updates_registry_server_after_idempotent_retry(aweb_cloud_db):
    db_infra = _DbInfra(aweb_cloud_db.aweb_db, aweb_cloud_db.oss_db)
    slug = f"registry-idem-{uuid.uuid4().hex[:8]}"
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)

    first = await bootstrap_identity(
        db_infra,
        project_slug=slug,
        alias="durable-idem",
        human_name="Durable Test",
        agent_type="human",
        did=did_key,
        public_key=encode_public_key(public_key),
        custody="self",
        lifetime="persistent",
        mint_api_key=False,
    )

    assert first.stable_id is not None
    registry_client = _AlreadyRegisteredRegistryClient(did_aw=first.stable_id, did_key=did_key)

    second = await bootstrap_identity(
        db_infra,
        project_slug=slug,
        alias="durable-idem",
        human_name="Durable Test",
        agent_type="human",
        did=did_key,
        public_key=encode_public_key(public_key),
        custody="self",
        lifetime="persistent",
        mint_api_key=False,
        registry_client=registry_client,
        registry_server_url="https://new.example",
        registry_signing_key=signing_key,
    )

    assert second.agent_id == first.agent_id
    assert registry_client.register_calls == [(did_key, signing_key, "https://new.example")]
    assert registry_client.update_calls == [(first.stable_id, "https://new.example", signing_key)]


@pytest.mark.asyncio
async def test_bootstrap_identity_skips_registry_sync_for_self_custodial_without_signing_key(
    aweb_cloud_db, caplog
):
    db_infra = _DbInfra(aweb_cloud_db.aweb_db, aweb_cloud_db.oss_db)
    slug = f"registry-skip-{uuid.uuid4().hex[:8]}"
    signing_key, public_key = generate_keypair()
    did_key = did_from_public_key(public_key)
    registry_client = _FakeRegistryClient()

    with caplog.at_level("INFO"):
        result = await bootstrap_identity(
            db_infra,
            project_slug=slug,
            alias="durable-skip",
            human_name="Durable Skip",
            agent_type="human",
            did=did_key,
            public_key=encode_public_key(public_key),
            custody="self",
            lifetime="persistent",
            mint_api_key=False,
            registry_client=registry_client,
            registry_server_url="https://aweb.example",
        )

    assert result.stable_id is not None
    assert registry_client.register_calls == []
    assert registry_client.update_calls == []
    assert "Skipping registry sync for self-custodial permanent identity" in caplog.text
