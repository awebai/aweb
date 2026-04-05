from __future__ import annotations

import uuid

import pytest

from aweb.awid import (
    AlreadyRegisteredError,
    did_from_public_key,
    encode_public_key,
    generate_keypair,
    reset_custody_key_cache,
)
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
        self.mapping_calls: list[tuple[str, bytes]] = []
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

    async def get_mapping(self, did_aw: str, signing_key: bytes):
        self.mapping_calls.append((did_aw, signing_key))

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
    assert registry_client.resolve_calls == [first.stable_id]
    assert registry_client.mapping_calls == [(first.stable_id, signing_key)]
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


@pytest.mark.asyncio
async def test_bootstrap_identity_reinit_ignores_custody_key_decrypt_failure(
    aweb_cloud_db, caplog, monkeypatch
):
    db_infra = _DbInfra(aweb_cloud_db.aweb_db, aweb_cloud_db.oss_db)
    aweb_db = aweb_cloud_db.aweb_db
    slug = f"registry-decrypt-{uuid.uuid4().hex[:8]}"
    project = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.projects}} (slug, name)
        VALUES ($1, $2)
        RETURNING project_id
        """,
        slug,
        slug,
    )
    assert project is not None
    monkeypatch.setenv("AWEB_CUSTODY_KEY", "11" * 32)
    reset_custody_key_cache()
    agent = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}}
            (project_id, alias, human_name, agent_type, did, public_key, stable_id,
             custody, signing_key_enc, lifetime, access_mode)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'custodial', $8, 'persistent', 'open')
        RETURNING agent_id
        """,
        project["project_id"],
        "durable-custodial",
        "Durable Custodial",
        "human",
        "did:key:z6Mktestexisting",
        "test-public-key",
        "did:aw:testexisting",
        b"not-a-real-encrypted-key",
    )
    assert agent is not None
    registry_client = _FakeRegistryClient()

    with caplog.at_level("ERROR"):
        result = await bootstrap_identity(
            db_infra,
            project_slug=slug,
            alias="durable-custodial",
            human_name="Durable Custodial",
            agent_type="human",
            custody="self",
            lifetime="persistent",
            mint_api_key=False,
            registry_client=registry_client,
            registry_server_url="https://aweb.example",
        )

    assert result.agent_id == str(agent["agent_id"])
    assert registry_client.register_calls == []
    assert registry_client.update_calls == []
    assert "Failed to decrypt signing key during bootstrap re-init" in caplog.text


@pytest.mark.asyncio
async def test_bootstrap_identity_rejects_alias_with_different_did(aweb_cloud_db):
    """Re-init with the same alias but a different DID must be rejected."""
    db_infra = _DbInfra(aweb_cloud_db.aweb_db, aweb_cloud_db.oss_db)
    slug = f"alias-clash-{uuid.uuid4().hex[:8]}"

    _, pub1 = generate_keypair()
    did1 = did_from_public_key(pub1)

    await bootstrap_identity(
        db_infra,
        project_slug=slug,
        alias="taken",
        did=did1,
        public_key=encode_public_key(pub1),
        custody="self",
        lifetime="ephemeral",
    )

    _, pub2 = generate_keypair()
    did2 = did_from_public_key(pub2)

    with pytest.raises(ValueError, match="already in use"):
        await bootstrap_identity(
            db_infra,
            project_slug=slug,
            alias="taken",
            did=did2,
            public_key=encode_public_key(pub2),
            custody="self",
            lifetime="ephemeral",
        )
