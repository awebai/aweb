"""Tests for aweb.custody — encrypted key storage and server-side signing."""

from __future__ import annotations

import os
import secrets

import pytest
import pytest_asyncio

from aweb.did import did_from_public_key, generate_keypair
from aweb.signing import canonical_payload, verify_signature, VerifyResult


# --- encrypt / decrypt ---


class TestEncryptDecryptSigningKey:
    def test_roundtrip(self):
        from aweb.custody import decrypt_signing_key, encrypt_signing_key

        master_key = secrets.token_bytes(32)
        private_key = secrets.token_bytes(32)
        encrypted = encrypt_signing_key(private_key, master_key)
        recovered = decrypt_signing_key(encrypted, master_key)
        assert recovered == private_key

    def test_encrypted_differs_from_plaintext(self):
        from aweb.custody import encrypt_signing_key

        master_key = secrets.token_bytes(32)
        private_key = secrets.token_bytes(32)
        encrypted = encrypt_signing_key(private_key, master_key)
        assert encrypted != private_key

    def test_different_master_key_fails(self):
        from aweb.custody import decrypt_signing_key, encrypt_signing_key

        master_key_1 = secrets.token_bytes(32)
        master_key_2 = secrets.token_bytes(32)
        private_key = secrets.token_bytes(32)
        encrypted = encrypt_signing_key(private_key, master_key_1)
        with pytest.raises(Exception):
            decrypt_signing_key(encrypted, master_key_2)

    def test_tampered_ciphertext_fails(self):
        from aweb.custody import decrypt_signing_key, encrypt_signing_key

        master_key = secrets.token_bytes(32)
        private_key = secrets.token_bytes(32)
        encrypted = encrypt_signing_key(private_key, master_key)
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        with pytest.raises(Exception):
            decrypt_signing_key(bytes(tampered), master_key)

    def test_unique_nonces(self):
        """Each encryption should produce different ciphertext (random nonce)."""
        from aweb.custody import encrypt_signing_key

        master_key = secrets.token_bytes(32)
        private_key = secrets.token_bytes(32)
        enc1 = encrypt_signing_key(private_key, master_key)
        enc2 = encrypt_signing_key(private_key, master_key)
        assert enc1 != enc2

    def test_rejects_wrong_length_master_key(self):
        from aweb.custody import encrypt_signing_key

        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_signing_key(secrets.token_bytes(32), secrets.token_bytes(16))


# --- get_custody_key ---


class TestGetCustodyKey:
    def test_returns_bytes_from_hex_env(self, monkeypatch):
        from aweb.custody import get_custody_key

        key_hex = secrets.token_hex(32)
        monkeypatch.setenv("AWEB_CUSTODY_KEY", key_hex)
        result = get_custody_key()
        assert result == bytes.fromhex(key_hex)

    def test_returns_none_when_not_set(self, monkeypatch):
        from aweb.custody import get_custody_key

        monkeypatch.delenv("AWEB_CUSTODY_KEY", raising=False)
        result = get_custody_key()
        assert result is None

    def test_returns_none_for_empty_string(self, monkeypatch):
        from aweb.custody import get_custody_key

        monkeypatch.setenv("AWEB_CUSTODY_KEY", "")
        result = get_custody_key()
        assert result is None

    def test_rejects_wrong_length_hex(self, monkeypatch):
        from aweb.custody import get_custody_key

        monkeypatch.setenv("AWEB_CUSTODY_KEY", "deadbeef")
        with pytest.raises(ValueError, match="32 bytes"):
            get_custody_key()


# --- sign_on_behalf (requires DB) ---


class TestSignOnBehalf:
    @pytest_asyncio.fixture
    async def seeded_custodial_agent(self, aweb_db_infra, monkeypatch):
        """Create a project with a custodial agent that has an encrypted signing key."""
        from uuid import UUID

        from aweb.custody import encrypt_signing_key

        master_key = secrets.token_bytes(32)
        monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())

        private_key, public_key = generate_keypair()
        did = did_from_public_key(public_key)
        encrypted_key = encrypt_signing_key(private_key, master_key)

        aweb_db = aweb_db_infra.get_manager("aweb")
        project = await aweb_db.fetch_one(
            """
            INSERT INTO {{tables.projects}} (slug, name)
            VALUES ($1, $2)
            RETURNING project_id
            """,
            "custody-test",
            "Custody Test",
        )
        project_id = project["project_id"]

        agent = await aweb_db.fetch_one(
            """
            INSERT INTO {{tables.agents}}
                (project_id, alias, human_name, agent_type, did, public_key, custody, signing_key_enc, lifetime)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING agent_id
            """,
            project_id,
            "custodial-agent",
            "Custodial Agent",
            "agent",
            did,
            public_key.hex(),
            "custodial",
            encrypted_key,
            "persistent",
        )
        agent_id = str(agent["agent_id"])

        return {
            "agent_id": agent_id,
            "project_id": str(project_id),
            "private_key": private_key,
            "public_key": public_key,
            "did": did,
            "master_key": master_key,
        }

    @pytest.mark.asyncio
    async def test_sign_on_behalf_produces_verifiable_signature(
        self, aweb_db_infra, seeded_custodial_agent
    ):
        from aweb.custody import sign_on_behalf

        seed = seeded_custodial_agent
        message_fields = {
            "from": "custody-test/custodial-agent",
            "from_did": seed["did"],
            "to": "other/agent",
            "to_did": "did:key:zFake",
            "type": "mail",
            "subject": "test",
            "body": "hello from custodial agent",
            "timestamp": "2026-02-21T12:00:00Z",
        }
        signature = await sign_on_behalf(seed["agent_id"], message_fields, aweb_db_infra)
        assert signature is not None

        payload = canonical_payload(message_fields)
        result = verify_signature(seed["did"], payload, signature)
        assert result == VerifyResult.VERIFIED

    @pytest.mark.asyncio
    async def test_sign_on_behalf_returns_none_when_no_custody_key(
        self, aweb_db_infra, seeded_custodial_agent, monkeypatch
    ):
        from aweb.custody import sign_on_behalf

        monkeypatch.delenv("AWEB_CUSTODY_KEY", raising=False)
        seed = seeded_custodial_agent
        message_fields = {
            "from": "custody-test/custodial-agent",
            "from_did": seed["did"],
            "to": "other/agent",
            "to_did": "did:key:zFake",
            "type": "mail",
            "subject": "test",
            "body": "test",
            "timestamp": "2026-02-21T12:00:00Z",
        }
        result = await sign_on_behalf(seed["agent_id"], message_fields, aweb_db_infra)
        assert result is None

    @pytest.mark.asyncio
    async def test_sign_on_behalf_raises_for_unknown_agent(self, aweb_db_infra, monkeypatch):
        from aweb.custody import sign_on_behalf

        monkeypatch.setenv("AWEB_CUSTODY_KEY", secrets.token_hex(32))
        import uuid

        with pytest.raises(ValueError, match="not found"):
            await sign_on_behalf(str(uuid.uuid4()), {"body": "x"}, aweb_db_infra)

    @pytest.mark.asyncio
    async def test_sign_on_behalf_raises_for_self_custodial_agent(
        self, aweb_db_infra, monkeypatch
    ):
        """Self-custodial agents have no encrypted key — signing on behalf should fail."""
        from uuid import UUID

        monkeypatch.setenv("AWEB_CUSTODY_KEY", secrets.token_hex(32))

        private_key, public_key = generate_keypair()
        did = did_from_public_key(public_key)

        aweb_db = aweb_db_infra.get_manager("aweb")
        project = await aweb_db.fetch_one(
            """
            INSERT INTO {{tables.projects}} (slug, name)
            VALUES ($1, $2)
            RETURNING project_id
            """,
            "self-custody-test",
            "Self Custody Test",
        )
        agent = await aweb_db.fetch_one(
            """
            INSERT INTO {{tables.agents}}
                (project_id, alias, human_name, agent_type, did, public_key, custody, lifetime)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING agent_id
            """,
            project["project_id"],
            "self-agent",
            "Self Agent",
            "agent",
            did,
            public_key.hex(),
            "self",
            "persistent",
        )

        from aweb.custody import sign_on_behalf

        with pytest.raises(ValueError, match="no encrypted signing key"):
            await sign_on_behalf(
                str(agent["agent_id"]),
                {"body": "x"},
                aweb_db_infra,
            )


# --- destroy_signing_key ---


class TestDestroySigningKey:
    @pytest.mark.asyncio
    async def test_destroy_removes_encrypted_key(self, aweb_db_infra, monkeypatch):
        from uuid import UUID

        from aweb.custody import destroy_signing_key, encrypt_signing_key

        master_key = secrets.token_bytes(32)
        monkeypatch.setenv("AWEB_CUSTODY_KEY", master_key.hex())

        private_key, public_key = generate_keypair()
        did = did_from_public_key(public_key)
        encrypted_key = encrypt_signing_key(private_key, master_key)

        aweb_db = aweb_db_infra.get_manager("aweb")
        project = await aweb_db.fetch_one(
            "INSERT INTO {{tables.projects}} (slug, name) VALUES ($1, $2) RETURNING project_id",
            "destroy-test",
            "Destroy Test",
        )
        agent = await aweb_db.fetch_one(
            """
            INSERT INTO {{tables.agents}}
                (project_id, alias, human_name, agent_type, did, public_key, custody, signing_key_enc, lifetime)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING agent_id
            """,
            project["project_id"],
            "destroy-agent",
            "Destroy Agent",
            "agent",
            did,
            public_key.hex(),
            "custodial",
            encrypted_key,
            "persistent",
        )
        agent_id = str(agent["agent_id"])

        await destroy_signing_key(agent_id, aweb_db_infra)

        row = await aweb_db.fetch_one(
            "SELECT signing_key_enc FROM {{tables.agents}} WHERE agent_id = $1",
            UUID(agent_id),
        )
        assert row["signing_key_enc"] is None

    @pytest.mark.asyncio
    async def test_destroy_raises_for_unknown_agent(self, aweb_db_infra):
        from aweb.custody import destroy_signing_key
        import uuid

        with pytest.raises(ValueError, match="not found"):
            await destroy_signing_key(str(uuid.uuid4()), aweb_db_infra)
