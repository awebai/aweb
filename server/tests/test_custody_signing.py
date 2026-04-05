"""Tests for custodial signing — sign_on_behalf must fail loud when misconfigured."""

from __future__ import annotations

import os
import uuid

import pytest

from aweb.awid.custody import CustodyError, encrypt_signing_key, reset_custody_key_cache, sign_on_behalf
from aweb.awid.did import did_from_public_key, encode_public_key, generate_keypair


class _DbInfra:
    is_initialized = True

    def __init__(self, aweb_db):
        self._aweb_db = aweb_db

    def get_manager(self, name: str = "aweb"):
        if name == "aweb":
            return self._aweb_db
        raise KeyError(name)


async def _create_project(aweb_db):
    """Insert a minimal project row and return its project_id."""
    project_id = uuid.uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.projects}} (project_id, slug, name)
        VALUES ($1, $2, $3)
        """,
        project_id,
        f"test-{project_id.hex[:8]}",
        "Test Project",
    )
    return project_id


async def _create_agent(aweb_db, project_id, *, custody="custodial", signing_key_enc=None):
    """Insert a minimal agent row and return its agent_id and seed."""
    seed, pub = generate_keypair()
    did = did_from_public_key(pub)
    public_key = encode_public_key(pub)
    agent_id = uuid.uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type, custody, did, public_key,
             signing_key_enc, lifetime)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        agent_id,
        project_id,
        f"test-{agent_id.hex[:8]}",
        "Test Agent",
        "agent",
        custody,
        did,
        public_key,
        signing_key_enc,
        "persistent",
    )
    return str(agent_id), seed


MESSAGE_FIELDS = {
    "from": "test-agent",
    "to": "other-agent",
    "to_did": "",
    "type": "chat",
    "subject": "",
    "body": "hello",
    "timestamp": "2026-04-02T00:00:00Z",
}


@pytest.fixture(autouse=True)
def _reset_custody_key():
    reset_custody_key_cache()
    yield
    reset_custody_key_cache()


@pytest.mark.asyncio
async def test_custodial_agent_raises_when_custody_key_missing(aweb_cloud_db):
    """Custodial agent + no AWEB_CUSTODY_KEY must raise, not silently return None."""
    db = _DbInfra(aweb_cloud_db.aweb_db)
    project_id = await _create_project(aweb_cloud_db.aweb_db)
    agent_id, _ = await _create_agent(aweb_cloud_db.aweb_db, project_id)

    env_backup = os.environ.pop("AWEB_CUSTODY_KEY", None)
    try:
        with pytest.raises(CustodyError, match="AWEB_CUSTODY_KEY"):
            await sign_on_behalf(agent_id, MESSAGE_FIELDS, db)
    finally:
        if env_backup is not None:
            os.environ["AWEB_CUSTODY_KEY"] = env_backup


@pytest.mark.asyncio
async def test_custodial_agent_raises_when_signing_key_missing(aweb_cloud_db):
    """Custodial agent with NULL signing_key_enc must raise, not silently return None."""
    master_key = bytes.fromhex("aa" * 32)
    db = _DbInfra(aweb_cloud_db.aweb_db)
    project_id = await _create_project(aweb_cloud_db.aweb_db)
    # Create custodial agent with no signing key (simulates creation without AWEB_CUSTODY_KEY)
    agent_id, _ = await _create_agent(
        aweb_cloud_db.aweb_db, project_id, custody="custodial", signing_key_enc=None
    )

    env_backup = os.environ.get("AWEB_CUSTODY_KEY")
    os.environ["AWEB_CUSTODY_KEY"] = master_key.hex()
    try:
        with pytest.raises(CustodyError, match="signing key"):
            await sign_on_behalf(agent_id, MESSAGE_FIELDS, db)
    finally:
        if env_backup is not None:
            os.environ["AWEB_CUSTODY_KEY"] = env_backup
        else:
            os.environ.pop("AWEB_CUSTODY_KEY", None)


@pytest.mark.asyncio
async def test_self_custodial_agent_returns_none(aweb_cloud_db):
    """Self-custodial agent should return None — server doesn't sign for them."""
    db = _DbInfra(aweb_cloud_db.aweb_db)
    project_id = await _create_project(aweb_cloud_db.aweb_db)
    agent_id, _ = await _create_agent(
        aweb_cloud_db.aweb_db, project_id, custody="self", signing_key_enc=None
    )

    env_backup = os.environ.pop("AWEB_CUSTODY_KEY", None)
    try:
        result = await sign_on_behalf(agent_id, MESSAGE_FIELDS, db)
        assert result is None
    finally:
        if env_backup is not None:
            os.environ["AWEB_CUSTODY_KEY"] = env_backup


@pytest.mark.asyncio
async def test_custodial_agent_signs_when_properly_configured(aweb_cloud_db):
    """Custodial agent with key + AWEB_CUSTODY_KEY should return signature tuple."""
    master_key = bytes.fromhex("aa" * 32)
    db = _DbInfra(aweb_cloud_db.aweb_db)
    project_id = await _create_project(aweb_cloud_db.aweb_db)
    agent_id, seed = await _create_agent(aweb_cloud_db.aweb_db, project_id)

    # Update the agent with an encrypted signing key
    encrypted = encrypt_signing_key(seed, master_key)
    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.agents}} SET signing_key_enc = $1 WHERE agent_id = $2
        """,
        encrypted,
        uuid.UUID(agent_id),
    )

    env_backup = os.environ.get("AWEB_CUSTODY_KEY")
    os.environ["AWEB_CUSTODY_KEY"] = master_key.hex()
    try:
        result = await sign_on_behalf(agent_id, MESSAGE_FIELDS, db)
        assert result is not None
        from_did, signature, signing_key_id, signed_payload = result
        assert from_did.startswith("did:key:z")
        assert signature  # non-empty
        assert signing_key_id == from_did
        assert signed_payload  # non-empty
    finally:
        if env_backup is not None:
            os.environ["AWEB_CUSTODY_KEY"] = env_backup
        else:
            os.environ.pop("AWEB_CUSTODY_KEY", None)


@pytest.mark.asyncio
async def test_custodial_agent_raises_when_did_missing(aweb_cloud_db):
    """Custodial agent with no did:key must raise instead of returning an empty signer."""
    master_key = bytes.fromhex("bb" * 32)
    db = _DbInfra(aweb_cloud_db.aweb_db)
    project_id = await _create_project(aweb_cloud_db.aweb_db)
    agent_id, seed = await _create_agent(aweb_cloud_db.aweb_db, project_id)

    encrypted = encrypt_signing_key(seed, master_key)
    await aweb_cloud_db.aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET signing_key_enc = $1,
            did = ''
        WHERE agent_id = $2
        """,
        encrypted,
        uuid.UUID(agent_id),
    )

    env_backup = os.environ.get("AWEB_CUSTODY_KEY")
    os.environ["AWEB_CUSTODY_KEY"] = master_key.hex()
    try:
        with pytest.raises(CustodyError, match="did:key"):
            await sign_on_behalf(agent_id, MESSAGE_FIELDS, db)
    finally:
        if env_backup is not None:
            os.environ["AWEB_CUSTODY_KEY"] = env_backup
        else:
            os.environ.pop("AWEB_CUSTODY_KEY", None)
