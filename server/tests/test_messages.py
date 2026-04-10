"""Tests for identity-scoped messaging delivery and policy checks."""

from __future__ import annotations

import pytest

from nacl.signing import SigningKey

from awid.did import did_from_public_key
from aweb.messaging.messages import (
    deliver_message,
    get_agent_by_alias,
    get_agent_by_id,
    resolve_agent_by_did,
)
from aweb.service_errors import ForbiddenError, NotFoundError


def _make_did_key():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    return did_from_public_key(pk)


class _DbShim:
    def __init__(self, aweb_db):
        self._db = aweb_db

    def get_manager(self, name="aweb"):
        return self._db


class _RegistryStub:
    def __init__(self, team_members: dict[tuple[str, str], list[dict[str, str]]]):
        self.team_members = team_members

    async def list_team_certificates(self, domain: str, name: str, *, active_only: bool = True):
        del active_only
        return [
            type(
                "TeamCertificate",
                (),
                {
                    "certificate_id": item.get("certificate_id", "cert-1"),
                    "member_did_key": item.get("member_did_key", ""),
                    "member_did_aw": item.get("member_did_aw"),
                    "member_address": item.get("member_address"),
                    "alias": item.get("alias", ""),
                    "lifetime": item.get("lifetime", "persistent"),
                    "issued_at": item.get("issued_at", "2026-01-01T00:00:00Z"),
                },
            )()
            for item in self.team_members.get((domain, name), [])
        ]


async def _insert_team(aweb_db, team_id: str):
    name, domain = team_id.split(":", 1)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, 'did:key:z6Mkteam')
        ON CONFLICT DO NOTHING
        """,
        team_id,
        domain,
        name,
    )


async def _insert_agent(
    aweb_db,
    *,
    team_id: str,
    alias: str,
    did_key: str,
    did_aw: str,
    address: str,
    messaging_policy: str = "everyone",
):
    row = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.agents}} (
            team_id, did_key, did_aw, address, alias, lifetime, role, messaging_policy
        )
        VALUES ($1, $2, $3, $4, $5, 'persistent', 'developer', $6)
        RETURNING agent_id
        """,
        team_id,
        did_key,
        did_aw,
        address,
        alias,
        messaging_policy,
    )
    return str(row["agent_id"])


@pytest.mark.asyncio
async def test_deliver_message_cross_identity_to_contact(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")

    alice_did_key = _make_did_key()
    bob_did_key = _make_did_key()
    alice_did_aw = "did:aw:alice"
    bob_did_aw = "did:aw:bob"

    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=alice_did_key,
        did_aw=alice_did_aw,
        address="acme.com/alice",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=bob_did_key,
        did_aw=bob_did_aw,
        address="otherco.com/bob",
        messaging_policy="contacts",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.contacts}} (owner_did, contact_address, label)
        VALUES ($1, $2, 'Alice')
        """,
        bob_did_aw,
        "acme.com/alice",
    )

    msg_id, created_at = await deliver_message(
        db_shim,
        from_did=alice_did_aw,
        to_did=bob_did_aw,
        from_alias="alice",
        to_alias="bob",
        sender_address="acme.com/alice",
        subject="Hello",
        body="Hi Bob!",
        priority="normal",
    )

    assert msg_id is not None
    assert created_at is not None
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT * FROM {{tables.messages}} WHERE message_id = $1",
        msg_id,
    )
    assert row["from_did"] == alice_did_aw
    assert row["to_did"] == bob_did_aw
    assert row["from_alias"] == "alice"
    assert row["to_alias"] == "bob"


@pytest.mark.asyncio
async def test_deliver_message_rejects_non_contact_sender(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")

    alice_did_aw = "did:aw:alice"
    bob_did_aw = "did:aw:bob"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=_make_did_key(),
        did_aw=alice_did_aw,
        address="acme.com/alice",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="otherco.com/bob",
        messaging_policy="contacts",
    )

    with pytest.raises(ForbiddenError, match="contacts"):
        await deliver_message(
            db_shim,
            from_did=alice_did_aw,
            to_did=bob_did_aw,
            from_alias="alice",
            to_alias="bob",
            sender_address="acme.com/alice",
            subject="Hello",
            body="Hi Bob!",
            priority="normal",
        )


@pytest.mark.asyncio
async def test_deliver_message_team_policy_requires_shared_team(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")

    alice_did_aw = "did:aw:alice"
    bob_did_aw = "did:aw:bob"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=_make_did_key(),
        did_aw=alice_did_aw,
        address="acme.com/alice",
    )
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="otherco.com/bob",
        messaging_policy="team",
    )

    registry = _RegistryStub({})

    with pytest.raises(ForbiddenError, match="shared-team"):
        await deliver_message(
            db_shim,
            registry_client=registry,
            from_did=alice_did_aw,
            to_did=bob_did_aw,
            from_alias="alice",
            to_alias="bob",
            sender_address="acme.com/alice",
            subject="Hello",
            body="Hi Bob!",
            priority="normal",
        )


@pytest.mark.asyncio
async def test_deliver_message_team_policy_allows_active_shared_team_cert(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")

    alice_did_key = _make_did_key()
    alice_did_aw = "did:aw:alice"
    bob_did_aw = "did:aw:bob"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="acme.com/bob",
        messaging_policy="team",
    )
    registry = _RegistryStub(
        {
            ("acme.com", "backend"): [
                {
                    "member_did_aw": alice_did_aw,
                    "member_did_key": alice_did_key,
                    "alias": "alice",
                }
            ]
        }
    )

    msg_id, _ = await deliver_message(
        db_shim,
        registry_client=registry,
        from_did=alice_did_aw,
        to_did=bob_did_aw,
        from_alias="alice",
        to_alias="bob",
        sender_address="acme.com/alice",
        subject="Hello",
        body="Hi Bob!",
        priority="normal",
    )
    assert msg_id is not None


@pytest.mark.asyncio
async def test_deliver_message_org_policy_allows_same_namespace_active_cert(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "ops:acme.com")

    alice_did_key = _make_did_key()
    alice_did_aw = "did:aw:alice"
    bob_did_aw = "did:aw:bob"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:acme.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="acme.com/bob",
        messaging_policy="org",
    )
    registry = _RegistryStub(
        {
            ("acme.com", "backend"): [
                {
                    "member_did_aw": alice_did_aw,
                    "member_did_key": alice_did_key,
                    "alias": "alice",
                }
            ]
        }
    )

    msg_id, _ = await deliver_message(
        db_shim,
        registry_client=registry,
        from_did=alice_did_aw,
        to_did=bob_did_aw,
        from_alias="alice",
        to_alias="bob",
        sender_address="acme.com/alice",
        subject="Hello",
        body="Hi Bob!",
        priority="normal",
    )
    assert msg_id is not None


@pytest.mark.asyncio
async def test_deliver_message_org_policy_blocks_other_namespace(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "ops:acme.com")
    await _insert_team(aweb_cloud_db.aweb_db, "backend:otherco.com")

    alice_did_aw = "did:aw:alice"
    bob_did_aw = "did:aw:bob"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:acme.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="acme.com/bob",
        messaging_policy="org",
    )
    registry = _RegistryStub(
        {
            ("otherco.com", "backend"): [
                {
                    "member_did_aw": alice_did_aw,
                    "member_did_key": _make_did_key(),
                    "alias": "alice",
                }
            ]
        }
    )

    with pytest.raises(ForbiddenError, match="same org"):
        await deliver_message(
            db_shim,
            registry_client=registry,
            from_did=alice_did_aw,
            to_did=bob_did_aw,
            from_alias="alice",
            to_alias="bob",
            sender_address="otherco.com/alice",
            subject="Hello",
            body="Hi Bob!",
            priority="normal",
        )


@pytest.mark.asyncio
async def test_deliver_message_everyone_allows_unconnected_sender(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")
    bob_did_aw = "did:aw:bob"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="otherco.com/bob",
        messaging_policy="everyone",
    )

    msg_id, _ = await deliver_message(
        db_shim,
        from_did="did:aw:alice",
        to_did=bob_did_aw,
        from_alias="acme.com/alice",
        to_alias="bob",
        sender_address="acme.com/alice",
        subject="Hello",
        body="Hi Bob!",
        priority="normal",
    )
    row = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT from_agent_id, to_agent_id FROM {{tables.messages}} WHERE message_id = $1",
        msg_id,
    )
    assert row["from_agent_id"] is None
    assert row["to_agent_id"] is not None


@pytest.mark.asyncio
async def test_deliver_message_nobody_blocks_all_delivery(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "ops:otherco.com")
    bob_did_aw = "did:aw:bob"
    await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="ops:otherco.com",
        alias="bob",
        did_key=_make_did_key(),
        did_aw=bob_did_aw,
        address="otherco.com/bob",
        messaging_policy="nobody",
    )

    with pytest.raises(ForbiddenError, match="does not accept"):
        await deliver_message(
            db_shim,
            from_did="did:aw:alice",
            to_did=bob_did_aw,
            from_alias="acme.com/alice",
            to_alias="bob",
            sender_address="acme.com/alice",
            subject="Hello",
            body="Hi Bob!",
            priority="normal",
        )


@pytest.mark.asyncio
async def test_resolve_agent_helpers(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    await _insert_team(aweb_cloud_db.aweb_db, "backend:acme.com")
    alice_did_aw = "did:aw:alice"
    alice_id = await _insert_agent(
        aweb_cloud_db.aweb_db,
        team_id="backend:acme.com",
        alias="alice",
        did_key=_make_did_key(),
        did_aw=alice_did_aw,
        address="acme.com/alice",
    )

    by_alias = await get_agent_by_alias(db_shim, team_id="backend:acme.com", alias="alice")
    assert by_alias is not None
    assert str(by_alias["agent_id"]) == alice_id

    by_id = await get_agent_by_id(db_shim, team_id="backend:acme.com", agent_id=alice_id)
    assert by_id is not None
    assert by_id["alias"] == "alice"

    by_did = await resolve_agent_by_did(db_shim, alice_did_aw)
    assert by_did is not None
    assert by_did["alias"] == "alice"

    missing = await resolve_agent_by_did(db_shim, "did:aw:missing")
    assert missing is None


@pytest.mark.asyncio
async def test_deliver_message_recipient_not_found(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    with pytest.raises(NotFoundError, match="Recipient"):
        await deliver_message(
            db_shim,
            from_did="did:aw:alice",
            to_did="did:aw:missing",
            from_alias="alice",
            to_alias="missing",
            sender_address="acme.com/alice",
            subject="test",
            body="test",
            priority="normal",
        )
