"""Tests for the contacts service layer against the team-based schema."""

from __future__ import annotations

import pytest

from aweb.messaging.contacts import (
    add_contact,
    get_contact_addresses,
    is_address_in_contacts,
    list_contacts,
    remove_contact,
)
from aweb.service_errors import ConflictError, ValidationError


@pytest.fixture
def _team(aweb_cloud_db):
    """Insert a team row for tests. Returns the db manager."""
    import asyncio

    db = aweb_cloud_db.aweb_db
    asyncio.get_event_loop().run_until_complete(
        db.execute(
            """
            INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
            VALUES ('acme.com/backend', 'acme.com', 'backend', 'did:key:z6Mktest')
            ON CONFLICT DO NOTHING
            """,
        )
    )
    return db


class _DbShim:
    """Minimal shim matching the db.get_manager() interface."""

    def __init__(self, aweb_db):
        self._db = aweb_db

    def get_manager(self, name="aweb"):
        return self._db


@pytest.mark.asyncio
async def test_add_and_list_contacts(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    aweb_db = aweb_cloud_db.aweb_db

    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('acme.com/backend', 'acme.com', 'backend', 'did:key:z6Mktest')
        ON CONFLICT DO NOTHING
        """,
    )

    result = await add_contact(
        db_shim,
        team_id="acme.com/backend",
        contact_address="example.com/alice",
        label="Alice at Example",
    )

    assert result["contact_address"] == "example.com/alice"
    assert result["label"] == "Alice at Example"
    assert result["contact_id"]

    contacts = await list_contacts(db_shim, team_id="acme.com/backend")
    assert len(contacts) == 1
    assert contacts[0]["contact_address"] == "example.com/alice"


@pytest.mark.asyncio
async def test_add_duplicate_contact_raises(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    aweb_db = aweb_cloud_db.aweb_db

    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('acme.com/backend', 'acme.com', 'backend', 'did:key:z6Mktest')
        ON CONFLICT DO NOTHING
        """,
    )

    await add_contact(db_shim, team_id="acme.com/backend", contact_address="example.com/bob", label="")

    with pytest.raises(ConflictError, match="already exists"):
        await add_contact(db_shim, team_id="acme.com/backend", contact_address="example.com/bob", label="")


@pytest.mark.asyncio
async def test_remove_contact(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    aweb_db = aweb_cloud_db.aweb_db

    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('acme.com/backend', 'acme.com', 'backend', 'did:key:z6Mktest')
        ON CONFLICT DO NOTHING
        """,
    )

    result = await add_contact(db_shim, team_id="acme.com/backend", contact_address="example.com/carol", label="")
    contact_id = result["contact_id"]

    await remove_contact(db_shim, team_id="acme.com/backend", contact_id=contact_id)

    contacts = await list_contacts(db_shim, team_id="acme.com/backend")
    assert len(contacts) == 0


@pytest.mark.asyncio
async def test_get_contact_addresses(aweb_cloud_db):
    db_shim = _DbShim(aweb_cloud_db.aweb_db)
    aweb_db = aweb_cloud_db.aweb_db

    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('acme.com/backend', 'acme.com', 'backend', 'did:key:z6Mktest')
        ON CONFLICT DO NOTHING
        """,
    )

    await add_contact(db_shim, team_id="acme.com/backend", contact_address="example.com", label="")
    await add_contact(db_shim, team_id="acme.com/backend", contact_address="other.org/dave", label="")

    addrs = await get_contact_addresses(db_shim, team_id="acme.com/backend")
    assert addrs == {"example.com", "other.org/dave"}


def test_is_address_in_contacts_exact():
    contacts = {"example.com/alice", "other.org"}
    assert is_address_in_contacts("example.com/alice", contacts) is True
    assert is_address_in_contacts("example.com/bob", contacts) is False


def test_is_address_in_contacts_domain_match():
    contacts = {"example.com"}
    assert is_address_in_contacts("example.com/alice", contacts) is True
    assert is_address_in_contacts("other.org/alice", contacts) is False
