from __future__ import annotations

from uuid import uuid4

import pytest

from aweb.awid.did import did_from_public_key, generate_keypair


@pytest.mark.asyncio
async def test_teams_table_insert_and_unique_constraint(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    _, pub = generate_keypair()
    team_did_key = did_from_public_key(pub)

    team_id = uuid4()
    await db.execute(
        """
        INSERT INTO {{tables.teams}}
            (team_id, domain, name, display_name, team_did_key, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        team_id,
        "acme.com",
        "backend",
        "Backend Team",
        team_did_key,
        "did:key:z6MkTest",
    )

    row = await db.fetch_one(
        "SELECT * FROM {{tables.teams}} WHERE team_id = $1",
        team_id,
    )
    assert row is not None
    assert row["domain"] == "acme.com"
    assert row["name"] == "backend"
    assert row["display_name"] == "Backend Team"
    assert row["team_did_key"] == team_did_key
    assert row["created_by"] == "did:key:z6MkTest"
    assert row["deleted_at"] is None

    # Unique constraint on (domain, name) must reject duplicates
    with pytest.raises(Exception, match="unique|duplicate"):
        await db.execute(
            """
            INSERT INTO {{tables.teams}}
                (team_id, domain, name, team_did_key)
            VALUES ($1, $2, $3, $4)
            """,
            uuid4(),
            "acme.com",
            "backend",
            team_did_key,
        )


@pytest.mark.asyncio
async def test_team_certificates_table_and_constraints(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    _, team_pub = generate_keypair()
    team_did_key = did_from_public_key(team_pub)
    _, member_pub = generate_keypair()
    member_did_key = did_from_public_key(member_pub)

    team_id = uuid4()
    await db.execute(
        """
        INSERT INTO {{tables.teams}}
            (team_id, domain, name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_id,
        "example.com",
        "infra",
        team_did_key,
    )

    cert_id = str(uuid4())
    await db.execute(
        """
        INSERT INTO {{tables.team_certificates}}
            (team_id, certificate_id, member_did_key, member_did_aw,
             member_address, alias, lifetime)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        team_id,
        cert_id,
        member_did_key,
        "did:aw:abc123",
        "example.com/alice",
        "alice",
        "permanent",
    )

    row = await db.fetch_one(
        "SELECT * FROM {{tables.team_certificates}} WHERE certificate_id = $1",
        cert_id,
    )
    assert row is not None
    assert row["member_did_key"] == member_did_key
    assert row["alias"] == "alice"
    assert row["lifetime"] == "permanent"
    assert row["issued_at"] is not None
    assert row["revoked_at"] is None

    # Unique constraint on (team_id, certificate_id) must reject duplicates
    with pytest.raises(Exception, match="unique|duplicate"):
        await db.execute(
            """
            INSERT INTO {{tables.team_certificates}}
                (team_id, certificate_id, member_did_key, alias)
            VALUES ($1, $2, $3, $4)
            """,
            team_id,
            cert_id,
            member_did_key,
            "bob",
        )


@pytest.mark.asyncio
async def test_team_certificates_lifetime_check_constraint(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    _, team_pub = generate_keypair()
    team_did_key = did_from_public_key(team_pub)

    team_id = uuid4()
    await db.execute(
        """
        INSERT INTO {{tables.teams}}
            (team_id, domain, name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_id,
        "check.example",
        "ops",
        team_did_key,
    )

    with pytest.raises(Exception, match="check|violates"):
        await db.execute(
            """
            INSERT INTO {{tables.team_certificates}}
                (team_id, certificate_id, member_did_key, alias, lifetime)
            VALUES ($1, $2, $3, $4, $5)
            """,
            team_id,
            str(uuid4()),
            "did:key:z6MkTest",
            "bad",
            "invalid_lifetime",
        )


@pytest.mark.asyncio
async def test_team_certificates_foreign_key_to_teams(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")

    # Insert into team_certificates with non-existent team_id must fail
    with pytest.raises(Exception, match="foreign key|violates"):
        await db.execute(
            """
            INSERT INTO {{tables.team_certificates}}
                (team_id, certificate_id, member_did_key, alias)
            VALUES ($1, $2, $3, $4)
            """,
            uuid4(),
            str(uuid4()),
            "did:key:z6MkTest",
            "orphan",
        )
