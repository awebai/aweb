"""Storage invariants of the identity tree (docs/id-certificates.md §3, §4).

The registration gate serializes writers with row locks; these constraints are
the last line that keeps a lost race from producing a second head, a second
use of one invitation or a second open namespace epoch.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest
from pgdbm.errors import QueryError

T0 = datetime(2026, 10, 26, 0, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 10, 26, 0, 1, 0, tzinfo=timezone.utc)
INVITATION = UUID("00000000-0000-4000-8000-000000000001")


async def _identity(db, id_, *, kind="human", domain="example.com"):
    await db.execute(
        """
        INSERT INTO {{tables.id_identities}} (id, domain, kind, first_registered_at)
        VALUES ($1, $2, $3, $4)
        """,
        id_, domain, kind, T0,
    )


async def _certificate(db, certificate_id, id_, *, superseded_at=None, invitation_id=None, issuer_key_seq=1):
    await db.execute(
        """
        INSERT INTO {{tables.id_certificates}}
            (certificate_id, id, domain, parent_kind, parent_id, kind, issuer_key,
             signed_json, supporting_chain_json, issuer_key_seq, invitation_id,
             registered_at, superseded_at)
        VALUES ($1, $2, 'example.com', 'namespace', 'example.com', 'human', 'did:key:z6Mk',
                '{}', '{}', $3, $4, $5, $6)
        """,
        certificate_id, id_, issuer_key_seq, invitation_id, T0, superseded_at,
    )


async def _epoch(db, seq, *, retired_at=None, domain="example.com", continuity="replaced"):
    await db.execute(
        """
        INSERT INTO {{tables.id_namespace_epochs}}
            (domain, seq, did_key, continuity, registered_at, retired_at)
        VALUES ($1, $2, 'did:key:z6Mk', $5, $3, $4)
        """,
        domain, seq, T0, retired_at, continuity,
    )


@pytest.mark.asyncio
async def test_an_identity_has_at_most_one_current_head(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    await _identity(db, "did:aw:alice")
    await _certificate(db, "sha256:aa", "did:aw:alice", superseded_at=T1)
    await _certificate(db, "sha256:bb", "did:aw:alice")
    with pytest.raises(QueryError):
        await _certificate(db, "sha256:cc", "did:aw:alice")


@pytest.mark.asyncio
async def test_an_invitation_registers_one_certificate(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    await _identity(db, "did:aw:alice")
    await _identity(db, "did:aw:bob")
    await _certificate(db, "sha256:aa", "did:aw:alice", invitation_id=INVITATION)
    with pytest.raises(QueryError):
        await _certificate(db, "sha256:bb", "did:aw:bob", invitation_id=INVITATION)


@pytest.mark.asyncio
async def test_a_certificate_revision_is_registered_once(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    await _identity(db, "did:aw:alice")
    await _certificate(db, "sha256:aa", "did:aw:alice", superseded_at=T1)
    with pytest.raises(QueryError):
        await _certificate(db, "sha256:aa", "did:aw:alice")


@pytest.mark.asyncio
async def test_issuer_key_sequences_are_positive(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    await _identity(db, "did:aw:alice")
    with pytest.raises(QueryError):
        await _certificate(db, "sha256:aa", "did:aw:alice", issuer_key_seq=0)


@pytest.mark.asyncio
async def test_identity_kind_is_human_or_agent(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    await _identity(db, "did:aw:alice", kind="human")
    await _identity(db, "did:aw:agent", kind="agent")
    with pytest.raises(QueryError):
        await _identity(db, "did:aw:team", kind="team")


@pytest.mark.asyncio
async def test_revocation_cutoff_never_follows_revocation_time(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    await _identity(db, "did:aw:alice")
    await db.execute(
        "UPDATE {{tables.id_identities}} SET revoked_at = $1, effective_from = $1, revoked_by = 'did:key:z6Mk'"
        " WHERE id = 'did:aw:alice'",
        T1,
    )
    with pytest.raises(QueryError):
        await db.execute(
            "UPDATE {{tables.id_identities}} SET effective_from = $1 WHERE id = 'did:aw:alice'",
            datetime(2026, 10, 26, 0, 2, 0, tzinfo=timezone.utc),
        )
    with pytest.raises(QueryError):
        await db.execute(
            "UPDATE {{tables.id_identities}} SET revoked_at = NULL WHERE id = 'did:aw:alice'"
        )


@pytest.mark.asyncio
async def test_a_domain_has_one_open_namespace_epoch_per_sequence(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    await _epoch(db, 1, retired_at=T1)
    await _epoch(db, 2)
    with pytest.raises(QueryError):
        await _epoch(db, 3)
    with pytest.raises(QueryError):
        await _epoch(db, 2, retired_at=T1)
    with pytest.raises(QueryError):
        await _epoch(db, 0, retired_at=T1, domain="other.example")
    await _epoch(db, 1, domain="other.example")


@pytest.mark.asyncio
async def test_a_revision_cannot_be_superseded_at_its_registration_time(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    await _identity(db, "did:aw:alice")
    with pytest.raises(QueryError):
        await _certificate(db, "sha256:aa", "did:aw:alice", superseded_at=T0)


@pytest.mark.asyncio
async def test_an_epoch_cannot_retire_at_its_registration_time(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    with pytest.raises(QueryError):
        await _epoch(db, 1, retired_at=T0)


@pytest.mark.asyncio
async def test_a_revision_carries_its_identity_kind_and_domain(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    await _identity(db, "did:aw:alice", kind="agent")
    with pytest.raises(QueryError):
        await _certificate(db, "sha256:aa", "did:aw:alice")
    await _identity(db, "did:aw:bob", domain="other.example")
    with pytest.raises(QueryError):
        await _certificate(db, "sha256:bb", "did:aw:bob")


@pytest.mark.asyncio
async def test_epoch_continuity_is_rotated_or_replaced(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    await _epoch(db, 1, retired_at=T1, continuity="replaced")
    await _epoch(db, 2, continuity="rotated")
    with pytest.raises(QueryError):
        await _epoch(db, 1, domain="other.example", continuity="dns_exact")
