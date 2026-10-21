"""Storing each team's chain: appending events, signing checkpoints, starting epochs.

Every write holds the lock on the team's row in ``chain_heads``, so team_seq is
assigned once, in order and without gaps, and a checkpoint witnesses a head no
append can move under it. ``docs/logs-chain.md`` specifies the bytes.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from aweb_naapp.hooks.envelope import Envelope
from awid.did import did_from_public_key
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager

from aweb_logs.chain import (
    SALT_BYTES,
    Checkpoint,
    Genesis,
    Link,
    Receipt,
    artefact_sha256,
    content_commitment,
    format_time,
    link_for,
    producer_origin,
    sign_checkpoint,
    sign_receipt,
)
from aweb_logs.verify import Content, StoredEvent


@dataclass(frozen=True)
class LogsSigner:
    """logs' installation as it signs: its origin and its receipt and checkpoint key."""

    logs_origin: str
    kid: str
    signing_key: SigningKey

    @property
    def did_key(self) -> str:
        return did_from_public_key(bytes(self.signing_key.verify_key))


@dataclass(frozen=True)
class Appended:
    """The event is in the chain. ``receipt`` is its signing bytes and signature;
    ``duplicate`` says it was already there and this is the original receipt."""

    receipt: tuple[bytes, str]
    duplicate: bool


@dataclass(frozen=True)
class Conflicted:
    """The team already holds this event id with other bytes. Nothing was
    appended, and the conflict is kept as a fault."""

    event_id: uuid.UUID


class OriginMismatch(Exception):
    """The signer is not the origin of the team's current epoch. Only
    :func:`open_next_epoch` moves a team's chain to another origin."""


@dataclass(frozen=True)
class _Head:
    chain_epoch: int
    team_seq: int
    event_hash: str
    logs_origin: str

    def check_signer(self, signer: LogsSigner) -> None:
        if signer.logs_origin != self.logs_origin:
            raise OriginMismatch(
                f"epoch {self.chain_epoch} belongs to {self.logs_origin}, not {signer.logs_origin}"
            )


async def append(
    db: AsyncDatabaseManager,
    signer: LogsSigner,
    *,
    event: Envelope,
    signing_bytes: bytes,
    signature: str,
    key_evidence: Mapping[str, Any],
    received_at: datetime,
) -> Appended | Conflicted:
    """Append a verified event to its team's chain and sign its receipt, in one
    transaction. A redelivery of the same bytes returns the original receipt.

    A purged event's bytes are gone, so its redelivery is compared only on what
    the skeleton keeps, its hook and producer origin."""
    event_id = uuid.UUID(event.event_id)
    async with db.transaction() as tx:
        head = await _locked_head(tx, signer, event.team_id, received_at)
        head.check_signer(signer)
        stored = await tx.fetch_one(
            "SELECT signing_bytes, signature, hook, producer_origin, receipt_bytes,"
            " receipt_signature FROM {{tables.chain_events}} WHERE team_id = $1 AND event_id = $2",
            event.team_id,
            event_id,
        )
        if stored is not None:
            receipt = (bytes(stored["receipt_bytes"]), stored["receipt_signature"])
            if stored["signing_bytes"] is None:
                same = (stored["hook"], stored["producer_origin"]) == (
                    event.hook,
                    producer_origin(event),
                )
            else:
                same = (
                    bytes(stored["signing_bytes"]) == signing_bytes
                    and stored["signature"] == signature
                )
            if same:
                return Appended(receipt=receipt, duplicate=True)
            await tx.execute(
                "INSERT INTO {{tables.chain_faults}}"
                " (team_id, event_id, kind, refused_sha256, key_evidence)"
                " VALUES ($1, $2, 'event_conflict', $3, $4::jsonb)",
                event.team_id,
                event_id,
                hashlib.sha256(signing_bytes).hexdigest(),
                json.dumps(dict(key_evidence), sort_keys=True),
            )
            return Conflicted(event_id=event_id)

        salt = os.urandom(SALT_BYTES)
        link = link_for(
            event,
            chain_epoch=head.chain_epoch,
            team_seq=head.team_seq + 1,
            prev_event_hash=head.event_hash,
            received_at=format_time(received_at),
            content_commitment=content_commitment(salt, signing_bytes, signature),
        )
        event_hash = link.event_hash()
        receipt = sign_receipt(
            signer.signing_key,
            Receipt(
                team_id=event.team_id,
                event_id=event.event_id,
                chain_epoch=link.chain_epoch,
                team_seq=link.team_seq,
                event_hash=event_hash,
                received_at=link.received_at,
                logs_origin=signer.logs_origin,
                kid=signer.kid,
                did_key=signer.did_key,
            ),
        )
        await tx.execute(
            "INSERT INTO {{tables.chain_events}}"
            " (team_id, chain_epoch, team_seq, event_id, prev_event_hash, event_hash,"
            "  received_at, hook, producer_origin, content_commitment, salt, signing_bytes,"
            "  signature, key_evidence, receipt_bytes, receipt_signature)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15, $16)",
            link.team_id,
            link.chain_epoch,
            link.team_seq,
            event_id,
            link.prev_event_hash,
            event_hash,
            link.received_at,
            link.hook,
            link.producer_origin,
            link.content_commitment,
            salt,
            signing_bytes,
            signature,
            json.dumps(dict(key_evidence), sort_keys=True),
            receipt[0],
            receipt[1],
        )
        await _move_head(
            tx, event.team_id, _Head(link.chain_epoch, link.team_seq, event_hash, head.logs_origin)
        )
        return Appended(receipt=receipt, duplicate=False)


async def issue_checkpoint(
    db: AsyncDatabaseManager, signer: LogsSigner, team_id: str, *, issued_at: datetime
) -> tuple[bytes, str]:
    """Sign a checkpoint of the team's current head, linked to the epoch's
    previous checkpoint. A team with no chain has nothing to checkpoint."""
    async with db.transaction() as tx:
        head = await _existing_head(tx, team_id)
        if head is None:
            raise LookupError(f"team {team_id} has no chain")
        head.check_signer(signer)
        return await _checkpoint(tx, signer, team_id, head, issued_at)


async def open_next_epoch(
    db: AsyncDatabaseManager,
    signer: LogsSigner,
    team_id: str,
    *,
    at: datetime,
    logs_origin: str | None = None,
) -> tuple[bytes, str]:
    """Close the team's current epoch with a final checkpoint, signed under that
    epoch's origin, and start the next, whose genesis records that checkpoint.
    The next epoch belongs to ``logs_origin``, or to the signer's origin when it
    is not given. Returns the final checkpoint."""
    async with db.transaction() as tx:
        head = await _existing_head(tx, team_id)
        if head is None:
            raise LookupError(f"team {team_id} has no chain")
        head.check_signer(signer)
        final = await _checkpoint(tx, signer, team_id, head, at)
        genesis = Genesis(
            team_id=team_id,
            chain_epoch=head.chain_epoch + 1,
            logs_origin=logs_origin or signer.logs_origin,
            created_at=format_time(at),
            previous_checkpoint_sha256=artefact_sha256(final[0]),
        )
        await _insert_epoch(tx, genesis)
        await _move_head(
            tx, team_id, _Head(genesis.chain_epoch, 0, genesis.hash(), genesis.logs_origin)
        )
        return final


async def load_epoch(
    db: AsyncDatabaseManager, team_id: str, chain_epoch: int
) -> tuple[Genesis, list[StoredEvent]]:
    """One team epoch's genesis and stored events, in team_seq order, for verify."""
    epoch = await db.fetch_one(
        "SELECT logs_origin, created_at, previous_checkpoint_sha256"
        " FROM {{tables.chain_epochs}} WHERE team_id = $1 AND chain_epoch = $2",
        team_id,
        chain_epoch,
    )
    if epoch is None:
        raise LookupError(f"team {team_id} has no epoch {chain_epoch}")
    genesis = Genesis(
        team_id=team_id,
        chain_epoch=chain_epoch,
        logs_origin=epoch["logs_origin"],
        created_at=epoch["created_at"],
        previous_checkpoint_sha256=epoch["previous_checkpoint_sha256"],
    )
    rows = await db.fetch_all(
        "SELECT team_seq, prev_event_hash, event_hash, received_at, hook, producer_origin,"
        " content_commitment, salt, signing_bytes, signature, key_evidence, purge_act"
        " FROM {{tables.chain_events}} WHERE team_id = $1 AND chain_epoch = $2"
        " ORDER BY team_seq",
        team_id,
        chain_epoch,
    )
    return genesis, [_stored_event(team_id, chain_epoch, row) for row in rows]


def _stored_event(team_id: str, chain_epoch: int, row: Mapping[str, Any]) -> StoredEvent:
    link = Link(
        chain_epoch=chain_epoch,
        team_id=team_id,
        team_seq=row["team_seq"],
        prev_event_hash=row["prev_event_hash"],
        received_at=row["received_at"],
        hook=row["hook"],
        producer_origin=row["producer_origin"],
        content_commitment=row["content_commitment"],
    )
    content = None
    if row["signing_bytes"] is not None:
        content = Content(
            salt=bytes(row["salt"]),
            signing_bytes=bytes(row["signing_bytes"]),
            signature=row["signature"],
            producer_did_key=json.loads(row["key_evidence"])["did_key"],
        )
    return StoredEvent(
        link=link, event_hash=row["event_hash"], content=content, purge_act=row["purge_act"]
    )


async def _locked_head(tx: Any, signer: LogsSigner, team_id: str, at: datetime) -> _Head:
    """The team's head, locked, creating its first epoch on its first event."""
    head = await _existing_head(tx, team_id)
    if head is not None:
        return head
    genesis = Genesis(
        team_id=team_id, chain_epoch=1, logs_origin=signer.logs_origin, created_at=format_time(at)
    )
    await _insert_epoch(tx, genesis)
    await tx.execute(
        "INSERT INTO {{tables.chain_heads}} (team_id, chain_epoch, team_seq, event_hash)"
        " VALUES ($1, 1, 0, $2) ON CONFLICT (team_id) DO NOTHING",
        team_id,
        genesis.hash(),
    )
    head = await _existing_head(tx, team_id)
    assert head is not None
    return head


async def _existing_head(tx: Any, team_id: str) -> _Head | None:
    row = await tx.fetch_one(
        "SELECT chain_epoch, team_seq, event_hash FROM {{tables.chain_heads}}"
        " WHERE team_id = $1 FOR UPDATE",
        team_id,
    )
    if row is None:
        return None
    # Read only once the head is locked: a join locked with it could pair a
    # head another writer just moved with the epoch row it replaced.
    logs_origin = await tx.fetch_value(
        "SELECT logs_origin FROM {{tables.chain_epochs}} WHERE team_id = $1 AND chain_epoch = $2",
        team_id,
        row["chain_epoch"],
    )
    return _Head(row["chain_epoch"], row["team_seq"], row["event_hash"], logs_origin)


async def _insert_epoch(tx: Any, genesis: Genesis) -> None:
    await tx.execute(
        "INSERT INTO {{tables.chain_epochs}}"
        " (team_id, chain_epoch, logs_origin, created_at, previous_checkpoint_sha256, genesis_hash)"
        " VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (team_id, chain_epoch) DO NOTHING",
        genesis.team_id,
        genesis.chain_epoch,
        genesis.logs_origin,
        genesis.created_at,
        genesis.previous_checkpoint_sha256,
        genesis.hash(),
    )


async def _move_head(tx: Any, team_id: str, head: _Head) -> None:
    await tx.execute(
        "UPDATE {{tables.chain_heads}} SET chain_epoch = $2, team_seq = $3, event_hash = $4"
        " WHERE team_id = $1",
        team_id,
        head.chain_epoch,
        head.team_seq,
        head.event_hash,
    )


async def _checkpoint(
    tx: Any, signer: LogsSigner, team_id: str, head: _Head, issued_at: datetime
) -> tuple[bytes, str]:
    previous = await tx.fetch_one(
        "SELECT checkpoint_sha256 FROM {{tables.chain_checkpoints}}"
        " WHERE team_id = $1 AND chain_epoch = $2 ORDER BY position DESC LIMIT 1",
        team_id,
        head.chain_epoch,
    )
    previous_sha256 = previous["checkpoint_sha256"] if previous is not None else None
    signing, signature = sign_checkpoint(
        signer.signing_key,
        Checkpoint(
            team_id=team_id,
            chain_epoch=head.chain_epoch,
            team_seq=head.team_seq,
            event_hash=head.event_hash,
            issued_at=format_time(issued_at),
            logs_origin=signer.logs_origin,
            kid=signer.kid,
            did_key=signer.did_key,
            previous_checkpoint_sha256=previous_sha256,
        ),
    )
    await tx.execute(
        "INSERT INTO {{tables.chain_checkpoints}}"
        " (team_id, chain_epoch, team_seq, event_hash, signing_bytes, signature,"
        "  checkpoint_sha256, previous_checkpoint_sha256)"
        " VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        team_id,
        head.chain_epoch,
        head.team_seq,
        head.event_hash,
        signing,
        signature,
        artefact_sha256(signing),
        previous_sha256,
    )
    return signing, signature
