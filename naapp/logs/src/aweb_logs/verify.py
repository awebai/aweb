"""Verifying one team epoch's chain, and the receipts and checkpoints given against it.

``docs/logs-chain.md`` states what ``verify`` reports and why. This is the pure
chain check: it reads stored events and artefacts and touches no database.
Producer and hook sequence gaps inside binding intervals, and conflicting
deliveries, come from logs' records of bindings and faults.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from aweb_naapp.hooks import envelope as hook_envelope
from aweb_naapp.hooks.strictjson import Refused

from aweb_logs.chain import (
    Checkpoint,
    Genesis,
    Link,
    Receipt,
    content_commitment,
    open_checkpoint,
    open_receipt,
    producer_origin,
)


@dataclass(frozen=True)
class Content:
    """An event's retained content, and the producer key ingest verified it against."""

    salt: bytes
    signing_bytes: bytes
    signature: str
    producer_did_key: str


@dataclass(frozen=True)
class StoredEvent:
    """One stored event: its skeleton and hash, and its content unless purged."""

    link: Link
    event_hash: str
    content: Content | None = None
    # The act that purged the content, an opaque reference.
    purge_act: str | None = None


@dataclass(frozen=True)
class Break:
    team_seq: int
    reason: str


@dataclass(frozen=True)
class PurgedRange:
    first: int
    last: int
    act: str


@dataclass(frozen=True)
class Contradiction:
    artefact: str
    index: int
    reason: str


@dataclass(frozen=True)
class ChainReport:
    first_break: Break | None
    missing: tuple[tuple[int, int], ...]
    purged: tuple[PurgedRange, ...]
    contradicted: tuple[Contradiction, ...]

    @property
    def intact(self) -> bool:
        return self.first_break is None and not self.missing and not self.contradicted

    def to_json(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "intact": self.intact,
            "missing": [[first, last] for first, last in self.missing],
            "purged": [
                {"from": purged.first, "to": purged.last, "act": purged.act}
                for purged in self.purged
            ],
            "contradicted": [
                {"artefact": c.artefact, "index": c.index, "reason": c.reason}
                for c in self.contradicted
            ],
        }
        if self.first_break is not None:
            report["first_break"] = {
                "team_seq": self.first_break.team_seq,
                "reason": self.first_break.reason,
            }
        return report


def verify_chain(
    genesis: Genesis,
    events: Sequence[StoredEvent],
    *,
    receipt_keys: frozenset[str],
    checkpoint_keys: frozenset[str],
    receipts: Sequence[tuple[bytes, str]] = (),
    checkpoints: Sequence[tuple[bytes, str]] = (),
) -> ChainReport:
    """Recompute a team epoch's chain from its genesis and check each artefact
    against it. ``receipt_keys`` and ``checkpoint_keys`` are the did:keys the
    logs manifest declares for each purpose."""
    genesis_hash = genesis.hash()
    first_break: Break | None = None
    missing: list[tuple[int, int]] = []
    purged: list[PurgedRange] = []
    hashes: dict[int, str] = {0: genesis_hash}
    prev_hash = genesis_hash
    expected_seq = 1

    for event in sorted(events, key=lambda stored: stored.link.team_seq):
        seq = event.link.team_seq
        if seq in hashes:
            first_break = first_break or Break(seq, "sequence_duplicate")
            continue
        if seq > expected_seq:
            missing.append((expected_seq, seq - 1))
            linked = True
        else:
            linked = event.link.prev_event_hash == prev_hash
        reason = _event_fault(genesis, event, linked)
        if reason is not None:
            first_break = first_break or Break(seq, reason)
        if event.content is None and event.purge_act is not None:
            _extend_purged(purged, seq, event.purge_act)
        hashes[seq] = event.event_hash
        prev_hash = event.event_hash
        expected_seq = seq + 1

    contradicted = [
        Contradiction("receipt", index, reason)
        for index, (signing, signature) in enumerate(receipts)
        if (
            reason := _contradiction(
                signing, signature, open_receipt, receipt_keys, genesis, hashes
            )
        )
    ]
    contradicted += [
        Contradiction("checkpoint", index, reason)
        for index, (signing, signature) in enumerate(checkpoints)
        if (
            reason := _contradiction(
                signing, signature, open_checkpoint, checkpoint_keys, genesis, hashes
            )
        )
    ]
    return ChainReport(first_break, tuple(missing), tuple(purged), tuple(contradicted))


def _event_fault(genesis: Genesis, event: StoredEvent, linked: bool) -> str | None:
    """The first fault of one stored event, in the contract's order, or None."""
    link = event.link
    if link.team_id != genesis.team_id or link.chain_epoch != genesis.chain_epoch:
        return "wrong_chain"
    if not linked:
        return "prev_hash_mismatch"
    try:
        if link.event_hash() != event.event_hash:
            return "event_hash_mismatch"
    except Refused:
        return "event_hash_mismatch"
    content = event.content
    if content is None:
        return None if event.purge_act is not None else "content_missing"
    try:
        commitment = content_commitment(content.salt, content.signing_bytes, content.signature)
    except Refused:
        return "commitment_mismatch"
    if commitment != link.content_commitment:
        return "commitment_mismatch"
    try:
        envelope = hook_envelope.verify(
            content.signing_bytes, content.signature, team_id=genesis.team_id
        )
    except Refused:
        return "provenance_invalid"
    if envelope.producer_did_key != content.producer_did_key:
        return "provenance_invalid"
    if envelope.hook != link.hook or producer_origin(envelope) != link.producer_origin:
        return "skeleton_mismatch"
    return None


def _extend_purged(purged: list[PurgedRange], seq: int, act: str) -> None:
    if purged and purged[-1].act == act and purged[-1].last == seq - 1:
        purged[-1] = PurgedRange(purged[-1].first, seq, act)
    else:
        purged.append(PurgedRange(seq, seq, act))


def _contradiction(
    signing: bytes,
    signature: str,
    open_artefact: Callable[[bytes, str], Receipt | Checkpoint],
    keys: frozenset[str],
    genesis: Genesis,
    hashes: dict[int, str],
) -> str | None:
    """Why the chain contradicts one artefact, or None when it holds."""
    try:
        artefact = open_artefact(signing, signature)
    except Refused:
        return "signature_invalid"
    if artefact.did_key not in keys:
        return "signature_invalid"
    if (artefact.team_id, artefact.chain_epoch, artefact.logs_origin) != (
        genesis.team_id,
        genesis.chain_epoch,
        genesis.logs_origin,
    ):
        return "wrong_chain"
    stored = hashes.get(artefact.team_seq)
    if stored is None:
        return "not_in_chain"
    if stored != artefact.event_hash:
        return "hash_mismatch"
    return None
