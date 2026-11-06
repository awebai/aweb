"""Verifying one team epoch's chain, and the receipts and checkpoints given against it.

``docs/logs-chain.md`` states what ``verify`` reports and why. This is the pure
chain check: it reads stored events and artefacts and touches no database.
Producer and hook sequence gaps inside binding intervals, and conflicting
deliveries, come from logs' records of bindings and faults.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from aweb_naapp.hooks import envelope as hook_envelope
from aweb_naapp.hooks.strictjson import Refused
from awid.log import canonical_server_origin

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
    key_evidence: Mapping[str, Any] | None = None


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


@dataclass(frozen=True)
class DeliveryReport:
    """Findings from retained, authenticated observations, never completeness."""

    gaps: tuple[dict[str, Any], ...]
    sequence_conflicts: tuple[dict[str, Any], ...]
    unassessed: tuple[dict[str, Any], ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "scope": "observed_internal_only", "gaps": list(self.gaps),
            "sequence_conflicts": list(self.sequence_conflicts),
            "unassessed": list(self.unassessed),
        }


def verify_deliveries(genesis: Genesis, events: Sequence[StoredEvent]) -> DeliveryReport:
    """Report internal holes/reused sequences within admitted observation intervals.

    This does not redefine the shared producer counter. Installations, generations
    and binding activations bound what this receiver can establish. Rotation does
    not start an interval, and arrival order says nothing about counter restarts.
    An absent prefix/trailing event, or a missing lifecycle snapshot, cannot prove
    loss. Purged/invalid content could cover a hole and prevents that inference.
    """
    groups: dict[str, tuple[dict[str, Any], dict[int, set[str]]]] = {}
    identity_sequences: dict[str, tuple[dict[str, Any], dict[int, set[str]]]] = {}
    uncertain_identities: set[str] = set()
    uncertain_origins: set[tuple[str, str]] = set()
    unassessed: list[dict[str, Any]] = []
    for stored in events:
        reason = _event_fault(genesis, stored, linked=True)
        if stored.content is None or reason is not None:
            uncertain_origins.add((stored.link.hook, stored.link.producer_origin))
            unassessed.append({"team_seq": stored.link.team_seq, "reason": reason or "purged"})
            continue
        event = hook_envelope.verify(stored.content.signing_bytes, stored.content.signature,
                                     team_id=genesis.team_id)
        if event.producer_kind == "client":
            continue
        identity = _producer_identity(event)
        identity_key = json.dumps([event.fields["catalog"], event.hook, identity], sort_keys=True)
        evidence = stored.key_evidence or {}
        admissions = evidence.get("admissions")
        contexts = []
        if isinstance(admissions, list) and admissions:
            for admitted in admissions:
                try:
                    contexts.append(_observation(genesis, event, admitted))
                except (ValueError, KeyError, TypeError):
                    # An uncertain lifecycle span cannot be turned into continuity.
                    contexts = []
                    break
        if not contexts:
            uncertain_identities.add(identity_key)
            unassessed.append({"team_seq": stored.link.team_seq,
                               "reason": "binding_evidence_unavailable"})
            continue
        if identity_key not in identity_sequences:
            identity_sequences[identity_key] = ({"team_id": event.team_id, "catalog": event.fields["catalog"],
                                                "hook": event.hook, "producer": identity}, {})
        identity_sequences[identity_key][1].setdefault(event.fields["producer"]["seq"], set()).add(event.event_id)
        for interval_key, context in contexts:
            group_key = json.dumps([identity_key, interval_key])
            if group_key not in groups:
                groups[group_key] = (context, {})
            groups[group_key][1].setdefault(event.fields["producer"]["seq"], set()).add(event.event_id)

    gaps: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for group_key, (context, observed) in sorted(groups.items()):
        identity_key = json.loads(group_key)[0]
        identity = context["producer"]
        origin = identity["origin"]
        uncertain = (identity_key in uncertain_identities
                     or (context["hook"], origin) in uncertain_origins)
        seqs = sorted(observed)
        if not uncertain:
            for before, after in zip(seqs, seqs[1:], strict=False):
                if after > before + 1:
                    gaps.append({**context, "from": before + 1, "to": after - 1,
                                 "classification": "unexplained"})
    for _, (context, observed) in sorted(identity_sequences.items()):
        for seq, event_ids in sorted(observed.items()):
            if len(event_ids) > 1:
                conflicts.append({**context, "seq": seq, "event_ids": sorted(event_ids)})
    return DeliveryReport(tuple(gaps), tuple(conflicts), tuple(unassessed))


def _producer_identity(event: hook_envelope.Envelope) -> dict[str, Any]:
    producer = event.fields["producer"]
    names: tuple[str, ...] = ("kind", "origin")
    if event.producer_kind == "app":
        names += ("app_id", "installation_id", "generation")
    return {name: producer[name] for name in names}


def _observation(
    genesis: Genesis, event: hook_envelope.Envelope, admission: Any,
) -> tuple[str, dict[str, Any]]:
    if not isinstance(admission, dict):
        raise ValueError("missing admission")
    registration = admission["registration"]
    interval = [_interval(event, registration, "registration")]
    if registration["origin"] != genesis.logs_origin:
        raise ValueError("another receiver")
    production_id = None
    if event.producer_kind == "app":
        production = admission["production"]
        interval.append(_interval(event, production, "production"))
        for name in ("app_id", "origin", "installation_id", "generation"):
            if production[name] != event.fields["producer"][name]:
                raise ValueError("another production")
        production_id = production["binding_id"]
    else:
        if not isinstance(admission.get("server_url"), str):
            raise ValueError("missing anchored server")
        if canonical_server_origin(admission["server_url"]) != event.fields["producer"]["origin"]:
            raise ValueError("unanchored core origin")
    context = {
        "team_id": event.team_id, "catalog": event.fields["catalog"], "hook": event.hook,
        "producer": _producer_identity(event), "registration_id": registration["binding_id"],
        "production_id": production_id,
    }
    return json.dumps(interval, sort_keys=True), context


def _interval(event: hook_envelope.Envelope, binding: Any, kind: str) -> dict[str, Any]:
    if not isinstance(binding, dict):
        raise ValueError("missing binding")
    if (binding["team_id"], binding["kind"], binding["state"], binding["catalog_id"],
        binding["catalog_version"], binding["hook"]) != (
        event.team_id, kind, "active", event.fields["catalog"]["id"],
        event.fields["catalog"]["version"], event.hook,
    ):
        raise ValueError("another binding scope")
    active = datetime.strptime(binding["active_from"], "%Y-%m-%dT%H:%M:%S.%fZ")
    occurred = datetime.strptime(event.fields["occurred_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
    if occurred < active or binding.get("revoked_at") is not None or binding.get("ended_by") is not None:
        raise ValueError("outside active interval")
    names = ("binding_id", "app_id", "origin", "installation_id", "generation", "digest",
             "method", "path", "active_from")
    return {name: binding[name] for name in names}


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
    stored_events: dict[int, StoredEvent] = {}
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
        stored_events[seq] = event
        prev_hash = event.event_hash
        expected_seq = seq + 1

    contradicted = [
        Contradiction("receipt", index, reason)
        for index, (signing, signature) in enumerate(receipts)
        if (
            reason := _contradiction(
                signing, signature, open_receipt, receipt_keys, genesis, hashes, stored_events
            )
        )
    ]
    contradicted += [
        Contradiction("checkpoint", index, reason)
        for index, (signing, signature) in enumerate(checkpoints)
        if (
            reason := _contradiction(
                signing, signature, open_checkpoint, checkpoint_keys, genesis, hashes, stored_events
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
    stored_events: dict[int, StoredEvent],
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
    if isinstance(artefact, Receipt) and not _receipt_names_event(
        artefact, stored_events[artefact.team_seq]
    ):
        return "event_mismatch"
    return None


def _receipt_names_event(receipt: Receipt, event: StoredEvent) -> bool:
    """Whether a receipt names the event stored at its sequence: its receipt time
    always, and its event id while the content is retained."""
    if receipt.received_at != event.link.received_at:
        return False
    if event.content is None:
        return True
    try:
        envelope = hook_envelope.open_envelope(event.content.signing_bytes)
    except Refused:
        return False
    return envelope.event_id == receipt.event_id
