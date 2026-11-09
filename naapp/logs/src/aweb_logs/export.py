"""A team's exported log, ``aweb.logs-export/1``, and its verification with no server.

``docs/logs-chain.md`` specifies the bundle: JSON Lines of strict canonical
objects, a header, then each epoch's genesis and its events in position order,
each followed by the receipt and checkpoints that witness it. That placement
lets :func:`verify_bundle` check each epoch in one pass, with state that does
not grow with the epoch. The bundle is not signed: it proves what its hashes
and logs-signed artefacts prove, under the keys the verifier accepts, and its
report says how far that reaches.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, BinaryIO

from aweb_naapp.hooks.strictjson import (
    Refused,
    canonical,
    decode_base64url,
    encode_base64url,
    parse_canonical_object,
)

from aweb_logs.chain import (
    Checkpoint,
    Genesis,
    Link,
    Receipt,
    artefact_sha256,
    open_checkpoint,
    open_receipt,
)
from aweb_logs.verify import (
    ChainReport,
    Content,
    Contradiction,
    EpochState,
    StoredEvent,
    opened_artefact,
    position_fault,
)

EXPORT_TYPE = "aweb.logs-export"
# The longest line a bundle holds, its newline excluded. An event line carries
# at most one hook envelope (MAX_ENVELOPE_BYTES, 256 KiB), base64url-encoded,
# beside its link and key evidence; this leaves room for those and refuses a
# line no exporter writes before a verifier holds it whole.
MAX_LINE_BYTES = 1 << 20
_EVIDENCE_TEXT = ("kid", "did_key", "installation_id")
_EVIDENCE_LISTS = ("purposes", "binding_ids")


class BundleMalformed(ValueError):
    """The bundle is not a well-formed export; ``line`` counts from 1."""

    def __init__(self, line: int, reason: str) -> None:
        super().__init__(f"line {line}: {reason}")
        self.line = line
        self.reason = reason


def _line(record: Mapping[str, Any]) -> bytes:
    return canonical(dict(record)) + b"\n"


def header_line(team_id: str) -> bytes:
    return _line({"v": 1, "type": EXPORT_TYPE, "team_id": team_id})


def genesis_line(genesis: Genesis) -> bytes:
    return _line({"genesis": genesis.fields()})


def event_line(event: StoredEvent) -> bytes:
    """An event's record. Its ``key_evidence`` is the producer key logs verified
    the envelope against."""
    if event.key_evidence is None:
        raise ValueError("an exported event carries its key evidence")
    stored: dict[str, Any] = {
        "link": event.link.fields(),
        "event_hash": event.event_hash,
        "key_evidence": {
            name: value
            for name, value in event.key_evidence.items()
            if name in (*_EVIDENCE_TEXT, *_EVIDENCE_LISTS, "generation") and value is not None
        },
    }
    if event.content is not None:
        stored["content"] = {
            "salt": encode_base64url(event.content.salt),
            "signing_bytes": encode_base64url(event.content.signing_bytes),
            "signature": event.content.signature,
        }
    if event.purge_act is not None:
        stored["purge_act"] = event.purge_act
    return _line({"event": stored})


def receipt_line(signing_bytes: bytes, signature: str) -> bytes:
    return _line({"receipt": _artefact_json(signing_bytes, signature)})


def checkpoint_line(signing_bytes: bytes, signature: str) -> bytes:
    return _line({"checkpoint": _artefact_json(signing_bytes, signature)})


def _artefact_json(signing_bytes: bytes, signature: str) -> dict[str, str]:
    return {"signing_bytes": encode_base64url(signing_bytes), "signature": signature}


@dataclass(frozen=True)
class EpochReport:
    chain_epoch: int
    chain: ChainReport
    linked: bool
    anchored_to: int | None
    unanchored: tuple[int, int] | None

    def to_json(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "chain_epoch": self.chain_epoch,
            **self.chain.to_json(),
            "linked": self.linked,
        }
        if self.anchored_to is not None:
            report["anchored_to"] = self.anchored_to
        if self.unanchored is not None:
            report["unanchored"] = list(self.unanchored)
        return report


@dataclass(frozen=True)
class BundleReport:
    receipt_keys: frozenset[str]
    checkpoint_keys: frozenset[str]
    epochs: tuple[EpochReport, ...]
    # (chain_epoch, team_seq, SHA-256 of its signing bytes) of the last checkpoint that holds.
    last_checkpoint: tuple[int, int, str] | None
    witnesses_contradicted: tuple[Contradiction, ...]

    @property
    def intact(self) -> bool:
        return (
            all(epoch.chain.intact and epoch.linked for epoch in self.epochs)
            and not self.witnesses_contradicted
        )

    def to_json(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "intact": self.intact,
            "accepted_keys": {
                "receipt": sorted(self.receipt_keys),
                "checkpoint": sorted(self.checkpoint_keys),
            },
            "epochs": [epoch.to_json() for epoch in self.epochs],
            "witnesses": {
                "contradicted": [
                    {"artefact": c.artefact, "index": c.index, "reason": c.reason}
                    for c in self.witnesses_contradicted
                ]
            },
        }
        if self.last_checkpoint is not None:
            epoch, team_seq, digest = self.last_checkpoint
            report["last_checkpoint"] = {
                "chain_epoch": epoch,
                "team_seq": team_seq,
                "signing_bytes_sha256": digest,
            }
        return report


@dataclass
class _Witness:
    kind: str
    index: int
    signing: bytes
    signature: str
    artefact: Receipt | Checkpoint


@dataclass
class _Epoch:
    """One epoch's pass over the bundle: the chain state, the position the next
    artefact witnesses, and the coverage so far."""

    genesis: Genesis
    linked: bool
    witnessed: set[int]
    state: EpochState = field(init=False)
    position: tuple[int, str, StoredEvent | None] = field(init=False)
    contradicted: list[Contradiction] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=lambda: {"receipt": 0, "checkpoint": 0})
    anchored_to: int | None = None
    first_unanchored: int | None = None
    last_seq: int = 0
    # Checkpoints that hold at the current position; at the end, the epoch's head checkpoints.
    head_checkpoints: set[str] = field(default_factory=set)
    positions: dict[int, tuple[str, StoredEvent]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.state = EpochState(self.genesis)
        self.position = (0, self.state.genesis_hash, None)

    def event(self, event: StoredEvent) -> None:
        seq = event.link.team_seq
        if self.last_seq and seq == self.last_seq:
            self.state.fail(seq, "sequence_duplicate")
            return
        if seq < self.last_seq:
            self.state.fail(seq, "misplaced")
            return
        self.state.add(event)
        self.position = (seq, event.event_hash, event)
        self.last_seq = seq
        self.head_checkpoints = set()
        if self.first_unanchored is None:
            self.first_unanchored = seq
        if seq in self.witnessed:
            self.positions[seq] = (event.event_hash, event)

    def artefact(self, kind: str, signing: bytes, signature: str, keys: frozenset[str]) -> bool:
        """Check one of the bundle's artefacts at the current position; whether it holds."""
        index = self.counts[kind]
        self.counts[kind] += 1
        opener = open_receipt if kind == "receipt" else open_checkpoint
        artefact, reason = opened_artefact(signing, signature, opener, keys, self.genesis)
        if artefact is not None:
            seq, stored_hash, stored_event = self.position
            if artefact.team_seq != seq:
                reason = "misplaced"
            else:
                reason = position_fault(artefact, stored_hash, stored_event)
        if reason is not None:
            self.contradicted.append(Contradiction(kind, index, reason))
            return False
        if kind == "checkpoint":
            self.anchored_to = self.position[0]
            self.first_unanchored = None
            self.head_checkpoints.add(artefact_sha256(signing))
        return True

    def witness_fault(self, witness: _Witness, keys: frozenset[str]) -> str | None:
        opener = open_receipt if witness.kind == "receipt" else open_checkpoint
        artefact, reason = opened_artefact(
            witness.signing, witness.signature, opener, keys, self.genesis
        )
        if artefact is None:
            return reason
        if artefact.team_seq == 0:
            return position_fault(artefact, self.state.genesis_hash, None)
        stored = self.positions.get(artefact.team_seq)
        if stored is None:
            return "not_in_chain"
        return position_fault(artefact, *stored)

    def report(self) -> EpochReport:
        unanchored = (
            (self.first_unanchored, self.last_seq) if self.first_unanchored is not None else None
        )
        return EpochReport(
            chain_epoch=self.genesis.chain_epoch,
            chain=self.state.report(self.contradicted),
            linked=self.linked,
            anchored_to=self.anchored_to,
            unanchored=unanchored,
        )


def verify_bundle(
    bundle: BinaryIO,
    *,
    receipt_keys: frozenset[str],
    checkpoint_keys: frozenset[str],
    witness_receipts: Sequence[tuple[bytes, str]] = (),
    witness_checkpoints: Sequence[tuple[bytes, str]] = (),
) -> BundleReport:
    """Verify a bundle, read line by line from ``bundle``, against the receipt
    and checkpoint keys the verifier accepts and the witnesses it holds
    independently of the exporter. A line longer than :data:`MAX_LINE_BYTES` is
    refused before it is read whole. Raises :class:`BundleMalformed` for a
    bundle that is not one."""
    keys = {"receipt": receipt_keys, "checkpoint": checkpoint_keys}
    witnesses: list[_Witness] = []
    contradicted: list[Contradiction] = []
    for kind, given in (("receipt", witness_receipts), ("checkpoint", witness_checkpoints)):
        opener = open_receipt if kind == "receipt" else open_checkpoint
        for index, (signing, signature) in enumerate(given):
            try:
                artefact = opener(signing, signature)
            except Refused:
                artefact = None
            if artefact is None or artefact.did_key not in keys[kind]:
                contradicted.append(Contradiction(kind, index, "signature_invalid"))
            else:
                witnesses.append(_Witness(kind, index, signing, signature, artefact))

    team_id: str | None = None
    epochs: list[EpochReport] = []
    current: _Epoch | None = None
    last_checkpoint: tuple[int, int, str] | None = None
    held: dict[tuple[str, int], str] = {}

    def close(epoch: _Epoch) -> None:
        epochs.append(epoch.report())
        for witness in witnesses:
            if (witness.kind, witness.index) in held:
                continue
            if witness.artefact.chain_epoch == epoch.genesis.chain_epoch:
                reason = epoch.witness_fault(witness, keys[witness.kind])
                if reason is not None:
                    held[(witness.kind, witness.index)] = reason

    number = 0
    while raw := bundle.readline(MAX_LINE_BYTES + 1):
        number += 1
        record = _record(raw, number)
        if team_id is None:
            team_id = _header(record, number)
            for witness in witnesses:
                if witness.artefact.team_id != team_id:
                    held[(witness.kind, witness.index)] = "wrong_chain"
            continue
        _one(record, number)
        ((name, value),) = record.items()
        if name == "genesis":
            genesis = _genesis(value, number)
            if current is not None:
                if genesis.chain_epoch <= current.genesis.chain_epoch:
                    raise BundleMalformed(number, "epochs are not in increasing order")
                close(current)
                linked = (
                    genesis.chain_epoch == current.genesis.chain_epoch + 1
                    and genesis.previous_checkpoint_sha256 in current.head_checkpoints
                )
            else:
                linked = genesis.chain_epoch == 1
            linked = linked and genesis.team_id == team_id
            witnessed = {
                witness.artefact.team_seq
                for witness in witnesses
                if witness.artefact.chain_epoch == genesis.chain_epoch
            }
            current = _Epoch(genesis=genesis, linked=linked, witnessed=witnessed)
            continue
        if current is None:
            raise BundleMalformed(number, f"a {name} record precedes its epoch's genesis")
        if name == "event":
            current.event(_event(value, number))
        else:
            signing, signature = _artefact(value, number)
            if current.artefact(name, signing, signature, keys[name]) and name == "checkpoint":
                last_checkpoint = (
                    current.genesis.chain_epoch,
                    current.position[0],
                    artefact_sha256(signing),
                )
    if team_id is None:
        raise BundleMalformed(number + 1, "the bundle has no header")
    if current is not None:
        close(current)

    present = {epoch.chain_epoch for epoch in epochs}
    for witness in witnesses:
        key = (witness.kind, witness.index)
        if key not in held and witness.artefact.chain_epoch not in present:
            held[key] = "epoch_absent"
    contradicted += [Contradiction(kind, index, reason) for (kind, index), reason in held.items()]
    contradicted.sort(key=lambda c: (c.artefact != "receipt", c.index))
    return BundleReport(
        receipt_keys=receipt_keys,
        checkpoint_keys=checkpoint_keys,
        epochs=tuple(epochs),
        last_checkpoint=last_checkpoint,
        witnesses_contradicted=tuple(contradicted),
    )


def _record(raw: bytes, number: int) -> dict[str, Any]:
    if not raw.endswith(b"\n"):
        if len(raw) > MAX_LINE_BYTES:
            raise BundleMalformed(number, f"a line is at most {MAX_LINE_BYTES} bytes")
        raise BundleMalformed(number, "a line ends with a newline")
    try:
        return parse_canonical_object(raw[:-1])
    except Refused as refused:
        raise BundleMalformed(number, f"not a strict canonical JSON object: {refused}") from None


def _header(record: dict[str, Any], number: int) -> str:
    if (
        set(record) != {"v", "type", "team_id"}
        or type(record["v"]) is not int
        or record["v"] != 1
        or record["type"] != EXPORT_TYPE
    ):
        raise BundleMalformed(number, f"the first line is the {EXPORT_TYPE} v1 header")
    team_id = record["team_id"]
    if not isinstance(team_id, str):
        raise BundleMalformed(number, "team_id")
    return team_id


def _one(record: dict[str, Any], number: int) -> None:
    if len(record) != 1 or next(iter(record)) not in ("genesis", "event", "receipt", "checkpoint"):
        raise BundleMalformed(number, "not a genesis, event, receipt or checkpoint record")


def _object(value: Any, number: int, required: set[str], optional: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or not required <= set(value) <= required | optional:
        raise BundleMalformed(number, "the record's fields")
    return value


def _genesis(value: Any, number: int) -> Genesis:
    fields = _object(
        value,
        number,
        {"team_id", "chain_epoch", "logs_origin", "created_at"},
        {"previous_checkpoint_sha256"},
    )
    genesis = Genesis(**fields)
    try:
        genesis.fields()
    except Refused as refused:
        raise BundleMalformed(number, f"genesis: {refused}") from None
    return genesis


def _event(value: Any, number: int) -> StoredEvent:
    stored = _object(
        value, number, {"link", "event_hash", "key_evidence"}, {"content", "purge_act"}
    )
    link_fields = _object(stored["link"], number, set(Link.__dataclass_fields__), set())
    for name, value in sorted(link_fields.items()):
        expected = int if name in ("chain_epoch", "team_seq") else str
        if type(value) is not expected:
            raise BundleMalformed(number, f"link {name}")
    evidence = _object(
        stored["key_evidence"],
        number,
        {"kid", "did_key", "purposes"},
        {"installation_id", "generation", "binding_ids"},
    )
    if not (
        all(isinstance(evidence.get(name, ""), str) for name in _EVIDENCE_TEXT)
        and all(
            isinstance(evidence.get(name, []), list)
            and all(isinstance(item, str) for item in evidence.get(name, []))
            for name in _EVIDENCE_LISTS
        )
        and type(evidence.get("generation", 1)) is int
    ):
        raise BundleMalformed(number, "key_evidence")
    if not isinstance(stored["event_hash"], str):
        raise BundleMalformed(number, "event_hash")
    content = None
    if "content" in stored:
        parts = _object(stored["content"], number, {"salt", "signing_bytes", "signature"}, set())
        try:
            content = Content(
                salt=decode_base64url(parts["salt"], "salt"),
                signing_bytes=decode_base64url(parts["signing_bytes"], "signing_bytes"),
                signature=parts["signature"],
                producer_did_key=evidence["did_key"],
            )
        except (Refused, TypeError) as refused:
            raise BundleMalformed(number, f"content: {refused}") from None
        if not isinstance(content.signature, str):
            raise BundleMalformed(number, "content signature")
    purge_act = stored.get("purge_act")
    if purge_act is not None and (not isinstance(purge_act, str) or not purge_act):
        raise BundleMalformed(number, "purge_act")
    return StoredEvent(
        link=Link(**link_fields),
        event_hash=stored["event_hash"],
        content=content,
        purge_act=purge_act,
        key_evidence=evidence,
    )


def _artefact(value: Any, number: int) -> tuple[bytes, str]:
    parts = _object(value, number, {"signing_bytes", "signature"}, set())
    if not isinstance(parts["signature"], str):
        raise BundleMalformed(number, "signature")
    try:
        return decode_base64url(parts["signing_bytes"], "signing_bytes"), parts["signature"]
    except (Refused, TypeError) as refused:
        raise BundleMalformed(number, f"signing_bytes: {refused}") from None
