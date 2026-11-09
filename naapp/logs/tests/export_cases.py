"""Exported team logs for the tests and for the logs export vector:
real signed envelopes, receipts and checkpoints, laid out as the bundle places
them, and the damage an exporter or anyone between it and the holder can do."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from aweb_logs.chain import Genesis, artefact_sha256
from aweb_logs.export import (
    checkpoint_line,
    event_line,
    genesis_line,
    header_line,
    receipt_line,
)
from aweb_logs.verify import StoredEvent

from .chain_cases import (
    ERASE_ACT,
    EVENT_IDS,
    LOGS_DID,
    append,
    checkpoint,
    content,
    genesis,
    receipt,
)
from .fixtures import OTHER_LOGS_SEED, TEAM_ID

Artefact = tuple[bytes, str]


def evidenced(event: StoredEvent) -> StoredEvent:
    """The event with the key evidence logs recorded when it admitted it."""
    assert event.content is not None
    return dataclasses.replace(
        event,
        key_evidence={
            "kid": "hook-2026-10",
            "did_key": event.content.producer_did_key,
            "purposes": ["hook-event"],
        },
    )


@dataclass
class Log:
    """A team log of two epochs: three events with a head checkpoint, then one
    event and a checkpoint after it."""

    first: Genesis
    chain: list[StoredEvent]
    head: Artefact
    second: Genesis
    second_chain: list[StoredEvent]
    second_head: Artefact


def two_epochs() -> Log:
    first = genesis()
    contents = [content(i) for i in range(3)]
    chain = [evidenced(event) for event in append(first, contents)]
    head = checkpoint(1, 3, chain[-1].event_hash)
    second = genesis(2, previous=artefact_sha256(head[0]))
    second_chain = [evidenced(event) for event in append(second, contents[:1])]
    second_head = checkpoint(2, 1, second_chain[0].event_hash)
    return Log(first, chain, head, second, second_chain, second_head)


def epoch_lines(
    start: Genesis,
    events: list[StoredEvent],
    *,
    checkpoints: list[tuple[int, Artefact]] = (),  # type: ignore[assignment]
    receipts: bool = True,
) -> list[bytes]:
    """An epoch's records in the bundle's placement; ``checkpoints`` are placed
    after the event at their ``team_seq``, or after the genesis for 0."""
    lines = [genesis_line(start)]
    lines += [checkpoint_line(*artefact) for team_seq, artefact in checkpoints if team_seq == 0]
    for event in events:
        lines.append(event_line(event))
        if receipts:
            lines.append(receipt_line(*receipt(event, _event_id(event))))
        lines += [
            checkpoint_line(*artefact)
            for team_seq, artefact in checkpoints
            if team_seq == event.link.team_seq
        ]
    return lines


def _event_id(event: StoredEvent) -> str:
    return EVENT_IDS[(event.link.team_seq - 1) % len(EVENT_IDS)]


def bundle(log: Log, *, second_epoch: bool = True, first_events: int = 3) -> list[bytes]:
    lines = [header_line(TEAM_ID)]
    head = [(3, log.head)] if first_events == 3 else []
    lines += epoch_lines(log.first, log.chain[:first_events], checkpoints=head)
    if second_epoch:
        lines += epoch_lines(log.second, log.second_chain, checkpoints=[(1, log.second_head)])
    return lines


def without(lines: list[bytes], line: bytes) -> list[bytes]:
    return [kept for kept in lines if kept != line]


@dataclass
class ExportCase:
    name: str
    lines: list[bytes]
    # What the report must hold, written by hand; the vector records the whole report.
    expect: dict[str, Any]
    witness_receipts: list[Artefact] = field(default_factory=list)
    witness_checkpoints: list[Artefact] = field(default_factory=list)
    receipt_keys: tuple[str, ...] = (LOGS_DID,)
    checkpoint_keys: tuple[str, ...] = (LOGS_DID,)


@dataclass
class MalformedCase:
    name: str
    lines: list[bytes]
    line: int


def _purged(log: Log) -> list[bytes]:
    chain = list(log.chain)
    chain[1] = dataclasses.replace(chain[1], content=None, purge_act=ERASE_ACT)
    lines = [header_line(TEAM_ID)]
    return lines + epoch_lines(log.first, chain, checkpoints=[(3, log.head)])


def _spliced(log: Log) -> list[bytes]:
    early = checkpoint(1, 2, log.chain[1].event_hash)
    second = genesis(2, previous=artefact_sha256(early[0]))
    lines = [header_line(TEAM_ID)]
    lines += epoch_lines(log.first, log.chain, checkpoints=[(2, early), (3, log.head)])
    return lines + epoch_lines(second, [evidenced(e) for e in append(second, [content(0)])])


def _third_after_first(log: Log) -> list[bytes]:
    third = genesis(3, previous=artefact_sha256(log.head[0]))
    lines = [header_line(TEAM_ID)]
    lines += epoch_lines(log.first, log.chain, checkpoints=[(3, log.head)])
    return lines + epoch_lines(third, [evidenced(e) for e in append(third, [content(0)])])


def _misplaced_receipt(log: Log) -> list[bytes]:
    lines = bundle(log, second_epoch=False)
    first = receipt_line(*receipt(log.chain[0], EVENT_IDS[0]))
    lines.remove(first)
    lines.insert(lines.index(event_line(log.chain[2])) + 1, first)
    return lines


def _reordered_events(log: Log) -> list[bytes]:
    lines = [header_line(TEAM_ID), genesis_line(log.first)]
    return lines + [event_line(log.chain[i]) for i in (0, 2, 1)]


def _duplicated_event(log: Log) -> list[bytes]:
    lines = [header_line(TEAM_ID), genesis_line(log.first)]
    return lines + [event_line(log.chain[i]) for i in (0, 1, 1, 2)]


def _altered_content(log: Log) -> list[bytes]:
    chain = list(log.chain)
    assert chain[0].content is not None
    other = chain[1].content
    assert other is not None
    chain[0] = dataclasses.replace(
        chain[0], content=dataclasses.replace(chain[0].content, salt=other.salt)
    )
    return [header_line(TEAM_ID), *epoch_lines(log.first, chain, checkpoints=[(3, log.head)])]


def _foreign_key_evidence(log: Log) -> list[bytes]:
    chain = list(log.chain)
    assert chain[1].key_evidence is not None and chain[2].content is not None
    chain[1] = dataclasses.replace(
        chain[1],
        key_evidence={**chain[1].key_evidence, "did_key": chain[2].content.producer_did_key},
    )
    return [header_line(TEAM_ID), *epoch_lines(log.first, chain, checkpoints=[(3, log.head)])]


def _foreign_checkpoint(log: Log) -> list[bytes]:
    forged = checkpoint(1, 3, log.chain[-1].event_hash, key_seed=OTHER_LOGS_SEED)
    lines = [header_line(TEAM_ID)]
    return lines + epoch_lines(log.first, log.chain, checkpoints=[(3, forged)])


def _epoch(chain_epoch: int, **extra: Any) -> dict[str, Any]:
    return {"chain_epoch": chain_epoch, **extra}


def cases() -> list[ExportCase]:
    log = two_epochs()
    later_receipt = receipt(log.chain[2], EVENT_IDS[2])
    return [
        ExportCase(
            "whole_log_of_two_epochs",
            bundle(log),
            {
                "intact": True,
                "epochs": [
                    _epoch(1, intact=True, linked=True, anchored_to=3),
                    _epoch(2, intact=True, linked=True, anchored_to=1),
                ],
                "last_checkpoint": {"chain_epoch": 2, "team_seq": 1},
            },
        ),
        ExportCase(
            "purged_event_keeps_its_skeleton_and_act",
            _purged(log),
            {
                "intact": True,
                "epochs": [
                    _epoch(1, intact=True, purged=[{"from": 2, "to": 2, "act": ERASE_ACT}])
                ],
            },
        ),
        ExportCase(
            "events_after_the_last_checkpoint_are_unanchored",
            without(bundle(log, second_epoch=False), checkpoint_line(*log.head)),
            {"intact": True, "epochs": [_epoch(1, intact=True, unanchored=[1, 3])]},
        ),
        ExportCase(
            "truncated_tail_verifies_alone",
            bundle(log, second_epoch=False, first_events=2),
            {"intact": True, "epochs": [_epoch(1, intact=True, unanchored=[1, 2])]},
        ),
        ExportCase(
            "truncated_tail_contradicts_a_later_receipt",
            bundle(log, second_epoch=False, first_events=2),
            {
                "intact": False,
                "witnesses": {
                    "contradicted": [{"artefact": "receipt", "index": 0, "reason": "not_in_chain"}]
                },
            },
            witness_receipts=[later_receipt],
        ),
        ExportCase(
            "dropped_final_epoch_verifies_alone",
            bundle(log, second_epoch=False),
            {"intact": True, "epochs": [_epoch(1, intact=True, anchored_to=3)]},
        ),
        ExportCase(
            "dropped_final_epoch_contradicts_its_checkpoint",
            bundle(log, second_epoch=False),
            {
                "intact": False,
                "witnesses": {
                    "contradicted": [
                        {"artefact": "checkpoint", "index": 0, "reason": "epoch_absent"}
                    ]
                },
            },
            witness_checkpoints=[log.second_head],
        ),
        ExportCase(
            "witnesses_that_hold",
            bundle(log),
            {"intact": True, "witnesses": {"contradicted": []}},
            witness_receipts=[later_receipt],
            witness_checkpoints=[log.head, log.second_head],
        ),
        ExportCase(
            "witness_signed_by_another_key",
            bundle(log),
            {
                "intact": False,
                "witnesses": {
                    "contradicted": [
                        {"artefact": "checkpoint", "index": 0, "reason": "signature_invalid"}
                    ]
                },
            },
            witness_checkpoints=[
                checkpoint(1, 3, log.chain[-1].event_hash, key_seed=OTHER_LOGS_SEED)
            ],
        ),
        ExportCase(
            "witness_of_another_team_than_the_bundle_is_wrong_chain",
            [header_line("other:example.com"), *bundle(log, second_epoch=False, first_events=2)[1:]],
            {
                "intact": False,
                "witnesses": {
                    "contradicted": [{"artefact": "receipt", "index": 0, "reason": "wrong_chain"}]
                },
            },
            witness_receipts=[later_receipt],
        ),
        ExportCase(
            "epoch_naming_an_earlier_checkpoint_is_unlinked",
            _spliced(log),
            {"intact": False, "epochs": [_epoch(1, linked=True), _epoch(2, linked=False)]},
        ),
        ExportCase(
            "skipped_epoch_is_unlinked",
            _third_after_first(log),
            {"intact": False, "epochs": [_epoch(1, linked=True), _epoch(3, linked=False)]},
        ),
        ExportCase(
            "bundle_starting_after_the_first_epoch_is_unlinked",
            [
                header_line(TEAM_ID),
                *epoch_lines(log.second, log.second_chain, checkpoints=[(1, log.second_head)]),
            ],
            {"intact": False, "epochs": [_epoch(2, intact=True, linked=False)]},
        ),
        ExportCase(
            "receipt_away_from_its_event_is_misplaced",
            _misplaced_receipt(log),
            {
                "intact": False,
                "epochs": [
                    _epoch(
                        1,
                        contradicted=[{"artefact": "receipt", "index": 1, "reason": "misplaced"}],
                    )
                ],
            },
        ),
        ExportCase(
            "event_out_of_position_order_is_misplaced",
            _reordered_events(log),
            {
                "intact": False,
                "epochs": [_epoch(1, first_break={"team_seq": 2, "reason": "misplaced"})],
            },
        ),
        ExportCase(
            "repeated_event_is_a_duplicate",
            _duplicated_event(log),
            {
                "intact": False,
                "epochs": [_epoch(1, first_break={"team_seq": 2, "reason": "sequence_duplicate"})],
            },
        ),
        ExportCase(
            "altered_content_breaks_its_commitment",
            _altered_content(log),
            {
                "intact": False,
                "epochs": [_epoch(1, first_break={"team_seq": 1, "reason": "commitment_mismatch"})],
            },
        ),
        ExportCase(
            "key_evidence_that_is_not_the_producer",
            _foreign_key_evidence(log),
            {
                "intact": False,
                "epochs": [_epoch(1, first_break={"team_seq": 2, "reason": "provenance_invalid"})],
            },
        ),
        ExportCase(
            "checkpoint_by_a_key_not_accepted_anchors_nothing",
            _foreign_checkpoint(log),
            {
                "intact": False,
                "epochs": [
                    _epoch(
                        1,
                        unanchored=[1, 3],
                        contradicted=[
                            {"artefact": "checkpoint", "index": 0, "reason": "signature_invalid"}
                        ],
                    )
                ],
            },
        ),
    ]


def _replace(index: int, line: bytes) -> Callable[[list[bytes]], list[bytes]]:
    return lambda lines: [*lines[:index], line, *lines[index + 1 :]]


def malformed_cases() -> list[MalformedCase]:
    log = two_epochs()
    lines = bundle(log)
    second_genesis = lines.index(genesis_line(log.second))
    return [
        MalformedCase("header_of_another_type", _replace(0, b'{"team_id":"x","type":"other","v":1}\n')(lines), 1),
        MalformedCase("no_header", lines[1:], 1),
        MalformedCase("line_not_canonical", _replace(2, lines[2].rstrip(b"\n") + b" \n")(lines), 3),
        MalformedCase("line_not_an_object", _replace(2, b"[]\n")(lines), 3),
        MalformedCase("event_before_its_genesis", [lines[0], lines[2], lines[1], *lines[3:]], 2),
        MalformedCase("record_of_an_unknown_kind", _replace(3, b'{"note":"x"}\n')(lines), 4),
        MalformedCase(
            "epochs_out_of_order",
            [*lines[:1], *lines[second_genesis:], *lines[1:second_genesis]],
            len(lines) - second_genesis + 2,
        ),
        MalformedCase(
            "first_genesis_with_an_empty_previous_checkpoint",
            _replace(1, _set_field(lines[1], "genesis", "previous_checkpoint_sha256", ""))(lines),
            2,
        ),
        MalformedCase(
            "first_genesis_with_a_number_for_previous_checkpoint",
            _replace(1, _set_field(lines[1], "genesis", "previous_checkpoint_sha256", 7))(lines),
            2,
        ),
        MalformedCase(
            "empty_purge_act",
            _replace(2, _set_field(lines[2], "event", "purge_act", ""))(lines),
            3,
        ),
        MalformedCase(
            "event_without_key_evidence",
            _replace(2, _drop_field(lines[2], "event", "key_evidence"))(lines),
            3,
        ),
    ]


def _drop_field(line: bytes, record: str, name: str) -> bytes:
    value = json.loads(line)
    del value[record][name]
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


def _set_field(line: bytes, record: str, name: str, value: Any) -> bytes:
    changed = json.loads(line)
    changed[record][name] = value
    if record == "event" and name == "purge_act":
        del changed[record]["content"]
    return (json.dumps(changed, separators=(",", ":"), sort_keys=True) + "\n").encode()
