"""Verifying an exported team log, ``aweb.logs-export/1`` (docs/logs-chain.md):
real signed envelopes, receipts and checkpoints, checked with no server."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from aweb_logs.chain import artefact_sha256
from aweb_logs.export import (
    BundleMalformed,
    checkpoint_line,
    event_line,
    genesis_line,
    header_line,
    receipt_line,
    verify_bundle,
)
from aweb_logs.verify import StoredEvent

from .chain_cases import (
    EVENT_IDS,
    LOGS_DID,
    append,
    checkpoint,
    content,
    genesis,
    receipt,
)
from .fixtures import TEAM_ID

KEYS = frozenset({LOGS_DID})


def evidenced(event: StoredEvent) -> StoredEvent:
    assert event.content is not None
    return dataclasses.replace(
        event,
        key_evidence={
            "kid": "hook-2026-10",
            "did_key": event.content.producer_did_key,
            "purposes": ["hook-event"],
        },
    )


def two_epochs() -> dict[str, Any]:
    """A log of two epochs: three events and a head checkpoint, then one event
    and a checkpoint after it."""
    first = genesis()
    contents = [content(i) for i in range(3)]
    chain = [evidenced(event) for event in append(first, contents)]
    head = checkpoint(1, 3, chain[-1].event_hash)
    second = genesis(2, previous=artefact_sha256(head[0]))
    second_chain = [evidenced(event) for event in append(second, contents[:1])]
    second_head = checkpoint(2, 1, second_chain[0].event_hash)
    return {
        "first": first,
        "chain": chain,
        "head": head,
        "second": second,
        "second_chain": second_chain,
        "second_head": second_head,
    }


def epoch_lines(start, events, *, checkpoints=(), receipts=True) -> list[bytes]:
    lines = [genesis_line(start)]
    for index, event in enumerate(events):
        lines.append(event_line(event))
        if receipts:
            lines.append(receipt_line(*receipt(event, EVENT_IDS[index])))
        lines += [
            checkpoint_line(*artefact)
            for team_seq, artefact in checkpoints
            if team_seq == event.link.team_seq
        ]
    return lines


def bundle(log: dict[str, Any], *, second_epoch: bool = True, first_events: int = 3) -> list[bytes]:
    lines = [header_line(TEAM_ID)]
    lines += epoch_lines(log["first"], log["chain"][:first_events], checkpoints=[(3, log["head"])])
    if second_epoch:
        lines += epoch_lines(log["second"], log["second_chain"], checkpoints=[(1, log["second_head"])])
    return lines


def verified(lines: list[bytes], **witnesses: Any) -> dict[str, Any]:
    return verify_bundle(
        lines, receipt_keys=KEYS, checkpoint_keys=KEYS, **witnesses
    ).to_json()


def test_a_whole_log_verifies_and_states_how_far_its_checkpoints_reach() -> None:
    log = two_epochs()
    report = verified(bundle(log))

    assert report["intact"] is True
    assert report["accepted_keys"] == {"receipt": [LOGS_DID], "checkpoint": [LOGS_DID]}
    assert [(e["chain_epoch"], e["linked"], e["anchored_to"]) for e in report["epochs"]] == [
        (1, True, 3),
        (2, True, 1),
    ]
    assert all("unanchored" not in epoch for epoch in report["epochs"])
    assert report["last_checkpoint"] == {
        "chain_epoch": 2,
        "team_seq": 1,
        "signing_bytes_sha256": artefact_sha256(log["second_head"][0]),
    }
    assert report["witnesses"] == {"contradicted": []}


def test_events_after_the_last_checkpoint_are_present_but_unanchored() -> None:
    log = two_epochs()
    head = checkpoint_line(*log["head"])
    lines = [line for line in bundle(log, second_epoch=False) if line != head]

    report = verified(lines)
    assert report["intact"] is True
    [epoch] = report["epochs"]
    assert "anchored_to" not in epoch
    assert epoch["unanchored"] == [1, 3]
    assert "last_checkpoint" not in report


def test_a_truncated_tail_verifies_alone_and_is_caught_by_a_later_witness() -> None:
    log = two_epochs()
    truncated = bundle(log, second_epoch=False, first_events=2)
    assert verified(truncated)["intact"] is True

    held = receipt(log["chain"][2], EVENT_IDS[2])
    report = verified(truncated, witness_receipts=[held])
    assert report["intact"] is False
    assert report["witnesses"]["contradicted"] == [
        {"artefact": "receipt", "index": 0, "reason": "not_in_chain"}
    ]


def test_a_dropped_final_epoch_is_caught_by_a_witness_of_it() -> None:
    log = two_epochs()
    report = verified(
        bundle(log, second_epoch=False), witness_checkpoints=[log["second_head"]]
    )
    assert report["intact"] is False
    assert report["witnesses"]["contradicted"] == [
        {"artefact": "checkpoint", "index": 0, "reason": "epoch_absent"}
    ]


def test_an_epoch_that_does_not_name_its_predecessors_head_is_unlinked() -> None:
    log = two_epochs()
    early = checkpoint(1, 2, log["chain"][1].event_hash)
    spliced = genesis(2, previous=artefact_sha256(early[0]))
    lines = [header_line(TEAM_ID)]
    lines += epoch_lines(log["first"], log["chain"], checkpoints=[(2, early), (3, log["head"])])
    lines += epoch_lines(spliced, [evidenced(e) for e in append(spliced, [content(0)])])

    report = verified(lines)
    assert report["intact"] is False
    assert [epoch["linked"] for epoch in report["epochs"]] == [True, False]


def test_a_receipt_away_from_its_event_is_misplaced() -> None:
    log = two_epochs()
    lines = bundle(log, second_epoch=False)
    first_receipt = receipt_line(*receipt(log["chain"][0], EVENT_IDS[0]))
    lines.remove(first_receipt)
    lines.insert(lines.index(event_line(log["chain"][2])) + 1, first_receipt)

    [epoch] = verified(lines)["epochs"]
    assert {"artefact": "receipt", "index": 1, "reason": "misplaced"} in epoch["contradicted"]


@pytest.mark.parametrize(
    ("damage", "line"),
    [
        (lambda lines: [b'{"v": 1}\n', *lines[1:]], 1),
        (lambda lines: [lines[0], lines[2], *lines[1:2], *lines[3:]], 2),
        (lambda lines: [*lines[:3], lines[3].rstrip(b"\n") + b" \n", *lines[4:]], 4),
    ],
    ids=["header-not-canonical", "event-before-genesis", "line-not-canonical"],
)
def test_a_malformed_bundle_is_refused_at_its_first_bad_line(damage, line: int) -> None:
    with pytest.raises(BundleMalformed) as refused:
        verified(damage(bundle(two_epochs())))
    assert refused.value.line == line
