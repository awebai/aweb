"""Verifying an exported team log, ``aweb.logs-export/1`` (docs/logs-chain.md):
real signed envelopes, receipts and checkpoints, checked with no server."""

from __future__ import annotations

from typing import Any

import pytest

from aweb_logs.chain import artefact_sha256
from aweb_logs.export import (
    BundleMalformed,
    checkpoint_line,
    verify_bundle,
)

from .chain_cases import EVENT_IDS, LOGS_DID, receipt
from .export_cases import bundle, two_epochs
from .export_vector import stream

KEYS = frozenset({LOGS_DID})


def verified(lines: list[bytes], **witnesses: Any) -> dict[str, Any]:
    return verify_bundle(
        stream(lines), receipt_keys=KEYS, checkpoint_keys=KEYS, **witnesses
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
        "signing_bytes_sha256": artefact_sha256(log.second_head[0]),
    }
    assert report["witnesses"] == {"contradicted": []}


def test_events_after_the_last_checkpoint_are_present_but_unanchored() -> None:
    log = two_epochs()
    head = checkpoint_line(*log.head)
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

    held = receipt(log.chain[2], EVENT_IDS[2])
    report = verified(truncated, witness_receipts=[held])
    assert report["intact"] is False
    assert report["witnesses"]["contradicted"] == [
        {"artefact": "receipt", "index": 0, "reason": "not_in_chain"}
    ]


def test_a_dropped_final_epoch_is_caught_by_a_witness_of_it() -> None:
    log = two_epochs()
    report = verified(
        bundle(log, second_epoch=False), witness_checkpoints=[log.second_head]
    )
    assert report["intact"] is False
    assert report["witnesses"]["contradicted"] == [
        {"artefact": "checkpoint", "index": 0, "reason": "epoch_absent"}
    ]


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
