"""A bundle line is at most MAX_LINE_BYTES, newline excluded, and the verifier
refuses a longer line without reading it whole (docs/logs-chain.md,
"Exporting a team's log")."""

from __future__ import annotations

import dataclasses
import io
import json
from typing import Any

import pytest
from aweb_naapp.hooks.envelope import MAX_ENVELOPE_BYTES

from aweb_logs.export import MAX_LINE_BYTES, BundleMalformed, event_line, verify_bundle

from .export_cases import two_epochs
from .export_vector import VECTOR_PATH, artefacts, stream

VECTOR: dict[str, Any] = json.loads(VECTOR_PATH.read_bytes())
PURGED = next(c for c in VECTOR["cases"] if c["name"] == "purged_event_keeps_its_skeleton_and_act")
ACT = PURGED["report"]["epochs"][0]["purged"][0]["act"]
PURGED_LINE = next(
    i for i, line in enumerate(PURGED["bundle_lines"]) if f'"purge_act":"{ACT}"' in line
)


def with_act_padded_to(length: int) -> tuple[list[bytes], str]:
    """The purged case with its purge act lengthened so its event line is ``length`` bytes."""
    line = PURGED["bundle_lines"][PURGED_LINE]
    act = ACT + "x" * (length - len(line))
    lines = list(PURGED["bundle_lines"])
    lines[PURGED_LINE] = line.replace(f'"purge_act":"{ACT}"', f'"purge_act":"{act}"')
    assert len(lines[PURGED_LINE]) == length
    return [line.encode("ascii") + b"\n" for line in lines], act


def verify(bundle: io.BufferedIOBase) -> dict[str, Any]:
    return verify_bundle(
        bundle,
        receipt_keys=frozenset(PURGED["receipt_keys"]),
        checkpoint_keys=frozenset(PURGED["checkpoint_keys"]),
        witness_receipts=artefacts(PURGED["witness_receipts"]),
        witness_checkpoints=artefacts(PURGED["witness_checkpoints"]),
    ).to_json()


def test_a_line_of_exactly_the_bound_is_verified() -> None:
    lines, act = with_act_padded_to(MAX_LINE_BYTES)
    report = verify(stream(lines))
    assert report["intact"] is True
    assert report["epochs"][0]["purged"] == [{"from": 2, "to": 2, "act": act}]


def test_a_line_one_byte_over_the_bound_is_refused_at_its_number() -> None:
    lines, _ = with_act_padded_to(MAX_LINE_BYTES + 1)
    with pytest.raises(BundleMalformed) as refused:
        verify(stream(lines))
    assert refused.value.line == PURGED_LINE + 1


class Endless(io.RawIOBase):
    """A header line, then a second line that never ends."""

    def __init__(self, header: bytes) -> None:
        self.header = header

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        view = memoryview(buffer).cast("B")
        given = self.header[: len(view)]
        self.header = self.header[len(given) :]
        view[: len(given)] = given
        view[len(given) :] = b"x" * (len(view) - len(given))
        return len(view)


def test_an_endless_line_is_refused_without_being_read_whole() -> None:
    header = PURGED["bundle_lines"][0].encode("ascii") + b"\n"
    with pytest.raises(BundleMalformed) as refused:
        verify(io.BufferedReader(Endless(header)))
    assert refused.value.line == 2


def test_the_largest_envelope_an_event_can_carry_fits_in_a_line() -> None:
    stored = two_epochs().chain[0]
    assert stored.content is not None
    largest = dataclasses.replace(
        stored,
        content=dataclasses.replace(stored.content, signing_bytes=b"\xff" * MAX_ENVELOPE_BYTES),
    )
    assert len(event_line(largest)) - 1 <= MAX_LINE_BYTES


def test_the_vector_pins_the_bound() -> None:
    assert VECTOR["scheme"]["max_line_bytes"] == MAX_LINE_BYTES
