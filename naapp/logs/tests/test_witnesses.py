"""Witness files: receipts and checkpoints a verifier holds independently of
the exporter, one per line in a bundle's own artefact line shape."""

from __future__ import annotations

import io

import pytest
from aweb_naapp.hooks.strictjson import canonical

from aweb_logs.chain import artefact_json
from aweb_logs.export import (
    MAX_LINE_BYTES,
    BundleMalformed,
    checkpoint_line,
    read_witnesses,
    receipt_line,
)

from .export_cases import cases


def _stream(lines: list[bytes]) -> io.BytesIO:
    return io.BytesIO(b"".join(lines))


def test_a_witness_file_reads_back_the_artefacts_written_as_its_lines() -> None:
    case = next(c for c in cases() if c.witness_receipts and c.witness_checkpoints)
    lines = [checkpoint_line(*a) for a in case.witness_checkpoints]
    lines += [receipt_line(*a) for a in case.witness_receipts]
    assert read_witnesses(_stream(lines)) == (case.witness_receipts, case.witness_checkpoints)


def test_an_ingest_ack_receipt_is_a_witness_line_as_it_stands() -> None:
    case = next(c for c in cases() if c.witness_receipts)
    ack = {"receipt": artefact_json(*case.witness_receipts[0])}
    assert read_witnesses(_stream([canonical(ack) + b"\n"])) == (case.witness_receipts[:1], [])


GOOD = b'{"receipt":{"signature":"s","signing_bytes":"YQ"}}\n'


@pytest.mark.parametrize(
    "bad",
    [
        b'{"genesis":{"chain_epoch":1}}\n',
        b'{"team_id":"x","type":"aweb.logs-export","v":1}\n',
        b'{"receipt":{"extra":1,"signature":"s","signing_bytes":"YQ"}}\n',
        b'{"receipt":{"signature":"s","signing_bytes":"Y+Q"}}\n',
        b'{"receipt": {"signature":"s","signing_bytes":"YQ"}}\n',
        b'{"checkpoint":{"signature":"s","signing_bytes":"YQ"},"receipt":{"signature":"s","signing_bytes":"YQ"}}\n',
        b"receipt\n",
        b'{"receipt":{"signature":"s","signing_bytes":"YQ"}}',
        b'{"receipt":{"signature":"' + b"s" * MAX_LINE_BYTES + b'","signing_bytes":"YQ"}}\n',
    ],
    ids=[
        "genesis",
        "header",
        "extra-field",
        "not-base64url",
        "not-canonical",
        "two-records",
        "not-json",
        "no-newline",
        "oversized",
    ],
)
def test_a_witness_line_that_is_not_an_artefact_is_refused_at_its_line(bad: bytes) -> None:
    with pytest.raises(BundleMalformed) as refused:
        read_witnesses(_stream([GOOD, bad]))
    assert refused.value.line == 2
