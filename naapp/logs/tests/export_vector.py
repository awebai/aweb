"""Building ``docs/vectors/logs-export-v1.json`` from the export cases, and reading it back."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

from aweb_logs.export import MAX_LINE_BYTES, verify_bundle

from .chain_vector import b64, unb64
from .export_cases import ExportCase, cases, malformed_cases

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTOR_PATH = AWEB_ROOT / "docs" / "vectors" / "logs-export-v1.json"

SCHEME = {
    "authority": "docs/logs-chain.md, 'Exporting a team's log'",
    "bundle": "JSON Lines: each entry of bundle_lines is one line without its newline; the bundle is every line followed by one newline; no line, its newline excluded, is longer than max_line_bytes",
    "cases": "receipt_keys and checkpoint_keys are the keys the verifier accepts; witness_receipts and witness_checkpoints are artefacts it holds independently of the exporter; report is what a bundle verifier must return",
    "malformed": "a bundle the verifier refuses; line is the number, from 1, of its first bad line",
    "max_line_bytes": MAX_LINE_BYTES,
    "encoding": "witness artefacts are signing_bytes_b64url (unpadded base64url) and signature (86 characters of standard base64, no padding)",
}


def _artefact_json(artefact: tuple[bytes, str]) -> dict[str, str]:
    return {"signing_bytes_b64url": b64(artefact[0]), "signature": artefact[1]}


def report(case: ExportCase) -> dict[str, Any]:
    return verify_bundle(
        stream(case.lines),
        receipt_keys=frozenset(case.receipt_keys),
        checkpoint_keys=frozenset(case.checkpoint_keys),
        witness_receipts=case.witness_receipts,
        witness_checkpoints=case.witness_checkpoints,
    ).to_json()


def _lines(lines: list[bytes]) -> list[str]:
    return [line.removesuffix(b"\n").decode("ascii") for line in lines]


def build_vector() -> dict[str, Any]:
    return {
        "name": "logs-export-v1",
        "status": "proposed (aweb-acgh.16.23); frozen once reviewed",
        "scheme": SCHEME,
        "cases": [
            {
                "name": case.name,
                "bundle_lines": _lines(case.lines),
                "receipt_keys": list(case.receipt_keys),
                "checkpoint_keys": list(case.checkpoint_keys),
                "witness_receipts": [_artefact_json(a) for a in case.witness_receipts],
                "witness_checkpoints": [_artefact_json(a) for a in case.witness_checkpoints],
                "report": report(case),
            }
            for case in cases()
        ],
        "malformed": [
            {"name": case.name, "bundle_lines": _lines(case.lines), "line": case.line}
            for case in malformed_cases()
        ],
    }


def render(vector: dict[str, Any]) -> bytes:
    return (json.dumps(vector, indent=2, sort_keys=True) + "\n").encode("ascii")


def stream(lines: list[bytes]) -> io.BytesIO:
    """A bundle's lines, each ending in its newline, as the stream a verifier reads."""
    return io.BytesIO(b"".join(lines))


def bundle_stream(entry: dict[str, Any]) -> io.BytesIO:
    return stream([line.encode("ascii") + b"\n" for line in entry["bundle_lines"]])


def artefacts(entries: list[dict[str, str]]) -> list[tuple[bytes, str]]:
    return [(unb64(entry["signing_bytes_b64url"]), entry["signature"]) for entry in entries]
