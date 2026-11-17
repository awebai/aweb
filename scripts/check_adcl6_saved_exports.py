#!/usr/bin/env python3
"""Exercise the journey's outside assertions on saved, real creation exports."""

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from adcl6_first_path import save


def check(saved, output, probe):
    output.mkdir(mode=0o700)
    first = json.loads((saved / "public-exports/first.json").read_text())
    second = json.loads((saved / "public-exports/second.json").read_text())
    cases = [
        ("positive-first", "first", first, None),
        ("positive-second", "second", second, None),
    ]
    altered = copy.deepcopy(first)
    assertion = altered["evidence"]["links"][0]["receipt"]["assertion"]
    encoded = assertion["signature"]
    signature = bytearray(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    signature[-1] ^= 1
    assertion["signature"] = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    cases.append(
        (
            "receipt-byte-flipped",
            "first",
            altered,
            "outside_proof_invalid:signature_invalid",
        )
    )
    altered = copy.deepcopy(second)
    for member in ("statement", "receipt"):
        altered["evidence"]["links"][0][member] = copy.deepcopy(
            first["evidence"]["links"][0][member]
        )
    cases.append(
        (
            "other-person-evidence",
            "second",
            altered,
            "outside_statement_invalid:binding_mismatch",
        )
    )
    altered = copy.deepcopy(first)
    altered["evidence"]["links"][0]["statement"]["evidence"]["creation"]["grade"] = (
        "password_only"
    )
    # The signed creation profile has no valid below-UV grade: this is malformed,
    # while the direct phase unit separately checks a below-UV result is refused.
    cases.append(
        ("grade-below-uv", "first", altered, "outside_statement_invalid:malformed")
    )
    altered = copy.deepcopy(first)
    # Keep both genuine certificate signatures: two namespace-issued siblings
    # cannot be spliced into a continuous parent/child presentation.
    altered["id_chain"]["certificates"] = [
        copy.deepcopy(second["id_chain"]["certificates"][0]),
        copy.deepcopy(first["id_chain"]["certificates"][0]),
    ]
    cases.append(
        (
            "broken-presented-continuity",
            "first",
            altered,
            "outside_identity_invalid:missing_parent",
        )
    )
    rows = []
    for name, person, export, expected in cases:
        path = output / (name + ".json")
        save(path, export)
        with tempfile.TemporaryDirectory(prefix="adcl6-check-") as temporary:
            root = Path(temporary)
            home, cwd = root / "home", root / "cwd"
            home.mkdir()
            cwd.mkdir()
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("adcl6_first_path.py").resolve()),
                    "check-saved-export",
                    "--probe",
                    str(probe),
                    "--original-export",
                    str(saved / f"public-exports/{person}.json"),
                    "--original-verdict",
                    str(saved / f"{person}-outside.json"),
                    "--export",
                    str(path),
                ],
                cwd=cwd,
                env={
                    "PATH": os.environ["PATH"],
                    "HOME": str(home),
                    "TMPDIR": str(root),
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                text=True,
                capture_output=True,
                timeout=30,
            )
            assert not list(home.iterdir()) and not (cwd / ".aw").exists()
        (output / (name + ".stdout.json")).write_text(result.stdout)
        (output / (name + ".stderr")).write_text(result.stderr)
        if expected is None:
            assert result.returncode == 0, result.stderr
        else:
            assert result.returncode == 1 and expected in result.stderr, (
                name,
                result.returncode,
                result.stderr,
            )
        rows.append(
            {"case": name, "exit": result.returncode, "expected_reason": expected}
        )
        print("PASS:", name, "exit", result.returncode, expected or "valid")
    save(
        output / "receipt.json",
        {
            "basis": "frozen original checked observation, not current public status",
            "controls": rows,
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--saved-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    args = parser.parse_args()
    check(args.saved_dir.resolve(), args.output.resolve(), args.probe.resolve())
