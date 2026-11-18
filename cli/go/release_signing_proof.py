#!/usr/bin/env python3
"""Prepare or verify a throwaway hardware proof; never generate or pin a key."""

import argparse
import base64
from enum import Enum
import json
from pathlib import Path
import subprocess

from generate_install_verifier import proof_verifier
from release_manifest import create_manifest, create_statement, parse_statement


class ProofCommand(Enum):
    PREPARE = "prepare"
    VERIFY = "verify"


def prepare_proof(*, directory, source_commit):
    directory.mkdir(mode=0o700)
    artifact = directory / "release-proof.bin"
    artifact.write_bytes(b"Throwaway aweb release-signing proof; never publish.\n")
    raw = create_manifest(
        version="0.0.0-rc.1",
        source_commit=source_commit,
        artifacts=[artifact],
        output=directory / "release-manifest.json",
    )
    (directory / "release-statement.txt").write_bytes(create_statement(raw))
    print((directory / "release-statement.txt").read_text(), end="")


def verify_proof(*, directory, public_key):
    # Reject a different algorithm or trailing DER bytes before extracting a pin.
    der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        capture_output=True,
        check=True,
    ).stdout
    prefix = bytes.fromhex("302a300506032b6570032100")
    if len(der) != len(prefix) + 32 or not der.startswith(prefix):
        raise ValueError(
            "proof public key must be exactly Ed25519 SubjectPublicKeyInfo"
        )
    keys = json.dumps({"proof-only": base64.b64encode(der[len(prefix) :]).decode()})
    (directory / "proof-keys.json").write_text(keys)
    statement = (directory / "release-statement.txt").read_bytes()
    parse_statement(statement)
    signature = (directory / "release-statement.rawsig").read_bytes()
    if len(signature) != 64:
        raise ValueError("proof signature must be 64 raw bytes")
    (directory / "release-manifest.sig").write_text(
        json.dumps(
            {
                "key_id": "proof-only",
                "statement": base64.b64encode(statement).decode(),
                "signature": base64.b64encode(signature).decode(),
            }
        )
        + "\n"
    )
    subprocess.run(
        [
            "go",
            "run",
            "./internal/releaseverify/cmd/proof",
            "--directory",
            str(directory),
        ],
        cwd=Path(__file__).resolve().parent,
        check=True,
    )
    script = proof_verifier(keys) + '\nverify_signed_release "$1" "$2" "$3" "$4"'
    original = directory / "release-manifest.json"
    tampered = directory / "tampered-manifest.json"
    tampered.write_bytes(original.read_bytes() + b"\n")
    for manifest in (original, tampered):
        result = subprocess.run(
            [
                "bash",
                "-c",
                script,
                "proof",
                str(directory / "release-proof.bin"),
                str(manifest),
                str(directory / "release-manifest.sig"),
                "0.0.0-rc.1",
            ],
            capture_output=True,
            text=True,
        )
        if manifest == original:
            if result.returncode:
                raise ValueError(f"shell refused original proof: {result.stderr}")
            print("PASS shell: signed statement -> exact manifest -> artifact")
        else:
            if (
                result.returncode == 0
                or "manifest digest" not in result.stderr
                or "Retry the installer" not in result.stderr
            ):
                raise ValueError(
                    f"shell did not give the expected tamper refusal: {result.stderr}"
                )
            print("PASS shell: tampered manifest refused with retry guidance")
    print("Proof files contain public material only; production pins remain unchanged.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--directory", type=Path, required=True)
    prepare.add_argument("--commit", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--directory", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    command = ProofCommand(args.command)
    if command is ProofCommand.PREPARE:
        prepare_proof(directory=args.directory.resolve(), source_commit=args.commit)
    else:
        verify_proof(
            directory=args.directory.resolve(), public_key=args.public_key.resolve()
        )


if __name__ == "__main__":
    main()
