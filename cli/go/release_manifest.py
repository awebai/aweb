#!/usr/bin/env python3
"""Stage, verify and read back provider-independent signed aw release bytes."""

from __future__ import annotations

import argparse
from enum import Enum
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request

SCHEMA = "aw-release-manifest-v1"
STATEMENT_SCHEMA = "aw-release-statement-v1"
MAX_STATEMENT_BYTES = 256


class ManifestCommand(Enum):
    CREATE = "create"
    VERIFY = "verify"
    READBACK = "readback"
    STATEMENT = "statement"
    ATTACH = "attach-signature"


HERE = Path(__file__).resolve().parent


def version_key(value):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-rc\.([1-9]\d*))?", value)
    if not match:
        raise ValueError("invalid release version")
    major, minor, patch, rc = match.groups()
    return int(major), int(minor), int(patch), rc is None, int(rc or 0)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest JSON key")
        result[key] = value
    return result


def parse_statement(statement):
    """Enforce docs/install-integrity.md:28-39, the bounded canonical statement."""
    if len(statement) > MAX_STATEMENT_BYTES:
        raise ValueError("release statement exceeds 256 bytes")
    match = re.fullmatch(
        rb"aw-release-statement-v1\nversion=(v?[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?)\n"
        rb"source_commit=([0-9a-f]{40}(?:[0-9a-f]{24})?)\n"
        rb"manifest_sha256=([0-9a-f]{64})\n",
        statement,
    )
    if not match:
        raise ValueError("invalid canonical release statement")
    return tuple(field.decode("ascii") for field in match.groups())


def create_statement(manifest_bytes):
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
    statement = (
        f"{STATEMENT_SCHEMA}\nversion={manifest['version']}\n"
        f"source_commit={manifest['source_commit']}\n"
        f"manifest_sha256={hashlib.sha256(manifest_bytes).hexdigest()}\n"
    ).encode("ascii")
    parse_statement(statement)
    return statement


def verify_manifest(
    *, manifest_bytes, signature_bytes, keys, requested_version, running_version=""
):
    signature = json.loads(signature_bytes, object_pairs_hook=unique_object)
    if not isinstance(signature, dict):
        raise ValueError("release signature envelope must be an object")
    public = base64.b64decode(keys.get(signature["key_id"], ""), validate=True)
    signed = base64.b64decode(signature["signature"], validate=True)
    statement = base64.b64decode(signature["statement"], validate=True)
    if len(statement) > MAX_STATEMENT_BYTES:
        raise ValueError("release statement exceeds 256 bytes")
    if len(public) != 32 or len(signed) != 64:
        raise ValueError("release signing key is not pinned or signature is malformed")
    # Ed25519 SubjectPublicKeyInfo prefix followed by the pinned public key.
    with tempfile.TemporaryDirectory(prefix="aw-release-verify-") as tmp:
        directory = Path(tmp)
        (directory / "key.der").write_bytes(
            bytes.fromhex("302a300506032b6570032100") + public
        )
        (directory / "statement").write_bytes(statement)
        (directory / "signature").write_bytes(signed)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                str(directory / "key.der"),
                "-rawin",
                "-in",
                str(directory / "statement"),
                "-sigfile",
                str(directory / "signature"),
            ],
            capture_output=True,
        )
        if result.returncode:
            raise ValueError(
                "invalid publisher signature (OpenSSL with Ed25519 support is required)"
            )
    statement_version, statement_commit, statement_digest = parse_statement(statement)
    if hashlib.sha256(manifest_bytes).hexdigest() != statement_digest:
        raise ValueError("release manifest digest does not match signed statement")
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
    if (
        manifest.get("version") != statement_version
        or manifest.get("source_commit") != statement_commit
    ):
        raise ValueError(
            "release statement version or source commit differs from manifest"
        )
    if manifest.get("schema") != SCHEMA or not re.fullmatch(
        r"[0-9a-f]{40}(?:[0-9a-f]{24})?", manifest.get("source_commit", "")
    ):
        raise ValueError("invalid release manifest schema or source commit")
    version = version_key(manifest["version"])
    if version < version_key(requested_version) or (
        running_version
        and running_version != "dev"
        and version < version_key(running_version)
    ):
        raise ValueError(
            "release manifest is older than requested_version or running version"
        )
    if version != version_key(requested_version):
        raise ValueError(
            "release manifest version does not match requested_version version"
        )
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError("release manifest must name its artifacts")
    for name, entry in artifacts.items():
        if (
            not name
            or Path(name).name != name
            or any(c in name for c in "\\\r\n")
            or not re.fullmatch(r"[0-9a-fA-F]{64}", entry["sha256"])
            or type(entry["size"]) is not int
            or entry["size"] < 0
        ):
            raise ValueError("invalid artifact entry")
    return manifest


def stream_digest(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def verify_artifact(file, manifest):
    entry = manifest["artifacts"].get(file.name)
    if entry is None:
        raise ValueError(f"{file.name} is absent from the signed manifest")
    with file.open("rb") as stream:
        digest = stream_digest(stream)
    if file.stat().st_size != entry["size"] or digest != entry["sha256"].lower():
        raise ValueError(f"digest mismatch for {file.name}")


def create_manifest(*, version, source_commit, artifacts, output):
    version_key(version)
    if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", source_commit):
        raise ValueError("source commit must be a full lowercase object id")
    entries = {}
    for file in artifacts:
        if file.name in entries:
            raise ValueError(f"duplicate artifact name {file.name}")
        with file.open("rb") as stream:
            digest = stream_digest(stream)
        entries[file.name] = {"sha256": digest, "size": file.stat().st_size}
    if not entries:
        raise ValueError("no artifacts staged")
    raw = (
        json.dumps(
            dict(
                schema=SCHEMA,
                version=version,
                source_commit=source_commit,
                artifacts=entries,
            ),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    # A staged manifest cannot be overwritten after a signature may exist.
    with output.open("xb") as file:
        file.write(raw)
    return raw


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise ValueError("release redirect must use HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, limit=1 << 20):
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("release readback must use HTTPS")
    with urllib.request.build_opener(HTTPSOnly()).open(url, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("release readback exceeds its size limit")
    return data


def readback_release(
    *,
    manifest_bytes,
    signature_bytes,
    keys,
    requested_version,
    locations,
    fetch_bytes=fetch,
):
    # The two independent locations must not be two paths on one provider host.
    if len({urllib.parse.urlsplit(url).netloc for url in locations}) < 2:
        raise ValueError("readback requires two independent HTTPS locations")
    manifest = verify_manifest(
        manifest_bytes=manifest_bytes,
        signature_bytes=signature_bytes,
        keys=keys,
        requested_version=requested_version,
    )
    for base in locations:
        if fetch_bytes(base.rstrip("/") + "/release-manifest.json") != manifest_bytes:
            raise ValueError("manifest readback bytes differ")
        if fetch_bytes(base.rstrip("/") + "/release-manifest.sig") != signature_bytes:
            raise ValueError("signature readback bytes differ")
        for name, entry in manifest["artifacts"].items():
            artifact = fetch_bytes(
                base.rstrip("/") + "/" + urllib.parse.quote(name), entry["size"]
            )
            if (
                len(artifact) != entry["size"]
                or hashlib.sha256(artifact).hexdigest() != entry["sha256"].lower()
            ):
                raise ValueError(f"digest mismatch in readback for {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("create")
    stage.add_argument("--version", required=True)
    stage.add_argument("--commit", required=True)
    stage.add_argument("--output", type=Path, required=True)
    stage.add_argument("artifacts", nargs="+", type=Path)
    statement = commands.add_parser("statement")
    statement.add_argument("--manifest", type=Path, required=True)
    statement.add_argument("--output", type=Path, required=True)
    attach = commands.add_parser("attach-signature")
    attach.add_argument("--statement", type=Path, required=True)
    attach.add_argument("--raw-signature", type=Path, required=True)
    attach.add_argument("--key-id", required=True)
    attach.add_argument("--output", type=Path, required=True)
    for name in ("verify", "readback"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--signature", type=Path, required=True)
        command.add_argument(
            "--keys", type=Path, default=HERE / "internal/releaseverify/keys.json"
        )
        command.add_argument("--requested", required=True)
        if name == "verify":
            command.add_argument("--current", default="")
            command.add_argument("--artifact", type=Path)
        else:
            command.add_argument("--url", action="append", required=True)
    args = parser.parse_args()
    command = ManifestCommand(args.command)
    try:
        if command is ManifestCommand.CREATE:
            create_manifest(
                version=args.version,
                source_commit=args.commit,
                artifacts=args.artifacts,
                output=args.output,
            )
        elif command is ManifestCommand.STATEMENT:
            with args.output.open("xb") as output:
                output.write(create_statement(args.manifest.read_bytes()))
        elif command is ManifestCommand.ATTACH:
            statement_bytes = args.statement.read_bytes()
            parse_statement(statement_bytes)
            signature = args.raw_signature.read_bytes()
            if len(signature) != 64:
                raise ValueError("raw Ed25519 signature must be 64 bytes")
            with args.output.open("x") as output:
                json.dump(
                    {
                        "key_id": args.key_id,
                        "statement": base64.b64encode(statement_bytes).decode(),
                        "signature": base64.b64encode(signature).decode(),
                    },
                    output,
                )
                output.write("\n")
        else:
            raw, detached = args.manifest.read_bytes(), args.signature.read_bytes()
            keys = json.loads(args.keys.read_bytes(), object_pairs_hook=unique_object)
            if command is ManifestCommand.READBACK:
                readback_release(
                    manifest_bytes=raw,
                    signature_bytes=detached,
                    keys=keys,
                    requested_version=args.requested,
                    locations=args.url,
                )
            else:
                manifest = verify_manifest(
                    manifest_bytes=raw,
                    signature_bytes=detached,
                    keys=keys,
                    requested_version=args.requested,
                    running_version=args.current,
                )
                if args.artifact:
                    verify_artifact(args.artifact, manifest)
        print("PASS: release manifest " + args.command)
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        artifact = getattr(args, "artifact", None)
        print(
            f"Cannot verify {artifact or 'release-manifest.json'}: {error}. Retry the installer or aw upgrade from a current signed release."
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
