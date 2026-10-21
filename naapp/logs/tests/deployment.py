"""A logs deployment's configuration for the tests: a key file per kid the
manifest template declares, and the template filled with the did:keys derived
from those files, as the deployment serves it (aweb-acin)."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from aweb_naapp.manifest import canonical_bytes
from aweb_naapp.signing_key import read_signing_key_file
from awid.did import did_from_public_key

from aweb_logs import MANIFEST_PATH


def template() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_bytes())


def template_kids() -> list[str]:
    return [entry["kid"] for entry in template()["app_keys"]]


def write_key_file(path: Path) -> Path:
    path.write_text(secrets.token_hex(32) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def write_key_files(directory: Path) -> dict[str, Path]:
    """A freshly generated key file for each kid of the template."""
    return {kid: write_key_file(directory / f"key-{index}") for index, kid in enumerate(template_kids())}


def did_key_of(key_file: Path) -> str:
    return did_from_public_key(bytes(read_signing_key_file(key_file).verify_key))


def filled_manifest(key_files: dict[str, Path]) -> bytes:
    """The template with each kid's did:key derived from its key file."""
    manifest = template()
    for entry in manifest["app_keys"]:
        entry["did_key"] = did_key_of(key_files[entry["kid"]])
    return canonical_bytes(manifest)
