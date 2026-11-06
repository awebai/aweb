"""A logs deployment's configuration for the tests: a key file per kid its
committed manifest template declares. The runtime fills the template's
app.id, origin and did:keys from configuration (aweb-acin); ``served_manifest``
is the same filling, for tests that read a manifest without running the app."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from aweb_naapp.manifest import fill_manifest
from aweb_naapp.signing_key import read_signing_key_file
from awid.did import did_from_public_key

from aweb_logs import MANIFEST_PATH

# A deployment's own app id: the hosted id is refused at any other reachable origin.
TEST_APP_ID = "logs-test"


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


def served_manifest(
    key_files: dict[str, Path], *, origin: str, manifest: dict[str, Any] | None = None
) -> bytes:
    """The bytes a deployment with these key files serves at ``origin``, for
    the committed template or another ``manifest`` template."""
    return fill_manifest(
        manifest if manifest is not None else template(),
        app_id=TEST_APP_ID,
        origin=origin,
        did_keys={kid: did_key_of(path) for kid, path in key_files.items()},
    )
