"""Content-addressed digests for blueprints and profiles.

The canonical form + digest are a cross-lane contract shared with the aw CLI (the
.2.9 conformance fixture) and verified byte-identical to the Go side. The digest
hashes blueprint CONTENT only, using the same canonical-JSON primitive as the
app manifest (``aweb_manifest.canonical_bytes`` — no second canonicalization).

Access-control attributes (visibility, owner_team) live on the Library record,
NOT in the hashed payload, so flipping a profile public never changes its digest.

- Blueprint payload (``aweb.blueprint.import-payload.v1``): every blueprint file, paths
  blueprint-relative.
- Profile payload (``aweb.blueprint.profile-payload.v1``): one profile's files,
  paths PROFILE-relative.
Files are sorted by POSIX path; each entry is {content_utf8, path, sha256}.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from library.aweb_manifest import canonical_bytes

BLUEPRINT_PAYLOAD_SCHEMA = "aweb.blueprint.import-payload.v1"
PROFILE_PAYLOAD_SCHEMA = "aweb.blueprint.profile-payload.v1"

# VCS, dependency, and build/cache directories never enter the hashed payload.
EXCLUDED_DIRS = frozenset(
    {".git", ".hg", ".svn", "node_modules", ".cache", "dist", "build", "target", "tmp", "vendor", "__pycache__"}
)


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def collect_files(root: Path) -> list[dict[str, str]]:
    """Collect content files under ``root`` into sorted payload entries with
    POSIX paths relative to ``root``. Excluded build/VCS directories are skipped."""
    root = root.resolve()
    entries: list[dict[str, str]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in relative.parts[:-1]):
            continue
        raw = path.read_bytes()
        entries.append(
            {
                "content_utf8": raw.decode("utf-8"),
                "path": relative.as_posix(),
                "sha256": _sha256_hex(raw),
            }
        )
    entries.sort(key=lambda entry: entry["path"])
    return entries


def payload(files: list[dict[str, str]], schema: str) -> dict[str, Any]:
    """The canonical payload object (files sorted by path)."""
    return {"files": sorted(files, key=lambda entry: entry["path"]), "schema": schema}


def payload_digest(files: list[dict[str, str]], schema: str) -> str:
    """``sha256:<hex>`` digest of the canonical payload."""
    return _sha256_hex(canonical_bytes(payload(files, schema)))


def blueprint_digest(blueprint_root: Path) -> str:
    return payload_digest(collect_files(blueprint_root), BLUEPRINT_PAYLOAD_SCHEMA)


def profile_digest(profile_root: Path) -> str:
    return payload_digest(collect_files(profile_root), PROFILE_PAYLOAD_SCHEMA)
