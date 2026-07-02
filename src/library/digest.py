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


def _payload_path(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _reject_symlink(root: Path, path: Path) -> None:
    raise ValueError(f"Symlink not allowed in payload: {_payload_path(root, path)}")


def _decode_utf8(root: Path, path: Path, raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"{_payload_path(root, path)}: "
            "blueprint canonical import payload requires UTF-8 text"
        ) from exc


def collect_files(root: Path) -> list[dict[str, str]]:
    """Collect content files under ``root`` into sorted payload entries with
    POSIX paths relative to ``root``. Excluded build/VCS directories are skipped."""
    if root.is_symlink():
        _reject_symlink(root, root)
    root = root.resolve()
    entries: list[dict[str, str]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            if path.is_symlink():
                _reject_symlink(root, path)
            if path.is_dir():
                if path.name not in EXCLUDED_DIRS:
                    pending.append(path)
                continue
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            raw = path.read_bytes()
            entries.append(
                {
                    "content_utf8": _decode_utf8(root, path, raw),
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
