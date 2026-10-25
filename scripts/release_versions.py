"""Release spellings and tree-only RC promotion checks (no qualification claim)."""

from __future__ import annotations

import copy
import json
import re
import subprocess
import tomllib
from pathlib import Path


SEMVER = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
PYTHON_VERSION = rf"{SEMVER}(?:rc[1-9][0-9]*)?"
NPM_VERSION = rf"{SEMVER}(?:-rc\.[1-9][0-9]*)?"
TAG_PATTERN = re.compile(
    rf"^(?:(server-v|awid-service-v|aweb-naapp-v)({PYTHON_VERSION})"
    rf"|(aw-v)({NPM_VERSION})"
    rf"|(awid-v|channel-v|pi-v|skills-v|a2a-gw-v)({SEMVER}))$"
)


class VersionRefusal(RuntimeError):
    pass


def python_version_key(version: str) -> tuple[int, int, int, int, int]:
    """PEP 440 ordering for our strict X.Y.Z[rcN] release subset."""
    if re.fullmatch(PYTHON_VERSION, version) is None:
        raise VersionRefusal(f"unsupported Python release version {version!r}")
    base, separator, serial = version.partition("rc")
    major, minor, patch = map(int, base.split("."))
    return major, minor, patch, 0 if separator else 1, int(serial) if separator else 0


def tag_parts(tag: str) -> tuple[str, str]:
    matched = TAG_PATTERN.fullmatch(tag)
    if not matched:
        raise VersionRefusal(f"unsupported release tag {tag!r}")
    groups = matched.groups()
    return next((groups[i], groups[i + 1]) for i in (0, 2, 4) if groups[i])


def final_version(version: str) -> str | None:
    matched = re.fullmatch(rf"({SEMVER})(?:rc[1-9][0-9]*|-rc\.[1-9][0-9]*)", version)
    return matched.group(1) if matched else None


def valid_version(path: str, value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(
        PYTHON_VERSION if path.endswith(".toml") else NPM_VERSION, value
    ) is not None


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True)
    if result.returncode:
        raise VersionRefusal(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _name(name: str) -> str:
    return name if name.startswith("@") else re.sub(r"[-_.]+", "-", name).lower()


def _read(root: Path, revision: str, path: str) -> dict:
    raw = _git(root, "show", f"{revision}:{path}")
    return tomllib.loads(raw) if path.endswith(".toml") or path.endswith("uv.lock") else json.loads(raw)


def _manifest(path: str) -> bool:
    return Path(path).name in {"pyproject.toml", "package.json"}


def _package(document: dict, path: str) -> dict:
    return document.get("project", {}) if path.endswith(".toml") else document


def _promote(value: str, name: str, promotions: dict) -> str:
    old, new = promotions.get(_name(name), (None, None))
    return new if value == old else value


def _python_pin(value: str, promotions: dict) -> str:
    # Keep extras, spacing, operators and markers unchanged; only pins or floors.
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)(\[[^\]]+\])?(\s*(?:==|>=)\s*)([^;\s]+)(.*)", value)
    if not match:
        return value
    name, extras, operator, version, tail = match.groups()
    return name + (extras or "") + operator + _promote(version, name, promotions) + tail


def _python_dependencies(value: object, promotions: dict) -> object:
    if isinstance(value, str):
        return _python_pin(value, promotions)
    if isinstance(value, list):
        return [_python_dependencies(item, promotions) for item in value]
    if isinstance(value, dict):
        return {key: _python_dependencies(item, promotions) for key, item in value.items()}
    return value


def _npm_package(document: dict, name: str, promotions: dict) -> None:
    if "version" in document:
        document["version"] = _promote(document["version"], name, promotions)
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        if field in document:
            document[field] = {dependency: _promote(value, dependency, promotions)
                               for dependency, value in document[field].items()}


def _normalize_manifest(document: dict, path: str, promotions: dict) -> dict:
    result = copy.deepcopy(document)
    package = _package(result, path)
    if path.endswith(".toml"):
        if "version" in package:
            package["version"] = _promote(package["version"], package.get("name", ""), promotions)
        for field in ("dependencies", "optional-dependencies"):
            if field in package:
                package[field] = _python_dependencies(package[field], promotions)
        if "dependency-groups" in result:
            result["dependency-groups"] = _python_dependencies(result["dependency-groups"], promotions)
    else:
        _npm_package(result, result.get("name", ""), promotions)
    return result


def _lock_pins(value: object, promotions: dict) -> object:
    if isinstance(value, list):
        return [_lock_pins(item, promotions) for item in value]
    if not isinstance(value, dict):
        return value
    result = {key: _lock_pins(item, promotions) for key, item in value.items()}
    name = result.get("name", "")
    if "version" in result:
        result["version"] = _promote(result["version"], name, promotions)
    if "specifier" in result:
        old, new = promotions.get(_name(name), (None, None))
        for operator in ("==", ">="):
            if old and result["specifier"] == operator + old:
                result["specifier"] = operator + new
    return result


def _artifact_changes(old: object, new: object) -> bool:
    """Only artifact metadata may differ, without adding/removing records."""
    if type(old) is not type(new):
        return False
    if isinstance(old, list):
        return len(old) == len(new) and all(_artifact_changes(a, b) for a, b in zip(old, new))
    if isinstance(old, dict):
        return old.keys() == new.keys() and all(
            key in {"url", "hash", "integrity", "size", "upload-time"} or old[key] == new[key]
            for key in old
        )
    return old == new


def _normalize_lock(old: dict, new: dict, path: str, promotions: dict) -> dict:
    result = copy.deepcopy(old)
    if path.endswith("uv.lock"):
        # Match records by normalized identity, never by their list positions.
        def key(record):
            return (_name(record["name"]), _promote(record["version"], record["name"], promotions),
                    json.dumps(record.get("source"), sort_keys=True))
        prior = {key(record): record for record in old.get("package", [])}
        after = {key(record): record for record in new.get("package", [])}
        if len(prior) != len(old.get("package", [])) or len(after) != len(new.get("package", [])) or prior.keys() != after.keys():
            raise VersionRefusal(f"{path}: added, removed or ambiguous lock record")
        normalized = []
        for identity in after:
            before, current = prior[identity], after[identity]
            record = _lock_pins(before, promotions)
            if before["version"] != current["version"]:
                for field in ("sdist", "wheels"):
                    if field in before or field in current:
                        if not _artifact_changes(before.get(field), current.get(field)):
                            raise VersionRefusal(f"{path}: changed artifact records for {before['name']}")
                        record[field] = current[field]
            normalized.append(record)
        result["package"] = normalized
    else:
        if old.get("packages", {}).keys() != new.get("packages", {}).keys():
            raise VersionRefusal(f"{path}: added or removed lock record")
        _npm_package(result, result.get("name", ""), promotions)
        for location, record in result.get("packages", {}).items():
            name = record.get("name") or location.rsplit("node_modules/", 1)[-1] or result.get("name", "")
            before_version = record.get("version")
            _npm_package(record, name, promotions)
            if before_version != record.get("version"):
                for field in ("resolved", "integrity"):
                    if field in record and field in new["packages"][location]:
                        record[field] = new["packages"][location][field]
    return result


def require_final_promotion(root: Path, tag: str, final_commit: str) -> str | None:
    """Return the compared RC tag; paired finals require a prior RC."""
    prefix, version = tag_parts(tag)
    if final_version(version) or prefix not in {"server-v", "awid-service-v", "aweb-naapp-v", "aw-v"}:
        return None
    suffix = "-rc." if prefix == "aw-v" else "rc"
    candidates = []
    for candidate in _git(root, "tag", "--list", prefix + version + suffix + "*").splitlines():
        match = re.fullmatch(re.escape(prefix + version + suffix) + r"([1-9][0-9]*)", candidate)
        if match:
            candidates.append((int(match.group(1)), candidate))
    if not candidates:
        raise VersionRefusal("final requires a prior RC of the same version; fetch tags or publish rc1 first")
    rc_tag = max(candidates)[1]
    rc_commit = _git(root, "rev-parse", rc_tag + "^{commit}").strip()
    _git(root, "merge-base", "--is-ancestor", rc_commit, final_commit)
    raw = _git(root, "diff", "--raw", "--no-renames", "-z", rc_commit, final_commit).split("\0")
    changes = []
    for index in range(0, len(raw) - 1, 2):
        header, path = raw[index], raw[index + 1]
        old_mode, new_mode, _old_blob, _new_blob, status = header.split()
        if status != "M" or old_mode[1:] != new_mode or new_mode != "100644":
            raise VersionRefusal(f"{path}: additions, deletions, renames and mode changes refuse")
        if not _manifest(path) and Path(path).name not in {"uv.lock", "package-lock.json"}:
            raise VersionRefusal(f"{path}: non-version file changed since {rc_tag}")
        changes.append((path, _read(root, rc_commit, path), _read(root, final_commit, path)))
    promotions = {}
    for path, old, new in changes:
        if _manifest(path):
            before, after = _package(old, path), _package(new, path)
            if before.get("version") != after.get("version"):
                prior, current = before.get("version"), after.get("version")
                if not valid_version(path, prior) or final_version(prior) != current:
                    raise VersionRefusal(f"{path}: version is not an exact RC-to-final promotion")
                name = _name(before.get("name", ""))
                if not name or before.get("name") != after.get("name"):
                    raise VersionRefusal(f"{path}: package identity changed")
                if name in promotions and promotions[name] != (prior, current):
                    raise VersionRefusal(f"{path}: conflicting package promotions")
                promotions[name] = (prior, current)
    for path, old, new in changes:
        normalized = _normalize_manifest(old, path, promotions) if _manifest(path) else _normalize_lock(old, new, path, promotions)
        if normalized != new:
            raise VersionRefusal(f"{path}: changes beyond version promotion or exact promoted pins or floors")
    print(f"Source identity matches {rc_tag} plus version promotion only; "
          "the coordinator must separately verify the Cloud green receipt for that exact RC before final tagging.")
    return rc_tag
