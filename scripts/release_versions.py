"""Release tag spellings."""

from __future__ import annotations

import re


SEMVER = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
PYTHON_VERSION = rf"{SEMVER}(?:rc[1-9][0-9]*)?"
NPM_VERSION = rf"{SEMVER}(?:-rc\.[1-9][0-9]*)?"
TAG_PATTERN = re.compile(
    rf"^(?:(server-v|awid-service-v|awid-v)({PYTHON_VERSION})"
    rf"|(aw-v)({NPM_VERSION})"
    rf"|(channel-v|pi-v|skills-v|a2a-gw-v)({SEMVER}))$"
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
