#!/usr/bin/env python3
"""Repository-side capture for the normalizer (aben, design section 6).

The I/O half that reads repositories: anchor tag discovery with peeled
identities, content-changed over a canonical scope against the anchor
commit with the fixed-point exclusions, and manifest version reads.
Registry-side capture (listing discovery) lives beside it; both feed the
pure normalize() and are called exactly once per pass so the
double-compute determinism check compares computation, not I/O.
"""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
from pathlib import Path

from release_normalizer import parse_version


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout


def discover_anchor_tags(repo: Path, prefix: str) -> dict[str, str]:
    """All grammar-conforming anchor tags on origin, peeled to commits.

    Non-grammar candidates under the prefix are excluded (logged by the
    caller); the version-namespace ambiguity stop belongs to the
    reconciler, which sees the raw listing when it needs it.
    """

    lines = _git(repo, "ls-remote", "origin", f"refs/tags/{prefix}*").splitlines()
    direct: dict[str, str] = {}
    peeled: dict[str, str] = {}
    for line in lines:
        sha, ref = line.split(None, 1)
        name = ref.removeprefix("refs/tags/")
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            direct[name] = sha
    tags: dict[str, str] = {}
    for name, sha in direct.items():
        version_text = name.removeprefix(prefix)
        if parse_version(version_text) is None:
            continue
        tags[version_text] = peeled.get(name, sha)
    return tags


def content_changed(
    repo: Path,
    anchor_sha: str,
    *,
    scope: tuple[str, ...],
    excluded: tuple[str, ...],
) -> bool:
    """Does the scope's content differ between the anchor commit and HEAD,
    ignoring the excluded version manifests and owned locks?"""

    names = _git(
        repo, "diff", "--name-only", f"{anchor_sha}..HEAD", "--", *scope
    ).splitlines()
    remaining = [name for name in names if name not in excluded]
    return bool(remaining)


def manifest_version(path: Path) -> str:
    """The committed version from a pyproject.toml or package.json."""

    if path.name == "package.json":
        return json.loads(path.read_text())["version"]
    if path.suffix == ".toml":
        return tomllib.load(path.open("rb"))["project"]["version"]
    raise ValueError(f"unsupported manifest kind: {path}")


class DiscoveryUnavailable(Exception):
    """The listing read failed; unavailability is never absence."""


class DiscoveryBoundExceeded(Exception):
    """History exceeds the supported discovery bound; truncation is not
    weather, so this is its own stop, distinct from unavailable."""


_DISCOVERY_PAGE_BOUND = 5


def _get_json(url: str, *, timeout: float, headers: dict[str, str] | None = None):
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            link = response.headers.get("Link", "")
            return json.loads(response.read().decode()), link
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None, ""
        raise DiscoveryUnavailable(f"{url}: HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise DiscoveryUnavailable(f"{url}: {error}") from error


def _grammar_versions(candidates) -> set[str]:
    return {text for text in candidates if parse_version(text) is not None}


def discover_pypi_versions(
    package: str, *, base: str = "https://pypi.org", timeout: float
) -> set[str]:
    """Every grammar-conforming released version, yanked included (a
    yanked version is a burned number)."""

    document, _ = _get_json(f"{base}/pypi/{package}/json", timeout=timeout)
    if document is None:
        return set()
    return _grammar_versions(document.get("releases", {}))


def discover_npm_versions(
    package: str, *, base: str = "https://registry.npmjs.org", timeout: float
) -> set[str]:
    """Every grammar-conforming version, deprecated included."""

    import urllib.parse

    quoted = urllib.parse.quote(package, safe="@")
    document, _ = _get_json(f"{base}/{quoted}", timeout=timeout)
    if document is None:
        return set()
    return _grammar_versions(document.get("versions", {}))


def discover_ghcr_versions(
    image: str, *, base: str = "https://ghcr.io", timeout: float, token: str
) -> set[str]:
    """Grammar-conforming tags from the v2 tags list; Link-header
    pagination traversed to a proven end or the product bound."""

    import re as _re

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = f"{base}/v2/{image}/tags/list"
    versions: set[str] = set()
    for _page in range(_DISCOVERY_PAGE_BOUND):
        document, link = _get_json(url, timeout=timeout, headers=headers)
        if document is None:
            return versions
        versions |= _grammar_versions(document.get("tags") or [])
        match = _re.search(r"<([^>]+)>;\s*rel=\"next\"", link)
        if match is None:
            return versions
        next_path = match.group(1)
        url = next_path if next_path.startswith("http") else f"{base}{next_path}"
    raise DiscoveryBoundExceeded(
        f"{image}: tag history exceeds {_DISCOVERY_PAGE_BOUND} pages"
    )


def discover_github_release_versions(
    repository: str,
    *,
    base: str = "https://api.github.com",
    timeout: float,
    token: str,
    tag_prefix: str = "v",
) -> set[str]:
    """Grammar-conforming release tags, drafts and prereleases included
    (both occupy), paginated to a proven end or the bound."""

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = f"{base}/repos/{repository}/releases?per_page=100"
    versions: set[str] = set()
    import re as _re

    for _page in range(_DISCOVERY_PAGE_BOUND):
        document, link = _get_json(url, timeout=timeout, headers=headers)
        if document is None:
            return versions
        for release in document:
            tag = release.get("tag_name", "")
            text = tag.removeprefix(tag_prefix)
            if parse_version(text) is not None:
                versions.add(text)
        match = _re.search(r"<([^>]+)>;\s*rel=\"next\"", link)
        if match is None:
            return versions
        url = match.group(1)
    raise DiscoveryBoundExceeded(
        f"{repository}: release history exceeds {_DISCOVERY_PAGE_BOUND} pages"
    )


import dataclasses as _dataclasses

from release_normalizer import CapturedArtifact, CapturedWorld, UnitMember


@_dataclasses.dataclass(frozen=True)
class CaptureSpec:
    """One artifact's capture instructions, assembled from the canonical
    ARTIFACTS entry (the wiring derives these; nothing here is a second
    inventory)."""

    name: str
    repo_key: str
    manifest_path: str
    derivation: str
    scope: tuple[str, ...]
    excluded: tuple[str, ...]
    anchor_kind: str
    anchor_value: str
    unit_targets: tuple[str, ...]


def assemble_captured_world(
    *,
    specs,
    repo_roots: dict[str, Path],
    discover_target,
    equality_groups,
    compatibility: str,
) -> CapturedWorld:
    """Build the pure normalizer's CapturedWorld: anchors and content
    facts from the repositories, occupancy through the injected
    discoverer (one call per unit target), manifests from version_source.

    content_changed is computed against the NEWEST anchor commit; for
    recoverable partials the reconciler pins its own previous complete P
    and the movement table is not consulted for the recovering artifact,
    so the newest-anchor comparison is the correct repository-side fact
    for every path that reads it. An artifact with no anchor at all is
    all new content.
    """

    artifacts: dict[str, CapturedArtifact] = {}
    for spec in specs:
        repo = repo_roots[spec.repo_key]
        if spec.anchor_kind == "tag_pattern":
            anchors = discover_anchor_tags(repo, spec.anchor_value)
        else:
            # oci_revision_label anchors are registry-side facts; the
            # discoverer supplies them per target and the repository
            # contributes no tag history.
            anchors = {}
        if anchors:
            from release_normalizer import parse_version as _parse

            newest = max(
                (parsed, text)
                for text in anchors
                if (parsed := _parse(text)) is not None
            )[1]
            changed = content_changed(
                repo,
                anchors[newest],
                scope=spec.scope,
                excluded=spec.excluded,
            )
        else:
            changed = True
        members = [
            UnitMember(name=target, occupied=dict(discover_target(target)))
            for target in spec.unit_targets
        ]
        artifacts[spec.name] = CapturedArtifact(
            manifest_version=manifest_version(repo / spec.manifest_path),
            content_changed=changed,
            derivation=spec.derivation,
            members=members,
            anchor_versions=anchors,
        )
    return CapturedWorld(
        artifacts=artifacts,
        equality_groups=tuple(equality_groups),
        compatibility=compatibility,
    )


VERSIONED_ARTIFACTS = (
    "aweb-server",
    "awid-service",
    "awid-image",
    "aw-cli",
    "channel-plugin",
    "pi-extension",
    "skills",
    "a2a-gateway-image",
    "ac-image",
)


def derive_capture_specs(artifacts) -> list[CaptureSpec]:
    """CaptureSpecs from the canonical entries - the one-owner rule: every
    field mirrors the entry; nothing is restated."""

    by_key = {entry.key: entry for entry in artifacts}
    specs: list[CaptureSpec] = []
    for key in VERSIONED_ARTIFACTS:
        entry = by_key[key]
        source = entry.version_source or ""
        if source.startswith("tag-history:"):
            derivation = "tag-history"
            manifest_path = "cli/go/npm/package.json"
        elif source.startswith("equals:"):
            derivation = "manifest"
            manifest_path = source.removeprefix("equals:")
        else:
            derivation = "manifest"
            manifest_path = source
        excluded = tuple(
            path
            for path in (
                manifest_path,
                *(lock.path for lock in entry.owned_locks),
            )
            if path
        )
        specs.append(
            CaptureSpec(
                name=key,
                repo_key=entry.repository,
                manifest_path=manifest_path,
                derivation=derivation,
                scope=entry.content_scope,
                excluded=excluded,
                anchor_kind=entry.anchor.kind,
                anchor_value=entry.anchor.value,
                unit_targets=entry.occupancy_unit,
            )
        )
    return specs


def read_oci_revision(
    image: str,
    version: str,
    *,
    base: str = "https://ghcr.io",
    token: str,
    timeout: float,
) -> str:
    """The org.opencontainers.image.revision label for a version tag -
    the ac-image anchor (aben design sections 7 and 8). Resolves the
    tag's manifest (following one index child when the tag is an index),
    then the config blob, then the label. Absence of the tag, the
    config, or the label raises with its own words; nothing here ever
    answers None.
    """

    headers = {
        "Accept": (
            "application/vnd.oci.image.index.v1+json, "
            "application/vnd.oci.image.manifest.v1+json, "
            "application/vnd.docker.distribution.manifest.list.v2+json, "
            "application/vnd.docker.distribution.manifest.v2+json"
        )
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    manifest, _ = _get_json(
        f"{base}/v2/{image}/manifests/{version}", timeout=timeout, headers=headers
    )
    if manifest is None:
        raise DiscoveryUnavailable(
            f"{image}:{version}: manifest absent while an anchor was expected"
        )
    if "manifests" in manifest:
        children = manifest.get("manifests") or []
        if not children:
            raise DiscoveryUnavailable(f"{image}:{version}: empty index")
        child_digest = children[0].get("digest")
        manifest, _ = _get_json(
            f"{base}/v2/{image}/manifests/{child_digest}",
            timeout=timeout,
            headers=headers,
        )
        if manifest is None:
            raise DiscoveryUnavailable(
                f"{image}:{version}: index child {child_digest} absent"
            )
    config_digest = (manifest.get("config") or {}).get("digest")
    if not config_digest:
        raise DiscoveryUnavailable(f"{image}:{version}: manifest has no config")
    config, _ = _get_json(
        f"{base}/v2/{image}/blobs/{config_digest}", timeout=timeout, headers=headers
    )
    if config is None:
        raise DiscoveryUnavailable(f"{image}:{version}: config blob absent")
    labels = ((config.get("config") or {}).get("Labels")) or {}
    revision = labels.get("org.opencontainers.image.revision")
    if not revision:
        raise DiscoveryUnavailable(
            f"{image}:{version}: config carries no "
            "org.opencontainers.image.revision label - anchorless image"
        )
    return revision
