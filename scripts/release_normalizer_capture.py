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


def remote_ref_snapshot(repo: Path) -> dict[str, str]:
    """Every ref on origin, in ONE round trip.

    A round trip costs the same whether it returns one ref or five
    hundred - measured on the real remote: 516 refs in 1.42s against a
    single ref in 1.27s - so one query per tag prefix is N round trips
    for a fact one answers.

    The stronger reason belongs beside the capture-once rule: N
    sequential reads observe a moving target. A tag created midway is
    present for the later queries and absent for the earlier ones, and
    the double-compute check cannot see it, because both computations
    read the same already-inconsistent capture. One bulk read is what
    makes the snapshot a snapshot.
    """

    refs: dict[str, str] = {}
    for line in _git(repo, "ls-remote", "origin").splitlines():
        if not line.strip():
            continue
        sha, ref = line.split(None, 1)
        refs[ref.strip()] = sha
    return refs


def anchor_tags_from(refs: dict[str, str], prefix: str) -> dict[str, str]:
    """The version-namespace anchor tags under a prefix, peeled, read
    out of a ref snapshot instead of off the network."""

    direct: dict[str, str] = {}
    peeled: dict[str, str] = {}
    for ref, sha in refs.items():
        name = ref.removeprefix("refs/tags/")
        if name == ref:
            continue
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            direct[name] = sha
    tags: dict[str, str] = {}
    for name, sha in direct.items():
        if not name.startswith(prefix):
            continue
        version_text = name.removeprefix(prefix)
        if parse_version(version_text) is None and not _NEAR_VERSION.match(
            version_text
        ):
            continue
        tags[version_text] = peeled.get(name, sha)
    return tags


_VERSION_FIELD_TOML = re.compile(r'(?m)^version\s*=\s*"[^"]*"')
# Structurally anchored to the top level (two-space indent), not first
# occurrence: a dependencies block placed before the version field must
# never absorb the mask (release-review's A3 hardening).
_VERSION_FIELD_JSON = re.compile(r'(?m)^ {2}"version"\s*:\s*"[^"]*"')


def _mask_version_field(text: str, name: str) -> str:
    """The owned version field replaced by a constant, so the
    normalizer's own patch is invisible while every other manifest byte
    - dependencies, build metadata - still counts as content."""

    pattern = (
        _VERSION_FIELD_JSON if name.endswith("package.json") else _VERSION_FIELD_TOML
    )
    return pattern.sub("version-masked", text, count=1)


def content_changed(
    repo: Path,
    anchor_sha: str,
    *,
    scope: tuple[str, ...],
    excluded: tuple[str, ...],
    masked: tuple[str, ...] = (),
) -> bool:
    """Does the scope's content differ between the anchor commit and HEAD?

    excluded paths (generated owned locks, and directories whose
    contents cannot reach the published artifact) are ignored entirely;
    masked paths (version manifests) are compared with only the owned
    version field normalized, so a dependency-only edit is movement
    while the fixed point's version patch is not. A masked file absent
    on either side is new or removed content.

    An excluded entry ending in "/" excludes that whole directory: a
    non-shipping directory holds many files and naming them one by one
    would go stale the moment someone adds another.
    """

    names = _git(
        repo, "diff", "--name-only", f"{anchor_sha}..HEAD", "--", *scope
    ).splitlines()
    prefixes = tuple(entry for entry in excluded if entry.endswith("/"))
    remaining = [
        name
        for name in names
        if name not in excluded and not name.startswith(prefixes)
    ]
    hard = [name for name in remaining if name not in masked]
    if hard:
        return True
    for name in remaining:
        try:
            anchored = _git(repo, "show", f"{anchor_sha}:{name}")
        except subprocess.CalledProcessError:
            return True
        current_path = repo / name
        if not current_path.exists():
            return True
        if _mask_version_field(anchored, name) != _mask_version_field(
            current_path.read_text(), name
        ):
            return True
    return False


def manifest_version(path: Path) -> str:
    """The committed version from a pyproject.toml or package.json."""

    if path.name == "package.json":
        return json.loads(path.read_text())["version"]
    if path.suffix == ".toml":
        with path.open("rb") as handle:
            return tomllib.load(handle)["project"]["version"]
    raise ValueError(f"unsupported manifest kind: {path}")


def ghcr_bearer(raw_token: str) -> str:
    """GHCR's registry API accepts the base64 of a GitHub token as the
    bearer directly (the same transformation verify_registry_adoption
    ships); a raw PAT gets 403 - measured by the A9 live probe, which
    is why this lives at the boundary instead of in every caller."""

    import base64

    return base64.b64encode(raw_token.encode()).decode() if raw_token else ""


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
        error.close()
        if error.code == 404:
            return None, ""
        raise DiscoveryUnavailable(f"{url}: HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise DiscoveryUnavailable(f"{url}: {error}") from error


_NEAR_VERSION = re.compile(r"^v?\d")
# Source-commit tags are not versions. The AC image publisher pushes
# exactly :VERSION and :SHA (design section 8), and it pushes the SHA
# BARE - no sha- prefix - so a short commit id beginning with a digit
# (about half of them) would otherwise be read as a near-version
# candidate and halt the train. Measured against the live registry:
# ghcr.io/awebai/ac serves ~90 of these.
_SOURCE_COMMIT_TAG = re.compile(r"^[0-9a-f]{7,40}$")
# OCI LINE POINTERS (plan-critic's ruling, OCI namespaces ONLY): v?MAJOR
# and v?MAJOR.MINOR with wholly numeric components are moving channel
# pointers, not releases. They are logged and dropped here, which is
# what makes the rest of their condition structural rather than merely
# unreached: a dropped tag is never dereferenced, so no code path can
# adopt a channel pointer's digest or revision label as a release
# identity. Exactly three numeric components remain strict release
# candidates; three-component near-misses (0.7.15rc1), four-or-more
# (1.2.3.4), and other digit-led shapes still stop by name. pypi, npm,
# GitHub releases and source tags do NOT inherit this exception.
_OCI_LINE_POINTER = re.compile(r"^v?[0-9]+(\.[0-9]+)?$")


def _oci_namespace_candidates(candidates) -> set[str]:
    """The OCI variant: version-namespace candidates minus the moving
    line pointers, which are logged rather than occupying."""

    return {
        text
        for text in _version_namespace_candidates(candidates)
        if not _OCI_LINE_POINTER.match(text)
    }


def _version_namespace_candidates(candidates) -> set[str]:
    """Every candidate that lives in the version namespace: grammar
    conformers occupy, and near-matching non-conformers (digit-led, like
    1.2 or 0.7.15-rc1) are KEPT so the reconciler can issue the named
    malformed-version-candidate stop - a silent filter here would decide
    the design's stop out of existence. Non-namespace names (latest,
    sha-*, branch tags) never occupy and are dropped."""

    return {
        text
        for text in candidates
        if _NEAR_VERSION.match(text) and not _SOURCE_COMMIT_TAG.match(text)
    }


def discover_pypi_versions(
    package: str, *, base: str = "https://pypi.org", timeout: float
) -> set[str]:
    """Every version-namespace released version, yanked included (a
    yanked version is a burned number)."""

    document, _ = _get_json(f"{base}/pypi/{package}/json", timeout=timeout)
    if document is None:
        return set()
    return _version_namespace_candidates(document.get("releases", {}))


def discover_npm_versions(
    package: str, *, base: str = "https://registry.npmjs.org", timeout: float
) -> set[str]:
    """Every version-namespace version, deprecated included."""

    import urllib.parse

    quoted = urllib.parse.quote(package, safe="@")
    document, _ = _get_json(f"{base}/{quoted}", timeout=timeout)
    if document is None:
        return set()
    return _version_namespace_candidates(document.get("versions", {}))


def discover_ghcr_versions(
    image: str, *, base: str = "https://ghcr.io", timeout: float, token: str
) -> set[str]:
    """Version-namespace tags from the v2 tags list; Link-header
    pagination traversed to a proven end or the product bound."""

    import re as _re

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = f"{base}/v2/{image}/tags/list"
    versions: set[str] = set()
    for _page in range(_DISCOVERY_PAGE_BOUND):
        document, link = _get_json(url, timeout=timeout, headers=headers)
        if document is None:
            return versions
        versions |= _oci_namespace_candidates(document.get("tags") or [])
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
    """Version-namespace release tags, drafts and prereleases included
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
            if _NEAR_VERSION.match(text):
                versions.add(text)
        match = _re.search(r"<([^>]+)>;\s*rel=\"next\"", link)
        if match is None:
            return versions
        url = match.group(1)
    raise DiscoveryBoundExceeded(
        f"{repository}: release history exceeds {_DISCOVERY_PAGE_BOUND} pages"
    )


import dataclasses as _dataclasses

from release_normalizer import (
    CapturedArtifact,
    CapturedWorld,
    UnitMember,
    format_version,
)


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
    masked: tuple[str, ...]
    # target -> release tag prefix, resolved from the canonical owner
    # (release_train.release_tag_prefix) so discovery cannot re-derive
    # it locally and drift from the read-back.
    tag_prefixes: dict[str, str]
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
    # ONE bulk ref read per remote, shared by every artifact anchored
    # in that repository - so the anchors are one snapshot rather than
    # one per prefix taken at different moments.
    ref_snapshots: dict[str, dict[str, str]] = {}
    for spec in specs:
        repo = repo_roots[spec.repo_key]
        members = [
            UnitMember(name=target, occupied=dict(discover_target(target)))
            for target in spec.unit_targets
        ]
        if spec.anchor_kind != "tag_pattern":
            raise ValueError(
                f"{spec.name}: unsupported anchor kind {spec.anchor_kind!r} - "
                "a release's identity is the tag in its own repository"
            )
        if spec.repo_key not in ref_snapshots:
            ref_snapshots[spec.repo_key] = remote_ref_snapshot(repo)
        anchors = anchor_tags_from(ref_snapshots[spec.repo_key], spec.anchor_value)
        from release_normalizer import parse_version as _parse

        conforming = [
            (parsed, text)
            for text in anchors
            if (parsed := _parse(text)) is not None
        ]
        # Anchors that are ALL near-matches carry no usable commit to
        # compare against; content is treated as changed and the
        # malformed keys flow to the reconciler's named stop - never a
        # ValueError from an empty max (the pkg-v0.3 world).
        if conforming:
            newest = max(conforming)[1]
            changed = content_changed(
                repo,
                anchors[newest],
                scope=spec.scope,
                excluded=spec.excluded,
                masked=spec.masked,
            )
        else:
            changed = True
        # A tag-history artifact's version source IS its tag history
        # (docs/release.md's artifact table). Its manifest is a
        # publish-time placeholder reading 0.0.0, and feeding that to
        # the movement table compares a version against a value that
        # was never one - which stopped the first real prepare.
        if spec.derivation == "tag-history" and conforming:
            captured_version = format_version(max(conforming)[0])
        else:
            captured_version = manifest_version(repo / spec.manifest_path)
        artifacts[spec.name] = CapturedArtifact(
            manifest_version=captured_version,
            content_changed=changed,
            derivation=spec.derivation,
            members=members,
            anchor_versions=anchors,
        )
    return CapturedWorld(
        artifacts=artifacts,
        equality_groups=tuple(equality_groups),
        compatibility=compatibility,
        server_awid_floor=read_server_awid_floor(repo_roots),
    )


_AWID_FLOOR = re.compile(r'"awid-service>=([0-9]+\.[0-9]+\.[0-9]+)"')


def read_server_awid_floor(repo_roots: dict[str, Path]) -> str:
    """The R1 consumer floor literal from server's manifest. Captured
    worlds always carry the literal or the empty marker - the engine
    stops by name on the marker when awid moves, so a missing literal
    can never silently skip the policy."""

    manifest = repo_roots["aweb"] / "server" / "pyproject.toml"
    if not manifest.exists():
        return ""
    match = _AWID_FLOOR.search(manifest.read_text())
    return match.group(1) if match else ""


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
            # The wrapper package's manifest; tag-history derivation does
            # not consume its version for movement, but capture reads it
            # and the path must be real (B1 caught the earlier guess).
            manifest_path = "cli/go/npm/aw/package.json"
        elif source.startswith("equals:"):
            derivation = "manifest"
            manifest_path = source.removeprefix("equals:")
        else:
            derivation = "manifest"
            manifest_path = source
        # Owned locks are generated wholesale and excluded; the manifest
        # stays IN the scope with only its owned version field masked,
        # so dependency and build-metadata edits are movement while the
        # normalizer's own version patch is not (the dependency-only
        # blind spot closed at its cause).
        # ... and paths the artifact declares as unable to reach its
        # published bytes, which are equally not movement.
        excluded = tuple(
            lock.path for lock in entry.owned_locks if lock.path
        ) + tuple(entry.content_exclusions)
        from release_train import release_tag_prefix

        tag_prefixes = {
            target: release_tag_prefix(entry, target.split(":", 2)[1])
            for target in (entry.occupancy_unit or ())
            if target.startswith("github:")
        }
        specs.append(
            CaptureSpec(
                name=key,
                repo_key=entry.repository,
                manifest_path=manifest_path,
                derivation=derivation,
                scope=entry.content_scope,
                excluded=excluded,
                masked=(manifest_path,),
                tag_prefixes=tag_prefixes,
                anchor_kind=entry.anchor.kind,
                anchor_value=entry.anchor.value,
                unit_targets=entry.occupancy_unit,
            )
        )
    return specs


