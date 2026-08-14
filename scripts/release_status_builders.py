#!/usr/bin/env python3
"""Per-fact status row builders (aben, design section 8).

Every independently checkable fact is its own row. pypi rows enforce the
exact filename contract (one sdist, one three-segment wheel, no extras -
the .gitignore stop's own class) with the registry's reported per-file
sha256; the npm row verifies declared integrity against freshly fetched
tarball bytes - the registry's claim about itself is never the evidence.
Unavailability propagates as UNAVAILABLE rows, never absence, never
success.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.error
import urllib.request

from release_status import Row


def _fetch(
    url: str, *, timeout: float, token: str = ""
) -> tuple[int, bytes]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        error.close()
        return error.code, b""
    except (urllib.error.URLError, TimeoutError):
        return -1, b""


def pypi_rows(
    package: str, version: str, *, base: str, timeout: float
) -> list[Row]:
    normalized = package.replace("-", "_")
    status, body = _fetch(
        f"{base}/pypi/{package}/{version}/json", timeout=timeout
    )
    facts = (
        f"pypi:{package} sdist {normalized}-{version}.tar.gz",
        f"pypi:{package} wheel",
        f"pypi:{package} filename set",
    )
    if status == -1 or status >= 500:
        return [
            Row(fact=fact, state="unavailable", evidence=f"HTTP {status}")
            for fact in facts
        ]
    if status == 404:
        return [
            Row(fact=fact, state="observed-absent", evidence="registry 404")
            for fact in facts
        ]
    document = json.loads(body)
    files = {
        item["filename"]: item.get("digests", {}).get("sha256", "")
        for item in document.get("urls", [])
    }
    sdist_name = f"{normalized}-{version}.tar.gz"
    wheel_re = re.compile(
        re.escape(normalized) + "-" + re.escape(version) + r"-[^-]+-[^-]+-[^-]+\.whl"
    )
    wheels = [name for name in files if wheel_re.fullmatch(name)]
    extras = [
        name for name in files if name != sdist_name and name not in wheels
    ]
    rows: list[Row] = []
    if sdist_name in files:
        rows.append(
            Row(
                fact=facts[0],
                state="observed-present",
                evidence=f"registry sha256 {files[sdist_name]}",
            )
        )
    else:
        rows.append(
            Row(fact=facts[0], state="observed-absent", evidence="not served")
        )
    if len(wheels) == 1:
        # The fact key is observation-independent (the wheel's name
        # goes to evidence) so the expected fact domain is derivable
        # from the card alone and missing facts are detectable by
        # set equality (C2).
        rows.append(
            Row(
                fact=facts[1],
                state="observed-present",
                evidence=f"{wheels[0]} registry sha256 {files[wheels[0]]}",
            )
        )
    else:
        rows.append(
            Row(
                fact=facts[1],
                state="conflict-unproven" if wheels else "observed-absent",
                evidence=f"wheels served: {wheels!r}",
            )
        )
    if extras:
        rows.append(
            Row(
                fact=facts[2],
                state="conflict-unproven",
                evidence=f"extras beyond the contract: {sorted(extras)!r}",
            )
        )
    else:
        rows.append(
            Row(
                fact=facts[2],
                state="observed-present"
                if sdist_name in files and len(wheels) == 1
                else "observed-absent",
                evidence="exactly one sdist and one wheel, no extras"
                if sdist_name in files and len(wheels) == 1
                else "contract set incomplete",
            )
        )
    return rows


def npm_tarball_row(
    package: str, version: str, *, base: str, timeout: float
) -> Row:
    fact = f"npm:{package} tarball integrity"
    status, body = _fetch(f"{base}/{package}/{version}", timeout=timeout)
    if status == -1 or status >= 500:
        return Row(fact=fact, state="unavailable", evidence=f"HTTP {status}")
    if status == 404:
        return Row(fact=fact, state="observed-absent", evidence="registry 404")
    dist = json.loads(body).get("dist", {})
    declared = dist.get("integrity", "")
    tarball_url = dist.get("tarball", "")
    t_status, tarball = _fetch(tarball_url, timeout=timeout)
    if t_status != 200:
        return Row(
            fact=fact, state="unavailable", evidence=f"tarball HTTP {t_status}"
        )
    algorithm, _, expected = declared.partition("-")
    digest = hashlib.new(algorithm or "sha512", tarball).digest()
    fetched_hex = digest.hex()
    expected_hex = (
        expected
        if all(c in "0123456789abcdef" for c in expected.lower())
        else base64.b64decode(expected).hex()
    ) if expected else ""
    if expected_hex and fetched_hex == expected_hex:
        return Row(
            fact=fact,
            state="observed-present",
            evidence=f"declared integrity equals fetched bytes ({fetched_hex[:16]}...)",
        )
    return Row(
        fact=fact,
        state="conflict-unproven",
        evidence=(
            f"declared {declared[:24]}... does not match fetched "
            f"{algorithm or 'sha512'}-{fetched_hex[:16]}..."
        ),
    )


def image_rows(
    image: str,
    version: str,
    *,
    expected_revision: str,
    required_platforms: tuple[str, ...],
    check_latest: bool,
    base: str,
    token: str,
    timeout: float,
) -> list[Row]:
    """Per-fact rows for one OCI image: index digest, each required
    platform, each child's source-revision label against the expected
    SHA, and mutable latest equal to the version digest where the
    publisher promises it. The source tag is a separate repository-side
    row owned by the caller."""

    # The fact family is STABLE across outcomes (C2): every branch
    # emits the same keys, so the expected fact domain is derivable
    # from the card alone and a dropped fact is set-detectable.
    facts = [
        f"ghcr:{image} {version} index digest",
        *(
            f"ghcr:{image} {version} {platform} revision label"
            for platform in required_platforms
        ),
        *((f"ghcr:{image} latest == {version}",) if check_latest else ()),
    ]
    status, body, digest = _fetch_manifest(
        f"{base}/v2/{image}/manifests/{version}", timeout, token
    )
    if status == -1 or status == 401 or status == 403 or status >= 500:
        return [
            Row(fact=fact, state="unavailable", evidence=f"HTTP {status}")
            for fact in facts
        ]
    if status == 404:
        return [
            Row(fact=fact, state="observed-absent", evidence="registry 404")
            for fact in facts
        ]
    index = json.loads(body)
    rows = [
        Row(
            fact=f"ghcr:{image} {version} index digest",
            state="observed-present",
            evidence=f"{digest}; source anchor {expected_revision}",
        )
    ]
    children = {
        f"{m.get('platform', {}).get('os', '?')}/{m.get('platform', {}).get('architecture', '?')}": m.get("digest")
        for m in index.get("manifests", [])
    }
    for platform in required_platforms:
        child = children.get(platform)
        if child is None:
            rows.append(
                Row(
                    fact=f"ghcr:{image} {version} {platform}",
                    state="observed-absent",
                    evidence=f"index children: {sorted(children)!r}",
                )
            )
            continue
        revision = _child_revision(base, image, child, timeout, token)
        if revision is None:
            rows.append(
                Row(
                    fact=f"ghcr:{image} {version} {platform} revision label",
                    state="unavailable",
                    evidence="config unreadable",
                )
            )
        elif revision == expected_revision:
            rows.append(
                Row(
                    fact=f"ghcr:{image} {version} {platform} revision label",
                    state="observed-present",
                    evidence=f"label equals source anchor {expected_revision}",
                )
            )
        else:
            rows.append(
                Row(
                    fact=f"ghcr:{image} {version} {platform} revision label",
                    state="conflict-unproven",
                    evidence=f"label {revision} != expected {expected_revision}",
                )
            )
    if check_latest:
        l_status, _l_body, l_digest = _fetch_manifest(
            f"{base}/v2/{image}/manifests/latest", timeout, token
        )
        if l_status != 200:
            rows.append(
                Row(
                    fact=f"ghcr:{image} latest == {version}",
                    state="unavailable" if l_status != 404 else "observed-absent",
                    evidence=f"latest HTTP {l_status}",
                )
            )
        elif l_digest == digest:
            rows.append(
                Row(
                    fact=f"ghcr:{image} latest == {version}",
                    state="observed-present",
                    evidence=f"latest digest equals version digest {digest}",
                )
            )
        else:
            rows.append(
                Row(
                    fact=f"ghcr:{image} latest == {version}",
                    state="conflict-unproven",
                    evidence=f"latest {l_digest} != version {digest}",
                )
            )
    return rows


def _fetch_manifest(
    url: str, timeout: float, token: str = ""
) -> tuple[int, bytes, str]:
    headers = {
        "Accept": (
            "application/vnd.oci.image.index.v1+json, "
            "application/vnd.oci.image.manifest.v1+json"
        )
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return (
                response.status,
                response.read(),
                response.headers.get("Docker-Content-Digest", ""),
            )
    except urllib.error.HTTPError as error:
        error.close()
        return error.code, b"", ""
    except (urllib.error.URLError, TimeoutError):
        return -1, b"", ""


def _child_revision(
    base: str, image: str, child_digest: str, timeout: float, token: str = ""
):
    status, body, _ = _fetch_manifest(
        f"{base}/v2/{image}/manifests/{child_digest}", timeout, token
    )
    if status != 200:
        return None
    config_digest = (json.loads(body).get("config") or {}).get("digest")
    if not config_digest:
        return None
    c_status, config, _ = _fetch_manifest(
        f"{base}/v2/{image}/blobs/{config_digest}", timeout, token
    )
    if c_status != 200:
        return None
    labels = ((json.loads(config).get("config") or {}).get("Labels")) or {}
    return labels.get("org.opencontainers.image.revision")


def github_release_rows(
    repository: str,
    tag: str,
    *,
    required_assets: tuple[str, ...],
    base: str,
    token: str,
    timeout: float,
) -> list[Row]:
    """The release object at its tag and every required asset, each a
    row of its own - a missing asset is absent beside present ones,
    never collapsed into one verdict."""

    release_fact = f"github:{repository} release {tag}"
    status, body = _fetch(
        f"{base}/repos/{repository}/releases/tags/{tag}",
        timeout=timeout,
        token=token,
    )
    if status == -1 or status >= 500:
        return [
            Row(fact=release_fact, state="unavailable", evidence=f"HTTP {status}")
        ]
    if status == 404:
        return [
            Row(fact=fact, state="observed-absent", evidence="release 404")
            for fact in (
                release_fact,
                *(
                    f"github:{repository} {tag} asset {name}"
                    for name in required_assets
                ),
            )
        ]
    served = {
        asset.get("name", "") for asset in json.loads(body).get("assets", [])
    }
    rows = [
        Row(
            fact=release_fact,
            state="observed-present",
            evidence=f"release object served with {len(served)} assets",
        )
    ]
    for name in required_assets:
        rows.append(
            Row(
                fact=f"github:{repository} {tag} asset {name}",
                state="observed-present" if name in served else "observed-absent",
                evidence="asset served" if name in served else "asset not served",
            )
        )
    return rows


def source_tag_row(repo, tag: str, *, expected_identity: str) -> Row:
    """The source anchor OBSERVED: the tag on origin, peeled, compared
    to the identity the card names. Positive equality only - a served
    tag at any other commit is conflict, never presence."""

    import subprocess

    listing = subprocess.run(
        ["git", "ls-remote", "origin", f"refs/tags/{tag}*"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    fact = f"source tag {tag}"
    direct = ""
    peeled = ""
    for line in listing:
        sha, ref = line.split(None, 1)
        if ref == f"refs/tags/{tag}^{{}}":
            peeled = sha
        elif ref == f"refs/tags/{tag}":
            direct = sha
    identity = peeled or direct
    if not identity:
        return Row(fact=fact, state="observed-absent", evidence="tag not on origin")
    if identity == expected_identity:
        return Row(
            fact=fact,
            state="observed-present",
            evidence=f"peeled to expected {identity}",
        )
    return Row(
        fact=fact,
        state="conflict-unproven",
        evidence=f"tag peels to {identity}, card names {expected_identity}",
    )


def image_alias_row(
    image: str,
    version: str,
    alias: str,
    *,
    base: str,
    token: str,
    timeout: float,
) -> Row:
    """The AC :SHA contract: the alias tag must serve EXACTLY the
    version tag's digest - equality of two independently fetched
    Docker-Content-Digest values, never an assumption that two names
    share bytes."""

    fact = f"ghcr:{image} {alias} digest == {version} digest"
    v_status, _v_body, v_digest = _fetch_manifest(
        f"{base}/v2/{image}/manifests/{version}", timeout, token
    )
    a_status, _a_body, a_digest = _fetch_manifest(
        f"{base}/v2/{image}/manifests/{alias}", timeout, token
    )
    if v_status in (-1, 401, 403) or v_status >= 500 or a_status in (-1, 401, 403) or a_status >= 500:
        return Row(
            fact=fact,
            state="unavailable",
            evidence=f"HTTP {v_status}/{a_status}",
        )
    if a_status == 404 or v_status == 404:
        return Row(
            fact=fact,
            state="observed-absent",
            evidence=f"version HTTP {v_status}, alias HTTP {a_status}",
        )
    if v_digest and v_digest == a_digest:
        return Row(
            fact=fact,
            state="observed-present",
            evidence=f"both tags serve {v_digest}",
        )
    return Row(
        fact=fact,
        state="conflict-unproven",
        evidence=f"version serves {v_digest}, alias serves {a_digest}",
    )


def external_release_binding_rows(
    repository: str,
    tag: str,
    *,
    expected_source_sha: str,
    base: str,
    token: str,
    timeout: float,
) -> list[Row]:
    """The external product repository's tag and its tree binding: the
    sync commits are stamped 'Sync exact aweb <sha>', so the tag's
    commit message binds the external tree to the exact aweb source the
    card names."""

    tag_fact = f"github:{repository} external tag {tag}"
    binding_fact = f"github:{repository} {tag} tree binding"
    status, body = _fetch(
        f"{base}/repos/{repository}/commits/{tag}", timeout=timeout, token=token
    )
    if status == -1 or status >= 500:
        return [
            Row(fact=tag_fact, state="unavailable", evidence=f"HTTP {status}"),
            Row(fact=binding_fact, state="unavailable", evidence=f"HTTP {status}"),
        ]
    if status == 404:
        return [
            Row(fact=tag_fact, state="observed-absent", evidence="tag 404"),
            Row(
                fact=binding_fact,
                state="observed-absent",
                evidence="no tag, no binding",
            ),
        ]
    document = json.loads(body)
    commit_sha = document.get("sha", "")
    message = (document.get("commit") or {}).get("message", "")
    rows = [
        Row(
            fact=tag_fact,
            state="observed-present",
            evidence=f"tag resolves commit {commit_sha}",
        )
    ]
    stamp = f"Sync exact aweb {expected_source_sha}"
    if stamp in message:
        rows.append(
            Row(
                fact=binding_fact,
                state="observed-present",
                evidence=f"sync stamp names {expected_source_sha}",
            )
        )
    elif "Sync exact aweb " in message:
        rows.append(
            Row(
                fact=binding_fact,
                state="conflict-unproven",
                evidence=f"sync stamp differs: {message.splitlines()[0]!r}",
            )
        )
    else:
        rows.append(
            Row(
                fact=binding_fact,
                state="conflict-unproven",
                evidence="commit carries no sync stamp",
            )
        )
    return rows
