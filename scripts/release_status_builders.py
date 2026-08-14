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


def _fetch(url: str, *, timeout: float) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, b""
    except (urllib.error.URLError, TimeoutError):
        return -1, b""


def pypi_rows(
    package: str, version: str, *, anchor: str, base: str, timeout: float
) -> list[Row]:
    normalized = package.replace("-", "_")
    status, body = _fetch(f"{base}/{package}/{version}/json", timeout=timeout)
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
                evidence=f"registry sha256 {files[sdist_name]}; anchor {anchor}",
            )
        )
    else:
        rows.append(
            Row(fact=facts[0], state="observed-absent", evidence="not served")
        )
    if len(wheels) == 1:
        rows.append(
            Row(
                fact=f"pypi:{package} wheel {wheels[0]}",
                state="observed-present",
                evidence=f"registry sha256 {files[wheels[0]]}; anchor {anchor}",
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
