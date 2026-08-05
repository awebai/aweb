#!/usr/bin/env python3
"""Emit the canonical Python distribution inventory from this interpreter."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re

SCHEMA = "aweb.server-runtime-inventory.v1"


def canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def main() -> None:
    constraints_digest = os.environ.get("AWEB_SKEW_SERVER_CONSTRAINTS_SHA256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", constraints_digest):
        raise SystemExit("missing canonical server constraints digest")

    versions: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = canonical_name(distribution.metadata["Name"])
        version = distribution.version
        if name in versions and versions[name] != version:
            raise SystemExit(
                f"multiple installed versions for {name}: "
                f"{versions[name]} and {version}"
            )
        versions[name] = version
    distributions = [
        {"name": name, "version": version}
        for name, version in sorted(versions.items())
    ]
    preimage = {
        "constraints_sha256": constraints_digest,
        "python_version": platform.python_version(),
        "distributions": distributions,
    }
    body = json.dumps(preimage, sort_keys=True, separators=(",", ":")).encode()
    report = {
        "schema": SCHEMA,
        **preimage,
        "sha256": hashlib.sha256(body).hexdigest(),
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
