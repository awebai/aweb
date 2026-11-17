#!/usr/bin/env python3
"""Refuse pinned uv caches in purgeable system temporary directories."""

from __future__ import annotations

import argparse
import posixpath
import re
import subprocess
from pathlib import Path

# Cover Make/shell/Docker assignments, Python/YAML mappings, Python defaults,
# and Docker's older ENV name value form. Dynamic uv cache dir lookups stay valid.
VALUES = (
    re.compile(r"\bUV_CACHE_DIR[\"']?\s*(?:[:?+]?=|:)\s*[\"']?([^\s\"';,)]+)"),
    re.compile(
        r"(?:get|setdefault|getenv)\(\s*[\"']UV_CACHE_DIR[\"']\s*,\s*[\"']([^\"']+)[\"']"
    ),
    re.compile(r"\bENV\s+UV_CACHE_DIR\s+[\"']?([^\s\"']+)"),
)


def temporary(value: str) -> bool:
    # A shell fallback is still a pin when the caller has no override.
    value = value.rsplit(":-", 1)[-1].rstrip("}")
    value = posixpath.normpath(value)
    return any(
        value == root or value.startswith(root + "/")
        for root in ("/tmp", "/private/tmp")
    )


def violations(path: Path, text: str) -> list[str]:
    return [
        f"{path}:{text.count(chr(10), 0, match.start()) + 1}: temporary uv cache {match[1]}"
        for pattern in VALUES
        for match in pattern.finditer(text)
        if temporary(match[1])
    ]


def check_repository(root: Path) -> list[str]:
    names = (
        subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
        )
        .decode()
        .split("\0")
    )
    problems = []
    for name in dict.fromkeys(names):
        path = Path(name)
        if not name or not (
            path.name in {"Makefile", "GNUmakefile", "Dockerfile"}
            or path.name.startswith("Dockerfile.")
            or path.suffix in {".mk", ".sh", ".py", ".go", ".yaml", ".yml"}
        ):
            continue
        source = root / path
        if source.is_file():
            problems.extend(violations(path, source.read_text()))
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    problems = check_repository(args.root)
    if problems:
        print("\n".join(problems))
        print("Use uv's persistent default or a persistent caller-selected cache.")
        return 1
    print("uv cache paths avoid system temporary directories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
