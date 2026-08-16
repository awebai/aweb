#!/usr/bin/env python3
"""Exit successfully only when an exact package version is publicly served."""

from __future__ import annotations

import sys

from release import Refusal, npm_present, pypi_present


def main(argv: list[str]) -> int:
    if len(argv) != 2 or ":" not in argv[0]:
        print(
            "usage: observe_public_target.py pypi:NAME|npm:NAME VERSION",
            file=sys.stderr,
        )
        return 2
    kind, package = argv[0].split(":", 1)
    try:
        if kind == "pypi":
            present = pypi_present(package, argv[1])
        elif kind == "npm":
            present = npm_present(package, argv[1])
        else:
            print(f"unsupported registry: {kind}", file=sys.stderr)
            return 2
    except Refusal as exc:
        print(f"public registry unavailable: {exc}", file=sys.stderr)
        return 2
    return 0 if present else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
