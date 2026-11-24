#!/usr/bin/env python3
"""The paths aweb gives up when the naapps move out, and the check that keeps them.

scripts/naapp_split_paths.json lists what this branch deletes from aweb (every
file under the deleted prefixes, plus single files elsewhere) and what it
moves (old path to new). Every merge from main runs

    python3 scripts/naapp_split.py check --base origin/main

which fails when main has a file under a deleted prefix that the list does not
name (it may be new contract code that belongs in naapp-contracts: classify it
with the boundary map's appendix scripts, then regenerate), when a listed
deletion is still present, or when a move's source returned or its target is
missing. `generate --base REF` rewrites the deleted list from REF's tree, keeping
the prefixes, the single files and the moves.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

LIST = Path(__file__).resolve().parent / "naapp_split_paths.json"


@dataclass(frozen=True)
class Paths:
    deleted_prefixes: tuple[str, ...]
    deleted: tuple[str, ...]
    moved: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path = LIST) -> Paths:
        data = json.loads(path.read_text())
        return cls(
            deleted_prefixes=tuple(data["deleted_prefixes"]),
            deleted=tuple(data["deleted"]),
            moved=dict(data["moved"]),
        )

    def dump(self, path: Path = LIST) -> None:
        data = {
            "deleted_prefixes": list(self.deleted_prefixes),
            "deleted": sorted(self.deleted),
            "moved": dict(sorted(self.moved.items())),
        }
        path.write_text(json.dumps(data, indent=2) + "\n")

    def under_prefix(self, path: str) -> bool:
        return path.startswith(self.deleted_prefixes)


def check(paths: Paths, *, base: Iterable[str], head: Iterable[str]) -> list[str]:
    base_files, head_files = set(base), set(head)
    listed = set(paths.deleted) | set(paths.moved)
    failures = [
        f"unlisted: {path} is under a deleted prefix"
        for path in sorted(base_files)
        if paths.under_prefix(path) and path not in listed
    ]
    failures += [
        f"stale: {path} is listed but main no longer has it"
        for path in sorted(listed)
        if path not in base_files
    ]
    failures += [f"not deleted: {path}" for path in sorted(paths.deleted) if path in head_files]
    for old, new in sorted(paths.moved.items()):
        if old in head_files:
            failures.append(f"not moved: {old} is still present")
        if new not in head_files:
            failures.append(f"not moved: {new} is missing")
    return failures


def generate(paths: Paths, *, base: Iterable[str]) -> Paths:
    """The deleted list for a base tree: every file under a prefix that is not moved,
    plus the single files listed outside the prefixes that the base still has."""
    base_files = set(base)
    singles = {path for path in paths.deleted if not paths.under_prefix(path)}
    under = {path for path in base_files if paths.under_prefix(path) and path not in paths.moved}
    return Paths(
        deleted_prefixes=paths.deleted_prefixes,
        deleted=tuple(sorted(under | (singles & base_files))),
        moved=paths.moved,
    )


def _tree(ref: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "-z", ref],
        check=True,
        capture_output=True,
    )
    return [name.decode() for name in result.stdout.split(b"\0") if name]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Check or regenerate the naapp split path list.")
    parser.add_argument("command", choices=("check", "generate"))
    parser.add_argument("--base", required=True, help="main's ref, e.g. origin/main")
    args = parser.parse_args(argv)
    paths = Paths.load()
    if args.command == "generate":
        generate(paths, base=_tree(args.base)).dump()
        return 0
    failures = check(paths, base=_tree(args.base), head=_tree("HEAD"))
    for failure in failures:
        print(failure)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
