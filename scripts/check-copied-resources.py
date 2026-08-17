#!/usr/bin/env python3
"""Verify that copied resources still match the sources they were copied from.

WHY. Some resources exist twice on purpose: the canonical skill bodies live in
skills/, and the Codex plugin ships its own copy under packages/. Nothing
regenerates those copies, so they drift by hand-editing one side — silently,
because both files are valid on their own and every other gate passes.

This is not hypothetical. During aweb-aazb.8.2 a skill's reference block had to
be removed from BOTH skills/aweb-bootstrap/SKILL.md and its packaged copy, and
the second edit happened only because the author noticed the copy existed. A
gate is the difference between noticing and being told.

WHAT THIS CHECKS. For each declared pair: every source has a copy, every copy
has a source, and the bytes are identical — for EVERY file under the resource,
not only its entry point. A first version of this gate compared SKILL.md alone
and silently ignored the references/ files beside it, which are copied the same
way and drift the same way.

WHAT IT DOES NOT CHECK. Whether the copy SHOULD exist — that is a packaging
decision. And it compares bytes, so it cannot tell a meaningful divergence from
a trailing newline; that is deliberate, since a copy that differs at all is a
copy nobody is maintaining.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

# (canonical source directory, copy directory). Each contains <name>/SKILL.md.
COPY_SETS = (
    ("skills", "packages/codex-plugin/skills"),
)

RESOURCE = "SKILL.md"


def names_in(root: Path, directory: str) -> set[str]:
    base = root / directory
    if not base.is_dir():
        return set()
    return {p.name for p in base.iterdir() if (p / RESOURCE).is_file()}


def files_under(base: Path) -> set[str]:
    """Every file in a resource, relative to it — not just its entry point."""
    return {
        str(p.relative_to(base)) for p in base.rglob("*") if p.is_file()
    }


def check(root: Path) -> list[str]:
    failures: list[str] = []
    for source_dir, copy_dir in COPY_SETS:
        sources = names_in(root, source_dir)
        copies = names_in(root, copy_dir)

        for name in sorted(sources - copies):
            failures.append(
                f"{source_dir}/{name}/{RESOURCE} has no copy at {copy_dir}/{name}/{RESOURCE}"
            )
        for name in sorted(copies - sources):
            failures.append(
                f"{copy_dir}/{name}/{RESOURCE} has no source at {source_dir}/{name}/{RESOURCE}"
            )
        for name in sorted(sources & copies):
            source_base = root / source_dir / name
            copy_base = root / copy_dir / name
            source_files = files_under(source_base)
            copy_files = files_under(copy_base)
            for rel in sorted(source_files - copy_files):
                failures.append(
                    f"{source_dir}/{name}/{rel} has no copy at {copy_dir}/{name}/{rel}"
                )
            for rel in sorted(copy_files - source_files):
                failures.append(
                    f"{copy_dir}/{name}/{rel} has no source at {source_dir}/{name}/{rel}"
                )
            for rel in sorted(source_files & copy_files):
                if (source_base / rel).read_bytes() != (copy_base / rel).read_bytes():
                    failures.append(
                        f"{copy_dir}/{name}/{rel} differs from "
                        f"{source_dir}/{name}/{rel}; edit the source and re-copy"
                    )
    return failures


def self_test(root: Path) -> int:
    if failures := check(root):
        print("self-test setup is not green:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        source_dir, copy_dir = COPY_SETS[0]

        def place(directory: str, name: str, body: str) -> Path:
            path = tmp / directory / name / RESOURCE
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
            return path

        place(source_dir, "alpha", "# alpha\n")
        copy = place(copy_dir, "alpha", "# alpha\n")
        if failures := check(tmp):
            print(f"self-test failed: matching copy rejected: {failures[0]}")
            return 1

        # Divergent content fails, and the message names the copy rather than the
        # source, because the copy is the side that gets forgotten.
        copy.write_text("# alpha edited\n", encoding="utf-8")
        failures = check(tmp)
        if not any("differs from" in f for f in failures):
            print("self-test failed: a divergent copy was not detected")
            return 1
        copy.write_text("# alpha\n", encoding="utf-8")

        # A trailing-newline-only difference still fails: a copy that differs at
        # all is a copy nobody is maintaining.
        copy.write_text("# alpha", encoding="utf-8")
        if not any("differs from" in f for f in check(tmp)):
            print("self-test failed: a whitespace-only divergence was not detected")
            return 1
        copy.write_text("# alpha\n", encoding="utf-8")

        # A new source with no copy fails — the shape that happens when someone
        # adds a skill and does not know the copy exists.
        place(source_dir, "beta", "# beta\n")
        if not any("has no copy" in f for f in check(tmp)):
            print("self-test failed: a source without a copy was not detected")
            return 1
        (tmp / source_dir / "beta" / RESOURCE).unlink()

        # A file BESIDE the entry point is compared too. This is the hole the
        # first version of this gate had: it compared SKILL.md and ignored the
        # references/ files copied alongside it.
        (tmp / source_dir / "alpha" / "references").mkdir(parents=True, exist_ok=True)
        (tmp / copy_dir / "alpha" / "references").mkdir(parents=True, exist_ok=True)
        (tmp / source_dir / "alpha" / "references" / "r.md").write_text("r\n")
        (tmp / copy_dir / "alpha" / "references" / "r.md").write_text("r\n")
        if failures := check(tmp):
            print(f"self-test failed: matching non-entry file rejected: {failures[0]}")
            return 1
        (tmp / copy_dir / "alpha" / "references" / "r.md").write_text("r edited\n")
        if not any("references/r.md" in f and "differs from" in f for f in check(tmp)):
            print("self-test failed: a divergent non-entry file was not detected")
            return 1
        (tmp / copy_dir / "alpha" / "references" / "r.md").unlink()
        if not any("references/r.md" in f and "has no copy" in f for f in check(tmp)):
            print("self-test failed: a missing non-entry copy was not detected")
            return 1
        (tmp / source_dir / "alpha" / "references" / "r.md").unlink()

        # An orphaned copy fails — the shape that happens when a source is
        # deleted and its copy is left behind.
        place(copy_dir, "gamma", "# gamma\n")
        if not any("has no source" in f for f in check(tmp)):
            print("self-test failed: an orphaned copy was not detected")
            return 1

    print(
        "self-test passed: matching copies accepted; divergent content, a "
        "whitespace-only divergence, a source without a copy, an orphaned copy, "
        "and a divergent or missing file beside the entry point each rejected"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path(__file__).resolve().parents[1], type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test(args.root)

    failures = check(args.root)
    if failures:
        print("copied resources have drifted from their sources:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    files = 0
    for source_dir, copy_dir in COPY_SETS:
        for name in names_in(args.root, source_dir) & names_in(args.root, copy_dir):
            files += len(files_under(args.root / source_dir / name))
    print(f"copied resources match their sources ({files} files checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
