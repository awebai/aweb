#!/usr/bin/env python3
"""Has this artifact's content changed since its newest release?

Prints `moved` or `unmoved`. Publication workflows ask before they
publish, so a branch move that did not touch an artifact cannot mint a
version for it.

Five of the six release-branch workflows never needed to ask: they read
their version out of the committed tree, so an unchanged tree re-derives
a version that is already public and the exact-publish triple adopts or
refuses. `aw-release.yml` derives its version from the WORLD - latest
published tag plus one - which can never collide with an existing tag,
so it minted a new aw-cli on every release-branch move and its own tag
preflight was structurally incapable of noticing.

The answer comes from the canonical record via the capture spec, never
from a path written here: the artifact's scope, exclusions and version
mask have one owner, and a workflow restating any of them would be the
same defect one level out.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_normalizer_capture as capture  # noqa: E402
import release_train as train  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", help="canonical artifact key")
    parser.add_argument(
        "--repo",
        default=".",
        type=Path,
        help="checkout to read; its HEAD is the candidate content",
    )
    args = parser.parse_args(argv)

    specs = {s.name: s for s in capture.derive_capture_specs(train.ARTIFACTS)}
    spec = specs.get(args.artifact)
    if spec is None:
        parser.error(
            f"{args.artifact} is not a versioned artifact in the canonical "
            f"record; known: {', '.join(sorted(specs))}"
        )

    # An unreadable remote must refuse, never answer. Reporting "unmoved"
    # on a failed observation would suppress a real release, and
    # reporting "moved" would mint one - observation failure is
    # permission for neither.
    refs = capture.remote_ref_snapshot(args.repo)
    movement = capture.anchor_movement(args.repo, spec, refs)
    print("moved" if movement.changed else "unmoved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
