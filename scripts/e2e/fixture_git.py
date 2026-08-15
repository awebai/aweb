"""The one owner of fixture git invocation.

Two host settings the gate container does not have, and both of them
have now cost a gate run:

- **identity.** `user.name`/`user.email` are set on a developer host and
  absent in the container, so `commit` fails there and passes here.
- **`init.defaultBranch`.** A developer host sets `main`; the container
  falls back to `master`. An unpinned bare remote therefore ends up with
  HEAD on a branch nothing was ever pushed to, so a later clone checks
  out NOTHING and `rev-parse HEAD` exits 128 - which is exactly how the
  D3 test passed where it was written and errored where it runs.

Both are pinned HERE rather than at call sites, because a call site that
can forget is a call site that will. Five modules currently carry their
own copy of this function and have already drifted into three variants
(two identity strings, and some doing an extra post-init step); that
migration is tracked by test_release_fixture_git_ownership, which also
refuses a NEW module that initialises a repository without going through
this one.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def git(*args: str, cwd: Path) -> str:
    """Run one git command with the host-dependent settings pinned."""

    if args and args[0] == "init" and not any(
        a in ("-b", "--initial-branch") for a in args
    ):
        args = (args[0], "-b", "main") + tuple(args[1:])
    return subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
