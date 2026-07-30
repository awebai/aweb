"""Refuse a pytest run that collects files git does not track.

pytest collects by filesystem, so an uncommitted file under a test package is
collected and counted like any other test. On CI that is harmless: the checkout
is made from a commit and there is nothing uncommitted to find. Locally the
working tree and the committed tree are not the same thing, and the release
gates run locally.

The consequence is not only a wrong count. A collected file EXECUTES, so an
uncommitted probe can fail a gate for a reason unrelated to the release, or pass
and be credited as coverage that exists in nobody's commit.

Tracked-ness is asked POSITIVELY: git ls-files lists what IS tracked, and
anything collected that is not in that list is refused. Asking the other way -
for untracked files - has to name an exclusion rule, and the standard one
(--exclude-standard) skips files matched by .gitignore. Those are still
collected by pytest, so a negative query answers a different question than the
one being asked and reports zero on a tree that has the problem.

Consumed by the package-root conftest.py of each gated suite. It belongs at the
package ROOT, not in tests/: a conftest is loaded only when something it applies
to is collected, so a check declared in tests/conftest.py is absent - not
failing, absent - whenever pytest is invoked on a path outside tests/. At the
rootdir it loads for every invocation. Moving it down narrows it silently,
because the narrowed version still passes.

The only way to make a collected file acceptable is to commit it. There is
deliberately no environment variable, marker file, or CI-detection bypass: an
escape hatch added for convenience is how this class of defect returns.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


class GitUnavailable(RuntimeError):
    """Raised when tracked-ness cannot be established at all."""


def _as_named(path: Path) -> Path:
    """Normalize a path without following a symlink in its final component.

    Resolving the whole path would replace a symlink with its target. A symlink
    is a file in its own right as far as collection goes: pytest collects it
    under its own name and runs every test it exposes, so an untracked symlink
    to a tracked file adds that file's tests to the suite a second time and
    inflates the count. Resolved, it reads as the tracked target and passes.

    The parent is resolved because it must match the parent of the path git
    reports; only the final component is left as collected.
    """
    return path.parent.resolve() / path.name


def _collected_files(items) -> set[Path]:
    paths = set()
    for item in items:
        raw = getattr(item, "path", None) or getattr(item, "fspath", None)
        if raw is None:
            continue
        paths.add(_as_named(Path(str(raw))))
    return paths


def _repo_root(cwd: Path) -> Path:
    try:
        return Path(
            subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=cwd,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        ).resolve()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GitUnavailable(str(exc)) from exc


def _tracked(paths: set[Path], root: Path, cwd: Path) -> set[Path]:
    """Return the subset of paths that git reports as tracked.

    Every path must already be known to lie under root. Passing git a path
    outside the work tree makes it exit 128, which would surface as "cannot
    establish tracked-ness" and hide the real situation.

    Raises GitUnavailable if git cannot answer. That is a refusal rather than a
    pass: these suites are collected from a checkout, so an environment without a
    work tree is one where the question cannot be answered and the answer cannot
    be assumed. Since the tests no longer ship in the sdist, no legitimate caller
    runs them outside a repository.
    """
    # Both flags are load-bearing, and both fail toward a refusal of the whole
    # suite rather than toward a pass:
    #
    # --full-name forces repo-root-relative output. Without it git reports paths
    # relative to the invocation directory, which silently mismatches the join
    # below and makes every tracked file look untracked.
    #
    # -z is not merely a delimiter choice. It also suppresses core.quotePath,
    # which is on by default and renders a non-ASCII path as an escaped, quoted
    # C string - "test_caf\303\251.py" for test_café.py. That does not
    # string-match the collected path, so without -z any tracked file with a
    # non-ASCII name reads as untracked.
    try:
        listed = subprocess.run(
            ["git", "ls-files", "-z", "--full-name", "--", *[str(p) for p in sorted(paths)]],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GitUnavailable(str(exc)) from exc
    return {_as_named(root / rel) for rel in listed.stdout.split("\0") if rel}


def refuse_untracked(config, items) -> None:
    """Raise pytest.UsageError if any collected file is not tracked by git."""
    collected = _collected_files(items)
    if not collected:
        return

    invocation = Path(str(config.rootpath))
    try:
        root = _repo_root(invocation)
        # A path outside the work tree cannot be tracked, and asking git about one
        # makes it exit 128 - which would be reported as an inability to establish
        # tracked-ness and hide a collected file that escaped the repository.
        inside = {p for p in collected if root in p.parents}
        outside = collected - inside
        tracked = _tracked(inside, root, invocation)
    except GitUnavailable as exc:
        raise pytest.UsageError(
            "cannot establish which collected files are tracked, so this suite "
            f"will not run: {exc}\n\n"
            "This suite is collected from a checkout and is not distributed, so "
            "there is no supported way to run it outside a git work tree. If you "
            "are running from an extracted archive, that archive should not have "
            "contained these tests."
        ) from exc

    untracked = sorted(inside - tracked)
    escaped = sorted(outside)
    if not untracked and not escaped:
        return

    message = ["this suite collected files that are in no commit of this repository:"]
    if untracked:
        message.append("\n  not tracked by git:\n")
        message.extend(f"    {p}\n" for p in untracked)
    if escaped:
        message.append("\n  outside the work tree, so not trackable here:\n")
        message.extend(f"    {p}\n" for p in escaped)
    message.append(
        "\nThe suite is collected from the working tree, not from the committed "
        "tree, so these files run and are counted even though they are in no "
        "commit. On CI they would not exist.\n\n"
        "Commit them if they belong to the suite - an uncommitted regression "
        "test is exactly this case, and the answer is to commit it. Move them "
        "out of this package if they do not."
    )
    raise pytest.UsageError("".join(message))
