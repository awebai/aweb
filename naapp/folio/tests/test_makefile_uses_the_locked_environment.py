"""The Makefile must reach folio's dependencies through uv, not through a bare interpreter.

Both halves of this were broken by the naapp move and neither was caught by anything:

  1. Every recipe carried ``PYTHONPATH=src:../aweb/awid/src:../pgdbm/src``, which resolved
     when folio was a sibling of aweb and pgdbm. Inside aweb/naapp/folio those paths point
     at naapp/aweb and naapp/pgdbm, neither of which exists.

  2. The sharper half: the recipes ran ``python3 -m ...``, which takes whatever is on PATH
     and so never used folio's locked environment at all. Correcting the paths alone would
     have left ``make test`` failing with "No module named pytest" on a machine whose
     ``uv sync --locked`` succeeds cleanly.

The move did not break folio's code. It broke an assumption its build encoded about where
folio lived - and the interpreter bug was there the whole time, hidden behind the paths.

These assertions are written over EVERY recipe rather than over ``test:`` alone. ``test:``
was the target anyone would think to guard, and ``compile``, ``run``, ``api-serve`` and
``api-stop`` carried the identical defect while nothing looked at them. A guard naming one
target would have let the others drift exactly as they did.
"""

from __future__ import annotations

import re
from pathlib import Path

_MAKEFILE = Path(__file__).resolve().parents[1] / "Makefile"


def _recipe_lines() -> list[str]:
    """Every command line in the Makefile - the tab-indented ones."""
    return [
        line
        for line in _MAKEFILE.read_text(encoding="utf-8").splitlines()
        if line.startswith("\t")
    ]


def test_no_recipe_resolves_dependencies_through_a_sibling_path() -> None:
    offenders = [line for line in _recipe_lines() if re.search(r"\.\./\w", line)]

    assert not offenders, (
        "a recipe reaches outside folio with a relative path, which stops resolving "
        "wherever folio is checked out next:\n  " + "\n  ".join(offenders)
    )


def test_no_recipe_invokes_a_bare_interpreter() -> None:
    """`python3 -m x` uses whatever is on PATH, so the locked environment is not used."""
    offenders = [
        line
        for line in _recipe_lines()
        if re.search(r"(?<!uv run )\bpython3?\b", line) and "uv run" not in line
    ]

    assert not offenders, (
        "a recipe invokes an interpreter without uv, so folio's locked dependencies are "
        "not the ones that run:\n  " + "\n  ".join(offenders)
    )


def test_the_test_target_runs_pytest_through_uv() -> None:
    """The specific assertion library makes about itself, kept so the two repos agree."""
    body = _MAKEFILE.read_text(encoding="utf-8").split("test:\n", 1)[1].split("\n\n", 1)[0]

    assert "uv run pytest" in body
    assert "python3 -m pytest" not in body
