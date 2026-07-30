"""Refuse to run this suite when it collects files git does not track.

The check itself, and the reasoning behind where it lives and why it has no
bypass, are in scripts/pytest_tracked_collection.py. This file exists at the
package root so the check is loaded on every invocation of this suite rather
than only when something under tests/ is collected.

The module is loaded by path rather than by putting scripts/ on sys.path, so
guarding this suite does not add every file in scripts/ to the import namespace
the suite itself resolves names against.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_guard_path = Path(__file__).resolve().parent.parent / "scripts" / "pytest_tracked_collection.py"
_spec = importlib.util.spec_from_file_location("pytest_tracked_collection", _guard_path)
_guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_guard)


def pytest_collection_modifyitems(config, items):
    _guard.refuse_untracked(config, items)
