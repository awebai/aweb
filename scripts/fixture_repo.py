"""Shared setup for temporary Git repositories used by host tests."""

from pathlib import Path
import subprocess


def init_fixture_repo(root: Path) -> None:
    """Initialize a fixture whose Python imports cannot dirty the checkout."""
    subprocess.run(["git", "init", "-qb", "main", str(root)], check=True,
                   capture_output=True, text=True)
    ignore = root / ".gitignore"
    existing = ignore.read_text() if ignore.exists() else ""
    ignore.write_text(existing + ("\n" if existing and not existing.endswith("\n") else "")
                      + "__pycache__/\n")
