"""Shared setup for temporary Git repositories used by host tests."""

from pathlib import Path
import os
import subprocess


def fixture_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """Keep tool/service settings, but give fixture Python its own defaults."""
    environment = dict(os.environ if env is None else env)
    for name in ("PYTHONPYCACHEPREFIX", "PYTHONDONTWRITEBYTECODE", "PYTHONPATH", "PYTHONSTARTUP"):
        environment.pop(name, None)
    return environment


def run_fixture(*args, env=None, **kwargs):
    """Run a host fixture command without the caller's Python configuration."""
    return subprocess.run(*args, env=fixture_env(env), **kwargs)


def init_fixture_repo(root: Path) -> None:
    """Initialize a fixture whose Python imports cannot dirty the checkout."""
    run_fixture(["git", "init", "-qb", "main", str(root)], check=True,
                capture_output=True, text=True)
    ignore = root / ".gitignore"
    existing = ignore.read_text() if ignore.exists() else ""
    ignore.write_text(existing + ("\n" if existing and not existing.endswith("\n") else "")
                      + "__pycache__/\n")
