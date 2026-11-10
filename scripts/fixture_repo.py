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


def write_artifact_fixture(root: Path) -> None:
    """Small retained bytes for scheduler/ledger boundary fixtures."""
    (root / 'scripts/artifact_fixture.py').write_text(
        'import hashlib,json,os,pathlib,subprocess\nfrom release_artifacts import build_inputs\n'
        'out=pathlib.Path(os.environ["CANDIDATE_ARTIFACT_DIR"]);out.mkdir(parents=True,exist_ok=True)\n'
        'payload=b"retained artifact fixture"; (out/"fixture.whl").write_bytes(payload)\n'
        'tree=subprocess.check_output(["git","rev-parse","HEAD^{tree}"],text=True).strip()\n'
        'row=dict(path="fixture.whl",package="fixture",version="1.0.0",sha256=hashlib.sha256(payload).hexdigest())\n'
        '(out/"manifest.json").write_text(json.dumps(dict(source_tree=tree,build_inputs=build_inputs(pathlib.Path.cwd()),files=[row])))\n')
