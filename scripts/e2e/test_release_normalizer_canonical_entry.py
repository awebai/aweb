"""A1: the canonical normalizer entry, end to end (aben amendments).

These tests run scripts/release_normalizer_main.py as a subprocess -
the exact process the Makefile's release-prepare starts - against
synthetic repositories and a local registry stand-in speaking the real
wire protocols. They are the permanent form of the shipment-gate
probe that found the capture path unable to complete a world holding a
real AC image: identities must arrive through the OCI protocol
(read_oci_revision), not be granted by a test fake.

Red on the pre-amendment engine:
- the occupied-AC-image world stops anchorless-version instead of
  reaching normal form, because capture never reads revision labels;
- the malformed near-version world sails through, because discovery
  silently filters non-grammar candidates the design says must stop.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "e2e"))

from registry_stand_in import RegistryStandIn  # noqa: E402

MAIN = REPO_ROOT / "scripts" / "release_normalizer_main.py"

MANIFESTS = {
    "server/pyproject.toml": ("toml", "1.27.1"),
    "awid/pyproject.toml": ("toml", "0.5.16"),
    "cli/go/npm/aw/package.json": ("json", "1.34.6"),
    "channel/package.json": ("json", "1.7.7"),
    "pi-extension/package.json": ("json", "0.3.7"),
    "packages/claude-skills/package.json": ("json", "0.2.13"),
}

AWEB_TAGS = (
    "server-v1.27.1",
    "awid-service-v0.5.16",
    "awid-v0.5.16",
    "aw-v1.34.6",
    "channel-v1.7.7",
    "pi-v0.3.7",
    "skills-v0.2.13",
    "a2a-gw-v1.27.1",
)

NPM_AW_PACKAGES = (
    "@awebai/aw",
    "@awebai/aw-linux-x64",
    "@awebai/aw-linux-arm64",
    "@awebai/aw-darwin-x64",
    "@awebai/aw-darwin-arm64",
    "@awebai/aw-windows-x64",
    "@awebai/aw-windows-arm64",
)


def _write_manifest(root: Path, rel: str, kind: str, version: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "toml":
        name = rel.split("/", 1)[0]
        path.write_text(f'[project]\nname = "{name}"\nversion = "{version}"\n')
    else:
        path.write_text(json.dumps({"name": rel, "version": version}) + "\n")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout


def _build_repo(root: Path, manifests: dict, tags: tuple[str, ...]) -> str:
    root.mkdir(parents=True)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "test@aweb.ai")
    _git(root, "config", "user.name", "canonical-entry test")
    for rel, (kind, version) in manifests.items():
        _write_manifest(root, rel, kind, version)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "world at rest")
    for tag in tags:
        _git(root, "tag", tag)
    _git(root, "remote", "add", "origin", str(root))
    return _git(root, "rev-parse", "HEAD").strip()


class CanonicalEntry(unittest.TestCase):
    """The subprocess entry over a world at rest with published images."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        base = Path(cls._tmp.name)
        cls.aweb_sha = _build_repo(base / "aweb", MANIFESTS, AWEB_TAGS)
        cls.ac_sha = _build_repo(
            base / "ac", {"backend/pyproject.toml": ("toml", "0.7.14")}, ()
        )
        cls.aweb_root = base / "aweb"
        cls.ac_root = base / "ac"

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def world_at_rest(self) -> dict:
        return {
            "pypi": {"aweb": ["1.27.1"], "awid-service": ["0.5.16"]},
            "npm": {
                **{p: ["1.34.6"] for p in NPM_AW_PACKAGES},
                "@awebai/claude-channel": ["1.7.7"],
                "@awebai/pi": ["0.3.7"],
                "@awebai/claude-skills": ["0.2.13"],
            },
            "ghcr": {
                "awebai/awid": {"0.5.16": self.aweb_sha},
                "awebai/a2a-gateway": {"1.27.1": self.aweb_sha},
                "awebai/ac": {"0.7.14": self.ac_sha},
            },
            "github": {"awebai/aw": ["1.34.6"], "awebai/aweb": ["0.2.13"]},
        }

    def run_entry(self, world: dict) -> subprocess.CompletedProcess:
        with RegistryStandIn(world) as registry:
            env = dict(os.environ)
            env.update(
                {
                    "AWEB_NORMALIZER_AWEB_ROOT": str(self.aweb_root),
                    "AWEB_NORMALIZER_AC_ROOT": str(self.ac_root),
                    "AWEB_NORMALIZER_PYPI_BASE": registry.base,
                    "AWEB_NORMALIZER_NPM_BASE": registry.base,
                    "AWEB_NORMALIZER_GHCR_BASE": registry.base,
                    "AWEB_NORMALIZER_GITHUB_BASE": registry.base,
                    "AWEB_NORMALIZER_TIMEOUT": "10",
                    "COMPAT_BREAK": "none",
                }
            )
            return subprocess.run(
                [sys.executable, str(MAIN)],
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )

    def test_world_with_existing_ac_image_reaches_normal_form(self) -> None:
        # The shipment-gate probe: an AC image published at 0.7.14 whose
        # revision label names the AC commit. Capture must obtain that
        # identity through the OCI protocol; a world at rest is normal
        # form, not a conflicting or anchorless stop.
        completed = self.run_entry(self.world_at_rest())
        self.assertEqual(
            completed.returncode,
            0,
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        self.assertIn("normal form", completed.stdout)

    def test_malformed_near_version_candidate_stops_by_name(self) -> None:
        # A near-matching candidate in a version namespace is the named
        # stop, never a silent filter (design section 2).
        world = self.world_at_rest()
        world["ghcr"]["awebai/ac"]["0.7.15-rc1"] = self.ac_sha
        completed = self.run_entry(world)
        self.assertEqual(
            completed.returncode,
            1,
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        self.assertIn("malformed-version-candidate", completed.stdout)
        self.assertIn("ac-image", completed.stdout)

    def test_identityless_image_tag_is_captured_not_crashed(self) -> None:
        # A grammar-conforming tag whose config carries no revision label
        # is identityless occupancy - a legitimate observation the
        # reconciler must judge, not a capture failure. With the only
        # anchor identity gone, the AC image cannot reconcile and the
        # run must stop with a named stop, not a traceback.
        world = self.world_at_rest()
        world["ghcr"]["awebai/ac"]["0.7.14"] = None
        completed = self.run_entry(world)
        self.assertEqual(
            completed.returncode,
            1,
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        self.assertIn("STOP", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
