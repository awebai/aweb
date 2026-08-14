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
        path.write_text(
            f'[project]\nname = "{name}"\nversion = "{version}"\n'
            'dependencies = ["dep>=1"]\n'
        )
    else:
        path.write_text(
            json.dumps({"name": rel, "version": version, "dependencies": {"dep": "^1"}})
            + "\n"
        )


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

    def test_shared_manifest_pair_patches_once_and_converges(self) -> None:
        # A2, the shipment gate's duplicate-manifest probe: awid-service
        # and awid-image both derive 0.5.16 from the one physical
        # awid/pyproject.toml. The apply path must edit that file
        # exactly once and reach the fixed point - not crash on the
        # second application finding nothing left to patch.
        _write_manifest(self.aweb_root, "awid/service.py", "json", "0.0.0")
        _git(self.aweb_root, "add", "-A")
        _git(self.aweb_root, "commit", "-q", "-m", "awid content moves")
        try:
            completed = self.run_entry(self.world_at_rest())
            self.assertEqual(
                completed.returncode,
                10,
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
            )
            self.assertNotIn("Traceback", completed.stderr)
            self.assertIn("awid-service: 0.5.16 -> 0.5.17", completed.stdout)
            self.assertIn("awid-image: 0.5.16 -> 0.5.17", completed.stdout)
            self.assertEqual(
                (self.aweb_root / "awid/pyproject.toml").read_text().count("0.5.17"),
                1,
                "the shared manifest carries the new version exactly once",
            )
        finally:
            _git(self.aweb_root, "checkout", "-q", "awid/pyproject.toml")
            _git(self.aweb_root, "reset", "-q", "--hard", "HEAD~1")

    def test_dependency_only_manifest_change_moves_the_artifact(self) -> None:
        # A3, the shipment gate's dependency blind spot: manifests carry
        # shipped dependencies, so a dep-only edit is a content change.
        # Only the owned version field is normalization noise; excluding
        # the whole file recreated the narrow-card defect for
        # dependency-only changes.
        manifest = self.aweb_root / "awid/pyproject.toml"
        manifest.write_text(manifest.read_text().replace("dep>=1", "dep>=2"))
        _git(self.aweb_root, "add", "-A")
        _git(self.aweb_root, "commit", "-q", "-m", "dependency floor moves")
        try:
            completed = self.run_entry(self.world_at_rest())
            self.assertEqual(
                completed.returncode,
                10,
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
            )
            self.assertIn("awid-service: 0.5.16 -> 0.5.17", completed.stdout)
            self.assertIn("awid-image: 0.5.16 -> 0.5.17", completed.stdout)
        finally:
            _git(self.aweb_root, "reset", "-q", "--hard", "HEAD~1")

    def test_dirty_checkout_stops_by_name(self) -> None:
        # A4: the normalizer's inputs are exact SHAs from CLEAN
        # checkouts; a dirty tree is a named stop before any capture.
        marker = self.aweb_root / "channel/package.json"
        original = marker.read_text()
        marker.write_text(original + "\n")
        try:
            completed = self.run_entry(self.world_at_rest())
            self.assertEqual(
                completed.returncode,
                1,
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
            )
            self.assertIn("dirty-checkout", completed.stdout)
            self.assertIn("aweb", completed.stdout)
        finally:
            marker.write_text(original)

    def test_moved_main_stops_by_name(self) -> None:
        # A4: origin's main advancing past the checkout is mains
        # movement - a named stop, not a world computed from stale
        # inputs.
        with tempfile.TemporaryDirectory() as ahead_dir:
            ahead = Path(ahead_dir) / "ahead"
            subprocess.run(
                ["git", "clone", "-q", str(self.ac_root), str(ahead)],
                check=True,
                capture_output=True,
            )
            _git(ahead, "config", "user.email", "test@aweb.ai")
            _git(ahead, "config", "user.name", "canonical-entry test")
            (ahead / "backend/note.txt").write_text("moved\n")
            _git(ahead, "add", "-A")
            _git(ahead, "commit", "-q", "-m", "main moves under the run")
            _git(self.ac_root, "remote", "set-url", "origin", str(ahead))
            try:
                completed = self.run_entry(self.world_at_rest())
                self.assertEqual(
                    completed.returncode,
                    1,
                    f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
                )
                self.assertIn("main-moved", completed.stdout)
                self.assertIn("ac", completed.stdout)
            finally:
                _git(self.ac_root, "remote", "set-url", "origin", str(self.ac_root))

    def test_patch_output_prints_base_shas_and_the_exact_diff(self) -> None:
        # A4 transport contract: PATCH NEEDED prints the base SHAs of
        # both repositories and the exact changed-file diff, so review
        # of the patch needs nothing but this output.
        manifest = self.aweb_root / "awid/pyproject.toml"
        manifest.write_text(manifest.read_text().replace("dep>=1", "dep>=2"))
        _git(self.aweb_root, "add", "-A")
        _git(self.aweb_root, "commit", "-q", "-m", "dependency floor moves")
        sha = _git(self.aweb_root, "rev-parse", "HEAD").strip()
        try:
            completed = self.run_entry(self.world_at_rest())
            self.assertEqual(
                completed.returncode,
                10,
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
            )
            self.assertIn(f"base aweb={sha}", completed.stdout)
            self.assertIn(f"base ac={self.ac_sha}", completed.stdout)
            self.assertIn('-version = "0.5.16"', completed.stdout)
            self.assertIn('+version = "0.5.17"', completed.stdout)
        finally:
            _git(self.aweb_root, "reset", "-q", "--hard", "HEAD~1")

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
