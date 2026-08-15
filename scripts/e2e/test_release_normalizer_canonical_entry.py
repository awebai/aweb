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
    # The aweb checkout carries the marketplace adapter the continue
    # command invokes; prepare refuses without it, so the fixture
    # models a checkout that could actually run a release.
    "scripts/pointer-adapter-marketplace-pointer.py": ("raw", "#\n"),
    "server/pyproject.toml": (
        "raw",
        '[project]\nname = "server"\nversion = "1.27.1"\n'
        'dependencies = ["awid-service>=0.5.16"]\n',
    ),
    "server/uv.lock": ("raw", "# lock v1\n"),
    "awid/uv.lock": ("raw", "# lock v1\n"),
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
    if kind == "raw":
        path.write_text(version)
    elif kind == "toml":
        name = rel.split("/", 1)[0]
        path.write_text(
            f'[project]\nname = "{name}"\nversion = "{version}"\n'
            'dependencies = ["dep>=1"]\n'
        )
    else:
        path.write_text(
            json.dumps(
                {"name": rel, "version": version, "dependencies": {"dep": "^1"}},
                indent=2,
            )
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


class _WorldFixture(unittest.TestCase):
    """The synthetic aweb/ac pair and registry stand-in shared by the
    canonical entry proofs; carries no tests of its own."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        # The pair lives under awebai/ so each repo's origin (itself)
        # satisfies the canonical-remote check the train enforces.
        base = Path(cls._tmp.name) / "awebai"
        cls.aweb_sha = _build_repo(base / "aweb", MANIFESTS, AWEB_TAGS)
        # A resolved AC checkout carries the scripts the continue
        # commands invoke; prepare refuses without them, by name, at
        # the fail-fast phase. The fixture models that rather than a
        # checkout that could never work.
        cls.ac_sha = _build_repo(
            base / "ac",
            {
                "backend/pyproject.toml": ("toml", "0.7.14"),
                "scripts/derive_release_floors.py": ("raw", "#\n"),
                "scripts/render_release_client.py": ("raw", "#\n"),
                "scripts/verify_registry_adoption.py": ("raw", "#\n"),
            },
            # ac-image is tag-anchored like every other artifact now:
            # its identity is the tag in its OWN repository.
            ("v0.7.14",),
        )
        # The aw product checkout joins the run pair: the external
        # binding is read from it with local git, so the phase refuses
        # without it rather than letting the binding go unchecked.
        cls.aw_sha = _build_repo(base / "aw", {"main.go": ("raw", "package main\n")}, ())
        cls.aweb_root = base / "aweb"
        cls.ac_root = base / "ac"
        cls.aw_root = base / "aw"
        cls.lock_script = base / "relock.sh"
        cls.lock_script.write_text(
            "#!/bin/sh\necho relocked >> uv.lock\n"
            "echo offline=${UV_OFFLINE:-unset} >> uv.lock\n"
        )
        cls.lock_script.chmod(0o755)

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
            # skills' release lives in its OWN repository, so it is
            # tagged with the canonical anchor prefix - the real shape
            # the first live prepare taught us.
            "github_tag_prefix": {"awebai/aweb": "skills-v"},
        }

    def run_entry(
        self,
        world: dict,
        *,
        lock_command: str | None = None,
        invariant_commands: str = "[]",
        aw_root: str | None = None,
    ) -> subprocess.CompletedProcess:
        # Tests override the invariant pass explicitly (default: none);
        # the production default list is pinned by its own unit test.
        with RegistryStandIn(world) as registry:
            env = dict(os.environ)
            env.update(
                {
                    "AWEB_NORMALIZER_INVARIANT_COMMANDS": invariant_commands,
                    "AWEB_NORMALIZER_LOCK_COMMAND": lock_command
                    or str(self.lock_script),
                    "AWEB_NORMALIZER_AWEB_ROOT": str(self.aweb_root),
                    "AWEB_NORMALIZER_AC_ROOT": str(self.ac_root),
                    "AWEB_NORMALIZER_AW_ROOT": aw_root or str(self.aw_root),
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

class CanonicalEntry(_WorldFixture):
    """The normalizer subprocess entry over the world at rest."""

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

    def test_awid_move_cascades_floor_lock_and_server_by_policy(self) -> None:
        # A4, the whole allowlisted patch through the entry: awid content
        # moves, so the R1 policy must ALSO edit server's floor literal,
        # move server (and by equality the gateway), regenerate the
        # owned locks of every patched manifest, and show all of it in
        # the transport diff - reaching the fixed point in one pass.
        _write_manifest(self.aweb_root, "awid/service.py", "json", "0.0.0")
        _git(self.aweb_root, "add", "-A")
        _git(self.aweb_root, "commit", "-q", "-m", "awid content moves")
        try:
            completed = self.run_entry(self.world_at_rest())
            out = f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            self.assertEqual(completed.returncode, 10, out)
            self.assertIn("awid-service: 0.5.16 -> 0.5.17", completed.stdout)
            self.assertIn("aweb-server: 1.27.1 -> 1.27.2", completed.stdout)
            self.assertIn("a2a-gateway-image: 1.27.1 -> 1.27.2", completed.stdout)
            server_manifest = (self.aweb_root / "server/pyproject.toml").read_text()
            self.assertIn("awid-service>=0.5.17", server_manifest, out)
            self.assertIn(
                "relocked", (self.aweb_root / "awid/uv.lock").read_text(), out
            )
            # C5: the regeneration itself runs offline, not only the
            # later invariant check.
            self.assertIn(
                "offline=1", (self.aweb_root / "awid/uv.lock").read_text(), out
            )
            self.assertIn(
                "relocked", (self.aweb_root / "server/uv.lock").read_text(), out
            )
            self.assertIn('+dependencies = ["awid-service>=0.5.17"]', completed.stdout)
            self.assertIn("+relocked", completed.stdout)
        finally:
            _git(self.aweb_root, "reset", "-q", "--hard", "HEAD~1")

    def test_lock_regeneration_failure_stops_by_name(self) -> None:
        # A failed lock command is a named stop, never a patch that
        # quietly shipped stale locks.
        _write_manifest(self.aweb_root, "awid/service.py", "json", "0.0.0")
        _git(self.aweb_root, "add", "-A")
        _git(self.aweb_root, "commit", "-q", "-m", "awid content moves")
        try:
            completed = self.run_entry(
                self.world_at_rest(), lock_command="false"
            )
            out = f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            self.assertEqual(completed.returncode, 1, out)
            self.assertIn("lock-regeneration-failed", completed.stdout)
        finally:
            _git(self.aweb_root, "reset", "-q", "--hard", "HEAD~1")

    def test_failing_invariant_stops_by_name_after_the_patch(self) -> None:
        # A4: the read-only invariant pass runs after patch application;
        # a failing invariant is the named stop, and the marker command
        # proves the pass saw the PATCHED tree.
        _write_manifest(self.aweb_root, "awid/service.py", "json", "0.0.0")
        _git(self.aweb_root, "add", "-A")
        _git(self.aweb_root, "commit", "-q", "-m", "awid content moves")
        marker = self.aweb_root.parent / "invariant-saw.toml"
        invariants = json.dumps(
            [
                {
                    "label": "sees-patched-tree",
                    "argv": ["cp", "awid/pyproject.toml", str(marker)],
                },
                {"label": "broken-invariant", "argv": ["false"]},
            ]
        )
        try:
            completed = self.run_entry(
                self.world_at_rest(), invariant_commands=invariants
            )
            out = f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            self.assertEqual(completed.returncode, 1, out)
            self.assertIn("invariant-failed", completed.stdout)
            self.assertIn("broken-invariant", completed.stdout)
            self.assertIn('version = "0.5.17"', marker.read_text(), out)
        finally:
            marker.unlink(missing_ok=True)
            _git(self.aweb_root, "reset", "-q", "--hard", "HEAD~1")

    def test_invariants_run_on_normal_form_too(self) -> None:
        marker = self.aweb_root.parent / "invariant-at-rest"
        invariants = json.dumps(
            [{"label": "at-rest", "argv": ["touch", str(marker)]}]
        )
        try:
            completed = self.run_entry(
                self.world_at_rest(), invariant_commands=invariants
            )
            out = f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            self.assertEqual(completed.returncode, 0, out)
            self.assertTrue(marker.exists(), out)
        finally:
            marker.unlink(missing_ok=True)

    def test_the_aw_binding_cannot_be_skipped_at_the_real_entry(self) -> None:
        """plan-critic's decisive requirement, and the one that decides
        whether the checkout's named stops are decoration.

        The external binding is answered from the local aw checkout, so
        a missing checkout must STOP THE RUN through the actual entry
        point - not degrade the binding to "not checked". That is the
        column-b lesson: a row that cannot run where it is supposed to,
        reporting nothing, is indistinguishable from a row that passed.

        Run as a subprocess against the real entry, with a CONTROL: the
        same world WITH the checkout reaches normal form. Without the
        control this would pass on an entry that refuses everything."""

        world = self.world_at_rest()

        # Control: the binding is satisfiable, and the run proceeds.
        healthy = self.run_entry(world)
        self.assertEqual(healthy.returncode, 0, healthy.stdout + healthy.stderr)

        # The same world, with the aw checkout taken away.
        missing = self.run_entry(world, aw_root=str(self.aw_root) + "-gone")
        self.assertEqual(
            missing.returncode, 1, missing.stdout + missing.stderr
        )
        self.assertIn("aw-checkout-absent", missing.stdout)
        self.assertIn("aw-cli", missing.stdout)
        self.assertNotIn("Traceback", missing.stderr)
        # It stops at the PRECONDITION - before any registry work - so
        # a run that cannot check the binding does no work at all.
        self.assertNotIn("normal form", missing.stdout)
        self.assertNotIn("PATCH NEEDED", missing.stdout)

    def test_identityless_image_tag_is_captured_not_crashed(self) -> None:
        # A published version with NO source tag in its own repository
        # is identityless occupancy - a legitimate observation the
        # reconciler must judge, not a capture failure. Under the tag
        # ruling that is the shape the old missing-revision-label case
        # became: the registry serves the version, nothing in the repo
        # says what it was built from, and the run must stop BY NAME
        # rather than traceback or guess.
        world = self.world_at_rest()
        # The registry serves a version the repository never tagged.
        # (Nulling the old revision LABEL would no longer test
        # anything: identity comes from the tag now, and the fixture
        # has one - the assertion would pass on a broken engine.)
        world["ghcr"]["awebai/ac"]["0.7.15"] = None
        completed = self.run_entry(world)
        self.assertEqual(
            completed.returncode,
            1,
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        self.assertIn("STOP", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)


class PrepareEntry(_WorldFixture):
    """A5: the one-command production entry - release_train.py prepare
    runs the normalizer phase in-process and builds the card from its
    projection."""

    def run_prepare(
        self, world: dict, *, gate: Path, extra_env: dict | None = None
    ) -> subprocess.CompletedProcess:
        with RegistryStandIn(world) as registry:
            env = dict(os.environ)
            env.update(
                {
                    "AWEB_NORMALIZER_INVARIANT_COMMANDS": "[]",
                    "AWEB_NORMALIZER_LOCK_COMMAND": str(self.lock_script),
                    "AWEB_NORMALIZER_AWEB_ROOT": str(self.aweb_root),
                    "AWEB_NORMALIZER_AC_ROOT": str(self.ac_root),
                    "AWEB_NORMALIZER_AW_ROOT": str(self.aw_root),
                    "AWEB_NORMALIZER_PYPI_BASE": registry.base,
                    "AWEB_NORMALIZER_NPM_BASE": registry.base,
                    "AWEB_NORMALIZER_GHCR_BASE": registry.base,
                    "AWEB_NORMALIZER_GITHUB_BASE": registry.base,
                    "AWEB_NORMALIZER_TIMEOUT": "10",
                    "PURPOSE": "canonical entry proof",
                    "COMPAT_BREAK": "none",
                    "AWEB_RELEASE_GATE_COMMAND": f"{sys.executable} {gate}",
                }
            )
            env.update(extra_env or {})
            return subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "release_train.py"), "prepare"],
                cwd=self.aweb_root,
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
            )

    def _gate_stub(self, marker: Path) -> Path:
        gate = self.aweb_root.parent / "gate-stub.py"
        gate.write_text(
            "import json, pathlib, sys\n"
            f"pathlib.Path({str(marker)!r}).write_text('ran')\n"
            'print(json.dumps({"suites": ["fixture"], "reference": "fixture.log"}))\n'
        )
        return gate

    def test_one_command_prepare_builds_the_card_from_the_projection(self) -> None:
        marker = self.aweb_root.parent / "gate-ran"
        try:
            completed = self.run_prepare(self.world_at_rest(), gate=self._gate_stub(marker))
            out = f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            self.assertEqual(completed.returncode, 0, out)
            self.assertIn("normal form", completed.stdout)
            self.assertEqual(completed.stdout.count('"disposition": "unmoved"'), 9, out)
            self.assertIn('"kind": "tag"', completed.stdout)
            self.assertIn(self.ac_sha, completed.stdout)
            self.assertTrue(marker.exists(), "the gate must run on normal form")
        finally:
            marker.unlink(missing_ok=True)

    def test_selected_older_sha_produces_a_card_for_that_selection(self) -> None:
        # C4, the critic's precision: a valid AWEB_SHA override selecting
        # an older-on-main commit must WORK - the projection computed
        # from that exact object, the card carrying that selection - not
        # refuse, and not silently card the newer HEAD's world.
        marker = self.aweb_root.parent / "gate-ran-override"
        older = self.aweb_sha
        _write_manifest(self.aweb_root, "server/moved.py", "json", "0.0.0")
        _git(self.aweb_root, "add", "-A")
        _git(self.aweb_root, "commit", "-q", "-m", "server content moves at HEAD")
        newer = _git(self.aweb_root, "rev-parse", "HEAD").strip()
        try:
            completed = self.run_prepare(
                self.world_at_rest(),
                gate=self._gate_stub(marker),
                extra_env={"AWEB_SHA": older},
            )
            out = f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            self.assertEqual(completed.returncode, 0, out)
            self.assertIn(f'"aweb_sha": "{older}"', completed.stdout, out)
            self.assertNotIn(newer, completed.stdout, out)
            # At the OLDER selection the world is at rest - nine unmoved
            # rows; the HEAD world would have moved the server pair.
            self.assertEqual(
                completed.stdout.count('"disposition": "unmoved"'), 9, out
            )
        finally:
            marker.unlink(missing_ok=True)
            _git(self.aweb_root, "reset", "-q", "--hard", older)

    def test_patch_needed_ends_the_command_before_any_test(self) -> None:
        marker = self.aweb_root.parent / "gate-ran"
        _write_manifest(self.aweb_root, "awid/service.py", "json", "0.0.0")
        _git(self.aweb_root, "add", "-A")
        _git(self.aweb_root, "commit", "-q", "-m", "awid content moves")
        try:
            completed = self.run_prepare(self.world_at_rest(), gate=self._gate_stub(marker))
            out = f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            self.assertEqual(completed.returncode, 10, out)
            self.assertIn("PATCH NEEDED", completed.stdout)
            self.assertFalse(marker.exists(), "no test may run past a patch stop")
            self.assertNotIn('"artifacts"', completed.stdout)
        finally:
            marker.unlink(missing_ok=True)
            _git(self.aweb_root, "reset", "-q", "--hard", "HEAD~1")


if __name__ == "__main__":
    unittest.main()
