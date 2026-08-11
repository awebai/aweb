#!/usr/bin/env python3
"""Behavioral contract for the fixed two-repository release train foundation.

The tests use real temporary git repositories, subprocesses, and a loopback HTTP
server.  Nothing contacts or mutates GitHub, a public registry, AC, Render, or a
production service.
"""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_train as rt


VERSIONS = {
    "awid-service": "0.5.15",
    "aweb-server": "1.27.1",
    "awid-image": "0.5.15",
    "aw-cli": "1.34.2",
    "channel-plugin": "1.7.6",
    "pi-extension": "0.3.6",
    "skills": "0.2.12",
    "a2a-gateway-image": "1.27.1",
    "ac-image": "0.7.12",
}
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def git(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def replace_artifact(key: str, **changes: object) -> tuple[rt.Artifact, ...]:
    return tuple(
        dataclasses.replace(artifact, **changes) if artifact.key == key else artifact
        for artifact in rt.ARTIFACTS
    )


class FixedContractTests(unittest.TestCase):
    def test_literal_contract_has_the_exact_release_inventory(self) -> None:
        rt.validate_fixed_contract(rt.ARTIFACTS, rt.DAG_EDGES, (rt.CARD_GIT_PATH,))
        self.assertEqual(len(rt.ARTIFACTS), 12)
        self.assertEqual(len(rt.DAG_EDGES), 10)
        self.assertEqual(
            rt.AW_NPM_PACKAGES,
            (
                "@awebai/aw",
                "@awebai/aw-linux-x64",
                "@awebai/aw-linux-arm64",
                "@awebai/aw-darwin-x64",
                "@awebai/aw-darwin-arm64",
                "@awebai/aw-windows-x64",
                "@awebai/aw-windows-arm64",
            ),
        )
        self.assertEqual(rt.AW_BINARIES, ("aw", "aweb-a2a-gw"))
        self.assertEqual(
            rt.SKILL_ZIPS,
            tuple(f"{name}.zip" for name in rt.SKILL_SOURCES),
        )
        self.assertEqual(rt.OCI_PLATFORMS, ("linux/amd64", "linux/arm64"))

        by_key = {artifact.key: artifact for artifact in rt.ARTIFACTS}
        self.assertEqual(
            by_key["aw-cli"].targets,
            ("github:awebai/aw:release",)
            + tuple(f"npm:{package}" for package in rt.AW_NPM_PACKAGES),
        )
        self.assertEqual(by_key["aw-cli"].outputs, rt.AW_BINARIES)
        self.assertEqual(by_key["skills"].outputs, rt.SKILL_ZIPS)
        self.assertEqual(by_key["skills"].bundled_inputs, rt.SKILL_SOURCES)
        self.assertEqual(by_key["pi-extension"].bundled_inputs,
                         ("channel-core",) + rt.SKILL_SOURCES)
        self.assertEqual(by_key["awid-image"].bundled_inputs, ("server-source",))
        self.assertEqual(by_key["a2a-gateway-image"].version_source,
                         "equals:server/pyproject.toml")
        self.assertEqual(
            {by_key["awid-site"].targets[0], by_key["aweb-site"].targets[0]},
            {
                "render-static:deploy-awid-landing",
                "render-static:deploy-landing",
            },
        )

    def test_added_or_reordered_edge_is_refused(self) -> None:
        added = rt.DAG_EDGES + (
            rt.ReleaseEdge(11, "ordering", ("a", "b"), "not approved"),
        )
        with self.assertRaisesRegex(rt.ContractError, "ten audited edges"):
            rt.validate_fixed_contract(rt.ARTIFACTS, added, (rt.CARD_GIT_PATH,))
        with self.assertRaisesRegex(rt.ContractError, "order or content"):
            rt.validate_fixed_contract(
                rt.ARTIFACTS,
                (rt.DAG_EDGES[1], rt.DAG_EDGES[0], *rt.DAG_EDGES[2:]),
                (rt.CARD_GIT_PATH,),
            )

    def test_omitted_artifact_platform_package_binary_or_zip_is_refused(self) -> None:
        mutations = {
            "artifact": rt.ARTIFACTS[:-1],
            "platform": replace_artifact("awid-image", platforms=("linux/amd64",)),
            "package": replace_artifact(
                "aw-cli", targets={a.key: a for a in rt.ARTIFACTS}["aw-cli"].targets[:-1]
            ),
            "binary": replace_artifact("aw-cli", outputs=("aw",)),
            "zip": replace_artifact("skills", outputs=rt.SKILL_ZIPS[:-1]),
        }
        for label, artifacts in mutations.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(rt.ContractError, "artifact inventory"):
                    rt.validate_fixed_contract(
                        artifacts, rt.DAG_EDGES, (rt.CARD_GIT_PATH,)
                    )

    def test_accidental_second_state_path_is_refused(self) -> None:
        with self.assertRaisesRegex(rt.ContractError, "one git-local card"):
            rt.validate_fixed_contract(
                rt.ARTIFACTS,
                rt.DAG_EDGES,
                (rt.CARD_GIT_PATH, ".release-state.json"),
            )


class ValidationTests(unittest.TestCase):
    def test_strict_shas_versions_and_lines(self) -> None:
        sha = "3f7a1c9e4b02d85617fa03cc9b1e4d7a5806e2f1"
        self.assertEqual(rt.validate_sha(sha, "source"), sha)
        self.assertEqual(rt.validate_version("1.2.3", "server"), "1.2.3")
        self.assertEqual(rt.validate_version("1.2.3-rc.1", "server"), "1.2.3-rc.1")
        self.assertEqual(rt.validate_line("release security fix", "purpose"),
                         "release security fix")
        self.assertEqual(rt.validate_compatibility("none"), "none")
        self.assertEqual(rt.validate_compatibility("drops removed v1 field"),
                         "drops removed v1 field")

        for bad in ("a" * 39, "A" * 40, "0" * 40, "g" * 40, " a" * 20):
            with self.subTest(sha=bad):
                with self.assertRaises(rt.ValidationError):
                    rt.validate_sha(bad, "source")
        for bad in ("v1.2.3", "1.2", "01.2.3", "1.2.3 ", "latest"):
            with self.subTest(version=bad):
                with self.assertRaises(rt.ValidationError):
                    rt.validate_version(bad, "server")
        for bad in ("", " ", "two\nlines", " leading", "trailing "):
            with self.subTest(line=bad):
                with self.assertRaises(rt.ValidationError):
                    rt.validate_line(bad, "purpose")
        for bad in ("NONE", "two\nlines", ""):
            with self.subTest(compatibility=bad):
                with self.assertRaises(rt.ValidationError):
                    rt.validate_compatibility(bad)


class CardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        git("init", "-q", "-b", "main", cwd=self.repo)
        git("config", "user.email", "release-test@example.invalid", cwd=self.repo)
        git("config", "user.name", "Release Test", cwd=self.repo)
        (self.repo / "source").write_text("one\n")
        git("add", "source", cwd=self.repo)
        git("commit", "-qm", "first", cwd=self.repo)
        self.aweb_sha = git("rev-parse", "HEAD", cwd=self.repo)
        (self.repo / "source").write_text("two\n")
        git("commit", "-qam", "second", cwd=self.repo)
        self.ac_sha = git("rev-parse", "HEAD", cwd=self.repo)
        self.addCleanup(self.tmp.cleanup)

    def card(self, **changes: object) -> rt.ReleaseCard:
        values: dict[str, object] = {
            "aweb_sha": self.aweb_sha,
            "ac_base_sha": self.ac_sha,
            "artifacts": tuple(
                rt.ArtifactSelection(name, VERSIONS[name], True)
                for name in rt.CARD_ARTIFACT_ORDER
            ),
            "compatibility": "none",
            "gates": (
                rt.GateEvidence(
                    "aweb-clean-docker",
                    self.aweb_sha,
                    "passed",
                    "logs/aweb-gate.log",
                    ("unit", "journeys", "artifact-builds"),
                ),
                rt.GateEvidence(
                    "compatibility",
                    self.aweb_sha,
                    "not-relevant",
                    "logs/compatibility.log",
                    ("boundary-selection",),
                ),
            ),
            "purpose": "release the reviewed reliability fixes",
            "deployments": rt.DeploymentSet(True, True, False),
            "final_ac_sha": None,
            "first_release_correction_pending": True,
        }
        values.update(changes)
        return rt.ReleaseCard.create(**values)

    def test_card_path_is_one_fixed_git_local_file(self) -> None:
        expected = git(
            "rev-parse", "--git-path", rt.CARD_GIT_PATH, cwd=self.repo
        )
        expected_path = Path(expected)
        if not expected_path.is_absolute():
            expected_path = self.repo / expected_path
        self.assertEqual(rt.card_path(self.repo), expected_path.resolve())
        self.assertNotEqual(rt.card_path(self.repo), self.repo / rt.CARD_GIT_PATH)

    def test_canonical_write_read_and_idempotent_same_card(self) -> None:
        card = self.card()
        path = rt.write_card(self.repo, card)
        first = path.read_bytes()
        self.assertEqual(first, card.canonical_bytes())
        self.assertEqual(rt.read_card(self.repo), card)
        self.assertEqual(rt.write_card(self.repo, card), path)
        self.assertEqual(path.read_bytes(), first)

    def test_unknown_or_malformed_card_fields_are_refused(self) -> None:
        path = rt.card_path(self.repo)
        path.parent.mkdir(parents=True, exist_ok=True)
        document = self.card().to_dict()
        document["release_id"] = "forbidden"
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(rt.CardFormatError, "unknown.*release_id"):
            rt.read_card(self.repo)

        document = self.card().to_dict()
        document["artifacts"][0]["extra"] = True
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(rt.CardFormatError, "unknown.*extra"):
            rt.read_card(self.repo)

        path.write_text('{"purpose":"first","purpose":"second"}')
        with self.assertRaisesRegex(rt.CardFormatError, "duplicate.*purpose"):
            rt.read_card(self.repo)

        path.write_text("not json")
        with self.assertRaisesRegex(rt.CardFormatError, "malformed"):
            rt.read_card(self.repo)

    def test_every_material_change_is_detected(self) -> None:
        original = self.card()
        selection = list(original.artifacts)
        selection[0] = dataclasses.replace(selection[0], moves=False)
        changes = {
            "purpose": self.card(purpose="a different release purpose"),
            "compatibility": self.card(compatibility="drops a removed field"),
            "sha": self.card(ac_base_sha=self.aweb_sha),
            "artifact set": self.card(artifacts=tuple(selection)),
        }
        for label, changed in changes.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(rt.MaterialMismatch, label.split()[0]):
                    rt.assert_material_matches(original, changed)

    def test_changed_existing_card_is_refused(self) -> None:
        rt.write_card(self.repo, self.card())
        with self.assertRaisesRegex(rt.MaterialMismatch, "purpose"):
            rt.write_card(
                self.repo,
                self.card(purpose="a materially different purpose"),
            )

    def test_done_consumes_the_card_and_replay_is_refused(self) -> None:
        card = self.card()
        path = rt.write_card(self.repo, card)
        rt.consume_card(self.repo, card)
        self.assertFalse(path.exists())
        with self.assertRaisesRegex(rt.CardUnavailable, "missing or consumed"):
            rt.consume_card(self.repo, card)
        self.assertFalse(any(path.parent.glob("*release*state*")))

    def test_card_enforces_complete_ordered_set_and_equal_versions(self) -> None:
        original = self.card()
        with self.assertRaisesRegex(rt.ValidationError, "artifact order"):
            self.card(artifacts=tuple(reversed(original.artifacts)))
        with self.assertRaisesRegex(rt.ValidationError, "a2a-gateway.*server"):
            self.card(
                artifacts=tuple(
                    dataclasses.replace(item, version="9.9.9")
                    if item.name == "a2a-gateway-image"
                    else item
                    for item in original.artifacts
                )
            )
        with self.assertRaisesRegex(rt.ValidationError, "AWID service.*image"):
            self.card(
                artifacts=tuple(
                    dataclasses.replace(item, version="9.9.9")
                    if item.name == "awid-image"
                    else item
                    for item in original.artifacts
                )
            )
        with self.assertRaisesRegex(rt.ValidationError, "final AC SHA.*pending"):
            self.card(final_ac_sha=self.aweb_sha)

    def test_production_and_first_correction_are_inferred_from_ac_image(self) -> None:
        original = self.card()
        ac_not_moving = tuple(
            dataclasses.replace(item, moves=False)
            if item.name == "ac-image"
            else item
            for item in original.artifacts
        )
        with self.assertRaisesRegex(rt.ValidationError, "production deployment"):
            self.card(artifacts=ac_not_moving)
        with self.assertRaisesRegex(rt.ValidationError, "first release correction"):
            self.card(
                artifacts=ac_not_moving,
                deployments=rt.DeploymentSet(False, True, False),
            )


class _RegistryHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/absent":
            self.send_error(404)
            return
        if self.path == "/unavailable":
            self.send_error(503)
            return
        if self.path == "/slow":
            time.sleep(0.2)
            body = json.dumps(
                {"state": "present", "version": "1.2.3", "digest": DIGEST}
            ).encode()
        elif self.path == "/exact":
            body = json.dumps(
                {"state": "present", "version": "1.2.3", "digest": DIGEST}
            ).encode()
        elif self.path == "/conflict":
            body = json.dumps(
                {"state": "present", "version": "1.2.3", "digest": OTHER_DIGEST}
            ).encode()
        elif self.path == "/malformed":
            body = b'{"state":"present","version":"1.2.3"}'
        elif self.path == "/unknown":
            body = json.dumps({"state": "absent", "error": "offline"}).encode()
        else:
            self.send_error(500)
            return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, _format: str, *args: object) -> None:
        pass


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _RegistryHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_registry_absence_exact_adoption_and_conflict_are_distinct(self) -> None:
        self.assertEqual(
            rt.observe_registry(
                self.base_url + "/absent", "1.2.3", DIGEST, timeout=1
            ),
            rt.RegistryOutcome.ABSENT,
        )
        self.assertEqual(
            rt.observe_registry(
                self.base_url + "/exact", "1.2.3", DIGEST, timeout=1
            ),
            rt.RegistryOutcome.EXACT,
        )
        self.assertEqual(
            rt.observe_registry(
                self.base_url + "/conflict", "1.2.3", DIGEST, timeout=1
            ),
            rt.RegistryOutcome.CONFLICT,
        )

    def test_timeout_or_unavailability_is_never_misread_as_absence(self) -> None:
        for path, timeout in (("/unavailable", 1), ("/slow", 0.02)):
            with self.subTest(path=path):
                with self.assertRaises(rt.ObservationUnavailable):
                    rt.observe_registry(
                        self.base_url + path, "1.2.3", DIGEST, timeout=timeout
                    )

    def test_malformed_registry_evidence_is_refused(self) -> None:
        for path in ("/malformed", "/unknown"):
            with self.subTest(path=path):
                with self.assertRaises(rt.ObservationMalformed):
                    rt.observe_registry(
                        self.base_url + path, "1.2.3", DIGEST, timeout=1
                    )

    def test_fake_executable_boundary_has_bounded_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            program = Path(tmp) / "boundary.py"
            program.write_text(
                "import sys,time\n"
                "mode=sys.argv[1]\n"
                "if mode == 'slow': time.sleep(0.2)\n"
                "if mode == 'fail': raise SystemExit(7)\n"
                "print('boundary-ok')\n"
            )
            result = rt.run_command(
                [sys.executable, str(program), "ok"], cwd=Path(tmp), timeout=1
            )
            self.assertEqual(result.stdout.strip(), "boundary-ok")
            with self.assertRaisesRegex(rt.CommandFailed, "exit 7"):
                rt.run_command(
                    [sys.executable, str(program), "fail"],
                    cwd=Path(tmp),
                    timeout=1,
                )
            with self.assertRaisesRegex(rt.CommandUnavailable, "timed out"):
                rt.run_command(
                    [sys.executable, str(program), "slow"],
                    cwd=Path(tmp),
                    timeout=0.02,
                )
            with self.assertRaisesRegex(rt.CommandUnavailable, "not available"):
                rt.run_command(
                    [str(Path(tmp) / "missing")], cwd=Path(tmp), timeout=1
                )


if __name__ == "__main__":
    unittest.main()
