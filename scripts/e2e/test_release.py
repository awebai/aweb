from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "automatic_release", ROOT / "scripts" / "release.py"
)
assert SPEC and SPEC.loader
release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release
SPEC.loader.exec_module(release)
sys.modules["release"] = release


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


observe_public_target = load_script("observe_public_target")
release_artifact_moved = load_script("release_artifact_moved")


def command(root: Path, *args: str) -> str:
    result = subprocess.run(args, cwd=root, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def repository() -> tuple[tempfile.TemporaryDirectory[str], Path]:
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    command(root, "git", "init", "-q")
    command(root, "git", "config", "user.name", "test")
    command(root, "git", "config", "user.email", "test@example.com")
    return temporary, root


def commit(root: Path, message: str = "commit") -> str:
    command(root, "git", "add", "-A")
    command(root, "git", "commit", "-qm", message)
    return command(root, "git", "rev-parse", "HEAD")


class VersionSelectionTest(unittest.TestCase):
    def make_python_artifact(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, object, str]:
        temporary, root = repository()
        package = root / "package"
        package.mkdir()
        (package / "pyproject.toml").write_text(
            '[project]\nname="demo"\nversion = "1.2.3"\n'
        )
        (package / "code.py").write_text("one\n")
        first = commit(root)
        command(root, "git", "tag", "demo-v1.2.3", first)
        artifact = release.Artifact(
            "demo", "demo-v", "package/pyproject.toml", ("package/",)
        )
        return temporary, root, artifact, first

    def test_unchanged_content_reuses_version(self) -> None:
        temporary, root, artifact, first = self.make_python_artifact()
        self.addCleanup(temporary.cleanup)
        (root / "unrelated").write_text("change\n")
        sha = commit(root)
        self.assertEqual(release.choose_version(root, sha, artifact), ("1.2.3", False))

    def test_changed_content_requires_reviewed_version_bump(self) -> None:
        temporary, root, artifact, first = self.make_python_artifact()
        self.addCleanup(temporary.cleanup)
        (root / "package" / "code.py").write_text("two\n")
        sha = commit(root)
        with self.assertRaisesRegex(
            release.Refusal, "next compatible version is 1.2.4"
        ):
            release.choose_version(root, sha, artifact)

    def test_version_declaration_is_release_content(self) -> None:
        temporary, root, artifact, first = self.make_python_artifact()
        self.addCleanup(temporary.cleanup)
        path = root / "package" / "pyproject.toml"
        path.write_text(path.read_text().replace("1.2.3", "1.2.4"))
        sha = commit(root)
        self.assertEqual(release.choose_version(root, sha, artifact), ("1.2.4", True))

    def test_explicit_minor_or_major_version_is_preserved(self) -> None:
        temporary, root, artifact, first = self.make_python_artifact()
        self.addCleanup(temporary.cleanup)
        path = root / "package" / "pyproject.toml"
        path.write_text(path.read_text().replace("1.2.3", "2.0.0"))
        (root / "package" / "code.py").write_text("breaking\n")
        sha = commit(root)
        self.assertEqual(release.choose_version(root, sha, artifact), ("2.0.0", True))


class IntentTest(unittest.TestCase):
    def intent(self) -> object:
        versions = {artifact.key: "1.2.3" for artifact in release.ARTIFACTS}
        return release.Intent("a" * 40, versions, ("aweb-server",))

    def test_round_trip_is_canonical_and_carries_publication_work(self) -> None:
        intent = self.intent()
        observed = release.Intent.parse(intent.document())
        self.assertEqual(observed, intent)
        self.assertEqual(
            json.dumps(
                json.loads(intent.document()), sort_keys=True, separators=(",", ":")
            ),
            intent.document(),
        )

    def test_unknown_or_missing_artifact_is_refused(self) -> None:
        value = json.loads(self.intent().document())
        del value["versions"]["skills"]
        with self.assertRaisesRegex(release.Refusal, "version domain"):
            release.Intent.parse(json.dumps(value))

    def test_publish_set_is_sorted_unique_and_closed(self) -> None:
        value = json.loads(self.intent().document())
        value["publish"] = ["skills", "skills"]
        with self.assertRaisesRegex(release.Refusal, "publish set"):
            release.Intent.parse(json.dumps(value))

    def test_unknown_intent_field_is_refused(self) -> None:
        value = json.loads(self.intent().document())
        value["foreign_sha"] = "b" * 40
        with self.assertRaisesRegex(release.Refusal, "unsupported shape"):
            release.Intent.parse(json.dumps(value))


class DependencyContractTest(unittest.TestCase):
    def test_awid_release_requires_matching_aweb_floor_before_gate(self) -> None:
        selections = [("1.2.3", False) for _artifact in release.ARTIFACTS]
        selections[1] = ("0.5.7", True)
        with (
            mock.patch.object(release, "git", return_value="a" * 40),
            mock.patch.object(release, "choose_version", side_effect=selections),
            mock.patch.object(release, "dependency_floor", return_value="0.5.6"),
        ):
            with self.assertRaisesRegex(release.Refusal, "awid-service floor.*0.5.7"):
                release.compute_intent(Path("/aweb"))


class CrashRecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        versions = {artifact.key: "1.2.3" for artifact in release.ARTIFACTS}
        self.intent = release.Intent("a" * 40, versions, ("aweb-server",))
        self.aweb = Path("/aweb")

    def patches(self, open_values: list[object | None]):
        return mock.patch.multiple(
            release,
            require_clean=mock.DEFAULT,
            require_main_tip=mock.DEFAULT,
            fetch=mock.DEFAULT,
            git=mock.Mock(return_value="a" * 40),
            open_intent=mock.Mock(side_effect=open_values),
            compute_intent=mock.Mock(return_value=(self.intent, {"aweb-server"})),
            missing_aweb_workflows=mock.Mock(return_value=set()),
            run=mock.DEFAULT,
            ensure_intent_tag=mock.DEFAULT,
            reconcile_aweb=mock.DEFAULT,
            mark_done=mock.DEFAULT,
        )

    def test_crash_after_intent_does_not_rerun_gate_or_choose_versions(self) -> None:
        with self.patches([None, self.intent]) as mocks:
            mocks["reconcile_aweb"].side_effect = [release.Refusal("crash"), None]
            with self.assertRaisesRegex(release.Refusal, "crash"):
                release.release(self.aweb)
            release.release(self.aweb)
            self.assertEqual(release.compute_intent.call_count, 1)
            gates = [
                call
                for call in mocks["run"].call_args_list
                if call.args and call.args[0] == ("scripts/release-gate.sh",)
            ]
            self.assertEqual(len(gates), 1)
            self.assertEqual(mocks["mark_done"].call_count, 1)

    def test_resume_reconciles_recorded_publication_set(self) -> None:
        with self.patches([self.intent]) as mocks:
            release.release(self.aweb)
            mocks["reconcile_aweb"].assert_called_once_with(
                self.aweb, self.intent, {"aweb-server"}
            )
            mocks["mark_done"].assert_called_once_with(self.aweb, self.intent)
            self.assertEqual(release.compute_intent.call_count, 0)

    def test_resume_materializes_recorded_source_when_checkout_advanced(self) -> None:
        with self.patches([self.intent]) as mocks:
            release.git.side_effect = ["c" * 40, "", "", "a" * 40]
            release.release(self.aweb)
            self.assertTrue(
                any(
                    call.args[1:4] == ("worktree", "add", "--detach")
                    for call in release.git.call_args_list
                )
            )
            self.assertEqual(mocks["reconcile_aweb"].call_count, 1)

    def test_absent_unchanged_output_refuses_before_intent_or_gate(self) -> None:
        with self.patches([None]) as mocks:
            release.compute_intent.return_value = (self.intent, set())
            release.missing_aweb_workflows.return_value = {"aw-release.yml"}
            with self.assertRaisesRegex(release.Refusal, "source is unchanged"):
                release.release(self.aweb)
            self.assertEqual(mocks["ensure_intent_tag"].call_count, 0)
            self.assertFalse(
                any(
                    call.args and call.args[0] == ("scripts/release-gate.sh",)
                    for call in mocks["run"].call_args_list
                )
            )


class PublicObservationTest(unittest.TestCase):
    def versions(self) -> dict[str, str]:
        values = {artifact.key: "1.2.3" for artifact in release.ARTIFACTS}
        return values

    def test_registry_unavailability_is_not_reported_as_absence(self) -> None:
        completed = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="connection refused"
        )
        with mock.patch.object(release.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(
                release.Refusal, "cannot observe public target"
            ):
                release.command_present(
                    Path("/repo"),
                    "docker",
                    "buildx",
                    "imagetools",
                    "inspect",
                    "example",
                    absent_markers=("manifest unknown",),
                )

    def test_exact_not_found_response_is_absence(self) -> None:
        completed = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="manifest unknown"
        )
        with mock.patch.object(release.subprocess, "run", return_value=completed):
            self.assertFalse(
                release.command_present(
                    Path("/repo"),
                    "docker",
                    "buildx",
                    "imagetools",
                    "inspect",
                    "example",
                    absent_markers=("manifest unknown",),
                )
            )

    def test_oci_digest_distinguishes_absent_from_unavailable(self) -> None:
        absent = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="example: not found"
        )
        unavailable = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="connection refused"
        )
        with mock.patch.object(release.subprocess, "run", return_value=absent):
            self.assertIsNone(release.oci_digest(Path("/repo"), "example"))
        with mock.patch.object(release.subprocess, "run", return_value=unavailable):
            with self.assertRaisesRegex(
                release.Refusal, "cannot observe public target"
            ):
                release.oci_digest(Path("/repo"), "example")

    def test_oci_digest_requires_one_exact_digest(self) -> None:
        wanted = "sha256:" + "a" * 64
        completed = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(wanted), stderr=""
        )
        with mock.patch.object(release.subprocess, "run", return_value=completed):
            self.assertEqual(release.oci_digest(Path("/repo"), "example"), wanted)

    def test_higher_public_package_version_is_refused(self) -> None:
        with mock.patch.object(
            release, "published_package_versions", return_value={"1.2.3", "1.2.4"}
        ):
            with self.assertRaisesRegex(release.Refusal, "above reviewed"):
                release.refuse_higher_public_versions(self.versions())

    def test_older_and_prerelease_versions_do_not_conflict(self) -> None:
        with (
            mock.patch.object(
                release,
                "published_package_versions",
                return_value={"1.2.2", "1.2.3", "1.2.4rc1", "latest"},
            ),
            mock.patch.object(release, "npm_latest", return_value="1.2.3"),
        ):
            release.refuse_higher_public_versions(self.versions())

    def test_wrong_npm_latest_is_refused_even_without_a_higher_version(self) -> None:
        with (
            mock.patch.object(
                release, "published_package_versions", return_value={"1.2.3"}
            ),
            mock.patch.object(release, "npm_latest", return_value="1.2.2"),
        ):
            with self.assertRaisesRegex(release.Refusal, "latest is 1.2.2"):
                release.refuse_higher_public_versions(self.versions())

    def test_workflow_observer_has_three_distinct_outcomes(self) -> None:
        with mock.patch.object(
            observe_public_target, "pypi_present", return_value=True
        ):
            self.assertEqual(observe_public_target.main(["pypi:aweb", "1.2.3"]), 0)
        with mock.patch.object(
            observe_public_target, "pypi_present", return_value=False
        ):
            self.assertEqual(observe_public_target.main(["pypi:aweb", "1.2.3"]), 1)
        with mock.patch.object(
            observe_public_target,
            "pypi_present",
            side_effect=release.Refusal("network down"),
        ):
            self.assertEqual(observe_public_target.main(["pypi:aweb", "1.2.3"]), 2)

    def test_workflow_movement_tokens_are_stable(self) -> None:
        with (
            mock.patch.object(
                release_artifact_moved.release,
                "latest_release",
                return_value=("1.2.3", "v1.2.3"),
            ),
            mock.patch.object(
                release_artifact_moved.release, "git", return_value="a" * 40
            ),
            mock.patch.object(
                release_artifact_moved.release,
                "content_changed",
                side_effect=[False, True],
            ),
            mock.patch("builtins.print") as output,
        ):
            self.assertEqual(release_artifact_moved.main(["aw-cli"]), 0)
            output.assert_called_with("unmoved")
            self.assertEqual(release_artifact_moved.main(["aw-cli"]), 0)
            output.assert_called_with("moving")


class WorkflowContractTest(unittest.TestCase):
    def test_a2a_gateway_has_independent_version_history(self) -> None:
        artifact = next(
            item for item in release.ARTIFACTS if item.key == "a2a-gateway-image"
        )
        self.assertIsNone(artifact.manifest)
        self.assertEqual(artifact.tag_prefix, "a2a-gw-v")
        self.assertEqual(artifact.content_paths, ("cli/go/",))

    def test_internal_operator_skill_does_not_move_customer_packages(self) -> None:
        for key in ("pi-extension", "skills"):
            artifact = next(item for item in release.ARTIFACTS if item.key == key)
            self.assertNotIn("skills/aweb-agent-instantiation/", artifact.content_paths)
            self.assertTrue(
                set(release.DEFAULT_SKILL_PATHS) <= set(artifact.content_paths)
            )

    def test_publishers_are_path_scoped_and_release_has_no_prompt(self) -> None:
        expectations = {
            "pypi-release.yml": ("awid/**", "server/**"),
            "npm-release.yml": ("channel/**", "skills/aweb-coordination/**"),
            "awid-image-release.yml": ("awid/**", "server/**"),
            "aw-release.yml": ("cli/go/**",),
            "a2a-gateway-release.yml": ("cli/go/**",),
        }
        for workflow, paths in expectations.items():
            text = (ROOT / ".github" / "workflows" / workflow).read_text()
            self.assertIn("branches: [release]", text)
            for path in paths:
                self.assertIn(f'"{path}"', text)
        source = (ROOT / "scripts" / "release.py").read_text()
        self.assertNotIn("input(", source)
        self.assertNotIn("COMPAT_BREAK", source)
        self.assertNotIn("PURPOSE", source)

    def test_publication_workflows_keep_exact_output_checks(self) -> None:
        checks = {
            "pypi-release.yml": "pypi-exact-publish.sh verify-published",
            "npm-release.yml": "npm-exact-publish.sh verify-published",
            "awid-image-release.yml": "oci-exact-publish.sh verify-published",
            "a2a-gateway-release.yml": "oci-exact-publish.sh verify-published",
        }
        for workflow, check in checks.items():
            self.assertIn(
                check, (ROOT / ".github" / "workflows" / workflow).read_text()
            )


if __name__ == "__main__":
    unittest.main()
