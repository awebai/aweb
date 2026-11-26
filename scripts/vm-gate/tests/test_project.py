"""One project's gate for its release command: admission, guest inputs and the flat receipt."""

import hashlib
import io
import json
import unittest
from unittest.mock import patch

from vm_gate import project
from vm_gate.cli import main
from test_config import hashes
from test_release import CloudFixture, commit
from test_source import git

MEMBER = "ghcr.io/awebai/ac@sha256:" + "b" * 64


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class ProjectJob(CloudFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"observed": self.observed, "commands": hashes(), "dpkg": "fixture=1"}))
        self.key = self.root / "hermes-key"
        self.key.write_text("test-only")
        self.key.chmod(0o600)
        self.files = self.root / "dist"
        self.files.mkdir()
        self.wheel = b"built aweb wheel"
        (self.files / "aweb-1.27.55-py3-none-any.whl").write_bytes(self.wheel)
        (self.files / "aweb-1.27.55.tar.gz").write_bytes(b"built aweb sdist")
        self.shipped = {
            "aweb-1.27.55-py3-none-any.whl": digest(self.wheel),
            "aweb-1.27.55.tar.gz": digest(b"built aweb sdist"),
        }
        self.config = self.root / "operator.json"
        self.config.write_text(
            json.dumps(
                {
                    "repo": str(self.repo),
                    "state_root": str(self.root / "state"),
                    "ledger": str(self.root / "state/ledger.tsv"),
                    "snapshot_manifest": str(self.manifest),
                    "token_file": str(self.root / "no-token"),
                    "owner": "seat",
                    "location": "location",
                    "snapshot_id": 1,
                    "hermes_key_file": str(self.key),
                    "merak": {
                        "manifest": str(self.manifest),
                        "platform": "linux/amd64",
                        "release_timeout_seconds": 9000,
                    },
                    "antares": {
                        "platform": "linux/arm64",
                        "backend": "native",
                        "root": str(self.root / "antares-jobs"),
                        "release_timeout_seconds": 9000,
                    },
                }
            )
        )
        self.receipt = self.root / "receipt.json"
        self.calls = []
        self.evidence = {}
        uid = patch("os.geteuid", return_value=501)
        uid.start()
        self.addCleanup(uid.stop)

    def runtime(self, **kwargs):
        """A machine that leaves exactly the evidence files in self.evidence."""
        self.calls.append(kwargs)
        evidence = kwargs["directory"] / "evidence"
        files = self.evidence

        class Runtime:
            def run(self):
                for relative, text in files.items():
                    path = evidence / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(text)
                return {"exit": 0, "infrastructure": None, "error": None}

        return Runtime()

    def invoke(self, project_name, *extra, sha=None, repo=None):
        code = main(
            [
                "--config",
                str(self.config),
                "run",
                "--project",
                project_name,
                "--repo",
                str(repo or (self.repo if project_name == "aweb" else self.cloud)),
                "--sha",
                sha or (self.sha if project_name == "aweb" else self.cloud_sha),
                "--intent",
                "train",
                "--machine",
                "merak",
                "--receipt",
                str(self.receipt),
                *extra,
            ],
            factory=self.runtime,
            out=io.StringIO(),
        )
        return code, json.loads(self.receipt.read_text())

    # aweb

    def aweb_evidence(self, *, rebuilt=None, wheels=True, suite="0"):
        rebuilt = self.shipped if rebuilt is None else rebuilt
        self.evidence = {
            "var/log/vm-gate/release/aweb/exit": suite + "\n",
            "var/log/vm-gate/release/aweb/rebuilt.json": json.dumps(rebuilt),
            "var/log/vm-gate/release/host-architecture": "x86_64\namd64\n",
        }
        if wheels:
            held = {
                service: {
                    "wheel": "aweb-1.27.55-py3-none-any.whl",
                    "container_wheel_sha256": wheels if isinstance(wheels, str) else digest(self.wheel),
                    "installed_version": "1.27.55",
                }
                for service in ("aweb-alpha", "aweb-beta")
            }
            self.evidence[f"tmp/aweb-candidate-gate-{self.sha}-20261126T000000Z-1/release-wheels.json"] = json.dumps(held)

    def test_aweb_release_gate_places_the_files_and_is_green_when_every_check_holds(self):
        self.aweb_evidence()
        code, receipt = self.invoke("aweb", "--files", str(self.files))
        self.assertEqual(code, 0, receipt)
        self.assertEqual(receipt["exit"], 0)
        self.assertEqual(receipt["project"], "aweb")
        self.assertEqual(receipt["sha"], self.sha)
        self.assertEqual(receipt["intent"], "train")
        self.assertEqual(receipt["command"], "make candidate-gate")
        self.assertEqual(receipt["files"], self.shipped)
        self.assertEqual(receipt["rebuilt_files"], self.shipped)
        self.assertEqual(
            receipt["installed_wheels"]["aweb-alpha"]["container_wheel_sha256"], digest(self.wheel)
        )
        self.assertEqual(receipt["host_architecture"], ["x86_64", "amd64"])
        self.assertTrue(all(value.startswith("sha256:") for value in receipt["files"].values()))
        [call] = self.calls
        self.assertIn("export AWEB_CANDIDATE_RELEASE_FILES=/opt/vm-gate/release-files", call["command"])
        self.assertIn("make candidate-gate", call["command"])
        self.assertIn(f'test "$(git rev-parse HEAD)" = {self.sha}', call["command"])
        self.assertIn("uv build --quiet --wheel --sdist", call["command"])
        placed = call["executor_factory"].keywords["files"]
        self.assertEqual(sorted(path.name for path in placed), sorted(self.shipped))
        # The guest's main is S itself, as the release job's aweb suite has it:
        # a full gate refuses a head that is not on the guest's main.
        self.assertEqual(call["source"]["scope"], "branch qualification")
        self.assertEqual(call["source"]["frozen_main"], self.sha)
        self.assertEqual(receipt["source_scope"], "branch qualification")

    def test_aweb_rebuild_beside_a_builders_own_marker_is_green(self):
        self.aweb_evidence(rebuilt={**self.shipped, ".gitignore": digest(b"*\n")})
        code, receipt = self.invoke("aweb", "--files", str(self.files))
        self.assertEqual(code, 0, receipt)
        self.assertEqual(receipt["rebuilt_files"], self.shipped)

    def test_aweb_rebuild_missing_a_shipped_file_is_red(self):
        self.aweb_evidence(rebuilt={"aweb-1.27.55-py3-none-any.whl": self.shipped["aweb-1.27.55-py3-none-any.whl"]})
        code, receipt = self.invoke("aweb", "--files", str(self.files))
        self.assertEqual(code, 1, receipt)

    def test_aweb_head_that_does_not_contain_main_is_refused_before_boot(self):
        git(self.repo, "checkout", "--quiet", "--detach", self.main)
        aside = commit(self.repo, "aside")
        moved = self.root / "teammate-aweb"
        git(self.root, "clone", "--quiet", str(self.remote), str(moved))
        git(moved, "config", "user.email", "fixture@example.invalid")
        git(moved, "config", "user.name", "Fixture")
        commit(moved, "landed")
        git(moved, "push", "--quiet", "origin", "HEAD:main")
        code, receipt = self.invoke("aweb", "--files", str(self.files), sha=aside)
        self.assertEqual(code, 2, receipt)
        self.assertIn("fast-forward", receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_aweb_rebuild_that_differs_from_the_files_is_red(self):
        self.aweb_evidence(rebuilt={**self.shipped, "aweb-1.27.55.tar.gz": digest(b"other")})
        code, receipt = self.invoke("aweb", "--files", str(self.files))
        self.assertEqual(code, 1, receipt)

    def test_aweb_container_holding_another_wheel_is_red(self):
        self.aweb_evidence(wheels=digest(b"another wheel"))
        code, receipt = self.invoke("aweb", "--files", str(self.files))
        self.assertEqual(code, 1, receipt)

    def test_aweb_green_suite_without_the_wheel_record_is_red(self):
        self.aweb_evidence(wheels=False)
        code, receipt = self.invoke("aweb", "--files", str(self.files))
        self.assertEqual(code, 1, receipt)
        self.assertIsNone(receipt["installed_wheels"])

    def test_aweb_red_suite_is_red(self):
        self.aweb_evidence(suite="2")
        code, receipt = self.invoke("aweb", "--files", str(self.files))
        self.assertEqual(code, 1, receipt)
        self.assertEqual(receipt["suite_exit"], 2)

    def test_aweb_refusals_write_a_receipt_and_start_no_machine(self):
        for extra, reason in (
            (("--image", MEMBER), "Cloud's inputs"),
            (("--aweb-source", self.sha), "Cloud's inputs"),
            (("--stages", "checks"), "full gate"),
        ):
            with self.subTest(extra=extra):
                code, receipt = self.invoke("aweb", "--files", str(self.files), *extra)
                self.assertEqual(code, 2, receipt)
                self.assertEqual(receipt["vm_gate"]["infrastructure"], "refused")
                self.assertIn(reason, receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_aweb_branch_intent_is_refused(self):
        code = main(
            ["--config", str(self.config), "run", "--project", "aweb", "--repo", str(self.repo), "--sha", self.sha,
             "--machine", "merak", "--receipt", str(self.receipt)],
            factory=self.runtime,
            out=io.StringIO(),
        )
        self.assertEqual(code, 2)
        self.assertIn("--intent train", json.loads(self.receipt.read_text())["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_aweb_on_a_native_machine_is_refused(self):
        code = main(
            ["--config", str(self.config), "run", "--project", "aweb", "--repo", str(self.repo), "--sha", self.sha,
             "--intent", "train", "--machine", "antares", "--receipt", str(self.receipt), "--files", str(self.files)],
            factory=self.runtime,
            out=io.StringIO(),
        )
        self.assertEqual(code, 2)
        self.assertIn("runs in a guest", json.loads(self.receipt.read_text())["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_a_project_without_a_receipt_is_refused(self):
        code = main(
            ["--config", str(self.config), "run", "--project", "aweb", "--repo", str(self.repo), "--sha", self.sha,
             "--intent", "train"],
            factory=self.runtime,
            out=io.StringIO(),
        )
        # With no receipt to write, the refusal takes run's own exit for a refusal.
        self.assertEqual(code, 78)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.calls, [])

    # ac

    def member(self, image, run_id, out):
        out.write_bytes(b"image")
        return {
            "image": image,
            "member": "sha256:" + "b" * 64,
            "config": "sha256:" + "d" * 64,
            "member_architecture": "amd64",
            "archive_sha256": "0" * 64,
        }

    def cloud_evidence(self, *, built=None, inputs=True, suite="0", built_line=True):
        built = built or self.sha
        self.evidence = {"var/log/vm-gate/release/cloud/exit": suite + "\n"}
        if inputs:
            self.evidence[f"tmp/ac-candidate-gate-{self.cloud_sha}/inputs.tsv"] = (
                f"cloud-sha\t{self.cloud_sha}\naweb-lock-source\t{self.sha}\naweb-lock-tag\tserver-v1.27.55\n"
                + (f"aweb-built-head\t{built}\n" if built_line else "")
            )

    def invoke_release_gate(self, *extra):
        with patch.object(project, "member_archive", self.member):
            return self.invoke("ac", "--image", MEMBER, "--aweb-source", self.sha, *extra)

    def test_ac_release_gate_reads_the_built_commit_from_cloud_evidence(self):
        self.cloud_evidence()
        code, receipt = self.invoke_release_gate()
        self.assertEqual(code, 0, receipt)
        self.assertEqual(receipt["project"], "ac")
        self.assertEqual(receipt["command"], "make release-gate")
        self.assertEqual(receipt["aweb_source"], self.sha)
        self.assertEqual(receipt["aweb_source_built"], self.sha)
        self.assertEqual(receipt["aweb_source_tag"], "server-v1.27.55")
        self.assertEqual(receipt["image"]["member"], "sha256:" + "b" * 64)
        self.assertEqual(receipt["image"]["config"], "sha256:" + "d" * 64)
        [call] = self.calls
        self.assertIn("make release-gate", call["command"])
        self.assertIn(f"AC_CANDIDATE_AWEB_LOCK_SOURCE_SHA={self.sha}", call["command"])
        self.assertNotIn("AC_CANDIDATE_AWEB_WHEELS", call["command"])
        self.assertNotIn("make candidate-gate", call["command"])
        inputs = call["executor_factory"].keywords["release"]
        self.assertEqual(inputs["files"], [])
        self.assertEqual(inputs["hermes_key"], self.key)

    def test_ac_built_commit_other_than_the_input_is_red(self):
        self.cloud_evidence(built="e" * 40)
        code, receipt = self.invoke_release_gate()
        self.assertEqual(code, 1, receipt)
        self.assertEqual(receipt["aweb_source_built"], "e" * 40)

    def test_ac_green_suite_without_cloud_inputs_is_red_and_copies_nothing(self):
        self.cloud_evidence(inputs=False)
        code, receipt = self.invoke_release_gate()
        self.assertEqual(code, 1, receipt)
        self.assertIsNone(receipt["aweb_source_built"])

    def test_ac_without_the_built_head_line_is_red_and_never_falls_back_to_the_input(self):
        self.cloud_evidence(built_line=False)
        code, receipt = self.invoke_release_gate()
        self.assertEqual(code, 1, receipt)
        self.assertIsNone(receipt["aweb_source_built"])

    def test_ac_files_are_refused(self):
        code, receipt = self.invoke("ac", "--files", str(self.files))
        self.assertEqual(code, 2)
        self.assertIn("aweb's input", receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_ac_image_without_aweb_source_is_refused(self):
        code, receipt = self.invoke("ac", "--image", MEMBER)
        self.assertEqual(code, 2)
        self.assertIn("--aweb-source", receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_ac_index_instead_of_member_is_refused(self):
        code, receipt = self.invoke("ac", "--image", "ghcr.io/awebai/ac:latest", "--aweb-source", self.sha)
        self.assertEqual(code, 2)
        self.assertIn("amd64 member", receipt["vm_gate"]["error"])

    def test_ac_release_on_a_moved_main_is_refused(self):
        moved = self.move_main()
        code, receipt = self.invoke_release_gate()
        self.assertEqual(code, 2)
        self.assertIn("Cloud main moved", receipt["vm_gate"]["error"])
        self.assertIn(moved, receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_ac_train_gate_is_green_only_when_every_stage_passed(self):
        head = self.train_head()
        for verdict, expected in (("PASSED", 0), ("FAILED", 1)):
            with self.subTest(verdict=verdict):
                self.calls.clear()
                self.evidence = {"var/log/vm-gate/release/cloud/exit": "0\n"}
                rows = "".join(
                    f"{stage}\t{verdict if stage == project.release.CLOUD_GATE_STAGES[0] else 'PASSED'}\t{stage}.log\t1s\n"
                    for stage in project.release.CLOUD_GATE_STAGES
                )
                self.evidence[f"tmp/ac-candidate-gate-{head}-1/summary.tsv"] = rows
                code, receipt = self.invoke("ac", sha=head)
                self.assertEqual(code, expected, receipt)
                self.assertEqual(receipt["command"], "make gate GATE_STAGES=all")
                self.assertNotIn("aweb_source_built", receipt)
                [call] = self.calls
                self.assertIn("make gate GATE_STAGES=all", call["command"])


if __name__ == "__main__":
    unittest.main()
