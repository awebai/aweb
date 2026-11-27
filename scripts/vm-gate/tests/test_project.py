"""One project's gate for its release command: admission, guest inputs and the flat receipt."""

import hashlib
import io
import json
import re
import unittest
from pathlib import Path
from unittest.mock import patch

from vm_gate import project
from vm_gate.cli import main
from test_config import hashes
from test_release import CloudFixture, commit
from test_source import git

# Cloud's gate takes the image index; the launcher resolves its amd64 member.
INDEX = "ghcr.io/awebai/ac@sha256:" + "a" * 64
MEMBER_DIGEST = "sha256:" + "b" * 64


# The pilot's release image index, in its own repository.
PILOT_INDEX = "ghcr.io/awebai/aweb-cloud@sha256:" + "c" * 64
PILOT_STAGES = ("tool-image", "checks", "storage", "image")

# One real aweb-cloud receipt, written by project_job with only the machine
# faked; the pilot's release tests load it as their launcher stand-in.
AWEB_CLOUD_RECEIPT_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures/aweb-cloud-release-receipt.json"
)

# One real ac receipt, written by project_job with only the machine faked. Cloud's
# release tests load it as their launcher stand-in, so a format change here fails
# there too; the test below keeps it equal in form to what project_job writes.
AC_RECEIPT_FIXTURE = (
    Path(__file__).resolve().parent / "fixtures/ac-release-receipt.json"
)


def form(value):
    """A receipt value's format: per-run values become their kind, fixed values stay."""
    if isinstance(value, dict):
        return {key: form(item) for key, item in value.items()}
    if isinstance(value, list):
        return [form(item) for item in value]
    if isinstance(value, str):
        for kind, pattern in (
            ("<digest>", r"sha256:[0-9a-f]{64}"),
            ("<commit>", r"[0-9a-f]{40}"),
            ("<run>", r"vm-[0-9a-f]{32}"),
            ("<path>", r"/\S+"),
        ):
            if re.fullmatch(pattern, value):
                return kind
    return value


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class ProjectJob(CloudFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(
            json.dumps(
                {"observed": self.observed, "commands": hashes(), "dpkg": "fixture=1"}
            )
        )
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
                    "container_wheel_sha256": wheels
                    if isinstance(wheels, str)
                    else digest(self.wheel),
                    "installed_version": "1.27.55",
                }
                for service in ("aweb-alpha", "aweb-beta")
            }
            self.evidence[
                f"tmp/aweb-candidate-gate-{self.sha}-20261126T000000Z-1/release-wheels.json"
            ] = json.dumps(held)

    def test_aweb_release_gate_places_the_files_and_is_green_when_every_check_holds(
        self,
    ):
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
            receipt["installed_wheels"]["aweb-alpha"]["container_wheel_sha256"],
            digest(self.wheel),
        )
        self.assertEqual(receipt["host_architecture"], ["x86_64", "amd64"])
        self.assertTrue(
            all(value.startswith("sha256:") for value in receipt["files"].values())
        )
        [call] = self.calls
        self.assertIn(
            "export AWEB_CANDIDATE_RELEASE_FILES=/opt/vm-gate/release-files",
            call["command"],
        )
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
        self.aweb_evidence(
            rebuilt={
                "aweb-1.27.55-py3-none-any.whl": self.shipped[
                    "aweb-1.27.55-py3-none-any.whl"
                ]
            }
        )
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
        self.aweb_evidence(
            rebuilt={**self.shipped, "aweb-1.27.55.tar.gz": digest(b"other")}
        )
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

    def test_a_missing_suite_exit_or_a_machine_fault_is_infrastructure(self):
        self.aweb_evidence()
        del self.evidence["var/log/vm-gate/release/aweb/exit"]
        code, receipt = self.invoke("aweb", "--files", str(self.files))
        self.assertEqual(code, 70, receipt)
        self.assertIsNone(receipt["suite_exit"])
        self.aweb_evidence()
        original = self.runtime

        def faulty(**kwargs):
            runtime = original(**kwargs)
            run = runtime.run
            runtime.run = lambda: {
                **run(),
                "exit": 70,
                "infrastructure": "infrastructure",
                "error": "lost",
            }
            return runtime

        self.runtime = faulty
        code, receipt = self.invoke("aweb", "--files", str(self.files))
        self.assertEqual(code, 70, receipt)
        self.assertEqual(receipt["vm_gate"]["infrastructure"], "infrastructure")

    def test_aweb_refusals_write_a_receipt_and_start_no_machine(self):
        for extra, reason in (
            (("--image", INDEX), "Cloud's inputs"),
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
            [
                "--config",
                str(self.config),
                "run",
                "--project",
                "aweb",
                "--repo",
                str(self.repo),
                "--sha",
                self.sha,
                "--machine",
                "merak",
                "--receipt",
                str(self.receipt),
            ],
            factory=self.runtime,
            out=io.StringIO(),
        )
        self.assertEqual(code, 2)
        self.assertIn(
            "--intent train", json.loads(self.receipt.read_text())["vm_gate"]["error"]
        )
        self.assertEqual(self.calls, [])

    def test_aweb_on_a_native_machine_is_refused(self):
        code = main(
            [
                "--config",
                str(self.config),
                "run",
                "--project",
                "aweb",
                "--repo",
                str(self.repo),
                "--sha",
                self.sha,
                "--intent",
                "train",
                "--machine",
                "antares",
                "--receipt",
                str(self.receipt),
                "--files",
                str(self.files),
            ],
            factory=self.runtime,
            out=io.StringIO(),
        )
        self.assertEqual(code, 2)
        self.assertIn(
            "runs in a guest", json.loads(self.receipt.read_text())["vm_gate"]["error"]
        )
        self.assertEqual(self.calls, [])

    def test_a_project_without_a_receipt_is_refused(self):
        code = main(
            [
                "--config",
                str(self.config),
                "run",
                "--project",
                "aweb",
                "--repo",
                str(self.repo),
                "--sha",
                self.sha,
                "--intent",
                "train",
            ],
            factory=self.runtime,
            out=io.StringIO(),
        )
        # With no receipt to write, the refusal takes run's own exit for a refusal.
        self.assertEqual(code, 78)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.calls, [])

    # ac

    def resolved(self, image, run_id, out):
        """release.image_archive: the index's amd64 member, saved for the guest."""
        self.assertEqual(image, INDEX)
        out.write_bytes(b"image")
        return {
            "image": image,
            "member": MEMBER_DIGEST,
            "config": "sha256:" + "d" * 64,
            "member_architecture": "amd64",
            "archive_sha256": "0" * 64,
        }

    def cloud_evidence(
        self, *, built=None, inputs=True, suite="0", built_line=True, stages=None
    ):
        built = built or self.sha
        self.evidence = {
            "var/log/vm-gate/release/cloud/exit": suite + "\n",
            # What a real guest writes: uname -m, then the engine's architecture.
            "var/log/vm-gate/release/host-architecture": "x86_64\nx86_64\n",
        }
        verdicts = (
            {stage: "PASSED" for stage in project.release.CLOUD_GATE_STAGES}
            if stages is None
            else stages
        )
        if verdicts:
            self.evidence[f"tmp/ac-candidate-gate-{self.cloud_sha}/summary.tsv"] = (
                "".join(
                    f"{stage}\t{verdict}\t{stage}.log\t1s\n"
                    for stage, verdict in verdicts.items()
                )
            )
        if inputs:
            self.evidence[f"tmp/ac-candidate-gate-{self.cloud_sha}/inputs.tsv"] = (
                f"cloud-sha\t{self.cloud_sha}\naweb-lock-source\t{self.sha}\naweb-lock-tag\tserver-v1.27.55\n"
                + (f"aweb-built-head\t{built}\n" if built_line else "")
            )

    def invoke_release_gate(self, *extra):
        with patch.object(project.release, "image_archive", self.resolved):
            return self.invoke(
                "ac", "--image", INDEX, "--aweb-source", self.sha, *extra
            )

    def test_ac_release_gate_reads_the_built_commit_from_cloud_evidence(self):
        self.cloud_evidence()
        code, receipt = self.invoke_release_gate()
        self.assertEqual(code, 0, receipt)
        self.assertEqual(receipt["project"], "ac")
        self.assertEqual(receipt["command"], "make release-gate")
        self.assertEqual(receipt["aweb_source"], self.sha)
        self.assertEqual(receipt["aweb_source_built"], self.sha)
        self.assertEqual(receipt["aweb_source_tag"], "server-v1.27.55")
        self.assertEqual(
            receipt["image"],
            {
                "index": "sha256:" + "a" * 64,
                "member": MEMBER_DIGEST,
                "config": "sha256:" + "d" * 64,
                "member_architecture": "amd64",
            },
        )
        # Every digest in the receipt is the bare sha256:<hex>, never a reference.
        for field in ("index", "member", "config"):
            self.assertRegex(receipt["image"][field], r"\Asha256:[0-9a-f]{64}\Z")
        [call] = self.calls
        self.assertIn("make release-gate", call["command"])
        # The gate proves the index and its member separately: two digests.
        self.assertIn(f"AC_CANDIDATE_RELEASE_IMAGE={INDEX}", call["command"])
        self.assertIn(
            f"AC_CANDIDATE_RELEASE_IMAGE_MEMBER={MEMBER_DIGEST}", call["command"]
        )
        self.assertIn(f"AC_CANDIDATE_AWEB_LOCK_SOURCE_SHA={self.sha}", call["command"])
        self.assertNotIn("AC_CANDIDATE_AWEB_WHEELS", call["command"])
        self.assertNotIn("make candidate-gate", call["command"])
        inputs = call["executor_factory"].keywords["release"]
        self.assertNotIn("files", inputs)
        self.assertEqual(inputs["hermes_key"], self.key)
        # One suite has the whole machine: no split, no budget passed.
        self.assertNotIn("vm_gate.budget", call["command"])
        self.assertNotIn("GATE_CPUS", call["command"])

    def test_ac_release_gate_is_green_only_when_every_stage_in_its_summary_passed(self):
        every = {stage: "PASSED" for stage in project.release.CLOUD_GATE_STAGES}
        first = project.release.CLOUD_GATE_STAGES[0]
        for name, stages, expected in (
            ("all passed", every, 0),
            ("one failed", {**every, first: "FAILED"}, 1),
            (
                "one row missing",
                {stage: v for stage, v in every.items() if stage != first},
                1,
            ),
            ("no summary", {}, 1),
        ):
            with self.subTest(name=name):
                self.calls.clear()
                self.cloud_evidence(stages=stages)
                code, receipt = self.invoke_release_gate()
                self.assertEqual(code, expected, receipt)
                expected_verdicts = {
                    stage: stages.get(stage, "MISSING") for stage in every
                }
                self.assertEqual(receipt["stages"], expected_verdicts)

    def test_the_ac_receipt_fixture_has_the_form_project_job_writes(self):
        self.cloud_evidence()
        code, receipt = self.invoke_release_gate()
        self.assertEqual(code, 0, receipt)
        fixture = json.loads(AC_RECEIPT_FIXTURE.read_text())
        self.assertEqual(form(receipt), form(fixture))
        self.assertEqual(form(fixture["image"]["index"]), "<digest>")
        self.assertEqual(form(fixture["aweb_source_built"]), "<commit>")

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

    def test_ac_without_the_built_head_line_is_red_and_never_falls_back_to_the_input(
        self,
    ):
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
        code, receipt = self.invoke("ac", "--image", INDEX)
        self.assertEqual(code, 2)
        self.assertIn("--aweb-source", receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_ac_image_named_by_tag_is_refused(self):
        code, receipt = self.invoke(
            "ac", "--image", "ghcr.io/awebai/ac:latest", "--aweb-source", self.sha
        )
        self.assertEqual(code, 2)
        self.assertIn("<repository>@sha256:<index>", receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

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
                # A stage run's summary opens with a comment row, which is no stage.
                rows = "# stage run, NOT release evidence: all\n" + "".join(
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

    # servers

    def servers_spec(
        self,
        *,
        bundle_sha256=None,
        commit_sha=None,
        steps=None,
        registry=True,
        **source,
    ):
        """A reviewed spec over a real servers bundle: one step, as D has it."""
        origin = self.root / "servers-origin"
        if not origin.exists():
            origin.mkdir()
            git(origin, "init", "-b", "main")
            git(origin, "config", "user.email", "fixture@example.invalid")
            git(origin, "config", "user.name", "Fixture")
            self.servers_sha = commit(origin, "journey")
            self.servers_bundle = self.root / "servers.bundle"
            git(origin, "bundle", "create", str(self.servers_bundle), "main")
        spec = {
            "sources": {
                "servers": {
                    "bundle": str(self.servers_bundle),
                    "bundle_sha256": bundle_sha256
                    or digest(self.servers_bundle.read_bytes()),
                    "ref": "refs/heads/main",
                    "commit": commit_sha or self.servers_sha,
                    **source,
                }
            },
            "steps": steps
            if steps is not None
            else [
                {
                    "name": "d",
                    "user": "gateuser",
                    "cwd": "servers",
                    "expect_exit": 0,
                    "command": "PYTHONUNBUFFERED=1 journey/rehearse.sh --core localhost:5000 {run_dir} --external-postgres",
                    "require": ["^DOWN: nothing of the project is left"],
                    "forbid": ["^DOWN FAILED"],
                }
            ],
        }
        if registry:
            spec["registry"] = {
                "name": "registry",
                "port": 5000,
                "image": "docker.io/library/registry@sha256:" + "a" * 64,
            }
        path = self.root / f"spec-{len(list(self.root.glob('spec-*.json')))}.json"
        path.write_text(json.dumps(spec))
        self.spec_digest = digest(path.read_bytes())
        return path

    def servers_evidence(
        self,
        *,
        verdict="passed",
        removed=True,
        guest_commit=None,
        exit_code="0",
        spec_sha256=None,
        error=None,
        collector_error=None,
    ):
        result = {
            "sources": {
                "servers": {
                    "shipped_bundle_sha256": digest(self.servers_bundle.read_bytes()),
                    "guest_commit": guest_commit or self.servers_sha,
                    "error": None,
                }
            },
            "registry": {
                "image": "docker.io/library/registry@sha256:" + "a" * 64,
                "started": True,
                "removed": removed,
                "error": None,
            },
            "steps": [
                {
                    "name": "d",
                    "uid": 1000,
                    "exit": 0,
                    "verdict": verdict,
                    "reason": None,
                    "collector_error": collector_error,
                }
            ],
            "versions": {"docker": "29.9.3", "compose": "2.40.0"},
            "error": error,
            "spec_sha256": spec_sha256 or self.spec_digest,
        }
        self.evidence = {
            "var/log/vm-gate/servers/result.json": json.dumps(result),
            "var/log/vm-gate/servers/exit": exit_code + "\n",
        }

    def invoke_servers(self, spec, *extra, repo=None, sha=None):
        return self.invoke(
            "servers",
            "--steps",
            str(spec),
            *extra,
            repo=repo or self.servers_bundle,
            sha=sha or self.servers_sha,
        )

    def test_servers_ships_the_spec_and_its_bundles_and_records_every_source(self):
        spec = self.servers_spec()
        self.servers_evidence()
        code, receipt = self.invoke_servers(spec)
        self.assertEqual(code, 0, receipt)
        [call] = self.calls
        self.assertIn(
            "vm_gate/servers_run.py /opt/vm-gate/servers-spec.json /var/log/vm-gate/servers",
            call["command"],
        )
        self.assertEqual(receipt["spec_sha256"], digest(spec.read_bytes()))
        bundle = digest(self.servers_bundle.read_bytes())
        self.assertEqual(
            receipt["sources"]["servers"],
            {
                "ref": "refs/heads/main",
                "commit": self.servers_sha,
                "author_bundle_sha256": bundle,
                "shipped_bundle_sha256": bundle,
                "guest_commit": self.servers_sha,
                "error": None,
            },
        )
        self.assertEqual(receipt["result"]["steps"][0]["uid"], 1000)
        servers = call["executor_factory"].keywords["servers"]
        # The guest gets the reviewed bytes and checks their digest itself.
        self.assertEqual(servers["spec_bytes"], spec.read_bytes())
        self.assertIn(f"--spec-sha256 {digest(spec.read_bytes())} ", call["command"])

    def test_servers_is_red_unless_every_step_passed_and_the_registry_is_gone(self):
        spec = self.servers_spec()
        for evidence in (
            {"verdict": "failed", "exit_code": "1"},
            {"removed": False, "exit_code": "1"},
            {"guest_commit": "0" * 40, "exit_code": "1"},
            {"verdict": "unrun", "exit_code": "0"},
        ):
            with self.subTest(evidence=evidence):
                self.servers_evidence(**evidence)
                code, receipt = self.invoke_servers(spec)
                self.assertEqual(code, 1, receipt)

    def test_servers_without_the_runners_record_is_infrastructure(self):
        spec = self.servers_spec()
        self.evidence = {}
        code, receipt = self.invoke_servers(spec)
        self.assertEqual(code, 70, receipt)
        self.assertIsNone(receipt["result"])
        # The runner's own exit is 1 for each of these; the controller makes them infrastructure.
        for evidence, reason in (
            (
                {"spec_sha256": "sha256:" + "0" * 64, "exit_code": "1"},
                "not the admitted",
            ),
            ({"error": "KeyError: 'user'", "exit_code": "1"}, "the runner failed"),
            (
                {
                    "collector_error": "OSError: disk full",
                    "verdict": "failed",
                    "exit_code": "1",
                },
                "evidence collection failed for d",
            ),
        ):
            with self.subTest(reason=reason):
                self.servers_evidence(**evidence)
                code, receipt = self.invoke_servers(spec)
                self.assertEqual(code, 70, receipt)
                self.assertIn(reason, receipt["result_error"])

    def test_servers_genuine_failure_is_red_and_success_green_beside_the_faults(self):
        spec = self.servers_spec()
        for evidence, expected in (
            ({"verdict": "failed", "exit_code": "1"}, 1),
            ({}, 0),
        ):
            with self.subTest(evidence=evidence):
                self.servers_evidence(**evidence)
                code, receipt = self.invoke_servers(spec)
                self.assertEqual(code, expected, receipt)
                self.assertIsNone(receipt["result_error"])

    def test_servers_refusals_write_a_receipt_and_start_no_machine(self):
        root_step = [
            {
                "name": "a",
                "user": "root",
                "cwd": "servers",
                "command": "true",
                "expect_exit": 0,
            }
        ]
        cases = (
            (
                self.servers_spec(bundle_sha256="sha256:" + "0" * 64),
                (),
                "not its author's",
            ),
            (self.servers_spec(commit_sha="1" * 40), (), "in the bundle is"),
            (self.servers_spec(registry=True, steps=root_step), (), "runs as gateuser"),
            (
                self.servers_spec(
                    steps=[
                        {
                            "name": "d",
                            "user": "gateuser",
                            "cwd": "servers",
                            "command": "if then",
                            "expect_exit": 0,
                        }
                    ]
                ),
                (),
                "syntax refused",
            ),
            (
                self.servers_spec(
                    steps=[
                        {
                            "name": "d",
                            "user": "gateuser",
                            "cwd": "naapp",
                            "command": "true",
                            "expect_exit": 0,
                        }
                    ]
                ),
                (),
                "not a source",
            ),
            (
                self.servers_spec(
                    steps=[
                        {
                            "name": "c",
                            "user": "gateuser",
                            "cwd": "servers",
                            "command": "true",
                            "expect_exit": 0,
                            "needs": ["b"],
                        }
                    ]
                ),
                (),
                "not an earlier step",
            ),
            (
                self.servers_spec(
                    steps=[
                        {
                            "name": "d",
                            "user": "gateuser",
                            "cwd": "servers",
                            "command": "true",
                            "expect_exit": 0,
                            "artifacts": ["{run_dir}/../world.env"],
                        }
                    ]
                ),
                (),
                "inside",
            ),
            (self.servers_spec(), ("--files", str(self.files)), "not servers'"),
        )
        for spec, extra, reason in cases:
            with self.subTest(reason=reason):
                code, receipt = self.invoke_servers(spec, *extra)
                self.assertEqual(code, 2, receipt)
                self.assertIn(reason, receipt["vm_gate"]["error"])
        spec = self.servers_spec()
        code, receipt = self.invoke_servers(spec, sha=self.sha)
        self.assertIn(
            "--repo and --sha are the spec's servers bundle",
            receipt["vm_gate"]["error"],
        )
        code, receipt = self.invoke(
            "servers", repo=self.servers_bundle, sha=self.servers_sha
        )
        self.assertIn("needs --steps", receipt["vm_gate"]["error"])
        code, receipt = self.invoke("aweb", "--steps", str(spec))
        self.assertIn(
            "--steps is the servers project's input", receipt["vm_gate"]["error"]
        )
        self.assertEqual(self.calls, [])

    # aweb-cloud: the pilot, Cloud-shaped with its own targets, names and stages

    def pilot_evidence(self, *, stages=None, suite="0", sha=None):
        sha = sha or self.cloud_sha
        rows = {stage: "PASSED" for stage in PILOT_STAGES} if stages is None else stages
        self.evidence = {
            "var/log/vm-gate/release/cloud/exit": suite + "\n",
            "var/log/vm-gate/release/host-architecture": "x86_64\nx86_64\n",
        }
        if rows:
            self.evidence[f"tmp/aweb-cloud-gate-{sha}/summary.tsv"] = "".join(
                f"{stage}\t{verdict}\t{stage}.log\t1\n"
                for stage, verdict in rows.items()
            )
        self.evidence[f"tmp/aweb-cloud-gate-{sha}/inputs.tsv"] = (
            f"source_sha\t{sha}\nscope\trelease\n"
        )

    def pilot_resolved(self, image, run_id, out):
        self.assertEqual(image, PILOT_INDEX)
        out.write_bytes(b"image")
        return {
            "image": image,
            "member": MEMBER_DIGEST,
            "config": "sha256:" + "d" * 64,
            "member_architecture": "amd64",
            "archive_sha256": "0" * 64,
        }

    def without_hermes_key(self):
        config = json.loads(self.config.read_text())
        del config["hermes_key_file"]
        self.config.write_text(json.dumps(config))

    def invoke_pilot_release(self, *extra):
        with patch.object(project.release, "image_archive", self.pilot_resolved):
            return self.invoke("aweb-cloud", "--image", PILOT_INDEX, *extra)

    def test_aweb_cloud_release_gate_runs_the_pilots_target_with_its_own_image_names(
        self,
    ):
        self.without_hermes_key()
        self.pilot_evidence()
        code, receipt = self.invoke_pilot_release()
        self.assertEqual(code, 0, receipt)
        self.assertEqual(receipt["project"], "aweb-cloud")
        self.assertEqual(
            receipt["command"], "python3 scripts/gate.py --require-release"
        )
        self.assertIsNone(receipt["aweb_source"])
        self.assertNotIn("aweb_source_built", receipt)
        self.assertEqual(receipt["stages"], {stage: "PASSED" for stage in PILOT_STAGES})
        self.assertEqual(
            receipt["real_main"], {"aweb-cloud": receipt["real_main"]["aweb-cloud"]}
        )
        [call] = self.calls
        self.assertIn("python3 scripts/gate.py --require-release >", call["command"])
        self.assertIn(f"RELEASE_IMAGE={PILOT_INDEX}", call["command"])
        self.assertIn(
            "RELEASE_IMAGE_ARCHIVE=/opt/vm-gate/cloud-image.tar", call["command"]
        )
        self.assertIn(f"RELEASE_IMAGE_MEMBER={MEMBER_DIGEST}", call["command"])
        for absent in ("AC_CANDIDATE_", "HERMES", "GATE_STAGES"):
            self.assertNotIn(absent, call["command"])
        self.assertIsNone(call["executor_factory"].keywords["release"]["hermes_key"])

    def test_aweb_cloud_train_gate_runs_every_stage(self):
        self.without_hermes_key()
        self.pilot_evidence()
        code, receipt = self.invoke("aweb-cloud")
        self.assertEqual(code, 0, receipt)
        self.assertEqual(receipt["command"], "python3 scripts/gate.py")
        [call] = self.calls
        self.assertRegex(call["command"], r"\npython3 scripts/gate.py >")
        self.assertNotIn("GATE_STAGES", call["command"])

    def test_aweb_cloud_is_green_only_when_every_row_passed_and_the_four_are_present(
        self,
    ):
        self.without_hermes_key()
        every = {stage: "PASSED" for stage in PILOT_STAGES}
        for name, stages, expected, recorded in (
            ("the four passed", every, 0, every),
            (
                "a new stage passed too",
                {**every, "decisions": "PASSED"},
                0,
                {**every, "decisions": "PASSED"},
            ),
            (
                "a new stage failed",
                {**every, "decisions": "FAILED"},
                1,
                {**every, "decisions": "FAILED"},
            ),
            (
                "one of the four failed",
                {**every, "storage": "FAILED"},
                1,
                {**every, "storage": "FAILED"},
            ),
            (
                "one of the four missing",
                {k: v for k, v in every.items() if k != "checks"},
                1,
                {
                    **{k: v for k, v in every.items() if k != "checks"},
                    "checks": "MISSING",
                },
            ),
            ("no summary", {}, 1, {stage: "MISSING" for stage in PILOT_STAGES}),
        ):
            with self.subTest(name=name):
                self.calls.clear()
                self.pilot_evidence(stages=stages)
                code, receipt = self.invoke_pilot_release()
                self.assertEqual(code, expected, receipt)
                self.assertEqual(receipt["stages"], recorded)

    def test_each_cloud_project_refuses_the_others_image(self):
        self.without_hermes_key()
        code, receipt = self.invoke("aweb-cloud", "--image", INDEX)
        self.assertEqual(code, 2, receipt)
        self.assertIn("ghcr.io/awebai/aweb-cloud", receipt["vm_gate"]["error"])
        code, receipt = self.invoke(
            "ac", "--image", PILOT_INDEX, "--aweb-source", self.sha
        )
        self.assertEqual(code, 2, receipt)
        self.assertIn("ghcr.io/awebai/ac", receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_ac_still_needs_the_hermes_key_and_aweb_cloud_does_not(self):
        self.without_hermes_key()
        code, receipt = self.invoke("ac")
        self.assertEqual(code, 2, receipt)
        self.assertIn("hermes_key_file", receipt["vm_gate"]["error"])
        self.pilot_evidence()
        code, receipt = self.invoke("aweb-cloud")
        self.assertEqual(code, 0, receipt)

    def test_aweb_cloud_files_are_refused_and_a_release_needs_no_aweb_source(self):
        self.without_hermes_key()
        code, receipt = self.invoke("aweb-cloud", "--files", str(self.files))
        self.assertEqual(code, 2, receipt)
        self.assertIn("--files", receipt["vm_gate"]["error"])
        self.pilot_evidence()
        code, receipt = self.invoke_pilot_release()
        self.assertEqual(code, 0, receipt)
        self.assertIsNone(receipt["aweb_source"])

    def test_aweb_cloud_on_a_native_machine_is_refused(self):
        self.without_hermes_key()
        code = main(
            [
                "--config",
                str(self.config),
                "run",
                "--project",
                "aweb-cloud",
                "--repo",
                str(self.cloud),
                "--sha",
                self.cloud_sha,
                "--intent",
                "train",
                "--machine",
                "antares",
                "--receipt",
                str(self.receipt),
            ],
            factory=self.runtime,
            out=io.StringIO(),
        )
        self.assertEqual(code, 2)
        self.assertIn(
            "runs in a guest", json.loads(self.receipt.read_text())["vm_gate"]["error"]
        )

    def test_the_aweb_cloud_receipt_fixture_has_the_form_project_job_writes(self):
        self.without_hermes_key()
        self.pilot_evidence()
        code, receipt = self.invoke_pilot_release()
        self.assertEqual(code, 0, receipt)
        fixture = json.loads(AWEB_CLOUD_RECEIPT_FIXTURE.read_text())
        self.assertEqual(form(receipt), form(fixture))
        self.assertEqual(fixture["project"], "aweb-cloud")

    def pilot_summary(self, text, *, directory=None):
        """The pilot's summary.tsv exactly as its gate writes it, raw."""
        self.pilot_evidence(stages={})
        self.evidence[
            f"tmp/{directory or 'aweb-cloud-gate-' + self.cloud_sha}/summary.tsv"
        ] = text

    def test_aweb_cloud_judges_its_one_raw_summary(self):
        self.without_hermes_key()
        four = "".join(f"{stage}\tPASSED\t{stage}.log\t1\n" for stage in PILOT_STAGES)
        for name, text, expected in (
            ("the four", four, 0),
            (
                "a further stage passed",
                four + "decisions\tPASSED\tdecisions.log\t3\n",
                0,
            ),
            (
                "a further stage not run",
                four + "decisions\tNOT RUN\tdecisions.log\t0\n",
                1,
            ),
            (
                "a stage failed, then passed",
                "checks\tFAILED\tchecks.log\t1\n" + four,
                1,
            ),
            ("a stage twice, both passed", four + "image\tPASSED\timage.log\t1\n", 1),
            ("a malformed row", four + "garbage\n", 1),
            ("an empty stage name", four + "\tPASSED\tx.log\t1\n", 1),
        ):
            with self.subTest(name=name):
                self.calls.clear()
                self.pilot_summary(text)
                code, receipt = self.invoke_pilot_release()
                self.assertEqual(code, expected, (name, receipt["stages"]))

    def test_aweb_cloud_reads_only_its_exact_directory(self):
        self.without_hermes_key()
        half = lambda stages: "".join(
            f"{stage}\tPASSED\t{stage}.log\t1\n" for stage in stages
        )
        self.pilot_summary(half(PILOT_STAGES[:2]))
        # A second directory whose rows would complete the four must not count.
        self.evidence[f"tmp/aweb-cloud-gate-{self.cloud_sha}-other/summary.tsv"] = half(
            PILOT_STAGES[2:]
        )
        code, receipt = self.invoke_pilot_release()
        self.assertEqual(code, 1, receipt)
        self.assertEqual(receipt["stages"]["storage"], "MISSING")

    def test_aweb_cloud_keeps_the_pilots_own_exit(self):
        self.without_hermes_key()
        for suite, expected, classification in (
            ("0", 0, None),
            ("1", 1, None),
            ("2", 2, "refused"),
            ("70", 70, "infrastructure"),
        ):
            with self.subTest(suite=suite):
                self.calls.clear()
                self.pilot_evidence(suite=suite)
                code, receipt = self.invoke_pilot_release()
                self.assertEqual(code, expected, receipt)
                self.assertEqual(receipt["suite_exit"], int(suite))
                self.assertEqual(receipt["suite_classification"], classification)
        # The guest runs the pilot's gate itself, so make cannot fold its exit into 2.
        [call] = self.calls
        self.assertIn("python3 scripts/gate.py --require-release", call["command"])
        self.assertNotIn("make release-gate", call["command"])

    def test_an_aweb_source_pin_nothing_can_attest_is_refused_before_boot(self):
        self.without_hermes_key()
        code, receipt = self.invoke_pilot_release("--aweb-source", self.sha)
        self.assertEqual(code, 2, receipt)
        self.assertIn("builds no aweb", receipt["vm_gate"]["error"])
        code, receipt = self.invoke("aweb-cloud", "--aweb-source", self.sha)
        self.assertEqual(code, 2, receipt)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
