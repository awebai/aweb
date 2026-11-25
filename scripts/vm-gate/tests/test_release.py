"""make release's one gate job, against real Git repositories and real shell."""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vm_gate import budget, release
from vm_gate.errors import Refused
from vm_gate.cli import main
from test_config import hashes
from test_source import GitFixture, git


def commit(repo, name, text="x"):
    (repo / name).write_text(text)
    git(repo, "add", name)
    git(repo, "commit", "-m", name)
    return git(repo, "rev-parse", "HEAD")


class CloudFixture(GitFixture):
    """Cloud's origin, a release checkout whose commit C sits on main, and a teammate."""

    def setUp(self):
        super().setUp()
        self.cloud_origin = self.root / "cloud.git"
        git(self.root, "init", "--bare", "-b", "main", str(self.cloud_origin))
        self.cloud = self.root / "cloud"
        git(self.root, "clone", str(self.cloud_origin), str(self.cloud))
        for repo in (self.cloud,):
            git(repo, "config", "user.email", "fixture@example.invalid")
            git(repo, "config", "user.name", "Fixture")
        self.cloud_main = commit(self.cloud, "base")
        git(self.cloud, "push", "origin", "HEAD:main")
        # make release pins: the version commit C on top of real main.
        self.cloud_sha = commit(self.cloud, "version", "0.8.86")

    def move_main(self):
        other = self.root / "teammate"
        git(self.root, "clone", str(self.cloud_origin), str(other))
        git(other, "config", "user.email", "fixture@example.invalid")
        git(other, "config", "user.name", "Fixture")
        moved = commit(other, "landed")
        git(other, "push", "origin", "HEAD:main")
        return moved


class ReleaseAdmission(CloudFixture, unittest.TestCase):
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
        (self.files / "aweb-1.27.54-py3-none-any.whl").write_bytes(b"wheel")
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
                    "hetzner": {
                        "platform": "linux/amd64",
                        "server_type": "ccx43",
                        "release_timeout_seconds": 10800,
                    },
                    "antares": {
                        "platform": "linux/arm64",
                        "backend": "native",
                        "root": str(self.root / "antares-jobs"),
                        "release_timeout_seconds": 9000,
                    },
                    "nowhere": {
                        "platform": "linux/amd64",
                        "backend": "teleport",
                        "release_timeout_seconds": 9000,
                    },
                }
            )
        )
        self.receipt = self.root / "gate-receipt.json"
        self.calls = []
        uid = patch("os.geteuid", return_value=501)
        uid.start()
        self.addCleanup(uid.stop)

    def factory(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("no machine may start for a refused release")

    def invoke(self, machine="merak", *extra):
        code = main(
            [
                "--config",
                str(self.config),
                "release",
                "--machine",
                machine,
                "--cloud-repo",
                str(self.cloud),
                "--cloud-sha",
                self.cloud_sha,
                "--cloud-image",
                "ghcr.io/awebai/ac@sha256:" + "a" * 64,
                "--receipt",
                str(self.receipt),
                "--aweb-lock-source-sha",
                self.sha,
                *extra,
            ],
            factory=self.factory,
            out=io.StringIO(),
        )
        return code, json.loads(self.receipt.read_text())

    def test_moved_main_refuses_before_boot_with_a_receipt(self):
        moved = self.move_main()
        code, receipt = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(receipt["exit"], 2)
        self.assertEqual(receipt["vm_gate"]["infrastructure"], "refused")
        self.assertIn("Cloud main moved", receipt["vm_gate"]["error"])
        self.assertIn(moved, receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_an_undeclared_machine_or_backend_is_refused(self):
        for machine, reason in (
            ("elsewhere", "no platform"),
            ("nowhere", "no backend"),
        ):
            with self.subTest(machine=machine):
                code, receipt = self.invoke(machine)
                self.assertEqual(code, 2)
                self.assertIn(reason, receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def factory_for_admission(self):
        class Runtime:
            def run(self):
                return {"exit": 0, "infrastructure": None}

        def factory(**kwargs):
            self.calls.append(kwargs)
            return Runtime()

        self.factory = factory

    def admitted(self, machine):
        def image_archive(image, run_id, out):
            out.write_bytes(b"image")
            return {
                "image": image,
                "member": "sha256:" + "b" * 64,
                "config": "sha256:" + "d" * 64,
                "member_architecture": "amd64",
                "archive_sha256": "0" * 64,
            }

        self.factory_for_admission()
        with patch.object(release, "image_archive", image_archive):
            return self.invoke(machine)

    def invoke_cloud_gate(self, machine="merak"):
        code = main(
            [
                "--config",
                str(self.config),
                "cloud-gate",
                "--machine",
                machine,
                "--cloud-repo",
                str(self.cloud),
                "--cloud-sha",
                self.cloud_sha,
                "--receipt",
                str(self.receipt),
            ],
            factory=self.factory,
            out=io.StringIO(),
        )
        return code, json.loads(self.receipt.read_text())

    def test_a_cloud_gate_runs_make_gate_through_the_release_job(self):
        self.factory_for_admission()

        def no_image(*args, **kwargs):
            raise AssertionError("a Cloud gate builds and ships no image")

        def no_key(*args, **kwargs):
            raise AssertionError("a Cloud gate needs no Hermes key")

        with patch.object(release, "image_archive", no_image), patch.object(
            release, "hermes_key", no_key
        ):
            code, receipt = self.invoke_cloud_gate()
        self.assertEqual(len(self.calls), 1, receipt)
        run = self.calls[0]
        self.assertIn("make gate ", run["command"])
        self.assertNotIn("make release-gate", run["command"])
        self.assertNotIn("AC_CANDIDATE_RELEASE_IMAGE", run["command"])
        self.assertNotIn("cloud-image.tar", run["command"])
        self.assertIn("python3 -m vm_gate.budget split", run["command"])
        inputs = run["executor_factory"].keywords["release"]
        self.assertIsNone(inputs["archive"])
        self.assertIsNone(inputs["hermes_key"])
        self.assertEqual(inputs["files"], [])
        self.assertEqual(receipt["cloud"]["command"], "make gate")
        self.assertNotIn("image", receipt["cloud"])
        self.assertNotIn("aweb", receipt)
        self.assertEqual(receipt["cloud"]["sha"], self.cloud_sha)

    def test_a_cloud_gate_refuses_a_moved_main_like_a_release(self):
        moved = self.move_main()
        code, receipt = self.invoke_cloud_gate()
        self.assertEqual(code, 2)
        self.assertIn("Cloud main moved", receipt["vm_gate"]["error"])
        self.assertIn(moved, receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_each_machine_from_config_is_admitted_on_its_backend(self):
        for machine, server_type, timeout in (
            ("hetzner", "ccx43", 10800),
            ("merak", None, 9000),
        ):
            with self.subTest(machine=machine):
                self.calls.clear()
                code, receipt = self.admitted(machine)
                self.assertEqual(len(self.calls), 1, receipt)
                args = self.calls[0]["args"]
                self.assertEqual(
                    (args.target, args.type, args.timeout),
                    (machine, server_type, timeout),
                )
                self.assertEqual(receipt["machine_platform"], "linux/amd64")
                self.assertEqual(receipt["timeout_seconds"], timeout)
        self.calls.clear()
        code, receipt = self.admitted("antares")
        self.assertEqual(len(self.calls), 1, receipt)
        native = self.calls[0]
        self.assertEqual(native["machine"]["root"], str(self.root / "antares-jobs"))
        self.assertIn("/jobs/x/home", native["script"]("/jobs/x"))
        self.assertEqual(receipt["machine_platform"], "linux/arm64")
        self.assertEqual(receipt["cloud"]["member_architecture"], "amd64")

    def test_an_arm64_host_refuses_a_member_that_is_not_amd64(self):
        def docker(*argv):
            if argv[:2] == ("buildx", "imagetools"):
                return json.dumps(
                    {
                        "manifests": [
                            {
                                "digest": "sha256:" + "a" * 64,
                                "platform": {"os": "linux", "architecture": "amd64"},
                            },
                            {
                                "digest": "sha256:" + "e" * 64,
                                "platform": {"os": "linux", "architecture": "arm64"},
                            },
                        ]
                    }
                )
            if argv[0] == "save":
                write_archive(Path(argv[2]), "arm64")
            return ""

        self.factory_for_admission()
        with patch.object(release, "docker", docker):
            code, receipt = self.invoke("antares")
        self.assertEqual(code, 2)
        self.assertIn("arm64, not amd64", receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_aweb_files_need_their_commit_and_the_commit_its_files(self):
        for extra in (("--aweb-sha", self.sha), ("--files", str(self.files))):
            with self.subTest(extra=extra[0]):
                code, receipt = self.invoke("merak", *extra)
                self.assertEqual(code, 2)
                self.assertIn("go together", receipt["vm_gate"]["error"])
        self.assertEqual(self.calls, [])

    def test_a_shared_hermes_key_is_refused(self):
        self.key.chmod(0o644)
        code, receipt = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn("hermes_key_file", receipt["vm_gate"]["error"])

    def test_release_commit_on_real_main_records_main(self):
        self.assertEqual(
            release.cloud_main(self.cloud, self.cloud_sha),
            {"real_main": {"ac": self.cloud_main}, "ac_parent_of_c": self.cloud_main},
        )


class CloudBundle(CloudFixture, unittest.TestCase):
    def test_bundle_main_is_the_release_commit_and_cloud_refs_are_untouched(self):
        refs = git(self.cloud, "for-each-ref")
        bundle = self.root / "cloud.bundle"
        digest = release.cloud_bundle(self.cloud, self.cloud_sha, bundle)
        self.assertEqual(digest, hashlib.sha256(bundle.read_bytes()).hexdigest())
        self.assertEqual(git(self.cloud, "for-each-ref"), refs)
        # The guest's way in: fetch the bundle's main into a fresh origin. A
        # bundle carries no HEAD, so git before 2.40 cannot clone one directly.
        self.assertEqual(
            git(self.root, "bundle", "list-heads", str(bundle)),
            f"{self.cloud_sha} refs/heads/main",
        )
        origin = self.root / "origin.git"
        git(self.root, "init", "--quiet", "--bare", str(origin))
        git(origin, "fetch", "--quiet", str(bundle), "refs/heads/main:refs/heads/main")
        self.assertEqual(git(origin, "rev-parse", "main"), self.cloud_sha)


def write_archive(path, architecture):
    """A docker save archive holding one image config of the given architecture."""
    config = json.dumps({"architecture": architecture, "os": "linux"}).encode()
    digest = hashlib.sha256(config).hexdigest()
    manifest = json.dumps([{"Config": "blobs/sha256/" + digest}]).encode()
    with tarfile.open(path, "w") as tar:
        for name, data in (
            ("manifest.json", manifest),
            ("blobs/sha256/" + digest, config),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return "sha256:" + digest


class ArchiveConfig(unittest.TestCase):
    def test_config_digest_and_architecture_come_from_the_saved_image(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "image.tar"
            digest = write_archive(archive, "amd64")
            self.assertEqual(release.archive_config(archive), (digest, "amd64"))
            self.assertEqual(release.shipped_member(archive), (digest, "amd64"))
            write_archive(archive, "arm64")
            with self.assertRaises(release.Refused):
                release.shipped_member(archive)


STUB_MAKE = """#!/bin/bash
# Records the environment each suite ran with, and fails a suite on request.
target="$1"
env | sort > "$STUB_RECORD/$target.env"
pwd > "$STUB_RECORD/$target.pwd"
case "$target" in
  release-gate|gate) sleep "${CLOUD_SLEEP:-0}"; exit "${CLOUD_EXIT:-0}" ;;
  candidate-gate) exit "${AWEB_EXIT:-0}" ;;
esac
exit 99
"""
# A guest engine of 12 CPUs and 60 GiB.
STUB_DOCKER = """#!/bin/bash
case "$*" in
  *NCPU*) echo "12 64424509440" ;;
  *Architecture*) echo x86_64 ;;
  *) exit 99 ;;
esac
"""
STUB_UV = """#!/bin/bash
# uv build --quiet --wheel --sdist --out-dir DIR PROJECT: writes PROJECT's files.
out="$6"; project="$7"
case "$project" in
  server) printf 'wheel' > "$out/aweb-1.27.54-py3-none-any.whl" ;;
  awid) printf 'other' > "$out/awid_service-0.5.43-py3-none-any.whl" ;;
esac
"""


@unittest.skipUnless(shutil.which("sha256sum"), "needs sha256sum")
class GuestScript(CloudFixture, unittest.TestCase):
    """The guest script itself, run in place of the guest with stub make and uv."""

    def setUp(self):
        super().setUp()
        self.remote = self.root / "opt"
        self.logs = self.root / "logs"
        self.home = self.root / "home"
        self.stubs = self.root / "stubs"
        self.record = self.root / "record"
        for d in (self.remote, self.logs, self.home, self.stubs, self.record):
            d.mkdir()
        git(self.root, "clone", "--quiet", str(self.repo), str(self.remote / "source"))
        git(self.remote / "source", "checkout", "--quiet", self.sha)
        self.bundle = release.cloud_bundle(
            self.cloud, self.cloud_sha, self.remote / "cloud.bundle"
        )
        (self.remote / "cloud-image.tar").write_bytes(b"image")
        self.archive = hashlib.sha256(b"image").hexdigest()
        for name, text in (("make", STUB_MAKE), ("uv", STUB_UV), ("docker", STUB_DOCKER)):
            (self.stubs / name).write_text(text)
            (self.stubs / name).chmod(0o755)

    def run_script(self, files, aweb=True, **env):
        script = release.guest_script(
            cloud_sha=self.cloud_sha,
            bundle_sha256=self.bundle,
            archive_sha256=self.archive,
            image="ghcr.io/awebai/ac@sha256:" + "a" * 64,
            member="sha256:" + "b" * 64,
            lock_source_sha=self.sha,
            aweb=self.sha if aweb else None,
            files=files,
            remote=str(self.remote),
            logs=str(self.logs),
            home=str(self.home),
            key="/run/key",
            files_dir="/opt/files",
        )
        environment = {
            "PATH": f"{self.stubs}:{os.environ['PATH']}",
            "HOME": str(self.home),
            "STUB_RECORD": str(self.record),
            "AWEB_GATE_LEDGER": str(self.root / "aweb-ledger.tsv"),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "PYTHONPATH": str(Path(release.__file__).resolve().parents[1]),
            **env,
        }
        return subprocess.run(
            ["bash", "-c", script], env=environment, capture_output=True, text=True
        )

    def suite_env(self, target):
        return dict(
            line.split("=", 1)
            for line in (self.record / f"{target}.env").read_text().splitlines()
            if "=" in line
        )

    def test_both_suites_run_each_with_its_own_inputs(self):
        files = {"aweb-1.27.54-py3-none-any.whl": hashlib.sha256(b"wheel").hexdigest()}
        result = self.run_script(files)
        self.assertEqual(result.returncode, 0, result.stderr)
        cloud = self.suite_env("release-gate")
        aweb = self.suite_env("candidate-gate")
        self.assertEqual(
            (self.record / "release-gate.pwd").read_text().strip(),
            str(self.home / "cloud-source"),
        )
        self.assertEqual(
            git(self.home / "cloud-source", "rev-parse", "HEAD"), self.cloud_sha
        )
        self.assertEqual(
            git(self.home / "cloud-source", "rev-parse", "origin/main"), self.cloud_sha
        )
        # Cloud's gate keeps its own ledger; aweb's gate writes the canonical one.
        self.assertEqual(
            cloud["AWEB_GATE_LEDGER"], str(self.logs / "release/cloud/ledger.tsv")
        )
        self.assertEqual(aweb["AWEB_GATE_LEDGER"], str(self.root / "aweb-ledger.tsv"))
        self.assertEqual(
            cloud["AC_CANDIDATE_RELEASE_IMAGE_MEMBER"], "sha256:" + "b" * 64
        )
        self.assertEqual(
            cloud["AC_CANDIDATE_RELEASE_IMAGE_ARCHIVE"],
            str(self.remote / "cloud-image.tar"),
        )
        self.assertEqual(cloud["AC_CANDIDATE_AWEB_WHEELS"], "/opt/files")
        self.assertEqual(cloud["AC_CANDIDATE_AWEB_WHEELS_SOURCE_SHA"], self.sha)
        self.assertEqual(cloud["AC_CANDIDATE_HERMES_ANTHROPIC_KEY_FILE"], "/run/key")
        self.assertNotIn("AC_CANDIDATE_RELEASE_IMAGE", aweb)
        rebuilt = json.loads((self.logs / "release/aweb/rebuilt.json").read_text())
        self.assertEqual(rebuilt, files)
        for suite in ("cloud", "aweb"):
            self.assertEqual((self.logs / f"release/{suite}/exit").read_text(), "0\n")

    def test_each_gate_gets_its_share_of_the_guest(self):
        result = self.run_script({"aweb-1.27.54-py3-none-any.whl": "x"})
        self.assertEqual(result.returncode, 0, result.stderr)
        cloud = self.suite_env("release-gate")
        aweb = self.suite_env("candidate-gate")
        # The stub guest is 12 CPUs and 61440 MiB, divided by the measured work.
        expected = budget.release_split(12, 61440, release.gate_weights())
        self.assertEqual(
            (cloud["GATE_CPUS"], aweb["GATE_CPUS"]),
            (str(expected["cloud"]["cpus"]), str(expected["aweb"]["cpus"])),
        )
        self.assertEqual(
            (cloud["GATE_MEMORY_MIB"], aweb["GATE_MEMORY_MIB"]),
            (str(expected["cloud"]["memory_mib"]), str(expected["aweb"]["memory_mib"])),
        )
        recorded = json.loads((self.logs / "release/split.json").read_text())
        self.assertEqual(recorded, expected)

    def test_a_cloud_gate_runs_make_gate_with_the_whole_guest(self):
        script = release.guest_script(
            cloud_sha=self.cloud_sha,
            bundle_sha256=self.bundle,
            archive_sha256=None,
            image=None,
            member=None,
            lock_source_sha=None,
            aweb=None,
            files={},
            remote=str(self.remote),
            logs=str(self.logs),
            home=str(self.home),
            cloud_target="gate",
        )
        (self.remote / "cloud-image.tar").unlink()
        environment = {
            "PATH": f"{self.stubs}:{os.environ['PATH']}",
            "HOME": str(self.home),
            "STUB_RECORD": str(self.record),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "PYTHONPATH": str(Path(release.__file__).resolve().parents[1]),
        }
        result = subprocess.run(
            ["bash", "-c", script], env=environment, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        cloud = self.suite_env("gate")
        self.assertFalse((self.record / "release-gate.env").exists())
        self.assertFalse((self.record / "candidate-gate.env").exists())
        self.assertNotIn("AC_CANDIDATE_RELEASE_IMAGE", cloud)
        self.assertNotIn("AC_CANDIDATE_HERMES_ANTHROPIC_KEY_FILE", cloud)
        self.assertEqual((cloud["GATE_CPUS"], cloud["GATE_MEMORY_MIB"]), ("12", "61440"))
        recorded = json.loads((self.logs / "release/split.json").read_text())
        self.assertEqual(recorded["cloud"], {"cpus": 12, "memory_mib": 61440})
        self.assertEqual((self.logs / "release/cloud/exit").read_text(), "0\n")

    def test_an_unknown_cloud_target_is_refused(self):
        with self.assertRaises(ValueError):
            release.guest_script(
                cloud_sha=self.cloud_sha,
                bundle_sha256=self.bundle,
                archive_sha256=None,
                image=None,
                member=None,
                lock_source_sha=None,
                aweb=None,
                files={},
                cloud_target="deploy",
            )

    def test_a_cloud_only_release_gives_cloud_the_whole_guest(self):
        result = self.run_script({}, aweb=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        cloud = self.suite_env("release-gate")
        self.assertEqual((cloud["GATE_CPUS"], cloud["GATE_MEMORY_MIB"]), ("12", "61440"))

    def test_a_red_suite_makes_the_job_red_and_both_exits_are_kept(self):
        for env, cloud_exit, aweb_exit in (
            ({"CLOUD_EXIT": "3"}, "3", "0"),
            ({"AWEB_EXIT": "2"}, "0", "2"),
        ):
            with self.subTest(env=env):
                result = self.run_script({"aweb-1.27.54-py3-none-any.whl": "x"}, **env)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(
                    (self.logs / "release/cloud/exit").read_text(), cloud_exit + "\n"
                )
                self.assertEqual(
                    (self.logs / "release/aweb/exit").read_text(), aweb_exit + "\n"
                )

    def test_a_cloud_only_release_runs_no_aweb_suite(self):
        result = self.run_script({}, aweb=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.record / "candidate-gate.env").exists())
        self.assertNotIn("AC_CANDIDATE_AWEB_WHEELS", self.suite_env("release-gate"))

    def test_a_changed_bundle_stops_the_job_before_any_suite(self):
        # Still a valid bundle whose main is the release commit, with other bytes.
        git(self.cloud, "branch", "extra", self.cloud_main)
        bundle = self.remote / "cloud.bundle"
        bundle.unlink()
        self.assertEqual(git(self.cloud, "rev-parse", "main"), self.cloud_sha)
        git(self.cloud, "bundle", "create", str(bundle), "main", "extra")
        result = self.run_script({}, aweb=False)
        self.assertEqual(result.returncode, 70)
        self.assertFalse((self.record / "release-gate.env").exists())


@unittest.skipUnless(shutil.which("sha256sum"), "needs sha256sum")
class NativeJob(CloudFixture, unittest.TestCase):
    """The native path end to end on this machine, with stub make and uv."""

    def setUp(self):
        super().setUp()
        from vm_gate.source import prepare

        self.directory = self.root / "state/runs/vm-native"
        self.directory.mkdir(parents=True)
        # The release commit carries the vm_gate split the job runs.
        package = Path(release.__file__).resolve().parent
        fixture_package = self.repo / "scripts/vm-gate/vm_gate"
        fixture_package.mkdir(parents=True)
        for name in ("__init__.py", "budget.py"):
            shutil.copy2(package / name, fixture_package / name)
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-m", "release split")
        self.sha = git(self.repo, "rev-parse", "HEAD")
        self.source = prepare(
            self.repo, self.sha, self.directory, observed=self.observed
        )
        stubs = self.root / "stubs"
        stubs.mkdir()
        for name, text in (("make", STUB_MAKE), ("uv", STUB_UV), ("docker", STUB_DOCKER)):
            (stubs / name).write_text(text)
            (stubs / name).chmod(0o755)
        self.record = self.root / "record"
        self.record.mkdir()
        environment = patch.dict(
            os.environ,
            {
                "PATH": f"{stubs}:{os.environ['PATH']}",
                "STUB_RECORD": str(self.record),
                "GIT_CONFIG_GLOBAL": "/dev/null",
            },
        )
        environment.start()
        self.addCleanup(environment.stop)
        self.bundle = self.root / "cloud.bundle"
        bundle_sha256 = release.cloud_bundle(self.cloud, self.cloud_sha, self.bundle)
        self.archive = self.root / "cloud-image.tar"
        self.archive.write_bytes(b"image")
        files = self.root / "dist"
        files.mkdir()
        (files / "aweb-1.27.54-py3-none-any.whl").write_bytes(b"wheel")
        key = self.root / "key"
        key.write_text("test-only")
        key.chmod(0o600)
        ledger = self.root / "ledger.tsv"
        ledger.write_text("")
        self.jobs = self.root / "jobs"
        self.jobs.mkdir()
        from vm_gate.native import NativeRuntime

        self.runtime = lambda timeout: NativeRuntime(
            config={"ledger": str(ledger), "owner": "seat"},
            directory=self.directory,
            source=self.source,
            script=lambda job: release.guest_script(
                cloud_sha=self.cloud_sha,
                bundle_sha256=bundle_sha256,
                archive_sha256=hashlib.sha256(b"image").hexdigest(),
                image="ghcr.io/awebai/ac@sha256:" + "a" * 64,
                member="sha256:" + "b" * 64,
                lock_source_sha=self.sha,
                aweb=self.sha,
                files={
                    "aweb-1.27.54-py3-none-any.whl": hashlib.sha256(
                        b"wheel"
                    ).hexdigest()
                },
                remote=job,
                logs=job + "/logs",
                home=job + "/home",
                key=job + "/hermes-key",
                files_dir=job + "/release-files",
            ),
            machine={"root": str(self.jobs)},
            inputs={
                "bundle": self.bundle,
                "archive": self.archive,
                "files": [files / "aweb-1.27.54-py3-none-any.whl"],
                "hermes_key": key,
            },
            timeout=timeout,
        )

    def test_both_suites_run_on_the_host_and_the_evidence_comes_back(self):
        result = self.runtime(120).run()
        self.assertEqual(result["exit"], 0, result)
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(result["ledger_rows_imported"], 0)
        evidence = self.directory / "evidence/var/log/vm-gate/release"
        for suite in ("cloud", "aweb"):
            self.assertEqual((evidence / suite / "exit").read_text(), "0\n")
        job = Path(result["job"])
        self.assertFalse((job / "hermes-key").exists())
        self.assertFalse((job / "cloud-image.tar").exists())
        cloud = (self.record / "release-gate.env").read_text()
        self.assertIn(
            f"AC_CANDIDATE_RELEASE_IMAGE_ARCHIVE={job}/cloud-image.tar", cloud
        )
        self.assertIn(f"AWEB_GATE_LEDGER={job}/logs/release/cloud/ledger.tsv", cloud)
        self.assertIn(
            f"AWEB_GATE_LEDGER={job}/ledger.tsv",
            (self.record / "candidate-gate.env").read_text(),
        )
        self.assertTrue((evidence / "host-architecture").read_text().strip())

    def test_the_deadline_stops_the_job_with_term_and_is_infrastructure(self):
        os.environ["CLOUD_SLEEP"] = "30"
        result = self.runtime(2).run()
        self.assertEqual(result["exit"], 124)
        self.assertEqual(result["infrastructure"], "infrastructure")
        self.assertFalse((Path(result["job"]) / "hermes-key").exists())


# Machine shapes, as (CPUs, MiB): small ones, 10 and 12 CPUs, arm64 native
# hosts, and Hetzner's dedicated sizes. The computation sees only numbers.
SHAPES = [
    (1, 2048),
    (2, 4096),
    (4, 8192),
    (10, 45056),
    (12, 51642),
    (12, 32768),
    (14, 98304),
    (8, 32768),
    (16, 65536),
    (32, 131072),
    (48, 196608),
    (96, 393216),
]


class Budget(unittest.TestCase):
    def gate_sizes(self, cpus, memory_mib):
        spec = importlib.util.spec_from_file_location(
            "gate_budget",
            Path(release.__file__).resolve().parents[2] / "gate_budget.py",
        )
        gate_budget = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate_budget)
        return gate_budget.size(cpus, memory_mib), gate_budget.workers

    def test_every_cpu_is_used_and_nothing_is_oversubscribed(self):
        measured = release.gate_weights()
        for cpus, memory_mib in SHAPES:
            for aweb in (True, False):
                weights = measured if aweb else {"cloud": measured["cloud"]}
                with self.subTest(cpus=cpus, memory_mib=memory_mib, aweb=aweb):
                    if aweb and cpus < 2:
                        with self.assertRaises(ValueError):
                            budget.release_split(cpus, memory_mib, weights)
                        continue
                    shares = budget.release_split(cpus, memory_mib, weights)
                    self.assertEqual(
                        shares["measured"], {"cpus": cpus, "memory_mib": memory_mib}
                    )
                    gates = [shares[g] for g in ("aweb", "cloud") if g in shares]
                    # The gates' shares are exactly the measured capacity.
                    self.assertEqual(sum(g["cpus"] for g in gates), cpus)
                    self.assertEqual(sum(g["memory_mib"] for g in gates), memory_mib)
                    self.assertTrue(all(g["cpus"] >= 1 for g in gates))
                    for gate in gates:
                        sizes, workers = self.gate_sizes(gate["cpus"], gate["memory_mib"])
                        for cap in ("runner_cpus", "builder_cpus", "sibling_cpus"):
                            self.assertEqual(sizes[cap], gate["cpus"])
                        count = sizes["server_workers"]
                        self.assertLessEqual(count, max(gate["cpus"] - 1, 0))
                        if count:
                            self.assertLessEqual(
                                workers.service_memory_mib(count), gate["memory_mib"] // 2
                            )

    def test_the_split_follows_the_gates_measured_work(self):
        weights = release.gate_weights()
        self.assertEqual(weights["aweb"], sum(json.loads(
            (Path(release.__file__).resolve().parents[3] / "candidate-gate/measured-work.json").read_text()
        )["lanes"].values()))
        heavy = budget.release_split(24, 98304, {"aweb": 1000, "cloud": 3000})
        self.assertEqual((heavy["aweb"]["cpus"], heavy["cloud"]["cpus"]), (6, 18))
        self.assertEqual(heavy["weights"], {"aweb": 1000, "cloud": 3000})
        for bad in ({"aweb": 1}, {"cloud": 0}, {"cloud": 1, "other": 1}, {"cloud": 1.5}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                budget.release_split(12, 51642, bad)

    def test_a_missing_cloud_figure_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "work.json"
            path.write_text(json.dumps({"lanes": {"unit": 10}}))
            with self.assertRaisesRegex(Refused, "Cloud"):
                release.gate_weights(path)

    def test_an_override_is_input_and_a_missing_value_is_measured(self):
        with patch.object(budget, "measure", return_value=(12, 51642)):
            self.assertEqual(
                budget.budget_from({}), (12, 51642, "cpus=measured,memory=measured")
            )
            self.assertEqual(
                budget.budget_from({"GATE_CPUS": "6"}),
                (6, 51642, "cpus=input,memory=measured"),
            )
        with patch.object(budget, "measure", side_effect=AssertionError("measured")):
            self.assertEqual(
                budget.budget_from({"GATE_CPUS": "6", "GATE_MEMORY_MIB": "1024"}),
                (6, 1024, "cpus=input,memory=input"),
            )
        for bad in ("0", "-1", "1.5", "six"):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "GATE_CPUS"):
                budget.budget_from({"GATE_CPUS": bad, "GATE_MEMORY_MIB": "1024"})


class Receipt(unittest.TestCase):
    def evidence(self, directory, suite, exit_code=None, rebuilt=None):
        root = Path(directory) / "evidence/var/log/vm-gate/release" / suite
        root.mkdir(parents=True, exist_ok=True)
        if exit_code is not None:
            (root / "exit").write_text(f"{exit_code}\n")
        if rebuilt is not None:
            (root / "rebuilt.json").write_text(json.dumps(rebuilt))

    def record(self, directory, files, result=None):
        return release.receipt(
            machine="merak",
            platform="linux/amd64",
            run_id="vm-1",
            result=result
            or {"exit": 0, "infrastructure": None, "ledger_rows_imported": 9},
            cloud_sha="c" * 40,
            image={
                "image": "ghcr.io/awebai/ac@sha256:" + "a" * 64,
                "member": "sha256:" + "b" * 64,
                "config": "sha256:" + "d" * 64,
            },
            main={"real_main": {"ac": "e" * 40}, "ac_parent_of_c": "e" * 40},
            files=files,
            aweb="f" * 40 if files else None,
            launcher_sha="1" * 40,
            timeout=9000,
            directory=directory,
        )

    def test_green_needs_both_suites_and_the_same_rebuilt_files(self):
        files = {"aweb-1.27.54-py3-none-any.whl": "9" * 64}
        with tempfile.TemporaryDirectory() as directory:
            self.evidence(directory, "cloud", 0)
            self.evidence(
                directory, "aweb", 0, {**files, "aweb-1.27.54.tar.gz": "8" * 64}
            )
            record = self.record(directory, files)
            self.assertEqual(release.exit_code(record), 0)
            self.assertEqual(record["aweb"]["rebuilt_files"], files)
            self.assertEqual(record["cloud"]["config"], "sha256:" + "d" * 64)
            self.assertEqual(record["real_main"], {"ac": "e" * 40})
            self.evidence(
                directory, "aweb", 0, {"aweb-1.27.54-py3-none-any.whl": "7" * 64}
            )
            self.assertEqual(release.exit_code(self.record(directory, files)), 1)

    def test_a_missing_suite_exit_is_infrastructure_and_a_red_suite_is_red(self):
        with tempfile.TemporaryDirectory() as directory:
            self.evidence(directory, "cloud")
            self.assertEqual(release.exit_code(self.record(directory, {})), 70)
            self.evidence(directory, "cloud", 4)
            self.assertEqual(release.exit_code(self.record(directory, {})), 1)
            infrastructure = {
                "exit": 70,
                "infrastructure": "infrastructure",
                "error": "lost",
            }
            self.assertEqual(
                release.exit_code(self.record(directory, {}, infrastructure)), 70
            )


if __name__ == "__main__":
    unittest.main()
