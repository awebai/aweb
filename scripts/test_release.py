"""aweb's release command against real Git, real uv builds and the real vm-gate receipt.

Only the machine, PyPI and GitHub are stand-ins. The gate stand-in runs vm-gate's
own admission and receipt code (`vm-gate run --project aweb`) with a runtime that
leaves the evidence a guest leaves, so the command reads the launcher's real
receipt format.
"""

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts/vm-gate"))
sys.path.insert(0, str(ROOT / "scripts/vm-gate/tests"))

import release  # noqa: E402
from vm_gate.cli import main as vm_gate_main  # noqa: E402
from test_config import hashes  # noqa: E402

SERVER_PYPROJECT = """[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "aweb"
version = "1.27.55"
requires-python = ">=3.12"

[tool.hatch.build.targets.wheel]
packages = ["src/aweb"]
"""
AWID_PYPROJECT = """[project]
name = "awid-service"
version = "0.5.43"
"""
WORKFLOW_RUN = "https://github.com/awebai/aweb/actions/runs/1 (completed, failure)"


def git(cwd, *args):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class PyPI:
    """Published files by (package, version), as pypi.org's JSON API lists them."""

    def __init__(self):
        self.files = {
            ("awid-service", "0.5.43"): [
                {
                    "filename": "awid_service-0.5.43.tar.gz",
                    "digests": {"sha256": "0" * 64},
                }
            ]
        }

    def download(self, url):
        name, version = (
            url.removeprefix("https://pypi.org/pypi/").removesuffix("/json").split("/")
        )
        if (name, version) not in self.files:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO())
        return json.dumps({"urls": self.files[(name, version)]}).encode()

    def upload(self, name, version, paths, *, digest=None):
        self.files[(name, version)] = [
            {
                "filename": path.name,
                "digests": {"sha256": digest or sha256(path).removeprefix("sha256:")},
                "yanked": False,
            }
            for path in paths
        ]


class Machine:
    """The guest: leaves the evidence a gate run leaves for the files it was given."""

    def __init__(self):
        self.mode = "green"

    def factory(self, **kwargs):
        evidence = kwargs["directory"] / "evidence"
        files = {
            path.name: sha256(path)
            for path in kwargs["executor_factory"].keywords["files"]
        }
        sha = kwargs["source"]["sha"]
        mode = self.mode

        class Runtime:
            def run(self):
                suite = evidence / "var/log/vm-gate/release/aweb"
                suite.mkdir(parents=True)
                (suite / "exit").write_text("1\n" if mode == "red" else "0\n")
                rebuilt = dict(files)
                if mode == "rebuild-differs":
                    rebuilt[sorted(rebuilt)[0]] = "sha256:" + "f" * 64
                (suite / "rebuilt.json").write_text(json.dumps(rebuilt))
                wheel = next(name for name in files if name.endswith(".whl"))
                held = files[wheel] if mode != "wheel-differs" else "sha256:" + "e" * 64
                run = evidence / f"tmp/aweb-candidate-gate-{sha}-20261126T000000Z-1"
                run.mkdir(parents=True)
                (run / "release-wheels.json").write_text(
                    json.dumps(
                        {
                            service: {
                                "wheel": wheel,
                                "container_wheel_sha256": held,
                                "installed_version": "1.27.55",
                            }
                            for service in ("aweb-alpha", "aweb-beta")
                        }
                    )
                )
                return {"exit": 0, "infrastructure": None, "error": None}

        return Runtime()


class Outside:
    def __init__(self, test):
        self.test = test
        self.pypi = PyPI()
        self.machine = Machine()
        self.publishing = "serve"
        self.tamper = None
        self.gates = []
        self.releases = []

    def build(self, source, out):
        release.Live().build(source, out)

    def download(self, url):
        return self.pypi.download(url)

    def gate(self, argv):
        self.gates.append(argv)
        with patch("os.geteuid", return_value=501):
            code = vm_gate_main(
                ["--config", str(self.test.config), *argv[1:]],
                factory=self.machine.factory,
                out=io.StringIO(),
            )
        if self.tamper:
            # A receipt that claims green over a check the command makes itself.
            path = Path(argv[argv.index("--receipt") + 1])
            record = json.loads(path.read_text())
            self.tamper(record)
            path.write_text(json.dumps(record))
        return code

    def github_release(self, repository, tag, files):
        self.releases.append((repository, tag, [path.name for path in files]))
        version = tag.removeprefix("server-v")
        if self.publishing == "serve":
            self.pypi.upload("aweb", version, files)
        elif self.publishing == "serve-other":
            self.pypi.upload("aweb", version, files, digest="d" * 64)

    def workflow_run(self, repository, tag):
        return WORKFLOW_RUN


class ReleaseBuild(unittest.TestCase):
    def test_each_real_build_publishes_exactly_its_staged_pair(self):
        # The real uv build, the release's own selection of the files it ships,
        # then the PyPI lane's inspection that publish_pypi runs on the assets.
        for name, directory in release.SOURCE_DIRECTORIES.items():
            with self.subTest(package=name), tempfile.TemporaryDirectory() as out:
                files = Path(out)
                release.Live().build(ROOT / directory, files)
                release.keep_shipped(files)
                version = release.tomllib.loads(
                    (ROOT / directory / "pyproject.toml").read_text()
                )["project"]["version"]
                result = subprocess.run(
                    [
                        "bash",
                        str(ROOT / "scripts/pypi-exact-publish.sh"),
                        "inspect-staged",
                        "--dist",
                        out,
                        "--package",
                        name,
                        "--version",
                        version,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout.count("STAGED: "), 2, result.stdout)


class ReleaseCommand(unittest.TestCase):
    def setUp(self):
        # The command tags as whoever runs it. Here that is a fixture identity, so
        # the tests do not depend on the host's git config: the gate's runner has none.
        identity = patch.dict(
            os.environ,
            GIT_AUTHOR_NAME="Release Fixture",
            GIT_AUTHOR_EMAIL="release-fixture@example.invalid",
            GIT_COMMITTER_NAME="Release Fixture",
            GIT_COMMITTER_EMAIL="release-fixture@example.invalid",
        )
        identity.start()
        self.addCleanup(identity.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.remote = self.tmp / "aweb.git"
        git(self.tmp, "init", "--quiet", "--bare", "-b", "main", str(self.remote))
        self.repo = self.tmp / "aweb"
        self.repo.mkdir()
        git(self.repo, "init", "--quiet", "-b", "main")
        git(self.repo, "config", "user.email", "fixture@example.invalid")
        git(self.repo, "config", "user.name", "Fixture")
        for relative, text in {
            "cli/go/go.mod": "module fixture\ngo 1.2.3\n",
            "candidate-gate/Dockerfile": "FROM python:3.12-slim\nARG GO_VERSION=1.2.3\nRUN node_22.x\nCOPY --from=ghcr.io/astral-sh/uv:0.1.2 /uv /bin/uv\n",
            "server/pyproject.toml": SERVER_PYPROJECT.replace("1.27.55", "1.27.54"),
            "server/src/aweb/__init__.py": "VERSION = '1.27.54'\n",
            "awid/pyproject.toml": AWID_PYPROJECT,
            ".gitignore": "ignored-state/\n",
        }.items():
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        git(self.repo, "add", ".")
        git(self.repo, "commit", "--quiet", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "remote", "add", "origin", str(self.remote))
        git(self.repo, "push", "--quiet", "origin", "HEAD:main")
        git(self.repo, "fetch", "--quiet", "origin")
        (self.repo / "server/pyproject.toml").write_text(SERVER_PYPROJECT)
        (self.repo / "server/src/aweb/__init__.py").write_text("VERSION = '1.27.55'\n")
        git(self.repo, "commit", "--quiet", "-am", "the fix and server 1.27.55")
        self.sha = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "push", "--quiet", "origin", "HEAD:refs/heads/release-head")
        observed = {"go": "1.2.3", "uv": "0.1.2", "node": "22", "python": "3.12"}
        manifest = self.tmp / "manifest.json"
        manifest.write_text(
            json.dumps(
                {"observed": observed, "commands": hashes(), "dpkg": "fixture=1"}
            )
        )
        self.config = self.tmp / "operator.json"
        self.config.write_text(
            json.dumps(
                {
                    "state_root": str(self.tmp / "vm-gate-state"),
                    "ledger": str(self.tmp / "vm-gate-state/ledger.tsv"),
                    "snapshot_manifest": str(manifest),
                    "token_file": str(self.tmp / "no-token"),
                    "owner": "seat",
                    "location": "location",
                    "snapshot_id": 1,
                    "merak": {
                        "manifest": str(manifest),
                        "platform": "linux/amd64",
                        "release_timeout_seconds": 9000,
                    },
                }
            )
        )
        self.outside = Outside(self)
        self.state = self.tmp / "state"

    def release(self, packages=("aweb",), state=None, deadline=0):
        return release.Release(
            self.repo,
            self.sha,
            list(packages),
            machine="merak",
            state=state or self.state,
            outside=self.outside,
            launcher="vm-gate",
            repository="awebai/aweb",
            poll_seconds=0,
            deadline_seconds=deadline,
        ).run()

    def land(self):
        git(self.repo, "push", "--quiet", "origin", f"{self.sha}:refs/heads/main")

    def receipt(self):
        return json.loads((self.state / "receipt.json").read_text())

    def test_release_gates_then_waits_for_landing_then_tags_publishes_and_checks(self):
        with self.assertRaisesRegex(
            release.ReleaseRefusal, "does not contain .*land it unchanged"
        ):
            self.release()
        state = self.receipt()
        built = state["steps"]["build"]["files"]
        self.assertEqual(
            sorted(built), ["aweb-1.27.55-py3-none-any.whl", "aweb-1.27.55.tar.gz"]
        )
        self.assertEqual(
            built,
            {path.name: sha256(path) for path in (self.state / "files").iterdir()},
        )
        gate = state["steps"]["gate"]["receipt"]
        self.assertEqual(
            (gate["project"], gate["sha"], gate["exit"]), ("aweb", self.sha, 0)
        )
        self.assertEqual(gate["files"], built)
        [argv] = self.outside.gates
        self.assertEqual(argv[argv.index("--files") + 1], str(self.state / "files"))
        self.assertIn("--intent", argv)
        self.assertNotIn("tag", state["steps"])
        self.assertIsNone(release.remote_tag(str(self.remote), "server-v1.27.55"))

        self.land()
        summary = self.release()
        self.assertIn("server-v1.27.55", summary)
        self.assertEqual(
            len(self.outside.gates), 1, "the landed commit reuses its gate"
        )
        self.assertEqual(
            release.remote_tag(str(self.remote), "server-v1.27.55"), self.sha
        )
        message = git(
            self.remote,
            "for-each-ref",
            "--format=%(contents)",
            "refs/tags/server-v1.27.55",
        )
        for name, digest in built.items():
            self.assertIn(f"{digest.removeprefix('sha256:')}  {name}", message)
        self.assertIn(f"Gated by run {gate['run_id']} on merak.", message)
        self.assertEqual(
            self.outside.releases,
            [
                (
                    "awebai/aweb",
                    "server-v1.27.55",
                    ["aweb-1.27.55-py3-none-any.whl", "aweb-1.27.55.tar.gz"],
                )
            ],
        )
        self.assertEqual(self.receipt()["steps"]["check"], {"aweb": "1.27.55"})

    def test_a_version_pypi_already_has_is_refused_before_any_build(self):
        self.outside.pypi.files[("aweb", "1.27.55")] = []
        with self.assertRaisesRegex(
            release.ReleaseRefusal, "PyPI already has aweb 1.27.55"
        ):
            self.release()
        self.assertEqual(self.outside.gates, [])
        self.assertFalse(any((self.state / "files").glob("*.whl")))

    def test_state_inside_an_ignored_directory_is_refused(self):
        state = self.tmp / "ignored-state" / "release"
        with self.assertRaisesRegex(release.ReleaseRefusal, "ignore rules"):
            self.release(state=state)
        self.assertEqual(self.outside.gates, [])

    def test_a_release_tag_at_another_commit_is_refused(self):
        git(self.repo, "tag", "-a", "server-v1.27.55", self.base, "-m", "elsewhere")
        git(self.repo, "push", "--quiet", "origin", "refs/tags/server-v1.27.55")
        self.land()
        with self.assertRaisesRegex(
            release.ReleaseRefusal, f"already identifies {self.base}"
        ):
            self.release()
        self.assertEqual(self.outside.releases, [])

    def test_a_local_tag_that_is_not_the_release_tag_is_refused_before_any_push(self):
        with self.assertRaises(release.ReleaseRefusal):
            self.release()
        checkout = self.state / "aweb"
        for make, reason in (
            (
                lambda: git(checkout, "tag", "server-v1.27.55", self.sha),
                "not an annotated tag",
            ),
            (
                lambda: git(
                    checkout,
                    "-c",
                    "user.name=f",
                    "-c",
                    "user.email=f@x",
                    "tag",
                    "-a",
                    "server-v1.27.55",
                    self.sha,
                    "-m",
                    "no files",
                ),
                "locks other files",
            ),
        ):
            with self.subTest(reason=reason):
                git(checkout, "tag", "-d", "server-v1.27.55") if git(
                    checkout, "tag", "--list", "server-v1.27.55"
                ) else None
                make()
                self.land()
                with self.assertRaisesRegex(release.ReleaseRefusal, reason):
                    self.release()
                self.assertIsNone(
                    release.remote_tag(str(self.remote), "server-v1.27.55")
                )

    def test_pypi_serving_other_digests_is_refused_naming_the_workflow_run(self):
        self.outside.publishing = "serve-other"
        self.land()
        with self.assertRaises(release.ReleaseRefusal) as refused:
            self.release()
        self.assertIn("serves", str(refused.exception))
        self.assertIn(WORKFLOW_RUN, str(refused.exception))
        self.assertNotIn("publish", self.receipt()["steps"])

    def test_pypi_never_serving_is_refused_naming_the_workflow_run(self):
        self.outside.publishing = "none"
        self.land()
        with self.assertRaisesRegex(
            release.ReleaseRefusal, "PyPI has no aweb 1.27.55 yet .*runs/1"
        ):
            self.release()

    def test_a_red_gate_is_kept_as_an_attempt_and_a_rerun_gates_again(self):
        self.outside.machine.mode = "red"
        with self.assertRaisesRegex(release.ReleaseRefusal, "the gate is red"):
            self.release()
        self.assertEqual(
            [attempt["exit"] for attempt in self.receipt()["gate_attempts"]], [1]
        )
        self.outside.machine.mode = "green"
        self.land()
        self.release()
        self.assertEqual(
            [attempt["exit"] for attempt in self.receipt()["gate_attempts"]], [1, 0]
        )

    def test_a_gate_whose_rebuild_differs_is_refused(self):
        self.outside.machine.mode = "rebuild-differs"
        with self.assertRaisesRegex(release.ReleaseRefusal, "the gate is red"):
            self.release()
        self.assertNotIn("gate", self.receipt()["steps"])

    def test_a_gate_whose_servers_held_another_wheel_is_refused(self):
        self.outside.machine.mode = "wheel-differs"
        with self.assertRaisesRegex(release.ReleaseRefusal, "the gate is red"):
            self.release()

    def test_a_green_receipt_over_another_wheel_or_rebuild_is_refused(self):
        def other_wheel(record):
            record["installed_wheels"]["aweb-beta"]["container_wheel_sha256"] = (
                "sha256:" + "e" * 64
            )

        def other_rebuild(record):
            record["rebuilt_files"] = {
                name: "sha256:" + "f" * 64 for name in record["rebuilt_files"]
            }

        for tamper, reason in (
            (other_wheel, "did not install the built wheel"),
            (other_rebuild, "rebuild of S differs"),
        ):
            with self.subTest(reason=reason):
                self.outside.tamper = tamper
                with self.assertRaisesRegex(release.ReleaseRefusal, reason):
                    self.release(state=self.tmp / reason.replace(" ", "-"))

    def test_files_changed_after_the_build_are_refused(self):
        with self.assertRaises(release.ReleaseRefusal):
            self.release()
        wheel = next((self.state / "files").glob("*.whl"))
        wheel.write_bytes(wheel.read_bytes() + b"\0")
        self.land()
        with self.assertRaisesRegex(
            release.ReleaseRefusal, "changed since they were built"
        ):
            self.release()

    def test_a_new_awid_service_is_refused_naming_what_the_gate_lacks(self):
        with self.assertRaisesRegex(
            release.ReleaseRefusal, "awid image built from that wheel.*both wheels"
        ):
            self.release(packages=("awid-service", "aweb"))
        del self.outside.pypi.files[("awid-service", "0.5.43")]
        with self.assertRaisesRegex(
            release.ReleaseRefusal, "awid-service 0.5.43 is not on PyPI"
        ):
            self.release(state=self.tmp / "state-2")
        self.assertEqual(self.outside.gates, [])


if __name__ == "__main__":
    unittest.main()
