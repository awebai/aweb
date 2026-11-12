#!/usr/bin/env python3
"""Opt-in real-image controls for package_lab; requires an assigned host slot.

Pass --image SERVICE=REF for secrets, logs, folio and library, plus the exact
--source-commit. --lab-source selects a frozen old tree for sensitivity proof.
No Docker operation runs during ordinary test discovery.
"""

import argparse
import ast
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = None


def docker(*args, input=None):
    return subprocess.check_output(
        ["docker", *args],
        input=input,
        text=True,
        timeout=600 if args[0] == "build" else 30,
    ).strip()


def owned_resources(label):
    return {
        "containers": docker("ps", "-aq", "--filter", "label=" + label).split(),
        "networks": docker("network", "ls", "-q", "--filter", "label=" + label).split(),
    }


def clean_owned(label):
    """Creation-time labels bind ownership even if the creator dies mid-call."""
    errors = []
    owned = owned_resources(label)
    for kind, identifiers in owned.items():  # containers before networks
        for identifier in identifiers:
            try:
                if kind == "containers":
                    docker("rm", "-f", "-v", identifier)
                else:
                    docker("network", "rm", identifier)
            except (subprocess.SubprocessError, OSError):
                errors.append((kind, identifier))
    remaining = owned_resources(label)
    if errors or any(remaining.values()):
        raise AssertionError(f"owned cleanup failed: {errors}; remaining={remaining}")


def docker_shim(real, label):
    # Only this run's private lab sees the shim. The actual Docker CLI handles
    # every operation; creation labels also cover the old unlabelled lab.
    # Its own container removals include anonymous PG volumes, too.
    return (
        "#!/usr/bin/env python3\nimport os,sys\na=sys.argv[1:]\n"
        + f"label={label!r}\nreal={real!r}\n"
        + "if a[:1]==['run']: a[1:1]=['--label',label]\n"
        + "elif a[:2]==['network','create']: a[2:2]=['--label',label]\n"
        + "elif a[:1]==['rm'] and '-v' not in a: a[1:1]=['-v']\n"
        + "os.execv(real,[real,*a])\n"
    )


class WrapperSource(unittest.TestCase):
    def test_private_wrapper_quotes_paths_without_a_shell(self):
        ast.parse(
            docker_shim("/path with spaces/real-docker", "aweb.package-proof=abc")
        )


class PackagedImageControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if CONFIG is None:
            raise unittest.SkipTest(
                "real images require explicit inputs and a host slot"
            )
        cls.images, cls.commit, cls.lab_source = CONFIG
        cls.base_ids = {
            name: docker("image", "inspect", "-f", "{{.Id}}", ref)
            for name, ref in cls.images.items()
        }

    def setUp(self):
        self.created_images = []
        self.runs = []

    def tearDown(self):
        errors = []
        for record in self.runs:
            try:
                clean_owned(record["label"])
            except (AssertionError, subprocess.SubprocessError, OSError) as exc:
                errors.append(str(exc))
            if record["directory"].exists():
                errors.append("private run directory remains")
        for image in reversed(self.created_images):
            try:
                docker("image", "rm", image)
            except (subprocess.SubprocessError, OSError):
                errors.append("mutant image removal failed: " + image)
        self.assertFalse(errors, errors)

    def run_lab(self, name, image, *, force_timeout=False, expected_commit=None):
        script = self.lab_source / "naapp" / name / "e2e/package_lab.py"
        command = [sys.executable, str(script), "--image", image]
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            str(self.lab_source / path)
            for path in (
                "naapp-lib/testing/src",
                "naapp-lib/src",
                "awid/src",
                "server/src",
            )
        )
        # Use the old CLI's supported interface for the actual baseline run;
        # an argparse failure must never masquerade as an identity refusal.
        help_result = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True,
            text=True,
            check=True,
            env=environment,
        )
        if "--source-commit" in help_result.stdout:
            command += [
                "--source-commit",
                self.commit if expected_commit is None else expected_commit,
            ]
        label = "aweb.package-proof=" + uuid.uuid4().hex
        real_docker = shutil.which("docker")
        self.assertIsNotNone(real_docker)
        with tempfile.TemporaryDirectory(prefix="naapp-proof-") as directory:
            root = Path(directory)
            record = {"label": label, "directory": root}
            self.runs.append(record)
            (root / "tmp").mkdir(mode=0o700)
            (root / "bin").mkdir(mode=0o700)
            shim = root / "bin/docker"
            # This executes the real Docker CLI. It only adds the ownership
            # label at CREATE, including for the frozen, previously-unlabelled lab.
            shim.write_text(docker_shim(real_docker, label))
            shim.chmod(0o700)
            environment["PATH"] = str(root / "bin") + os.pathsep + environment["PATH"]
            environment["TMPDIR"] = str(root / "tmp")
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
                start_new_session=True,
            )
            try:
                if force_timeout:
                    # A short timeout before creation would be a vacuous control.
                    # Require real containers, a network and private fixture inputs first.
                    deadline = time.monotonic() + 60
                    while True:
                        observed = owned_resources(label)
                        if (
                            len(observed["containers"]) >= 2
                            and observed["networks"]
                            and any((root / "tmp").rglob("service.env"))
                        ):
                            record["before_timeout"] = observed
                            break
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise AssertionError(
                                "timeout control never created its real fixture"
                            )
                        time.sleep(0.2)
                stdout, stderr = process.communicate(
                    timeout=0.001 if force_timeout else 240
                )
                return subprocess.CompletedProcess(
                    command, process.returncode, stdout, stderr
                )
            finally:
                try:
                    if process.poll() is None:
                        # Kill the exact session we created, including pending CLI
                        # children, before querying/removing daemon-side resources.
                        os.killpg(process.pid, signal.SIGKILL)
                        process.communicate(timeout=10)
                finally:
                    clean_owned(label)

    def test_00_forced_timeouts_remove_owned_resources_and_private_files(self):
        for name in ("secrets", "logs"):
            with self.subTest(service=name):
                with self.assertRaises(subprocess.TimeoutExpired):
                    self.run_lab(name, self.base_ids[name], force_timeout=True)
                record = self.runs[-1]
                self.assertGreaterEqual(len(record["before_timeout"]["containers"]), 2)
                self.assertTrue(record["before_timeout"]["networks"])
                self.assertFalse(any(owned_resources(record["label"]).values()))
                self.assertFalse(record["directory"].exists())

    def mutant(self, name, instruction):
        source = self.images[name]
        self.assertRegex(source, r"^[A-Za-z0-9_./:@-]+$")
        self.assertEqual(
            docker("image", "inspect", "-f", "{{.Id}}", source), self.base_ids[name]
        )
        text = (
            f"FROM {source}\nLABEL aweb.package-control={uuid.uuid4().hex}\n"
            f"{instruction}\n"
        )
        image = docker("build", "-q", "-", input=text)
        self.created_images.append(image)
        self.assertEqual(
            docker("image", "inspect", "-f", "{{.Id}}", source), self.base_ids[name]
        )
        return image

    def test_01_correct_services_check_default_user_and_served_build(self):
        for name in ("secrets", "logs"):
            with self.subTest(service=name):
                result = self.run_lab(name, self.base_ids[name])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("packaged image default USER PASS", result.stdout)
                self.assertIn("packaged served build identity PASS", result.stdout)
                self.assertIn(
                    "owned containers/network/private generated files cleaned PASS",
                    result.stdout,
                )

    def test_02_wrong_served_sha_refuses_for_both_services(self):
        wrong = "b" * 40 if self.commit != "b" * 40 else "c" * 40
        for name in ("secrets", "logs"):
            with self.subTest(service=name):
                image = self.mutant(name, f"ENV {name.upper()}_GIT_SHA={wrong}")
                result = self.run_lab(name, image)
                self.assertNotEqual(
                    result.returncode, 0, "wrong served SHA stayed green"
                )
                self.assertIn(
                    "packaged build identity mismatch", result.stdout + result.stderr
                )

    def assert_preflight_build_refusal(self, result):
        self.assertNotEqual(result.returncode, 0, "wrong image revision stayed green")
        self.assertIn("packaged build identity mismatch", result.stdout + result.stderr)
        self.assertNotIn("packaged image default USER PASS", result.stdout)

    def test_02b_wrong_revision_label_refuses_before_default_user_probe(self):
        wrong = "c" * 40 if self.commit != "c" * 40 else "d" * 40
        for name in ("secrets", "logs"):
            with self.subTest(service=name):
                # Only the label changes; the baked service GIT_SHA stays intact.
                image = self.mutant(
                    name, f"LABEL org.opencontainers.image.revision={wrong}"
                )
                self.assert_preflight_build_refusal(self.run_lab(name, image))

    def test_02c_wrong_expected_commit_refuses_an_unmodified_image(self):
        wrong = "d" * 40 if self.commit != "d" * 40 else "e" * 40
        for name in ("secrets", "logs"):
            with self.subTest(service=name):
                # Label and served SHA agree, but neither is the requested commit.
                result = self.run_lab(name, self.base_ids[name], expected_commit=wrong)
                self.assert_preflight_build_refusal(result)

    def test_03_root_and_wrong_image_users_refuse_for_both_services(self):
        for name in ("secrets", "logs"):
            for user in ("0:0", "10002:10002"):
                with self.subTest(service=name, user=user):
                    image = self.mutant(name, f"USER {user}")
                    result = self.run_lab(name, image)
                    self.assertNotEqual(
                        result.returncode, 0, "wrong image USER stayed green"
                    )
                    self.assertIn(
                        "packaged image USER mismatch", result.stdout + result.stderr
                    )

    def test_04_all_service_images_run_with_declared_numeric_user(self):
        for name, image in self.base_ids.items():
            with self.subTest(service=name):
                declared = docker("image", "inspect", "-f", "{{.Config.User}}", image)
                self.assertEqual(declared, "10001:10001")
                container = "naapp-user-control-" + uuid.uuid4().hex[:12]
                try:
                    result = docker(
                        "run",
                        "--name",
                        container,
                        "--network",
                        "none",
                        "--read-only",
                        "--entrypoint",
                        "/app/.venv/bin/python",
                        image,
                        "-I",
                        "-c",
                        "import json,os;print(json.dumps([os.geteuid(),os.getegid()]))",
                    )
                    self.assertEqual(json.loads(result), [10001, 10001])
                finally:
                    if docker("ps", "-aq", "--filter", f"name=^/{container}$"):
                        docker("rm", "-f", container)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image", action="append", required=True, metavar="SERVICE=REF"
    )
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--lab-source", type=Path, default=ROOT)
    args = parser.parse_args()
    images = dict(value.split("=", 1) for value in args.image)
    if set(images) != {"secrets", "logs", "folio", "library"}:
        parser.error("need secrets, logs, folio and library images")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("source commit must be a full lowercase SHA")
    CONFIG = images, args.source_commit, args.lab_source.resolve()
    unittest.main(argv=[sys.argv[0]])
