#!/usr/bin/env python3
"""Opt-in real-image controls for package_lab; requires an assigned host slot.

Pass --image SERVICE=REF for secrets, logs, folio and library, plus the exact
--source-commit. --lab-source selects a frozen old tree for sensitivity proof.
No Docker operation runs during ordinary test discovery.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = None


def docker(*args, input=None):
    return subprocess.check_output(["docker", *args], input=input, text=True).strip()


def lab_resources():
    result = set()
    for kind, args in (
        ("container", ["ps", "-a", "--format", "{{.ID}} {{.Names}}"]),
        ("network", ["network", "ls", "--format", "{{.ID}} {{.Name}}"]),
    ):
        for row in docker(*args).splitlines():
            if re.search(r" (secrets|logs)-package-", row):
                result.add((kind, row))
    return result


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
        self.before = lab_resources()

    def tearDown(self):
        remaining = lab_resources() - self.before
        for image in reversed(self.created_images):
            docker("image", "rm", image)
        self.assertFalse(remaining, "packaged lab leaked its containers or network")

    def run_lab(self, name, image):
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
            command += ["--source-commit", self.commit]
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=240,
            check=False,
            env=environment,
        )

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
