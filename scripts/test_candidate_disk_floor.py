#!/usr/bin/env python3
"""The entry-point disk wait uses read-only probes before Docker allocation."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts/candidate-docker-gate.sh"


class CandidateDiskFloorTests(unittest.TestCase):
    def invoke(
        self,
        samples,
        floor=None,
        desktop=None,
        reserve=None,
        mode="--wait-for-disk",
        release=False,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = {
                "uname": "printf 'Linux\\n'",
                "docker": 'printf "%s\\n" "$*" >> "$PROBE_LOG"; test "$1" = info || exit 91; printf "%s\\n" "$PROBE_DOCKER_ROOT"',
                "df": 'test "$1" = -Pk && test "$2" = "$PROBE_ROOT" || exit 92; value=$(head -1 "$PROBE_SAMPLES"); tail -n +2 "$PROBE_SAMPLES" > "$PROBE_SAMPLES.next"; mv "$PROBE_SAMPLES.next" "$PROBE_SAMPLES"; printf "Filesystem 1024-blocks Used Available Capacity Mounted on\\nfixture 999999999 0 %s 0%% /fixture\\n" "$value"',
                "sleep": 'printf "%s\\n" "$*" >> "$PROBE_SLEEPS"',
            }
            for name, body in commands.items():
                path = root / name
                path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
                path.chmod(0o755)
            sample_path = root / "samples"
            sample_path.write_text("".join(f"{value}\n" for value in samples))
            env = {
                k: v
                for k, v in os.environ.items()
                if k not in {"AWEB_GATE_MIN_FREE_GB", "AWEB_GATE_RESERVE_GB"}
            }
            env.update(
                PATH=str(root) + os.pathsep + env["PATH"],
                PROBE_ROOT=str(root),
                PROBE_DOCKER_ROOT=str(root),
                PROBE_LOG=str(root / "docker.log"),
                PROBE_SAMPLES=str(sample_path),
                PROBE_SLEEPS=str(root / "sleep.log"),
            )
            if desktop is not None:
                (root / "uname").write_text("#!/bin/sh\nprintf 'Darwin\\n'\n")
                env["HOME"] = str(root)
                env["PROBE_DOCKER_ROOT"] = "/var/lib/docker"
                data = root / (
                    "moved Docker data"
                    if desktop
                    else "Library/Containers/com.docker.docker/Data/vms/0/data"
                )
                data.mkdir(parents=True)
                (data / "Docker.raw").touch()
                env["PROBE_ROOT"] = str((data / "Docker.raw").resolve())
                if desktop:
                    settings = (
                        root
                        / "Library/Group Containers/group.com.docker/settings-store.json"
                    )
                    settings.parent.mkdir(parents=True)
                    settings.write_text(json.dumps({"dataFolder": str(data)}))
            if floor is not None:
                env["AWEB_GATE_MIN_FREE_GB"] = str(floor)
            if reserve is not None:
                env["AWEB_GATE_RESERVE_GB"] = str(reserve)
            command = ["bash", str(GATE), mode]
            if release:
                override = root / "override.mk"
                override.write_text(
                    "test-naapp-e2e:\n\t@echo SELF_TEST_STARTED; exit 91\n"
                )
                command = [
                    "make",
                    "-f",
                    str(ROOT / "Makefile"),
                    "-f",
                    str(override),
                    "release-candidate",
                    "TAGS=aw-v1.2.3",
                    "CLI_VERSION=1.2.3",
                    "STAGE_AW_FINAL=1",
                ]
            # Host scheduling can delay shell/make startup. The sleep-call
            # and allocation assertions below prove the no-wait boundary;
            # this timeout only guards a hung fixture subprocess.
            result = subprocess.run(
                command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=30
            )
            log = (
                (root / "docker.log").read_text()
                if (root / "docker.log").exists()
                else ""
            )
            sleeps = (
                (root / "sleep.log").read_text()
                if (root / "sleep.log").exists()
                else ""
            )
            return result, log, sleeps

    def test_one_shot_refuses_before_sleep_or_allocation(self):
        result, docker, sleeps = self.invoke([int(109.4 * 1024**2)], mode="--check-disk")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("109.4 GiB free", result.stderr)
        self.assertIn("110 GiB", result.stderr)
        self.assertEqual(sleeps, "")
        self.assertTrue(
            all(line.startswith("info") for line in docker.splitlines()), docker
        )

    def test_release_refuses_disk_before_ledger_prerequisite(self):
        result, docker, sleeps = self.invoke([int(109.4 * 1024**2)], release=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("109.4 GiB free", result.stderr)
        self.assertNotIn("SELF_TEST_STARTED", result.stdout)
        self.assertEqual(sleeps, "")
        self.assertTrue(
            all(line.startswith("info") for line in docker.splitlines()), docker
        )

    def test_start_floor_reserves_one_gate_footprint(self):
        # A parallel gate peaked at 53 GB (vm-3f1940bd). Starting with 70 or
        # 109 GiB would cross the 50 GiB critical line: require its reserve too.
        result, docker, sleeps = self.invoke([70 * 1024**2, 109 * 1024**2, 110 * 1024**2])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sleeps.splitlines(), ["60", "60"])
        self.assertTrue(
            all(line.startswith("info") for line in docker.splitlines()), docker
        )

    def test_waits_once_per_minute_then_continues_at_default_floor(self):
        result, docker, sleeps = self.invoke([109 * 1024**2, 109 * 1024**2, 110 * 1024**2])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sleeps.splitlines(), ["60", "60"])
        self.assertEqual(result.stdout.count("candidate gate waiting:"), 2)
        self.assertIn("110 GiB (50 critical + 60 gate reserve)", result.stdout)
        self.assertTrue(
            all(line.startswith("info") for line in docker.splitlines()), docker
        )

    def test_equal_floor_passes_without_wait_or_allocation(self):
        result, docker, sleeps = self.invoke([110 * 1024**2])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sleeps, "")
        self.assertNotIn("waiting", result.stdout)
        self.assertTrue(
            all(line.startswith("info") for line in docker.splitlines()), docker
        )

    def test_invalid_floor_or_failed_measurement_refuses(self):
        for floor, samples in [
            ("bad", [100 * 1024**2]),
            ("-1", [100 * 1024**2]),
            (50, ["unavailable"]),
        ]:
            with self.subTest(floor=floor, samples=samples):
                result, docker, sleeps = self.invoke(samples, floor=floor)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("candidate gate refused:", result.stderr)
                self.assertEqual(sleeps, "")
                self.assertTrue(
                    all(line.startswith("info") for line in docker.splitlines()), docker
                )

    def test_an_override_raises_the_floor_and_never_lowers_it(self):
        result, _, sleeps = self.invoke([119 * 1024**2, 120 * 1024**2], reserve=70)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sleeps.splitlines(), ["60"])
        self.assertIn("120 GiB (50 critical + 70 gate reserve)", result.stdout)
        for floor, reserve, name in ((20, None, "AWEB_GATE_MIN_FREE_GB"), (None, 30, "AWEB_GATE_RESERVE_GB")):
            with self.subTest(floor=floor, reserve=reserve):
                result, docker, sleeps = self.invoke([500 * 1024**2], floor=floor, reserve=reserve)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(name, result.stderr)
                self.assertIn("would lower", result.stderr)
                self.assertEqual(docker, "")
                self.assertEqual(sleeps, "")
        for invalid in ("bad", "-1"):
            result, docker, _ = self.invoke([100 * 1024**2], reserve=invalid)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("AWEB_GATE_RESERVE_GB", result.stderr)
            self.assertEqual(docker, "")

    def test_desktop_measures_default_or_relocated_backing_filesystem(self):
        for relocated in (False, True):
            with self.subTest(relocated=relocated):
                result, docker, sleeps = self.invoke([110 * 1024**2], desktop=relocated)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(sleeps, "")
                self.assertTrue(
                    all(line.startswith("info") for line in docker.splitlines()), docker
                )


if __name__ == "__main__":
    unittest.main()
