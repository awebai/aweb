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
    def invoke(self, samples, floor=None, desktop=None):
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
            env = {k: v for k, v in os.environ.items() if k != "AWEB_GATE_MIN_FREE_GB"}
            env.update(PATH=str(root) + os.pathsep + env["PATH"],
                       PROBE_ROOT=str(root), PROBE_DOCKER_ROOT=str(root),
                       PROBE_LOG=str(root / "docker.log"),
                       PROBE_SAMPLES=str(sample_path), PROBE_SLEEPS=str(root / "sleep.log"))
            if desktop is not None:
                (root / "uname").write_text("#!/bin/sh\nprintf 'Darwin\\n'\n")
                env["HOME"] = str(root)
                env["PROBE_DOCKER_ROOT"] = "/var/lib/docker"
                data = root / ("moved Docker data" if desktop else "Library/Containers/com.docker.docker/Data/vms/0/data")
                data.mkdir(parents=True)
                (data / "Docker.raw").touch()
                env["PROBE_ROOT"] = str((data / "Docker.raw").resolve())
                if desktop:
                    settings = root / "Library/Group Containers/group.com.docker/settings-store.json"
                    settings.parent.mkdir(parents=True)
                    settings.write_text(json.dumps({"dataFolder": str(data)}))
            if floor is not None:
                env["AWEB_GATE_MIN_FREE_GB"] = str(floor)
            result = subprocess.run(["bash", str(GATE), "--wait-for-disk"],
                                    env=env, capture_output=True, text=True, timeout=5)
            log = (root / "docker.log").read_text() if (root / "docker.log").exists() else ""
            sleeps = (root / "sleep.log").read_text() if (root / "sleep.log").exists() else ""
            return result, log, sleeps

    def test_waits_once_per_minute_then_continues_at_default_floor(self):
        result, docker, sleeps = self.invoke([49 * 1024**2, 49 * 1024**2, 50 * 1024**2])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sleeps.splitlines(), ["60", "60"])
        self.assertEqual(result.stdout.count("candidate gate waiting:"), 2)
        self.assertIn("50 GiB", result.stdout)
        self.assertTrue(all(line.startswith("info") for line in docker.splitlines()), docker)

    def test_equal_floor_passes_without_wait_or_allocation(self):
        result, docker, sleeps = self.invoke([2 * 1024**2], floor=2)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sleeps, "")
        self.assertNotIn("waiting", result.stdout)
        self.assertTrue(all(line.startswith("info") for line in docker.splitlines()), docker)

    def test_invalid_floor_or_failed_measurement_refuses(self):
        for floor, samples in [("bad", [100 * 1024**2]), ("-1", [100 * 1024**2]), (50, ["unavailable"])]:
            with self.subTest(floor=floor, samples=samples):
                result, docker, sleeps = self.invoke(samples, floor=floor)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("candidate gate refused:", result.stderr)
                self.assertEqual(sleeps, "")
                self.assertTrue(all(line.startswith("info") for line in docker.splitlines()), docker)

    def test_desktop_measures_default_or_relocated_backing_filesystem(self):
        for relocated in (False, True):
            with self.subTest(relocated=relocated):
                result, docker, sleeps = self.invoke([50 * 1024**2], desktop=relocated)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(sleeps, "")
                self.assertTrue(all(line.startswith("info") for line in docker.splitlines()), docker)


if __name__ == "__main__":
    unittest.main()
