"""The release files helper and the federation journey's release-wheel mode."""

import hashlib
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import release_files  # noqa: E402


def write(directory: Path, *names: str) -> None:
    for name in names:
        (directory / name).write_bytes(f"bytes of {name}\n".encode())


class ReleaseFiles(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.dist = Path(temporary.name)

    def test_one_wheel_and_sdist_per_package_is_listed_with_prefixed_digests(self):
        write(self.dist, "aweb-1.27.55-py3-none-any.whl", "aweb-1.27.55.tar.gz")
        listed = release_files.digests(self.dist)
        expected = "sha256:" + hashlib.sha256(b"bytes of aweb-1.27.55.tar.gz\n").hexdigest()
        self.assertEqual(listed["aweb-1.27.55.tar.gz"], expected)
        self.assertEqual(set(listed), {"aweb-1.27.55-py3-none-any.whl", "aweb-1.27.55.tar.gz"})

    def test_a_file_no_release_builds_is_refused(self):
        write(self.dist, "aweb-1.27.55-py3-none-any.whl", "aweb-1.27.55.tar.gz", ".gitignore")
        with self.assertRaisesRegex(release_files.ReleaseFilesRefusal, "no release builds: .gitignore"):
            release_files.built_packages(self.dist)

    def test_a_wheel_without_its_sdist_is_refused(self):
        write(self.dist, "aweb-1.27.55-py3-none-any.whl")
        with self.assertRaisesRegex(release_files.ReleaseFilesRefusal, "one wheel and one sdist"):
            release_files.built_packages(self.dist)

    def test_two_versions_of_one_package_are_refused(self):
        write(
            self.dist,
            "aweb-1.27.55-py3-none-any.whl",
            "aweb-1.27.55.tar.gz",
            "aweb-1.27.56-py3-none-any.whl",
            "aweb-1.27.56.tar.gz",
        )
        with self.assertRaisesRegex(release_files.ReleaseFilesRefusal, "more than one version"):
            release_files.built_packages(self.dist)

    def test_awid_service_files_are_their_own_package(self):
        write(
            self.dist,
            "aweb-1.27.55-py3-none-any.whl",
            "aweb-1.27.55.tar.gz",
            "awid_service-0.5.44-py3-none-any.whl",
            "awid_service-0.5.44.tar.gz",
        )
        self.assertEqual(
            {name: version for name, (version, _w, _s) in release_files.built_packages(self.dist).items()},
            {"aweb": "1.27.55", "awid-service": "0.5.44"},
        )

    def test_the_listing_command_prints_sorted_digest_lines(self):
        write(self.dist, "aweb-1.27.55-py3-none-any.whl", "aweb-1.27.55.tar.gz")
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/release_files.py"), "listing", str(self.dist)],
            capture_output=True,
            text=True,
            check=True,
        )
        lines = result.stdout.splitlines()
        self.assertEqual([line.split("  ")[1] for line in lines], sorted(["aweb-1.27.55-py3-none-any.whl", "aweb-1.27.55.tar.gz"]))
        self.assertTrue(all(line.startswith("sha256:") for line in lines))


class ReleaseWheelJourney(unittest.TestCase):
    """The real driver and the real journey's input checks; only Docker is intercepted."""

    def run_driver(self, dist: Path, root: Path) -> tuple[subprocess.CompletedProcess, Path]:
        bind = root / "bind"
        bind.mkdir()
        captured = root / "compose.yml"
        docker = root / "docker"
        docker.write_text(
            "#!/bin/bash\n"
            'if [[ "$1" == compose && " $* " == *" build "* ]]; then\n'
            "  while [[ $# -gt 0 ]]; do\n"
            '    if [[ "$1" == -f ]]; then cp "$2" "$CAPTURED"; fi\n'
            "    shift\n"
            "  done\n"
            "  exit 86\n"
            "fi\n"
            "exit 0\n"
        )
        docker.chmod(0o755)
        env = dict(
            os.environ,
            PATH=str(root) + os.pathsep + os.environ["PATH"],
            CAPTURED=str(captured),
            AWEB_DOCKER_BIND_ROOT=str(bind),
            AWEB_FED_E2E_BUILD="1",
            AWEB_CANDIDATE_RELEASE_FILES=str(dist),
            CANDIDATE_LOG_DIR=str(root),
        )
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/e2e-federation-release-wheel.sh")],
            env=env,
            text=True,
            capture_output=True,
            timeout=300,
        )
        return result, captured

    def test_both_servers_build_from_the_release_server_wheel(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = root / "dist"
            dist.mkdir()
            write(dist, "aweb-1.27.55-py3-none-any.whl", "aweb-1.27.55.tar.gz")
            wheel_sha256 = hashlib.sha256(b"bytes of aweb-1.27.55-py3-none-any.whl\n").hexdigest()
            result, captured = self.run_driver(dist, root)
            self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
            compose = captured.read_text()
            with open(ROOT / "server/uv.lock", "rb") as handle:
                [mcp] = [p["version"] for p in tomllib.load(handle)["package"] if p["name"] == "mcp"]
            self.assertEqual(compose.count("AWEB_WHEEL: aweb-1.27.55-py3-none-any.whl"), 2, compose)
            self.assertEqual(compose.count(f"AWEB_WHEEL_SHA256: {wheel_sha256}"), 2, compose)
            self.assertEqual(compose.count("AWEB_VERSION: 1.27.55"), 2, compose)
            self.assertEqual(compose.count(f"MCP_VERSION: {mcp}"), 2, compose)
            self.assertNotIn("dockerfile: server/Dockerfile", compose)

    def test_release_files_with_a_stray_file_stop_before_any_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = root / "dist"
            dist.mkdir()
            write(dist, "aweb-1.27.55-py3-none-any.whl", "aweb-1.27.55.tar.gz", "notes.txt")
            result, captured = self.run_driver(dist, root)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotEqual(result.returncode, 86)
            self.assertIn("files no release builds: notes.txt", result.stderr)
            self.assertFalse(captured.exists())


if __name__ == "__main__":
    unittest.main()
