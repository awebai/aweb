"""Real shell/npm process regressions for the install boundary (no binary execution)."""

import hashlib
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class InstallChecksumTest(unittest.TestCase):
    def shell(self, commands, *, environment=None):
        source = (ROOT / "install.sh").read_text().rsplit('main "$@"', 1)[0]
        return subprocess.run(
            ["/bin/bash", "-c", source + "\n" + commands],
            env=environment,
            capture_output=True,
            text=True,
        )

    def test_missing_and_mismatch_refuse_with_filename_and_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "aw_1.0.0_linux_amd64.tar.gz"
            artifact.write_bytes(b"original archive")
            checksums = Path(tmp) / "checksums.txt"
            for content in ("", "0" * 64 + "  " + artifact.name + "\n"):
                checksums.write_text(content)
                result = self.shell(f'verify_checksum "{artifact}" "{checksums}"')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(artifact.name, result.stdout + result.stderr)
                self.assertIn("Retry the installer", result.stdout + result.stderr)

    def test_exact_digest_passes_but_duplicate_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "aw_1.0.0_linux_amd64.tar.gz"
            artifact.write_bytes(b"archive")
            checksums = Path(tmp) / "checksums.txt"
            line = (
                hashlib.sha256(artifact.read_bytes()).hexdigest()
                + "  "
                + artifact.name
                + "\n"
            )
            checksums.write_text(line)
            self.assertEqual(
                self.shell(f'verify_checksum "{artifact}" "{checksums}"').returncode, 0
            )
            checksums.write_text(line + line)
            self.assertNotEqual(
                self.shell(f'verify_checksum "{artifact}" "{checksums}"').returncode, 0
            )

    def test_checksum_trailing_fields_are_refused_even_beside_a_valid_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "aw_1.0.0_linux_amd64.tar.gz"
            artifact.write_bytes(b"archive")
            checksum = hashlib.sha256(artifact.read_bytes()).hexdigest()
            checksums = Path(tmp) / "checksums.txt"
            for content in (
                f"{checksum}  {artifact.name} garbage\n",
                f"{checksum}  {artifact.name}\n{checksum}  {artifact.name} garbage\n",
            ):
                checksums.write_text(content)
                result = self.shell(f'verify_checksum "{artifact}" "{checksums}"')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(artifact.name, result.stdout + result.stderr)
                self.assertIn("Retry the installer", result.stdout + result.stderr)

    def test_extraction_refusal_names_archive_and_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for extension in ("tar.gz", "zip"):
                artifact = directory / ("aw_1.0.0_linux_amd64." + extension)
                artifact.write_bytes(b"not an archive")
                result = self.shell(
                    f'extract_release_binary "{artifact}" "{directory / "aw"}"'
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"Cannot extract {artifact.name}", result.stderr)
                self.assertIn("retry the installer", result.stderr.lower())

    def test_missing_unzip_has_file_specific_install_instruction(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            artifact = directory / "aw_1.0.0_windows_amd64.zip"
            artifact.write_bytes(b"archive")
            result = self.shell(
                f'extract_release_binary "{artifact}" "{directory / "aw.exe"}"',
                environment={**os.environ, "PATH": str(directory)},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(artifact.name, result.stderr)
            self.assertIn("Install unzip and retry the installer.", result.stderr)

    def test_staging_refusal_preserves_existing_file_and_has_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            candidate, blocker = (
                directory / "candidate",
                directory / "blocked-directory",
            )
            candidate.write_bytes(b"verified candidate")
            blocker.write_bytes(b"existing file")
            destination = blocker / "aw"
            result = self.shell(
                f'stage_verified_binary "{candidate}" "{destination}" "aw_1.0.0_linux_amd64.tar.gz"'
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(str(destination), result.stderr)
            self.assertIn("aw_1.0.0_linux_amd64.tar.gz", result.stderr)
            self.assertIn(
                "Check destination directory permissions and retry the installer.",
                result.stderr,
            )
            self.assertEqual(blocker.read_bytes(), b"existing file")

    def test_staging_replaces_only_the_serving_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            candidate, serving = directory / "candidate", directory / "aw"
            candidate.write_bytes(b"verified candidate")
            serving.write_bytes(b"old executable")
            result = self.shell(
                f'stage_verified_binary "{candidate}" "{serving}" "aw_1.0.0_linux_amd64.tar.gz"'
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(serving.read_bytes(), b"verified candidate")
            self.assertEqual(list(directory.glob(".aw-install.*")), [])


class NpmInstallerTest(unittest.TestCase):
    def test_failed_verified_fetch_refuses_without_replacing_launcher(self):
        node = shutil.which("node")
        self.assertIsNotNone(node)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bin").mkdir()
            launcher = root / "bin/aw"
            launcher.write_text("original launcher")
            (root / "platform.js").write_bytes(
                (ROOT / "npm/aw/platform.js").read_bytes()
            )
            (root / "package.json").write_text('{"version":"1.0.0"}')
            (root / "install.js").write_bytes((ROOT / "npm/aw/install.js").read_bytes())
            result = subprocess.run(
                [node, str(root / "install.js")],
                env={**os.environ, "PATH": tmp},
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Retry: npm install @awebai/aw --force", result.stderr)
            self.assertEqual(launcher.read_text(), "original launcher")
            self.assertFalse(list(root.glob("*.tgz")))

    def test_optional_platform_package_installs_original_bytes(self):
        node = shutil.which("node")
        key = subprocess.check_output(
            [node, "-p", 'process.platform+" "+require("os").arch()'], text=True
        ).strip()
        platform, arch = key.split()
        if platform == "win32":
            self.skipTest("Unix hardlink installer")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bin").mkdir()
            launcher = root / "bin/aw"
            launcher.write_text("original launcher")
            native = (
                root
                / "node_modules/@awebai"
                / ("aw-" + platform + "-" + arch)
                / "bin/aw"
            )
            native.parent.mkdir(parents=True)
            native.write_bytes(b"exact verified package bytes")
            native.chmod(0o755)
            (root / "platform.js").write_bytes(
                (ROOT / "npm/aw/platform.js").read_bytes()
            )
            (root / "package.json").write_text('{"version":"1.0.0"}')
            (root / "install.js").write_bytes((ROOT / "npm/aw/install.js").read_bytes())
            result = subprocess.run(
                [node, str(root / "install.js")],
                env={**os.environ, "npm_config_user_agent": "npm/test"},
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(launcher.read_bytes(), native.read_bytes())


if __name__ == "__main__":
    unittest.main()
