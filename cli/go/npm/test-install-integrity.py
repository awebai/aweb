"""Real shell/npm process regressions for the install boundary (no binary execution)."""

import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import io
import os
import pwd
import shutil
import ssl
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import threading
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


class ReleaseInstallerProcessTest(unittest.TestCase):
    def setUp(self):
        self.sandbox = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.sandbox.chmod(0o755)
        self.home = self.sandbox / "home"
        self.home.mkdir()
        self.bin = self.home / ".local/bin"
        self.bin.mkdir(parents=True)
        self.tools = self.sandbox / "tools"
        self.tools.mkdir()
        self.tools.chmod(0o755)
        # GNU tar invokes gzip through PATH when extracting the release archive.
        for tool in (
            "awk", "cat", "chmod", "cp", "curl", "grep", "head", "mktemp",
            "mkdir", "mv", "rm", "sed", "tar", "gzip", "tr", "uname", "basename", "shasum", "sha256sum",
            "codesign", "openssl",
        ):
            if executable := shutil.which(tool):
                (self.tools / tool).symlink_to(executable)
        self.installer = self.sandbox / "install.sh"
        self.installer.write_bytes((ROOT / "install.sh").read_bytes())
        self.installer.chmod(0o644)
        self.credentials = {}
        if os.geteuid() == 0:
            nobody = pwd.getpwnam("nobody")
            self.credentials = {
                "user": nobody.pw_uid, "group": nobody.pw_gid, "extra_groups": [],
            }
            for path in (self.home, self.bin.parent, self.bin):
                os.chown(path, nobody.pw_uid, nobody.pw_gid)
        elif os.access("/usr/local/bin", os.W_OK):
            self.fail("Run the installer test as a user who cannot write /usr/local/bin.")

        release_root = self.sandbox / "release"
        self.assets = release_root / "v1.0.0"
        self.assets.mkdir(parents=True)
        self.cert = self.sandbox / "cert.pem"
        key = self.sandbox / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
             "-subj", "/CN=localhost", "-keyout", key, "-out", self.cert],
            check=True, capture_output=True,
        )
        self.cert.chmod(0o644)

        class ReleaseFiles(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(release_root), **kwargs)

            def log_message(self, *_args):
                pass

        server = self.enterContext(ThreadingHTTPServer(("127.0.0.1", 0), ReleaseFiles))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        self.base_url = f"https://localhost:{server.server_port}"

    def install(self, **extra_env):
        environment = {
            "HOME": str(self.home),
            "PATH": f"{self.bin}:{self.tools}",
            "AW_VERSION": "v1.0.0",
            "AW_RELEASE_BASE_URL": self.base_url,
            "CURL_CA_BUNDLE": str(self.cert),
            "AW_NO_UPDATE_CHECK": "1",
            **extra_env,
        }
        return subprocess.run(
            ["/bin/bash", str(self.installer)], cwd=self.sandbox,
            env=environment, stdin=subprocess.DEVNULL, capture_output=True,
            text=True, timeout=150, **self.credentials,
        )

    def create_archive(self):
        system = {"Darwin": "darwin", "Linux": "linux", "FreeBSD": "freebsd"}[
            os.uname().sysname
        ]
        machine = os.uname().machine
        arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}[machine]
        archive = self.assets / f"aw_1.0.0_{system}_{arch}.tar.gz"
        content = Path(shutil.which("true")).read_bytes()
        with tarfile.open(archive, "w:gz") as tar:
            entry = tarfile.TarInfo("aw")
            entry.size = len(content)
            entry.mode = 0o755
            tar.addfile(entry, io.BytesIO(content))
        (self.assets / "checksums.txt").write_text(
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
        )
        return archive

    def test_headless_install_without_python_warns_and_uses_checksum(self):
        self.create_archive()
        (self.assets / "release-manifest.json").write_text("{}")
        (self.assets / "release-manifest.sig").write_text("{}")
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("publisher signature was not verified", result.stderr)
        self.assertIn("Checksum verified", result.stdout)
        self.assertTrue((self.bin / "aw").is_file())

    def test_unsigned_release_still_installs_with_checksum(self):
        self.create_archive()
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("The release has no signed manifest", result.stderr)
        self.assertIn("Checksum verified", result.stdout)
        self.assertTrue((self.bin / "aw").is_file())

    def test_incomplete_signing_pair_still_refuses_without_python(self):
        self.create_archive()
        for name in ("release-manifest.sig", "release-manifest.json"):
            with self.subTest(present=name):
                asset = self.assets / name
                asset.write_text("{}")
                result = self.install()
                asset.unlink()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("Retry the installer to fetch the complete release", result.stderr)
                self.assertFalse((self.bin / "aw").exists())

    def test_invalid_signing_pair_with_verifier_refuses(self):
        self.create_archive()
        (self.assets / "release-manifest.json").write_text("{}")
        (self.assets / "release-manifest.sig").write_text(
            '{"key_id":"untrusted","signature":"","statement":""}'
        )
        (self.tools / "python3").symlink_to(sys.executable)
        result = self.install()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("release signing key is not pinned or signature is malformed", result.stderr)
        self.assertFalse((self.bin / "aw").exists())

    def test_checksum_failure_does_not_trigger_source_fallback(self):
        archive = self.create_archive()
        archive.write_bytes(b"modified after checksums were published")
        result = self.install()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"Digest mismatch for {archive.name}", result.stderr)
        self.assertNotIn("No release archive", result.stderr)
        self.assertFalse((self.bin / "aw").exists())

    def test_missing_archive_builds_the_requested_tag(self):
        for tool in ("git", "go"):
            executable = shutil.which(tool)
            self.assertIsNotNone(executable, f"Install {tool} to run the tagged-source test.")
            (self.tools / tool).symlink_to(executable)
        repo = self.sandbox / "source"
        repo.mkdir()
        package = repo / "cmd/aw"
        package.mkdir(parents=True)
        (repo / "go.mod").write_text("module github.com/awebai/aw\n\ngo 1.20\n")

        def git(*args):
            subprocess.run(
                ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", *args],
                cwd=repo, check=True, capture_output=True,
            )

        def commit(text):
            (package / "main.go").write_text(f'package main\nfunc main() {{ println("{text}") }}\n')
            git("add", ".")
            git("commit", "-qm", text)

        git("init", "-q")
        commit("tagged-release")
        git("tag", "v1.0.0")
        commit("untagged-main")
        (self.assets / "checksums.txt").write_text("0" * 64 + "  another-platform.tar.gz\n")
        result = self.install(
            GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", CGO_ENABLED="0",
            GIT_CONFIG_COUNT="2", GIT_CONFIG_KEY_0=f"url.{repo.as_uri()}.insteadOf",
            GIT_CONFIG_VALUE_0="https://github.com/awebai/aw.git",
            GIT_CONFIG_KEY_1="safe.directory", GIT_CONFIG_VALUE_1=str(repo),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No release archive", result.stderr)
        built = subprocess.run([self.bin / "aw"], check=True, capture_output=True, text=True)
        self.assertEqual(built.stderr.strip(), "tagged-release")


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
