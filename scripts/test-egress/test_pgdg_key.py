"""The isolated image installs its PGDG key even when the key host is down."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def pgdg_key_step():
    # Execute the image's actual key setup, stopping before apt repository I/O.
    logical = (HERE / "Dockerfile").read_text().replace("\\\n", " ")
    step = next(line[4:] for line in logical.splitlines()
                if line.startswith("RUN ") and "/etc/apt/keyrings/pgdg.gpg" in line)
    setup, separator, _ = step.partition("&& echo")
    if not separator:
        raise AssertionError("cannot isolate key setup from apt repository configuration")
    return setup.strip()


class PgdgKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A short path also works with gpg-agent's Unix socket length limit.
        cls.gpg_home = tempfile.TemporaryDirectory(prefix="pgdg-test-", dir="/tmp")
        cls.addClassCleanup(cls.gpg_home.cleanup)
        cls.addClassCleanup(subprocess.run,
                            ["gpgconf", "--homedir", cls.gpg_home.name, "--kill", "gpg-agent"],
                            check=True, capture_output=True)
        subprocess.run(["gpg", "--no-options", "--homedir", cls.gpg_home.name, "--batch",
                        "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
                        "Wrong repository test key <test@example.invalid>", "ed25519", "sign", "0"],
                       check=True, capture_output=True)
        cls.wrong_key = subprocess.check_output(
            ["gpg", "--no-options", "--homedir", cls.gpg_home.name, "--batch", "--armor", "--export"])

    def test_image_key_setup_succeeds_when_curl_fails_with_18(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            marker = directory / "curl-called"
            curl = directory / "curl"
            curl.write_text("#!/bin/sh\n: > \"$CURL_CALLED\"\n"
                            "echo 'simulated curl (18): HTTP/2 stream failure' >&2\nexit 18\n")
            curl.chmod(0o755)
            keyring = directory / "pgdg.gpg"
            command = pgdg_key_step().replace("/src", shlex.quote(str(ROOT)))
            command = command.replace("/etc/apt/keyrings/pgdg.gpg", shlex.quote(str(keyring)))
            environment = {**os.environ, "PATH": str(directory) + os.pathsep + os.environ["PATH"],
                           "CURL_CALLED": str(marker), "GNUPGHOME": self.gpg_home.name,
                           "LC_ALL": "C"}
            result = subprocess.run(["bash", "-c", command], env=environment,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists(), "image key setup attempted a network fetch")
            self.assertTrue(keyring.is_file())
            inspected = subprocess.check_output(
                ["gpg", "--no-options", "--homedir", self.gpg_home.name, "--batch", "--with-colons",
                 "--show-keys", str(keyring)], text=True)
            self.assertIn("fpr:::::::::B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8:", inspected)

    def assert_key_refused(self, content, diagnostic):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            key, output = directory / "key.asc", directory / "keyring.gpg"
            key.write_bytes(content)
            output.write_bytes(b"existing keyring")
            result = subprocess.run(["bash", str(HERE / "install-pgdg-key.sh"), str(key), str(output)],
                                    env={**os.environ, "LC_ALL": "C"}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(diagnostic, result.stderr)
            self.assertEqual(output.read_bytes(), b"existing keyring")

    def test_a_different_valid_key_is_refused_before_replacing_the_keyring(self):
        self.assert_key_refused(self.wrong_key, "PGDG signing key fingerprint mismatch")

    def test_appending_another_key_does_not_extend_the_apt_trust(self):
        self.assert_key_refused((HERE / "keys/ACCC4CF8.asc").read_bytes() + self.wrong_key,
                                "PGDG signing key fingerprint mismatch")

    def test_invalid_key_material_is_refused_before_replacing_the_keyring(self):
        self.assert_key_refused(b"not an OpenPGP key", "no valid OpenPGP data")


if __name__ == "__main__":
    unittest.main()
