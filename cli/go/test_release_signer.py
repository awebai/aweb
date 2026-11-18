"""Signer refusals must end with safe operator recovery before device access."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SIGNER = Path(__file__).resolve().parent / "sign_release_statement.py"
RECOVERY = (
    "Stop and ask sign-verify or Antares to review this error before retrying. "
    "Do not guess PINs, regenerate keys or change device configuration."
)


def signer_command():
    # Exercise the documented command when installed, and local guards without
    # the optional SDK on ordinary build hosts. Neither path needs a device.
    ykman = shutil.which("ykman")
    return (
        [ykman, "script", "--force", "--", str(SIGNER)]
        if ykman
        else [sys.executable, str(SIGNER)]
    )


class ReleaseSignerFailureTest(unittest.TestCase):
    def test_local_preflight_failures_stop_for_review_before_device_use(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            statement = root / "release-statement.txt"
            public = root / "public.pem"
            signature = root / "signature"
            canonical = (
                "aw-release-statement-v1\nversion=0.0.0-rc.1\n"
                f"source_commit={'a' * 40}\nmanifest_sha256={'b' * 64}\n"
            )
            for case in (
                "missing statement",
                "invalid statement",
                "missing public key",
                "existing signature",
            ):
                with self.subTest(case=case):
                    statement.unlink(missing_ok=True)
                    public.unlink(missing_ok=True)
                    signature.unlink(missing_ok=True)
                    if case != "missing statement":
                        statement.write_text(
                            "invalid" if case == "invalid statement" else canonical
                        )
                    if case == "existing signature":
                        public.write_bytes(
                            b"preflight must stop before SDK/public-key parsing"
                        )
                        signature.write_bytes(b"preserve existing output")
                    result = subprocess.run(
                        [
                            *signer_command(),
                            "--serial",
                            "123456",
                            "--public-key",
                            str(public),
                            "--statement",
                            str(statement),
                            "--signature",
                            str(signature),
                        ],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn(RECOVERY, result.stderr)
                    self.assertIn(str(statement), result.stderr)
                    self.assertIn("123456", result.stderr)
                    self.assertIn("PIV slot 9c", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertNotIn("Touch this YubiKey", result.stdout)
                    self.assertNotIn("PIV PIN", result.stdout)
                    if case == "existing signature":
                        self.assertEqual(
                            signature.read_bytes(), b"preserve existing output"
                        )
                    else:
                        self.assertFalse(signature.exists())

    def test_invalid_arguments_also_stop_for_review(self):
        result = subprocess.run(
            [*signer_command(), "--serial", "invalid"], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(RECOVERY, result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
