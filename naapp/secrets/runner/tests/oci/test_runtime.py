"""Real installed runtime capability checks; not M7 worker/release acceptance."""

import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from aweb_secrets_runner.oci_platform import require_memory_directory


@unittest.skipUnless(os.environ.get("AWEB_SECRETS_OCI_PROOF") == "1", "explicit Linux OCI proof")
class RuntimeCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/memory")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        require_memory_directory(self.root)
        self.layout = self.root / "image"
        self.command("umoci", "init", "--layout", str(self.layout))
        self.image = str(self.layout) + ":test"
        self.command("umoci", "new", "--image", self.image)
        layer = self.root / "layer.tar"
        with tarfile.open(layer, "w") as archive:
            archive.add("/usr/bin/busybox", arcname="bin/busybox")
            for name in ("bin/env", "bin/pwd"):
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = "busybox"
                archive.addfile(info)
            info = tarfile.TarInfo("pinned-work")
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(info)
        self.command("umoci", "raw", "add-layer", "--image", self.image, str(layer))
        self.command(
            "umoci",
            "config",
            "--image",
            self.image,
            "--config.entrypoint",
            "/must-not-execute",
            "--config.cmd",
            "image-default",
            "--config.env",
            "IMAGE_DEFAULT=must-not-inherit",
            "--config.workingdir",
            "/absent",
        )

    def command(self, *args):
        return subprocess.run(
            args,
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            umask=0o077,
        )

    def run_job(self, env, args=("/bin/env",), cwd="/pinned-work"):
        bundle, state = self.root / "bundle", self.root / "state"
        self.command("umoci", "unpack", "--rootless", "--image", self.image, str(bundle))
        bundle.chmod(0o700)
        state.mkdir(mode=0o700)
        require_memory_directory(bundle)
        require_memory_directory(state)
        config_file = bundle / "config.json"
        config = json.loads(config_file.read_bytes())
        config["process"].update(args=list(args), cwd=cwd, env=env, terminal=False)
        config_file.write_text(json.dumps(config))
        config_file.chmod(0o600)
        result = subprocess.run(
            [
                "runc",
                "--root",
                str(state),
                "--rootless=true",
                "run",
                "--bundle",
                str(bundle),
                "proof",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            umask=0o077,
        )
        self.assertEqual(list(state.iterdir()), [])
        self.assertEqual(config_file.stat().st_mode & 0o777, 0o600)
        return result

    def test_explicit_nonempty_home_preserves_the_complete_environment(self):
        expected = {"HOME": "/pinned-home", "DECLARED": "non-credential-test-value"}
        result = self.run_job([f"{name}={value}" for name, value in expected.items()])
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = dict(line.split("=", 1) for line in result.stdout.decode().splitlines())
        self.assertEqual(observed, expected)

    def test_missing_home_demonstrates_unsupported_environment(self):
        result = self.run_job(["DECLARED=non-credential-test-value"])
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = dict(line.split("=", 1) for line in result.stdout.decode().splitlines())
        self.assertEqual(observed, {"DECLARED": "non-credential-test-value", "HOME": "/"})

    def test_empty_home_is_replaced_and_therefore_unsupported(self):
        result = self.run_job(["HOME=", "DECLARED=non-credential-test-value"])
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = dict(line.split("=", 1) for line in result.stdout.decode().splitlines())
        self.assertEqual(observed, {"DECLARED": "non-credential-test-value", "HOME": "/"})

    def test_pinned_working_directory_overrides_conflicting_image_default(self):
        result = self.run_job(["HOME=/pinned-home"], args=("/bin/pwd",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"/pinned-work\n")

    def test_failure_cleans_the_runtime_internal_state(self):
        result = self.run_job(["HOME=/pinned-home"], args=("/absent",))
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
