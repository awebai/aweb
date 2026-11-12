import copy
import unittest
from vm_gate.errors import Refused
from vm_gate.native_host import validate_profile, preparation_program


def profile():
    return {
        "profile": "native-arm64-oci-v1",
        "apt": {
            "uri": "https://download.docker.com/linux/ubuntu",
            "suite": "noble",
            "component": "stable",
            "architecture": "arm64",
            "key_primary_fingerprint": "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
            "key_sha256": "a" * 64,
            "packages": {
                name: {
                    "Package": name,
                    "Version": "5:29.9.3-1~ubuntu.24.04~noble"
                    if name != "containerd.io"
                    else "2.4.2-4~ubuntu.24.04~noble",
                    "Architecture": "arm64",
                    "Filename": "dists/noble/pool/stable/arm64/" + name + ".deb",
                    "SHA256": "b" * 64,
                }
                for name in ["docker-ce", "docker-ce-cli", "containerd.io"]
            },
        },
    }


class Profile(unittest.TestCase):
    def test_distinct_profile_has_no_snapshot_fallback(self):
        p = profile()
        validate_profile(p)
        for key, value in [
            ("profile", "snapshot"),
            ("uri", "http://untrusted.invalid"),
            ("architecture", "amd64"),
            ("key_primary_fingerprint", "F" * 40),
        ]:
            q = copy.deepcopy(p)
            if key == "profile":
                q[key] = value
            else:
                q["apt"][key] = value
            with self.subTest(key=key), self.assertRaises(Refused):
                validate_profile(q)

    def test_payload_and_package_identity_are_required(self):
        for key, value in [
            ("SHA256", "bad"),
            ("Architecture", "amd64"),
            ("Filename", "../../bad.deb"),
            ("Version", "evil;command"),
        ]:
            q = profile()
            q["apt"]["packages"]["docker-ce"][key] = value
            with self.subTest(key=key), self.assertRaises(Refused):
                validate_profile(q)

    def test_preparation_checks_os_before_install_and_pins_payloads(self):
        program = preparation_program(profile())
        self.assertLess(program.index("uname -m"), program.index("apt-get update"))
        self.assertIn("sha256sum -c", program)
        self.assertIn("apt-cache show", program)
        self.assertIn("getent passwd 1000", program)
        self.assertIn("gpg --show-keys", program)
        self.assertNotIn("qemu", program)
        self.assertNotIn("safe.directory", program)


if __name__ == "__main__":
    unittest.main()
