import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from vm_gate.errors import Refused
from vm_gate.native_oci import (
    validate_host,
    validate_image,
    verify_archive,
    qualify_pair,
    parse_receipt,
)

SHA = "a" * 40
IDENTITY = {
    "sha256": hashlib.sha256(b"archive").hexdigest(),
    "bytes": 7,
    "index": "sha256:" + "b" * 64,
    "source_sha": SHA,
    "version": "1.2.3",
}


def receipt(platform):
    return {
        **IDENTITY,
        "native_platform": platform,
        "native_pass": True,
        "exit": 0,
        "machine": "aarch64" if platform.endswith("arm64") else "x86_64",
        "uid": 1001,
    }


def host():
    return {
        "uid": 1000,
        "os_id": "ubuntu",
        "os_version": "24.04",
        "machine": "aarch64",
        "dpkg_architecture": "arm64",
        "docker_os": "linux",
        "docker_architecture": "aarch64",
        "docker_version": "29.9.3",
        "docker_group": True,
        "packages": {
            "docker-ce": "pinned",
            "docker-ce-cli": "pinned",
            "containerd.io": "pinned",
        },
        "commands": {"docker": {"sha256": "c" * 64, "path": "/usr/bin/docker"}},
    }


class NativeOCI(unittest.TestCase):
    def test_host_contract_refuses_uid_arch_os_and_docker_drift(self):
        expected = host()
        validate_host(expected, expected)
        for key, value in [
            ("uid", 0),
            ("machine", "x86_64"),
            ("os_version", "22.04"),
            ("docker_architecture", "x86_64"),
            ("docker_version", "wrong"),
            ("docker_group", False),
        ]:
            with self.subTest(key=key), self.assertRaises(Refused):
                changed = copy.deepcopy(expected)
                changed[key] = value
                validate_host(changed, expected)
        for key, value in [("commands", {}), ("packages", {})]:
            with self.subTest(key=key), self.assertRaises(Refused):
                changed = copy.deepcopy(expected)
                changed[key] = value
                validate_host(changed, expected)

    def test_stock_arm_image_is_not_an_x86_snapshot(self):
        image = {
            "id": 161547270,
            "status": "available",
            "architecture": "arm",
            "type": "system",
            "name": "ubuntu-24.04",
            "os_flavor": "ubuntu",
            "os_version": "24.04",
            "disk_size": 4,
        }
        validate_image(image, 80)
        for key, value in [
            ("architecture", "x86"),
            ("type", "snapshot"),
            ("os_version", "22.04"),
            ("id", 1),
        ]:
            with self.subTest(key=key), self.assertRaises(Refused):
                validate_image({**image, key: value}, 80)

    def test_archive_marker_without_completed_native_probe_is_refused(self):
        output = (
            "server image archive receipt="
            + json.dumps({**IDENTITY, "native_platform": "linux/arm64"})
            + "\n"
        )
        with self.assertRaises(Refused):
            parse_receipt(output, SHA, "linux/arm64", 0)
        output += (
            "server image linux/arm64 PASS: "
            + repr({"uid": 1001, "machine": "aarch64", "version": "1.2.3"})
            + "\n"
        )
        self.assertTrue(parse_receipt(output, SHA, "linux/arm64", 0)["native_pass"])
        with self.assertRaises(Refused):
            parse_receipt(output, SHA, "linux/arm64", 1)
        with self.assertRaises(Refused):
            parse_receipt(output, "f" * 40, "linux/arm64", 0)

    def test_archive_missing_corrupt_symlink_and_size_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "server.oci.tar"
            with self.assertRaises(Refused):
                verify_archive(p, IDENTITY)
            p.write_bytes(b"archive")
            verify_archive(p, IDENTITY)
            with self.assertRaises(Refused):
                verify_archive(p, {**IDENTITY, "bytes": 8})
            p.write_bytes(b"corrupt")
            with self.assertRaises(Refused):
                verify_archive(p, IDENTITY)
            p.unlink()
            p.symlink_to(Path(d) / "target")
            p.resolve().write_bytes(b"archive")
            with self.assertRaises(Refused):
                verify_archive(p, IDENTITY)

    def test_both_native_receipts_same_archive_source_version_index_required(self):
        a, b = receipt("linux/amd64"), receipt("linux/arm64")
        self.assertEqual(qualify_pair(a, b)["source_sha"], SHA)
        for key, value in [
            ("sha256", "d" * 64),
            ("index", "sha256:" + "e" * 64),
            ("source_sha", "f" * 40),
            ("version", "other"),
            ("native_platform", "linux/amd64"),
            ("native_pass", False),
            ("uid", 0),
            ("exit", 1),
        ]:
            with self.subTest(key=key), self.assertRaises(Refused):
                qualify_pair(a, {**b, key: value})
        with self.assertRaises(Refused):
            qualify_pair(a, None)


if __name__ == "__main__":
    unittest.main()
