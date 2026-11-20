import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vm_gate.errors import Refused
from vm_gate.merak import endpoint
from vm_gate import merak_host


class MerakTests(unittest.TestCase):
    def test_requires_content_addressed_images(self):
        with self.assertRaises(Refused):
            endpoint({"merak": {"base_sha256": "latest"}})
        base = "a" * 64
        launcher = "sha256:" + "b" * 64
        self.assertEqual(
            endpoint({"merak": {"base_sha256": base, "launcher_image_id": launcher}}),
            ("merak", base, launcher),
        )

    def test_cleanup_requires_owned_directory_and_checks_removed_id(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(merak_host, "ROOT", Path(tmp)),
        ):
            run = "vm-" + "a" * 32
            job = Path(tmp) / "runs" / run
            job.mkdir(parents=True)
            (job / "owner").write_text("other")
            with self.assertRaises(ValueError):
                merak_host.remove_guest(job)
            (job / "owner").write_text(run)
            with patch.object(
                merak_host, "docker", side_effect=["abcd", "", "", "abcd"]
            ):
                with self.assertRaises(RuntimeError):
                    merak_host.remove_guest(job)
            self.assertTrue(job.is_dir())
            with patch.object(merak_host, "docker", side_effect=["abcd", "", "", "", "", ""]):
                receipt = merak_host.remove_guest(job)
            self.assertTrue(receipt["exact_ids_absent"])
            self.assertEqual(receipt["container_ids"], ["abcd"])
            self.assertFalse(job.exists())
