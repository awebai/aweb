import ipaddress
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from vm_gate.config import select_target
from vm_gate.errors import Refused
from vm_gate.merak import endpoint
from vm_gate import merak_egress, merak_host

# RFC 7526 deprecated the 6to4 relay anycast prefix. The Merak operator
# separately denies the entire prefix in addition to the federation ranges.
DEPRECATED_6TO4_RELAY = ipaddress.IPv4Network("192.88.99.0/24")


class MerakTests(unittest.TestCase):
    def test_installed_egress_helper_matches_federation_ipv4_ranges(self):
        contract = Path(__file__).resolve().parents[3] / "docs/aweb-sot.md"
        # The R3 vector exercises addresses. The governing SoT enumerates CIDRs.
        ipv4 = contract.read_text().split("An IPv4 answer is refused in ", 1)[1]
        ipv4 = ipv4.split("An IPv6 answer is admitted", 1)[0]
        ranges = {
            ipaddress.IPv4Network(cidr)
            for cidr in re.findall(r"`([0-9.]+/[0-9]+)`", ipv4)
        }
        self.assertTrue(ranges)
        self.assertNotIn(DEPRECATED_6TO4_RELAY, ranges)
        installed = {
            ipaddress.IPv4Network(cidr.strip())
            for cidr in merak_egress.NON_PUBLIC.split(",")
        }
        self.assertEqual(installed, ranges | {DEPRECATED_6TO4_RELAY})

    def test_dispatch_defaults_and_explicit_machine(self):
        config = {"default_target": "merak"}
        for args, expected in [
            (SimpleNamespace(), ("merak", None)),
            (SimpleNamespace(type="ccx43"), ("hetzner", "ccx43")),
            (SimpleNamespace(target="hetzner"), ("hetzner", "ccx33")),
        ]:
            select_target(args, config)
            self.assertEqual((args.target, args.type), expected)
        with self.assertRaises(Refused):
            select_target(SimpleNamespace(type="ccx43", target="merak"), config)

    def test_capacity_counts_allocated_overlay_and_used_host_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            job = Path(tmp)
            disk = job / "disk.qcow2"
            disk.write_bytes(b"volume" * 1024)
            with patch.object(
                Path, "read_text", return_value="MemTotal: 100 kB\nMemAvailable: 40 kB"
            ):
                metrics = merak_host.observe_guest(job, 0)
            self.assertEqual(metrics["host_used_peak_bytes"], 60 * 1024)
            self.assertEqual(
                metrics["overlay_peak_allocated_bytes"], disk.stat().st_blocks * 512
            )
            self.assertGreater(metrics["filesystem_min_free_bytes"], 0)
            self.assertEqual(metrics["sample_errors"], 0)

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
            with (
                patch.object(
                    merak_host,
                    "docker",
                    side_effect=["abcd", "", "", "", "", "network", "", ""],
                ),
                patch.object(
                    merak_host, "firewall", return_value={"present": False}
                ) as firewall,
            ):
                receipt = merak_host.remove_guest(job)
            firewall.assert_called_once_with("remove", run)
            self.assertEqual(receipt["removed_network_ids"], ["network"])
            self.assertTrue(receipt["exact_ids_absent"])
            self.assertEqual(receipt["container_ids"], ["abcd"])
            self.assertFalse(job.exists())
