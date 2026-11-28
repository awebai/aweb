import ipaddress
import json
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


class FakeDocker:
    """The docker CLI over labelled containers, volumes and networks."""

    def __init__(
        self, containers, *, volumes=None, networks=None, sticky=(), unlabel=False
    ):
        self.containers = dict(containers)
        self.volumes = dict(volumes or {})
        self.networks = dict(networks or {})
        self.sticky = set(sticky)
        # A sticky container that loses its label still exists under its id.
        self.unlabel = unlabel

    @staticmethod
    def matching(resources, args):
        if "--filter" not in args:
            return list(resources)
        selector = args[args.index("--filter") + 1].removeprefix("label=")
        return [name for name, label in resources.items() if label == selector]

    def __call__(self, *args):
        if args[:2] == ("ps", "-aq"):
            return "\n".join(self.matching(self.containers, args))
        if args[0] == "rm":
            if args[-1] not in self.sticky:
                self.containers.pop(args[-1], None)
            elif self.unlabel:
                self.containers[args[-1]] = ""
            return ""
        if args[:2] == ("volume", "ls"):
            return "\n".join(self.matching(self.volumes, args))
        if args[:2] == ("network", "ls"):
            return "\n".join(self.matching(self.networks, args))
        if args[:2] == ("network", "rm"):
            self.networks.pop(args[2])
            return ""
        raise AssertionError(f"unexpected docker call: {args}")


class MerakTests(unittest.TestCase):
    def test_installed_egress_helper_matches_federation_ipv4_ranges(self):
        # The frozen federation egress vector, not the prose that describes it.
        vector = json.loads(
            (
                Path(__file__).resolve().parents[3]
                / "docs/vectors/egress-address-v1.json"
            ).read_text()
        )
        ranges = {ipaddress.IPv4Network(cidr) for cidr in vector["denied_ipv4"]}
        self.assertNotIn(DEPRECATED_6TO4_RELAY, ranges)
        installed = {
            ipaddress.IPv4Network(cidr.strip())
            for cidr in merak_egress.NON_PUBLIC.split(",")
        }
        self.assertEqual(installed, ranges | {DEPRECATED_6TO4_RELAY})
        # Every IPv4 address the vector says federation must refuse is dropped.
        denied = [
            address
            for address in map(ipaddress.ip_address, vector["public_denied"])
            if address.version == 4
        ]
        self.assertTrue(denied)
        for address in denied:
            self.assertTrue(
                any(address in network for network in installed), str(address)
            )

    def test_the_guest_gets_every_cpu_and_the_memory_the_host_spares(self):
        for cpus, memory_mib in [
            (4, 16384),
            (10, 32768),
            (12, 63488),
            (16, 65536),
            (64, 262144),
        ]:
            with self.subTest(cpus=cpus, memory_mib=memory_mib):
                guest_cpus, guest_memory = merak_host.guest_size(cpus, memory_mib)
                self.assertEqual(guest_cpus, cpus)
                spared = memory_mib - guest_memory - merak_host.QEMU_OVERHEAD_MIB
                self.assertGreaterEqual(spared, max(memory_mib // 8, 2048))
                self.assertLess(spared, max(memory_mib // 8, 2048) + 1)
        for cpus, memory_mib in [(0, 65536), (4, 4096), (4.0, 65536)]:
            with self.subTest(cpus=cpus, memory_mib=memory_mib):
                with self.assertRaises(ValueError):
                    merak_host.guest_size(cpus, memory_mib)

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
            label = f"{merak_host.LABEL}={run}"

            # Containers that survive "rm" model a daemon that did not remove them.
            # While anything of the run remains, its firewall rules and its
            # directory stay.
            for unlabel in (False, True):
                docker = FakeDocker({"abcd": label}, sticky={"abcd"}, unlabel=unlabel)
                with (
                    self.subTest(unlabel=unlabel),
                    patch.object(merak_host, "docker", docker),
                    patch.object(merak_host, "firewall") as firewall,
                    self.assertRaisesRegex(RuntimeError, "container still present"),
                ):
                    merak_host.remove_guest(job)
                firewall.assert_not_called()
                self.assertTrue(job.is_dir())
            with (
                patch.object(
                    merak_host,
                    "docker",
                    FakeDocker({"abcd": label}, volumes={"v": label}),
                ),
                patch.object(merak_host, "firewall") as firewall,
                self.assertRaisesRegex(RuntimeError, "volumes or networks remain"),
            ):
                merak_host.remove_guest(job)
            firewall.assert_not_called()
            self.assertTrue(job.is_dir())
            docker = FakeDocker(
                {"abcd": label, "unrelated": f"{merak_host.LABEL}=vm-{'b' * 32}"},
                networks={"network": label},
            )
            with (
                patch.object(merak_host, "docker", docker),
                patch.object(
                    merak_host, "firewall", return_value={"present": False}
                ) as firewall,
            ):
                receipt = merak_host.remove_guest(job)
            firewall.assert_called_once_with("remove", run)
            self.assertEqual(receipt["removed_network_ids"], ["network"])
            self.assertTrue(receipt["exact_ids_absent"])
            self.assertEqual(receipt["container_ids"], ["abcd"])
            self.assertEqual(set(docker.containers), {"unrelated"})
            self.assertEqual(docker.networks, {})
            self.assertFalse(job.exists())
