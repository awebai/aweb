import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vm_gate import memory


class MemoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.proc, self.cgroups = root / "proc", root / "cgroups"
        self.proc.mkdir()
        (self.proc / "meminfo").write_text("MemTotal: 100 kB\nMemAvailable: 40 kB\n")
        self.ids = ["a" * 64, "b" * 64]
        for n, cid in enumerate(self.ids, 100):
            p = self.proc / str(n)
            p.mkdir()
            (p / "cgroup").write_text(f"0::/docker-{cid}.scope/init\n")
            group = self.cgroups / f"docker-{cid}.scope/init"
            group.mkdir(parents=True)
            for field in memory.FIELDS:
                (group / field).write_text("10\n")
        patch = mock.patch.object(memory, "alive", True)
        patch.start()
        self.addCleanup(patch.stop)

    def command(self, args):
        if args == ["docker", "ps", "-q"]:
            return "\n".join(cid[:12] for cid in self.ids)
        cid = next(cid for cid in self.ids if cid.startswith(args[-1]))
        return json.dumps(
            [
                {
                    "Id": cid,
                    "Name": "/buildkit" if cid == self.ids[0] else "/runner",
                    "State": {"Pid": 100 + self.ids.index(cid)},
                    "Config": {"Image": "fixture", "Labels": {}},
                    "HostConfig": {"CpuShares": 5901, "NanoCpus": 0},
                }
            ]
        )

    def capture(self):
        with mock.patch.object(memory, "cmd", side_effect=self.command):
            return memory.sample(self.proc, self.cgroups)

    def test_complete_sample_keeps_denominator_and_concurrent_current_sum(self):
        sample = self.capture()
        self.assertTrue(sample["container_completeness"]["complete"])
        peak = memory.summarize_samples([sample])["concurrent_cgroup_current_peak"]
        self.assertEqual(
            (peak["bytes"], peak["memory_current_read"], peak["expected"]), (20, 2, 2)
        )
        self.assertEqual(peak["label"], "lower bound, 2 of 2 containers read")

    def test_each_containers_cpu_weight_is_recorded(self):
        # The weight docker was given and the one the kernel holds.
        for row in self.capture()["containers"]:
            self.assertEqual(row["host_config"]["CpuShares"], 5901)
            self.assertEqual(row["host_config"]["NanoCpus"], 0)
            self.assertEqual(row["cpu.weight"], "10")

    def test_persistent_missing_file_retains_pid_cgroup_filename_and_other_reads(self):
        filename = self.cgroups / f"docker-{self.ids[0]}.scope/init/memory.peak"
        filename.unlink()
        for _ in range(2):
            sample = self.capture()
            error = sample["container_errors"][0]
            self.assertEqual(error["pid"], 100)
            self.assertEqual(error["cgroup"], f"/docker-{self.ids[0]}.scope/init")
            self.assertEqual(error["filename"], str(filename))
            self.assertEqual(error["type"], "FileNotFoundError")
            self.assertEqual(sample["containers"][0]["memory.current"], "10")
            self.assertEqual(sample["container_completeness"]["fully_read"], 1)
            self.assertFalse(sample["container_completeness"]["complete"])

    def test_missing_current_is_explicit_lower_bound_without_dropping_other_fields(
        self,
    ):
        (self.cgroups / f"docker-{self.ids[0]}.scope/init/memory.current").unlink()
        sample = self.capture()
        result = memory.summarize_samples([sample])
        self.assertIn("cpu.stat", sample["containers"][0])
        self.assertEqual(
            result["concurrent_cgroup_current_peak"]["label"],
            "lower bound, 1 of 2 containers read",
        )
        self.assertEqual(result["concurrent_cgroup_current_peak_sum_bytes"], 10)
        self.assertFalse(result["sample_completeness"][0]["complete"])

    def test_proc_failure_retains_known_pid_and_actual_proc_filename(self):
        (self.proc / "100/cgroup").unlink()
        error = self.capture()["container_errors"][0]
        self.assertEqual(error["pid"], 100)
        self.assertIsNone(error["cgroup"])
        self.assertEqual(error["filename"], str(self.proc / "100/cgroup"))

    def test_missing_unified_cgroup_retains_proc_context_and_next_container(self):
        filename = self.proc / "100/cgroup"
        filename.write_text("1:memory:/docker/fixture\n")
        sample = self.capture()
        error = sample["container_errors"][0]
        self.assertEqual(error["pid"], 100)
        self.assertEqual(error["filename"], str(filename))
        self.assertEqual(error["type"], "StopIteration")
        self.assertEqual(sample["containers"][1]["memory.current"], "10")
        self.assertFalse(sample["container_completeness"]["complete"])

    def test_unavailable_inventory_is_not_zero_containers_or_zero_memory(self):
        with mock.patch.object(
            memory, "cmd", side_effect=subprocess.CalledProcessError(1, "docker")
        ):
            sample = memory.sample(self.proc, self.cgroups)
        receipt = memory.summarize_samples([sample])
        self.assertIsNone(receipt["sample_completeness"][0]["expected"])
        self.assertFalse(receipt["sample_completeness"][0]["complete"])
        self.assertIsNone(receipt["concurrent_cgroup_current_peak_sum_bytes"])

    def test_recorded_error_id_is_not_double_counted_with_a_partial_full_id_row(self):
        sample = {
            "containers": [{"id": self.ids[0], "memory.current": "12"}],
            "container_errors": [{"id": self.ids[0][:12], "type": "FileNotFoundError"}],
        }
        coverage = memory.completeness(sample)
        self.assertEqual(coverage["expected"], 1)
        self.assertFalse(coverage["complete"])


if __name__ == "__main__":
    unittest.main()
