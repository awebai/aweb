import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from vm_gate.errors import Infrastructure
from vm_gate.evidence import collect_archive

SHA = "a" * 40


class EvidenceTests(unittest.TestCase):
    def archive(self, files):
        memory = io.BytesIO()
        with tarfile.open(fileobj=memory, mode="w:gz") as t:
            for name, data in files.items():
                data = data.encode()
                item = tarfile.TarInfo(name)
                item.size = len(data)
                t.addfile(item, io.BytesIO(data))
        path = Path(self.tmp.name) / "evidence.tar.gz"
        path.write_bytes(memory.getvalue())
        return path

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_nested_fixture_pass_cannot_override_actual_sha_failure(self):
        main = f"tmp/aweb-candidate-gate-{SHA}-run/summary.tsv"
        other = "tmp/aweb-candidate-gate-" + ("b" * 40) + "-nested/summary.tsv"
        archive = self.archive(
            {
                main: (
                    "unit/test-server\tFAILED\ttest-egress/test-server/suite.log\t22s\texit 2\n"
                    "unit\tFAILED\tunit.log\t23s\t900s\n"
                ),
                other: "unit\tPASSED\tunit.log\t0s\t900s\n",
            }
        )
        result = collect_archive(archive, SHA, Path(self.tmp.name) / "unpacked")
        self.assertEqual(
            result["stages"],
            [{"stage": "unit", "status": "FAILED", "seconds": 23.0, "summary": main}],
        )
        self.assertTrue((Path(self.tmp.name) / "unpacked" / other).exists())
        self.assertEqual(
            result["targets"],
            [
                {
                    "stage": "unit",
                    "target": "test-server",
                    "status": "FAILED",
                    "seconds": 22.0,
                    "summary": main,
                    "log": "test-egress/test-server/suite.log",
                    "detail": "exit 2",
                }
            ],
        )

    def test_the_run_budget_and_a_stopped_stage_reach_the_summary(self):
        run = f"tmp/aweb-candidate-gate-{SHA}-run"
        archive = self.archive(
            {
                run + "/summary.tsv": (
                    "checks/test-shipping\tFAILED\tchecks.log\t40s\texit 2\n"
                    "checks\tFAILED\tchecks.log\t41s\t\n"
                    "unit\tSTOPPED\t-\t42s\tafter checks FAILED\n"
                ),
                run + "/budget.tsv": (
                    "cpus\t5.37\nmemory_mib\t22618\nsource\tcpus=input,memory=input\n"
                    "builder_cpu_shares\t9576\n"
                    "lane_cpu_shares\tchecks\t1333\nlane_share\tchecks\t0.5\n"
                    "lane_cpu_shares\tunit\t9576\nlane_share\tunit\t4.21\n"
                ),
                "tmp/aweb-candidate-gate-" + "b" * 40 + "-x/budget.tsv": "cpus\t1\n",
            }
        )
        result = collect_archive(archive, SHA, Path(self.tmp.name) / "out")
        self.assertEqual(
            result["budget"],
            {
                "cpus": 5.37,
                "memory_mib": 22618,
                "source": "cpus=input,memory=input",
                "builder_cpu_shares": 9576,
                "lane_cpu_shares": {"checks": 1333, "unit": 9576},
                "lane_share": {"checks": 0.5, "unit": 4.21},
            },
        )
        stopped = [row for row in result["stages"] if row["stage"] == "unit"]
        self.assertEqual(stopped[0]["status"], "STOPPED")
        self.assertEqual(stopped[0]["seconds"], 42.0)

    def test_reused_stage_is_explicit_with_no_fabricated_duration(self):
        output = f"gate: tree {'b' * 40} already passed checks; original log /retained/checks.log\n"
        archive = self.archive({"var/log/vm-gate/gate-output.log": output})
        result = collect_archive(archive, SHA, Path(self.tmp.name) / "out")
        self.assertEqual(result["stages"][0]["status"], "REUSED")
        self.assertIsNone(result["stages"][0]["seconds"])
        self.assertEqual(result["stages"][0]["original_log"], "/retained/checks.log")

    def test_archive_cannot_write_outside_evidence_directory(self):
        archive = self.archive({"../escaped": "wrong"})
        with self.assertRaisesRegex(Infrastructure, "unsafe archive"):
            collect_archive(archive, SHA, Path(self.tmp.name) / "out")
        self.assertFalse((Path(self.tmp.name) / "escaped").exists())

    def test_summary_preserves_child_exit_beside_conservative_interruption(self):
        receipt = {"raw_exit": 143, "child_exit": 0, "signal": 15, "interrupted": True}
        archive = self.archive(
            {"var/log/vm-gate/supervisor-receipt.json": json.dumps(receipt)}
        )
        result = collect_archive(archive, SHA, Path(self.tmp.name) / "out")
        self.assertEqual(result["supervision"], receipt)

    def test_memory_uses_concurrent_current_sum_not_sum_of_individual_highwaters(self):
        samples = [
            {
                "meminfo_kib": {"MemTotal": 100, "MemAvailable": 50},
                "containers": [
                    {"memory.current": "10", "memory.peak": "100"},
                    {"memory.current": "20", "memory.peak": "200"},
                ],
            },
            {
                "meminfo_kib": {"MemTotal": 100, "MemAvailable": 40},
                "containers": [
                    {"memory.current": "5", "memory.peak": "100"},
                    {"memory.current": "35", "memory.peak": "200"},
                ],
            },
        ]
        archive = self.archive(
            {"var/log/vm-gate/memory.jsonl": "\n".join(json.dumps(s) for s in samples)}
        )
        result = collect_archive(archive, SHA, Path(self.tmp.name) / "out")
        self.assertEqual(
            result["memory"]["concurrent_cgroup_current_peak_sum_bytes"], 40
        )
        self.assertEqual(result["memory"]["host_sampled_used_peak_bytes"], 60 * 1024)

    def test_incomplete_last_memory_line_does_not_discard_completed_stage_evidence(
        self,
    ):
        memory = (
            json.dumps(
                {
                    "meminfo_kib": {"MemTotal": 100, "MemAvailable": 40},
                    "containers": [{"memory.current": "12"}],
                }
            )
            + '\n{"time":'
        )
        archive = self.archive(
            {
                f"tmp/aweb-candidate-gate-{SHA}/summary.tsv": "checks\tPASSED\tchecks.log\t1s\n",
                f"tmp/aweb-candidate-gate-{SHA}/checks.log": "completed checks\n",
                "var/log/vm-gate/memory.jsonl": memory,
            }
        )
        result = collect_archive(archive, SHA, Path(self.tmp.name) / "out")
        self.assertEqual(result["stages"][0]["status"], "PASSED")
        self.assertEqual(
            result["memory"]["concurrent_cgroup_current_peak_sum_bytes"], 12
        )
        self.assertEqual(result["memory"]["host_sample_errors"], 1)
        self.assertIsNone(result["memory"]["sample_completeness"][1]["expected"])


if __name__ == "__main__":
    unittest.main()
