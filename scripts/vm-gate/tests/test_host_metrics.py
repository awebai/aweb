import tempfile
import unittest
from pathlib import Path

from vm_gate.host_metrics import capture


class HostMetricsTests(unittest.TestCase):
    def test_records_cpu_identity_counters_and_pressure_without_inference(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "cpuinfo").write_text(
                "processor: 0\nmodel name: fixture CPU\n\nprocessor: 1\nmodel name: fixture CPU\n"
            )
            (proc / "stat").write_text("cpu  10 2 3 40 5 6 7 8 9 1\ncpu0 1 2 3\n")
            (proc / "pressure").mkdir()
            for name in ("cpu", "io"):
                (proc / "pressure" / name).write_text("some avg10=1.00 total=42\n")
            before = capture(proc)
            self.assertEqual(before["status"], "complete")
            self.assertEqual(before["cpu_models"], [{"model name": "fixture CPU"}])
            self.assertEqual(before["cpu_ticks"]["steal"], 8)
            self.assertEqual(before["cpu_ticks"]["iowait"], 5)
            self.assertIn("total=42", before["pressure"]["io"])
            (proc / "stat").write_text("cpu  20 2 3 40 4 6 7 12 9 1\n")
            after = capture(proc)
            self.assertEqual(after["cpu_ticks"]["iowait"], 4)
            self.assertEqual(after["cpu_ticks"]["steal"], 12)

    def test_missing_metrics_remain_unknown_not_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            result = capture(Path(directory))
        self.assertEqual(result["status"], "partial")
        self.assertNotIn("cpu_ticks", result)
        self.assertEqual(result["errors"]["stat"]["errno"], 2)
        self.assertIsNone(result["pressure"]["cpu"])


if __name__ == "__main__":
    unittest.main()
