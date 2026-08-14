"""The failure-preserving stop report and B5 (aben R5, design section 8).

The original refusal stays primary; probe failures render as UNAVAILABLE
rows; exit is nonzero regardless of what reporting does - mutation-tested
with an edge refusal and an independent probe failure injected in one
run, both visible. B5 loads dev2's recorded fixture verbatim and the
table renders the historically true world: three present, two absent.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_status as rs  # noqa: E402
import release_status_report as rsr  # noqa: E402

FIXTURE = (
    REPO_ROOT
    / "scripts"
    / "e2e"
    / "fixtures"
    / "aben-column-b"
    / "b5-false-publication-status.json"
)


class StopReport(unittest.TestCase):
    def test_original_refusal_is_primary_and_exit_nonzero(self) -> None:
        report = rsr.stop_report(
            refusal="REFUSE: floor 0.5.15 is not release 0.5.16",
            rows=[rs.Row(fact="a", state="observed-present", evidence="e")],
        )
        self.assertTrue(report.text.startswith("REFUSE: floor"))
        self.assertNotEqual(report.exit_code, 0)

    def test_two_injected_failures_both_visible(self) -> None:
        # The design's mutation test: an edge refusal AND an independent
        # probe failure in one run - the caller receives both.
        def failing_probe():
            raise OSError("registry probe timed out")

        report = rsr.stop_report_with_probes(
            refusal="REFUSE: publish edge failed",
            probe=failing_probe,
        )
        self.assertIn("REFUSE: publish edge failed", report.text)
        self.assertIn("UNAVAILABLE", report.text)
        self.assertIn("timed out", report.text)
        self.assertNotEqual(report.exit_code, 0)

    def test_reporting_exception_never_replaces_the_diagnostic(self) -> None:
        def exploding_probe():
            raise RuntimeError("reporter bug")

        report = rsr.stop_report_with_probes(
            refusal="REFUSE: the load-bearing refusal",
            probe=exploding_probe,
        )
        self.assertTrue(report.text.startswith("REFUSE: the load-bearing refusal"))
        self.assertNotEqual(report.exit_code, 0)


class B5(unittest.TestCase):
    def test_b5_fixture_renders_the_historically_true_world(self) -> None:
        rows = rsr.rows_from_recorded_observations(json.loads(FIXTURE.read_text()))
        by_state = {}
        for row in rows:
            by_state.setdefault(row.state, []).append(row.fact)
        self.assertEqual(len(by_state.get("observed-present", [])), 3)
        self.assertEqual(len(by_state.get("observed-absent", [])), 2)
        joined = " ".join(by_state["observed-present"])
        self.assertIn("@awebai/aw", joined)
        self.assertIn("awid", joined)
        self.assertIn("a2a-gateway", joined)
        absent = " ".join(by_state["observed-absent"])
        self.assertIn("awid-service", absent)
        self.assertIn("aweb", absent)
        # The false packet is unwritable: the table IS the status.
        self.assertFalse(rs.done(rows))


if __name__ == "__main__":
    unittest.main()
