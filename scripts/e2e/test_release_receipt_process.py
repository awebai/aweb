#!/usr/bin/env python3
"""The official receipt reader, driven through a REAL subprocess.

In-process rd.main() calls do not exercise argument serialization, the
production parser, or process-boundary observer construction - the exact seam
that repeatedly disagreed with injected fixtures. These drive the shipped
script as a separate process and read its printed verdict.

The observer boundary is an explicit test transport (aweb.test-observation.v1),
refused by the driver under any externally trusted authority, because registry
observers cannot be constructed across a process boundary in a test.
"""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DRIVER = REPO_ROOT / "scripts" / "release_driver.py"
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_driver as rd  # noqa: E402
from test_release_driver import FixtureLanes, orchestration_state  # noqa: E402

# Imported only as a fixture helper. Binding the class name at module scope
# would make unittest collect its cases here too, so this module reports test
# counts that are not its own.


class ReceiptProcessTests(unittest.TestCase):
    def seed(self, root: Path, *, owes_delivery: bool, owner: str = "client"):
        # Imported inside the method: unittest collects TestCase subclasses from
        # module globals by TYPE, not by name, so binding this at module scope
        # made this file report other modules' cases as its own.
        from test_release_driver_cli import CliPathTests

        helper = CliPathTests("graph_file")
        graph_path = helper.graph_file(root)
        if owes_delivery:
            graph_path.write_text(graph_path.read_text().replace(
                f'[component."{owner}"]',
                f'[component."{owner}"]\n'
                'delivery_restart = { proof = "restart per host" }', 1))
        state = orchestration_state()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rd.main(["--graph", str(graph_path), "--store-root", str(root), "plan"],
                    providers=helper.providers_for(root, state))
        planned = json.loads(buffer.getvalue())
        graph = rd.Graph.load(graph_path)
        plan = rd.compute_plan(graph, state)
        lanes = FixtureLanes({n.component for n in plan.moving})
        rd.main(["--graph", str(graph_path), "release-run", "--allow-local-authority",
                 "--plan-id", planned["frozen_plan_id"],
                 "--plan-artifact-id", planned["plan_artifact_id"]],
                providers=helper.providers_for(root, state, lanes=lanes))
        authority = rd.FileDigestAuthority(root)
        receipt_id = next(k for k in authority.recorded_ids()
                          if k.startswith("receipt:"))
        receipt = rd.load_sealed_receipt(
            rd.FileArtifactStore(root).get(receipt_id),
            expected_digest=authority.expected_digest(receipt_id))
        observations = root / "observations.json"
        observations.write_text(json.dumps({
            "schema": "aweb.test-observation.v1",
            "entries": {
                name: {k: v for k, v in {
                    "version": e.version, "digest": e.digest, "phase": e.phase,
                    "pointer_state": e.pointer_state,
                    "delivery_proof": e.delivery_proof,
                    "delivery_outstanding": e.delivery_outstanding,
                    "digest_set": e.digest_set, "lane_ref": e.lane_ref,
                }.items() if v is not None}
                for name, e in receipt.entries.items()
            },
        }))
        return graph_path, planned, receipt_id, observations, receipt

    def read_receipt(self, root, graph_path, planned, receipt_id, observations):
        return subprocess.run(
            [sys.executable, str(DRIVER), "--graph", str(graph_path),
             "--store-root", str(root), "release-receipt",
             "--artifact-id", receipt_id,
             "--plan-id", planned["frozen_plan_id"],
             "--plan-artifact-id", planned["plan_artifact_id"],
             "--observation-file", str(observations)],
            capture_output=True, text=True, timeout=180)

    def test_a_delivered_release_matches_without_claiming_a_debt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path, planned, rid, obs, _ = self.seed(root, owes_delivery=False)
            result = self.read_receipt(root, graph_path, planned, rid, obs)
            self.assertIn("MATCH: receipt is anchored", result.stdout,
                          result.stdout + result.stderr)
            self.assertNotIn("MISMATCH", result.stdout)
            self.assertNotIn("OUTSTANDING", result.stdout)

    def test_the_pi_shape_reports_outstanding_without_a_pointer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path, planned, rid, obs, receipt = self.seed(
                root, owes_delivery=True, owner="client")
            self.assertEqual(
                receipt.entries["client"].delivery_outstanding,
                "delivery-restart-proof")
            result = self.read_receipt(root, graph_path, planned, rid, obs)
            self.assertIn("OUTSTANDING", result.stdout,
                          result.stdout + result.stderr)
            self.assertIn("client", result.stdout)

    def test_the_channel_shape_reports_outstanding_with_its_pointer(self):
        """The Channel production shape: a publishable component that BOTH
        forces a pointer and owes delivery. The pi shape (delivery, no pointer)
        is covered above; this is the one whose receipt carries a pointer node
        and a debt together."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path, planned, rid, obs, receipt = self.seed(
                root, owes_delivery=True, owner="plugin")
            self.assertEqual(
                receipt.entries["plugin"].delivery_outstanding,
                "delivery-restart-proof")
            self.assertIn("pointer", receipt.entries,
                          "the Channel shape must carry its forced pointer node")
            self.assertIsNotNone(receipt.entries["pointer"].pointer_state)
            result = self.read_receipt(root, graph_path, planned, rid, obs)
            self.assertIn("OUTSTANDING", result.stdout,
                          result.stdout + result.stderr)
            self.assertIn("plugin", result.stdout)

    def test_an_observation_that_disagrees_with_the_receipt_is_caught(self):
        """The control that the copied-from-receipt observation cannot provide.

        seed() writes the observation file FROM the receipt, so every value
        agrees by construction and no disagreement can ever be detected. This
        constructs the observation independently and mutates it, which is the
        only way to prove the reader compares two things rather than one thing
        with itself.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path, planned, rid, obs, receipt = self.seed(
                root, owes_delivery=False)
            document = json.loads(obs.read_text())
            name = sorted(document["entries"])[0]

            for label, mutate in (
                ("wrong version",
                 lambda e: e.update({"version": "9.9.9"})),
                ("wrong digest",
                 lambda e: e.update({"digest": "0" * 64})),
            ):
                with self.subTest(case=label):
                    forged = json.loads(obs.read_text())
                    mutate(forged["entries"][name])
                    path = root / f"forged-{label.replace(' ', '-')}.json"
                    path.write_text(json.dumps(forged))
                    result = self.read_receipt(
                        root, graph_path, planned, rid, path)
                    # "MATCH" is a SUBSTRING of "MISMATCH", so assertNotIn
                    # could never pass here. Assert the verdict itself.
                    self.assertIn("MISMATCH", result.stdout, result.stdout)
                    self.assertNotIn("MATCH: receipt is anchored", result.stdout)
                    self.assertNotEqual(result.returncode, 0)

    def test_a_missing_observation_is_refused(self):
        """Absent observation is not a pass."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path, planned, rid, obs, _ = self.seed(root, owes_delivery=False)
            empty = root / "empty.json"
            empty.write_text(json.dumps(
                {"schema": "aweb.test-observation.v1", "entries": {}}))
            result = self.read_receipt(root, graph_path, planned, rid, empty)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("MATCH: receipt is anchored", result.stdout)

    def test_the_test_transport_is_refused_under_a_trusted_authority(self):
        """The seam must never stand in for registry truth in a real release."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph_path, planned, rid, obs, _ = self.seed(root, owes_delivery=False)
            result = subprocess.run(
                [sys.executable, str(DRIVER), "--graph", str(graph_path),
                 "--store-root", str(root),
                 "--authority", "github-workflow-artifacts",
                 "release-receipt", "--artifact-id", rid,
                 "--plan-id", planned["frozen_plan_id"],
                 "--plan-artifact-id", planned["plan_artifact_id"],
                 "--observation-file", str(obs)],
                capture_output=True, text=True, timeout=180)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("MATCH: receipt is anchored", result.stdout)
            # The EXACT refusal, not merely a nonzero exit: missing credentials
            # or an unreachable artifact would also exit nonzero and would let
            # this pass without the guard ever running.
            self.assertIn("explicit test transport", result.stdout)
            self.assertIn("refused under", result.stdout)


if __name__ == "__main__":
    unittest.main()
