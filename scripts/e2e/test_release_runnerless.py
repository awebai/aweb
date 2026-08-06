#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release_driver as rd


class Adapter:
    def __init__(self, *, hosting="complete"):
        self.hosting = hosting
        self.stage_calls = 0
        self.published = None

    def stage(self, node, output, source_sha):
        self.stage_calls += 1
        (output / f"{node.component}-{node.version}.pkg").write_bytes(b"built-once")

    def publish(self, node, stage, files):
        self.published = {name: (stage / name).read_bytes() for name in files}
        return {"hosting": self.hosting, "continuation": "tag-and-release"}

    def observe(self, node, stage, files):
        return dict(files)


class RunnerlessTests(unittest.TestCase):
    def node(self):
        return rd.PlanNode(component="server", reason="changed", version="1.2.3")

    def test_local_stage_builds_once_and_records_exact_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Adapter()
            lane = rd.LocalRunnerlessLane("server", Path(tmp), adapter, "a" * 40)
            first = lane.stage(self.node())
            second = lane.stage(self.node())
            self.assertEqual(adapter.stage_calls, 1)
            self.assertEqual(first, second)
            self.assertEqual(first.digest, rd.canonical_digest_of_set(first.digest_set))

    def test_publish_consumes_the_exact_staged_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Adapter()
            lane = rd.LocalRunnerlessLane("server", Path(tmp), adapter, "a" * 40)
            staged = lane.stage(self.node())
            published = lane.publish(self.node(), staged)
            self.assertEqual(adapter.published, {"server-1.2.3.pkg": b"built-once"})
            self.assertEqual(published.digest_set, staged.digest_set)

    def test_runnerless_mode_requires_one_explicit_risk_authorization(self):
        with self.assertRaisesRegex(rd.ReceiptError, "risk authorization"):
            rd.runnerless_risk_approval(None, defer_g5=False)
        approval = rd.runnerless_risk_approval(
            "juan,2026-08-06T12:00:00Z,GitHub unavailable", defer_g5=True)
        self.assertTrue(approval.g5_deferred)
        self.assertIn("GitHub unavailable", approval.risk)
        graph = rd.Graph.from_dict({
            "component": {"server": {
                "source_paths": ["server/"],
                "version_source": {"type": "pyproject", "path": "x"},
                "tag_format": "server-v{version}",
                "verify": {"command": "true"},
            }},
            "edge": [],
        })
        plan = rd.Plan(moving=[self.node()], runtime_contract_edges=[])
        sealed, digest = rd.seal_receipt(
            plan, graph, source_sha="a" * 40,
            entries={"server": rd.ReceiptEntry(
                version="1.2.3", digest="d", phase="verified")},
            approvals={"runnerless-local-authority": approval},
        )
        receipt = rd.load_sealed_receipt(sealed, expected_digest=digest)
        risk = dict(receipt.approvals)["runnerless-local-authority"]
        self.assertEqual(risk["risk"], "GitHub unavailable")
        self.assertTrue(risk["g5_deferred"])

    def test_local_measurement_resolves_without_g5_deferral(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            edge = rd.RuntimeContractEdge(
                a="server", b="server", journey="federation",
                artifacts={"a": "pypi:aweb", "b": "pypi:aweb"},
                direction="both",
                supported={"set": "measured:local", "record": {}},
            )
            body = rd.canonical_json_bytes({
                "edge": {"a": "server", "b": "server"},
                "journey": "federation",
                "artifacts": edge.artifacts,
                "direction": "both",
                "supported_versions": {"server": ["1.26.35"]},
            })
            digest = __import__("hashlib").sha256(body).hexdigest()
            artifact_id = "measurement:local"
            store.put(artifact_id, body)
            authority.record(artifact_id, digest)
            resolver = rd.AnchoredMeasurementAuthority(
                store=store, authority=authority,
                accepted_authorities=("local-development",),
            )
            record = {
                "authority": "local-development",
                "artifact_id": artifact_id,
                "digest": digest,
            }
            self.assertEqual(
                resolver.resolve(record, edge)["supported_versions"],
                {"server": ["1.26.35"]},
            )

    def test_ship_gate_status_is_informational_and_never_blocks(self):
        with mock.patch.object(rd.subprocess, "run", side_effect=OSError("offline")):
            self.assertEqual(rd.ship_gate_warning("a" * 40)["status"], "unknown")
        completed = mock.Mock(returncode=0, stdout='[{"conclusion":"failure","url":"u"}]', stderr="")
        with mock.patch.object(rd.subprocess, "run", return_value=completed):
            self.assertEqual(rd.ship_gate_warning("a" * 40)["status"], "failure")

    def test_registry_success_can_defer_tag_release_as_resumable_continuation(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Adapter(hosting="deferred")
            lane = rd.LocalRunnerlessLane("server", Path(tmp), adapter, "a" * 40)
            staged = lane.stage(self.node())
            published = lane.publish(self.node(), staged)
            self.assertEqual(published.phase, "published")
            self.assertEqual(lane.receipt_metadata()["server"]["status"], "deferred")
            self.assertEqual(lane.receipt_metadata()["server"]["continuation"], "tag-and-release")


if __name__ == "__main__":
    unittest.main()
