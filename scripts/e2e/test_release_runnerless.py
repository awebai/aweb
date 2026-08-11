#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

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
            rd.runnerless_risk_approval(None)
        approval = rd.runnerless_risk_approval(
            "juan,2026-08-06T12:00:00Z,GitHub unavailable")
        self.assertIn("GitHub unavailable", approval.risk)
        # Accepting a runner outage is not accepting an unmeasured runtime
        # contract. The two arrive in the same troubled release, which is
        # exactly why one must not be recorded as the other.
        self.assertFalse(approval.g5_deferred)
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
        self.assertNotIn(
            "g5_deferred", risk,
            "a runner-outage record must not be sealed as G5 acceptance",
        )

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

    def test_registry_success_can_defer_tag_release_as_resumable_continuation(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Adapter(hosting="deferred")
            lane = rd.LocalRunnerlessLane("server", Path(tmp), adapter, "a" * 40)
            staged = lane.stage(self.node())
            published = lane.publish(self.node(), staged)
            self.assertEqual(published.phase, "published")
            self.assertEqual(lane.receipt_metadata()["server"]["status"], "deferred")
            self.assertEqual(lane.receipt_metadata()["server"]["continuation"], "tag-and-release")




class PointerAdapterFake:
    """Stands in for the executable that touches the other repository."""

    def __init__(self, *, drift=None):
        self.applied = None
        self.remote = {}
        self.drift = drift

    def intent(self, component, updates):
        return {"advertised": dict(updates)}

    def apply(self, component, updates, intent):
        self.applied = dict(updates)
        self.remote = dict(self.drift) if self.drift is not None else dict(updates)
        return {"ref": "commit-sha"}

    def read(self, component):
        return {"advertised": dict(self.remote)}


class PointerLaneThroughRunPlanTests(unittest.TestCase):
    """Drive run_plan with a REAL PointerLane.

    The lane tests below use a fake adapter, and the fake lane in
    test_release_driver returns the staged entry unchanged - so they agreed with
    the implementation instead of with run_plan's contract, and every one passed
    while a real pointer release could not publish at all.
    """

    def graph(self):
        return rd.Graph.from_dict({
            "component": {
                "client": {
                    "source_paths": ["client/"],
                    "version_source": {"type": "manifest", "path": "v"},
                    "tag_format": "client-v{version}",
                    "publish_lane": {"workflow": "wf/client.yml"},
                    "verify": {"command": "true"},
                },
                "pointer": {"publishable": False},
            },
            "edge": [{"type": "pointer", "from": "client", "to": ["pointer"]}],
        })

    def test_a_real_pointer_lane_publishes_and_seals(self):
        import sys as _sys, pathlib as _pathlib
        _sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent))
        from test_release_driver import (
            FixtureLanes, FixtureSkew, FixtureAuthority, SOURCE_SHA,
        )

        graph = self.graph()
        state = rd.FixtureState(
            changed_components={"client": True}, versions={"client": "1.1.0"},
            published_versions={"client": "1.0.0"},
        )
        plan = rd.compute_plan(graph, state)
        self.assertIn("pointer", {n.component for n in plan.moving})

        adapter = PointerAdapterFake()
        pointer_lane = rd.PointerLane(
            "pointer", adapter=adapter,
            updates=rd.pointer_updates(plan, graph)["pointer"],
            repository="github.com/example/plugins",
        )
        lanes = FixtureLanes(available={"client"})
        lanes._lanes = getattr(lanes, "_lanes", {})
        combined = rd.WorkflowLanes({"client": lanes, "pointer": pointer_lane})

        rd.run_plan(
            plan, graph, combined, skew=FixtureSkew(),
            authority=FixtureAuthority(),
            providers=rd.Providers(
                store=rd._MemoryStore(), authority=FixtureAuthority(),
            ),
            source_sha=SOURCE_SHA, approvals={}, state=state,
        )
        self.assertEqual(adapter.applied, {"client": "1.1.0"},
                         "the pointer effect must actually have been performed")


class PointerLaneTests(unittest.TestCase):
    """Publishing bytes is not delivering them: Claude Code re-resolves an npm
    plugin only when the marketplace entry advertises the new version. So the
    pointer is a real effect with a real lane, and a release that publishes the
    package and stops has not finished."""

    def node(self):
        return rd.PlanNode(component="marketplace-pointer", reason="pointer:channel")

    def lane(self, adapter):
        return rd.PointerLane(
            "marketplace-pointer",
            adapter=adapter,
            updates={"channel": "1.7.4"},
            repository="github.com/awebai/claude-plugins",
        )

    def test_stage_and_publish_agree_on_pointer_state(self):
        """run_plan requires the published entry to equal the staged one, so a
        state that changes between them refuses every pointer release - after
        the push has already landed. This asserts the contract, not the value."""
        lane = self.lane(PointerAdapterFake())
        node = self.node()
        staged = lane.stage(node)
        self.assertTrue(staged.digest)
        published = lane.publish(node, staged)
        self.assertEqual(published.pointer_state, staged.pointer_state)
        self.assertEqual(published.digest, staged.digest)

    def test_publish_applies_exactly_the_staged_intent_and_verifies(self):
        adapter = PointerAdapterFake()
        lane = self.lane(adapter)
        staged = lane.stage(self.node())
        published = lane.publish(self.node(), staged)
        self.assertEqual(adapter.applied, {"channel": "1.7.4"})
        self.assertEqual(published.pointer_state, "advertised")
        self.assertEqual(published.digest, staged.digest)
        lane.verify(self.node(), published)

    def test_a_pointer_that_did_not_land_is_refused(self):
        """The failure this lane exists to catch: the package is on the
        registry, the pointer was not updated, and nothing said so."""
        adapter = PointerAdapterFake(drift={"channel": "1.7.3"})
        lane = self.lane(adapter)
        staged = lane.stage(self.node())
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.publish(self.node(), staged)
        self.assertIn("1.7.3", str(caught.exception))

    def test_observe_reads_the_remote_not_the_intent(self):
        adapter = PointerAdapterFake(drift={"channel": "0.0.1"})
        lane = self.lane(adapter)
        staged = lane.stage(self.node())
        observed = lane.observe(self.node(), staged)
        self.assertEqual(observed.pointer_state, "stale")

    def test_a_pointer_with_nothing_to_advertise_is_refused(self):
        lane = rd.PointerLane(
            "marketplace-pointer", adapter=PointerAdapterFake(),
            updates={}, repository="github.com/awebai/claude-plugins",
        )
        with self.assertRaises(rd.ReceiptError):
            lane.stage(self.node())

if __name__ == "__main__":
    unittest.main()
