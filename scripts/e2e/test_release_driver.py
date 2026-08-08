"""Pure-logic tests for the release driver: graph validation, plan
computation with forced pointer consumers, declared-input satisfaction,
G5 declaration completeness, receipt sealing bound to an external digest,
structured approval, and lane orchestration that fails closed on
unavailable lanes. No network: state and lanes arrive through the same
provider interfaces the real driver uses, filled from fixtures.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_driver as rd

# A source SHA is a real 40-hex commit id everywhere the driver reads one: plan
# identities embed it and the repository measurement authority refuses anything
# else. Fixtures use these two so a test never asserts against a shape the
# production path would reject.
SOURCE_SHA = "3f7a1c9e4b02d85617fa03cc9b1e4d7a5806e2f1"
OTHER_SOURCE_SHA = "b28d4e6017ca395fbe7d10428af35c96d0e7b143"


def fixture_graph_dict() -> dict:
    return {
        "component": {
            "core": {
                "source_paths": ["core/"],
                "publishable": False,
            },
            "client": {
                "source_paths": ["client/"],
                "version_source": {"type": "manifest", "path": "client/version"},
                "tag_format": "client-v{version}",
                "publish_lane": {"workflow": "wf/client.yml"},
                "verify": {"command": "true"},
            },
            "plugin": {
                "source_paths": ["plugin/"],
                "version_source": {"type": "manifest", "path": "plugin/version"},
                "tag_format": "plugin-v{version}",
                "publish_lane": {"workflow": "wf/plugin.yml"},
                "verify": {"command": "true"},
            },
            "server": {
                "source_paths": ["server/"],
                "version_source": {"type": "manifest", "path": "server/version"},
                "tag_format": "server-v{version}",
                "publish_lane": {"workflow": "wf/server.yml"},
                "verify": {"command": "true"},
            },
            "cloud-pin": {
                "publishable": False,
                "credential_paths": [
                    {"env": "FIXTURE_GATE_ENV_FILE", "purpose": "migration gate"}
                ],
                "sibling_pins": [
                    {
                        "pin_file": "release-pin.toml",
                        "component": "server",
                        "checkout": "../server-src",
                        "repository": "github.com/example/server",
                    }
                ],
                "approval_required": True,
            },
            "pointer": {
                "publishable": False,
            },
        },
        "edge": [
            {"type": "bundled-build-input", "from": "core", "to": ["client", "plugin"]},
            {"type": "publication-prerequisite", "from": "client", "to": ["plugin"]},
            {"type": "pointer", "from": "plugin", "to": ["pointer"]},
            {"type": "pointer", "from": "server", "to": ["cloud-pin"]},
            {
                "type": "runtime-contract",
                "a": "client",
                "b": "server",
                "journey": "make fixture-journey",
                "artifacts": {"a": "registry:client", "b": "registry:server"},
                "direction": "both",
                "supported": {
                    "set": "measured:fixture-fleet-2026-08-01",
                    "record": {
                        "authority": "workflow-artifacts",
                        "artifact_id": "measurement:fixture-fleet-2026-08-01",
                        "digest": "fixture-digest",
                    },
                    "policy": "additive-only",
                },
            },
        ],
    }


def fixture_graph() -> rd.Graph:
    return rd.Graph.from_dict(fixture_graph_dict())


class GraphValidationTests(unittest.TestCase):
    def test_unknown_edge_type_is_refused(self) -> None:
        with self.assertRaises(rd.GraphError) as caught:
            rd.Graph.from_dict(
                {
                    "component": {"a": {"source_paths": ["a/"]}},
                    "edge": [{"type": "casual-suggestion", "from": "a", "to": ["a"]}],
                }
            )
        self.assertIn("casual-suggestion", str(caught.exception))

    def test_edge_naming_unknown_component_is_refused(self) -> None:
        for edge in (
            {"type": "publication-prerequisite", "from": "a", "to": ["ghost"]},
            {"type": "pointer", "from": "a", "to": ["ghost"]},
            {"type": "bundled-build-input", "from": "ghost", "to": ["a"]},
        ):
            with self.assertRaises(rd.GraphError) as caught:
                rd.Graph.from_dict(
                    {"component": {"a": {"source_paths": ["a/"]}}, "edge": [edge]}
                )
            self.assertIn("ghost", str(caught.exception))

    def test_sibling_pin_naming_unknown_component_is_refused(self) -> None:
        with self.assertRaises(rd.GraphError) as caught:
            rd.Graph.from_dict(
                {
                    "component": {
                        "a": {
                            "source_paths": ["a/"],
                            "sibling_pins": [
                                {
                                    "pin_file": "p.toml",
                                    "component": "ghost",
                                    "checkout": "../x",
                                }
                            ],
                        }
                    }
                }
            )
        self.assertIn("ghost", str(caught.exception))

    def test_prerequisite_cycle_is_refused(self) -> None:
        with self.assertRaises(rd.GraphError) as caught:
            rd.Graph.from_dict(
                {
                    "component": {
                        "a": {"source_paths": ["a/"]},
                        "b": {"source_paths": ["b/"]},
                    },
                    "edge": [
                        {"type": "publication-prerequisite", "from": "a", "to": ["b"]},
                        {"type": "publication-prerequisite", "from": "b", "to": ["a"]},
                    ],
                }
            )
        self.assertIn("cycle", str(caught.exception).lower())

    def test_runtime_contract_without_measured_support_is_declared_incomplete(
        self,
    ) -> None:
        """G5 forbids inventing floors: an edge whose support set is not an
        explicit measurement or an explicit approved deprecation loads, but
        carries declared_incomplete and blocks when touched."""
        data = fixture_graph_dict()
        data["edge"].append(
            {
                "type": "runtime-contract",
                "a": "plugin",
                "b": "server",
                "journey": "make other-journey",
                "artifacts": {"a": "registry:plugin", "b": "registry:server"},
                "direction": "both",
                "supported": {"policy": "additive-only"},
            }
        )
        graph = rd.Graph.from_dict(data)
        incomplete = [e for e in graph.runtime_contracts if e.declared_incomplete]
        self.assertEqual([(e.a, e.b) for e in incomplete], [("plugin", "server")])


class PlanTests(unittest.TestCase):
    def plan(self, changed: dict[str, bool], **kwargs) -> rd.Plan:
        graph = fixture_graph()
        state = rd.FixtureState(changed_components=changed, **kwargs)
        return rd.compute_plan(graph, state)

    def test_untouched_graph_plans_nothing(self) -> None:
        self.assertEqual(self.plan({}).moving, [])

    def test_plan_nodes_carry_resolved_versions(self) -> None:
        plan = self.plan({"server": True}, versions={"server": "2.1.0"})
        node = next(n for n in plan.moving if n.component == "server")
        self.assertEqual(node.version, "2.1.0")

    def test_top_level_pointer_edge_forces_consumer_after_source(self) -> None:
        """alice's counterexample: a declared pointer edge whose source moves
        must move the pointer target, ordered after the source."""
        plan = self.plan({"plugin": True, "core": False})
        order = [n.component for n in plan.moving]
        self.assertIn("pointer", order)
        self.assertLess(order.index("plugin"), order.index("pointer"))

    def test_pointer_consumer_moves_when_any_source_moves(self) -> None:
        """server -> cloud-pin is a pointer edge: server moving forces the
        pin consumer. This is the missed-AC-consumer class."""
        plan = self.plan({"server": True})
        order = [n.component for n in plan.moving]
        self.assertIn("cloud-pin", order)
        self.assertLess(order.index("server"), order.index("cloud-pin"))

    def test_bundled_input_change_is_measured_per_consumer_baseline(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={},
            bundled_changed_for={("core", "plugin"): True, ("core", "client"): False},
        )
        plan = rd.compute_plan(graph, state)
        moving = {n.component for n in plan.moving}
        self.assertIn("plugin", moving)
        self.assertNotIn("client", moving)

    def test_order_respects_publication_prerequisites(self) -> None:
        plan = self.plan({"core": True, "client": True, "plugin": True})
        order = [n.component for n in plan.moving]
        self.assertLess(order.index("client"), order.index("plugin"))

    def test_true_prerequisite_alone_does_not_drag_dependent(self) -> None:
        """client -> plugin is a prerequisite, not a pointer: client moving
        does not force an unchanged plugin, it only orders both when both move."""
        plan = self.plan({"client": True})
        self.assertNotIn("plugin", {n.component for n in plan.moving})

    def test_plan_names_touched_runtime_contract_edges(self) -> None:
        plan = self.plan({"client": True})
        touched = {(e.a, e.b) for e in plan.runtime_contract_edges}
        self.assertIn(("client", "server"), touched)


class VersionResolutionTests(unittest.TestCase):
    """Three distinct notions: current source version, latest registry-visible
    version, proposed candidate. A changed component whose source version is
    already published must fail named rather than propose a published version."""

    def test_source_ahead_of_published_becomes_the_candidate(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={"client": True},
            versions={"client": "2.1.0"},
            published_versions={"client": "2.0.9"},
        )
        plan = rd.compute_plan(graph, state)
        node = next(n for n in plan.moving if n.component == "client")
        self.assertEqual(node.version, "2.1.0")
        self.assertEqual(node.published_version, "2.0.9")
        version_problems = [
            p for p in rd.check_declared_inputs(graph, plan, state) if "version" in p
        ]
        self.assertEqual(version_problems, [])

    def test_already_published_source_version_fails_named(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={"server": True},
            versions={"server": "2.0.9"},
            published_versions={"server": "2.0.9"},
        )
        plan = rd.compute_plan(graph, state)
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertTrue(
            any("version not advanced" in p and "server" in p for p in problems),
            f"expected a named version-not-advanced failure, got {problems}",
        )

    def test_registry_behind_tag_disagreement_fails_closed(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={"server": True},
            versions={"server": "2.1.0"},
            published_versions={"server": "2.0.9"},
            tag_versions={"server": "2.1.0"},
        )
        plan = rd.compute_plan(graph, state)
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertTrue(
            any("tag" in p and "registry" in p for p in problems),
            f"a tag the registry does not confirm must fail closed, got {problems}",
        )


class PlanDigestTests(unittest.TestCase):
    def test_digest_binds_edge_declarations(self) -> None:
        """alice's counterexample: changing a floor or policy must change the
        digest — the digest binds the full canonical declarations."""
        base = fixture_graph_dict()
        graph_a = rd.Graph.from_dict(base)
        state = rd.FixtureState(changed_components={"client": True})
        digest_a = rd.plan_digest(rd.compute_plan(graph_a, state), graph_a)

        mutated = fixture_graph_dict()
        for edge in mutated["edge"]:
            if edge["type"] == "runtime-contract":
                edge["supported"] = {
                    "set": "approved-deprecation:record-1",
                    "record": {
                        "authority": "workflow-artifacts",
                        "artifact_id": "deprecation:record-1",
                        "digest": "d1",
                    },
                    "policy": "breaking-with-approved-deprecation",
                }
        graph_b = rd.Graph.from_dict(mutated)
        digest_b = rd.plan_digest(rd.compute_plan(graph_b, state), graph_b)
        self.assertNotEqual(digest_a, digest_b)

    def test_digest_is_stable(self) -> None:
        graph = fixture_graph()
        state = rd.FixtureState(changed_components={"client": True})
        a = rd.plan_digest(rd.compute_plan(graph, state), graph)
        b = rd.plan_digest(rd.compute_plan(graph, state), graph)
        self.assertEqual(a, b)


class InputSatisfactionTests(unittest.TestCase):
    def state(self, **kwargs) -> rd.FixtureState:
        return rd.FixtureState(changed_components={"server": True}, **kwargs)

    def problems(self, state: rd.FixtureState) -> list[str]:
        graph = fixture_graph()
        plan = rd.compute_plan(graph, state)
        return rd.check_declared_inputs(graph, plan, state)

    def test_missing_credential_path_fails_closed(self) -> None:
        problems = self.problems(self.state(env={}, existing_paths=set()))
        self.assertTrue(any("FIXTURE_GATE_ENV_FILE" in p for p in problems))

    def test_sibling_pin_requires_exact_checkout_sha(self) -> None:
        """Existence is not enough: the checkout HEAD must equal the pinned
        SHA — the exact abbj staging failure."""
        state = self.state(
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds", "../server-src"},
            pin_values={"release-pin.toml": "feedface"},
            checkout_heads={"../server-src": "deadbeef"},
            checkout_remotes={"../server-src": "github.com/example/server"},
        )
        problems = self.problems(state)
        self.assertTrue(
            any("feedface" in p and "deadbeef" in p for p in problems),
            f"pin/checkout SHA mismatch must be a named failure, got {problems}",
        )

    def test_sibling_pin_requires_declared_remote_identity(self) -> None:
        """A path whose HEAD happens to contain the pinned SHA object is not
        the declared repository: the checkout's remote identity must match."""
        state = self.state(
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds", "../server-src"},
            pin_values={"release-pin.toml": "feedface"},
            checkout_heads={"../server-src": "feedface"},
            checkout_remotes={"../server-src": "github.com/wrong/repo"},
        )
        problems = self.problems(state)
        self.assertTrue(
            any("remote" in p and "wrong/repo" in p for p in problems),
            f"remote identity mismatch must be a named failure, got {problems}",
        )

    def test_satisfied_inputs_including_exact_pin_pass(self) -> None:
        state = self.state(
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds", "../server-src"},
            pin_values={"release-pin.toml": "feedface"},
            checkout_heads={"../server-src": "feedface"},
            checkout_remotes={"../server-src": "github.com/example/server"},
        )
        self.assertEqual(self.problems(state), [])

    def test_touched_incomplete_runtime_contract_blocks(self) -> None:
        data = fixture_graph_dict()
        for edge in data["edge"]:
            if edge["type"] == "runtime-contract":
                edge["supported"] = {"policy": "additive-only"}
        graph = rd.Graph.from_dict(data)
        state = rd.FixtureState(changed_components={"client": True})
        plan = rd.compute_plan(graph, state)
        # The plan stays freezable and says the edge is incomplete; execution
        # is what refuses, so an operator can see what measurement is owed.
        self.assertFalse(
            [p for p in rd.check_declared_inputs(graph, plan, state)
             if "declared-incomplete" in p]
        )
        with self.assertRaises(rd.BlockedByDeclaredInputs) as caught:
            rd.require_runtime_support(plan, defer_g5=False, authorization=None)
        self.assertIn("declared-incomplete", str(caught.exception))


class ApprovalTests(unittest.TestCase):
    def test_empty_or_unstructured_approval_is_refused(self) -> None:
        graph = fixture_graph()
        plan = rd.compute_plan(graph, rd.FixtureState(changed_components={"server": True}))
        pin = next(n for n in plan.moving if n.component == "cloud-pin")
        for bad in (None, "", "juan"):
            with self.assertRaises(rd.ApprovalRequired):
                rd.require_approval(pin, approval=bad)
        rd.require_approval(pin, approval=rd.Approval(who="juan", when="2026-08-05"))


class ReceiptTests(unittest.TestCase):
    def make_plan(self) -> tuple[rd.Graph, rd.Plan]:
        graph = fixture_graph()
        plan = rd.compute_plan(
            graph, rd.FixtureState(changed_components={"client": True})
        )
        return graph, plan

    def entries_for(self, plan: rd.Plan) -> dict[str, rd.ReceiptEntry]:
        return {
            n.component: rd.ReceiptEntry(
                version=n.version or "0.0.0",
                digest=f"d-{n.component}",
                phase="verified",
                pointer_state="ok" if n.reason.startswith("pointer:") else None,
                delivery_proof=None,
            )
            for n in plan.moving
        }

    def test_seal_refuses_entry_set_mismatch(self) -> None:
        graph, plan = self.make_plan()
        with self.assertRaises(rd.ReceiptError):
            rd.seal_receipt(plan, graph, source_sha=SOURCE_SHA, entries={}, approvals={})
        extra = self.entries_for(plan)
        extra["stowaway"] = rd.ReceiptEntry(version="1.0.0", digest="dx")
        with self.assertRaises(rd.ReceiptError):
            rd.seal_receipt(plan, graph, source_sha=SOURCE_SHA, entries=extra, approvals={})

    def test_load_requires_external_expected_digest(self) -> None:
        """The seal is not self-contained: load verifies against a digest the
        caller obtained from an outside authority. Recomputing a checksum
        beside an edited body must not pass."""
        graph, plan = self.make_plan()
        sealed, digest = rd.seal_receipt(
            plan, graph, source_sha=SOURCE_SHA, entries=self.entries_for(plan), approvals={}
        )
        loaded = rd.load_sealed_receipt(sealed, expected_digest=digest)
        self.assertEqual(loaded.source_sha, SOURCE_SHA)

        import hashlib, json

        outer = json.loads(sealed)
        body = outer["body"].replace(SOURCE_SHA, OTHER_SOURCE_SHA)
        self.assertNotEqual(body, outer["body"], "the tamper changed nothing")
        forged = json.dumps(
            {"body": body, "seal": hashlib.sha256(body.encode()).hexdigest()}
        ).encode()
        with self.assertRaises(rd.ReceiptError):
            rd.load_sealed_receipt(forged, expected_digest=digest)

    def test_receipt_matches_run_compares_plan_and_source(self) -> None:
        graph, plan = self.make_plan()
        sealed, digest = rd.seal_receipt(
            plan, graph, source_sha=SOURCE_SHA, entries=self.entries_for(plan), approvals={}
        )
        receipt = rd.load_sealed_receipt(sealed, expected_digest=digest)
        ok, _ = rd.receipt_matches_run(receipt, plan, graph, source_sha=SOURCE_SHA)
        self.assertTrue(ok)
        ok, why = rd.receipt_matches_run(receipt, plan, graph, source_sha="other")
        self.assertFalse(ok)
        self.assertIn("source", why)


class FixtureLanes:
    """Records every call. Stages produce digests; publish returns what it is
    given so digest identity can be asserted by the driver."""

    def __init__(self, available: set[str]):
        self.available = available
        self.calls: list[tuple[str, str]] = []

    def has_lane(self, component: str) -> bool:
        return component in self.available

    def stage(self, node: rd.PlanNode) -> rd.ReceiptEntry:
        self.calls.append(("stage", node.component))
        return rd.ReceiptEntry(
            version=node.version or "0.0.0",
            digest=f"staged-{node.component}",
            pointer_state="pointer-ok" if node.reason.startswith("pointer:") else None,
            delivery_proof=None,
        )

    def publish(self, node: rd.PlanNode, staged: rd.ReceiptEntry) -> rd.ReceiptEntry:
        self.calls.append(("publish", node.component))
        return staged

    def verify(self, node: rd.PlanNode, published: rd.ReceiptEntry) -> None:
        self.calls.append(("verify", node.component))


class AllRecordsResolve:
    """Fixture measurement authority: every structured record resolves."""

    def resolve(self, record, edge):
        return {"digest": record.get("digest"), "edge": (edge.a, edge.b)}


class FixtureSkew:
    def __init__(self, available: bool = True):
        self.available = available
        self.executed: list[tuple[str, str]] = []

    def has_matrix(self, edge) -> bool:
        return self.available

    def execute(self, edge, staged: dict) -> None:
        self.executed.append((edge.a, edge.b))


class FixtureAuthority:
    """External authority: records digests by artifact identity at seal time
    and resolves them independently of anything the caller presents."""

    def __init__(self):
        self.recorded: dict[str, str] = {}

    def record(self, artifact_id: str, digest: str) -> None:
        self.recorded[artifact_id] = digest

    def expected_digest(self, artifact_id: str) -> str | None:
        return self.recorded.get(artifact_id)


def complete_fixture_graph() -> rd.Graph:
    """Fixture graph whose runtime contract is measured, so orchestration can
    proceed to publish in tests that are not about G5 blocking."""
    return rd.Graph.from_dict(fixture_graph_dict())


def orchestration_state(**kwargs) -> rd.FixtureState:
    defaults = dict(
        changed_components={"client": True, "plugin": True},
        versions={"client": "1.1.0", "plugin": "2.1.0"},
        published_versions={"client": "1.0.0", "plugin": "2.0.0"},
    )
    defaults.update(kwargs)
    return rd.FixtureState(**defaults)


class FourPhaseProtocolTests(unittest.TestCase):
    def run_fixture(self, lanes=None, skew=None, state=None, approvals=None):
        graph = complete_fixture_graph()
        state = state or orchestration_state()
        plan = rd.compute_plan(graph, state)
        lanes = lanes or FixtureLanes(
            available={n.component for n in plan.moving}
        )
        skew = skew or FixtureSkew()
        authority = FixtureAuthority()
        entries = rd.run_plan(
            plan,
            graph,
            lanes,
            skew=skew,
            authority=authority,
            source_sha=SOURCE_SHA,
            approvals=approvals or {},
            state=state,
            providers=rd.Providers(
                store=rd._MemoryStore(),
                authority=authority,
                measurement=AllRecordsResolve(),
            ),
        )
        return graph, plan, lanes, skew, authority, entries

    def test_every_stage_and_skew_precedes_the_first_publish(self) -> None:
        """alice's interleaving counterexample: stage a, publish a, stage b is
        forbidden. All stages bind digests, all touched skew matrices run
        against those bytes, and only then does the first publish happen."""
        graph, plan, lanes, skew, _, _ = self.run_fixture()
        kinds = [kind for kind, _ in lanes.calls]
        first_publish = kinds.index("publish")
        self.assertEqual(
            set(kinds[:first_publish]) & {"stage"},
            {"stage"},
        )
        self.assertNotIn("publish", kinds[:first_publish])
        stage_count = kinds[:first_publish].count("stage")
        self.assertEqual(
            stage_count,
            len(plan.moving),
            f"all {len(plan.moving)} stages must precede the first publish; calls={lanes.calls}",
        )
        self.assertTrue(skew.executed, "touched matrices must run before publish")

    def test_publishes_follow_plan_order_and_verify_follows_publish(self) -> None:
        _, plan, lanes, _, _, _ = self.run_fixture()
        publishes = [c for kind, c in lanes.calls if kind == "publish"]
        self.assertLess(publishes.index("client"), publishes.index("plugin"))
        kinds = [kind for kind, _ in lanes.calls]
        self.assertLess(kinds.index("publish"), kinds.index("verify"))

    def test_missing_skew_provider_blocks_before_any_lane_call(self) -> None:
        graph = complete_fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        lanes = FixtureLanes(available={n.component for n in plan.moving})
        with self.assertRaises(rd.SkewUnavailable):
            rd.run_plan(
                plan, graph, lanes,
                skew=FixtureSkew(available=False),
                authority=FixtureAuthority(),
                providers=rd.Providers(store=rd._MemoryStore(), authority=FixtureAuthority(), measurement=AllRecordsResolve()),
                source_sha=SOURCE_SHA, approvals={}, state=state,
            )
        self.assertEqual(lanes.calls, [])

    def test_missing_approval_refuses_before_any_lane_call(self) -> None:
        """alice's counterexample: with the approval-required node last, the
        first node was already published before refusal. Approvals preflight."""
        graph = complete_fixture_graph()
        state = orchestration_state(
            changed_components={"server": True, "client": True},
            versions={"server": "3.1.0", "client": "1.1.0"},
            published_versions={"server": "3.0.0", "client": "1.0.0"},
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds", "../server-src"},
            pin_values={"release-pin.toml": "feedface"},
            checkout_heads={"../server-src": "feedface"},
            checkout_remotes={"../server-src": "github.com/example/server"},
        )
        plan = rd.compute_plan(graph, state)
        lanes = FixtureLanes(available={n.component for n in plan.moving})
        with self.assertRaises(rd.ApprovalRequired):
            rd.run_plan(
                plan, graph, lanes,
                skew=FixtureSkew(), authority=FixtureAuthority(), providers=rd.Providers(store=rd._MemoryStore(), authority=FixtureAuthority(), measurement=AllRecordsResolve()),
                source_sha=SOURCE_SHA, approvals={}, state=state,
            )
        self.assertEqual(lanes.calls, [], "nothing may run before approvals check out")

    def test_published_digest_must_equal_staged_digest(self) -> None:
        class TamperingLanes(FixtureLanes):
            def publish(self, node, staged):
                self.calls.append(("publish", node.component))
                return rd.ReceiptEntry(
                    version=staged.version,
                    digest="something-else",
                    pointer_state=staged.pointer_state,
                    delivery_proof=staged.delivery_proof,
                )

        graph = complete_fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        lanes = TamperingLanes(available={n.component for n in plan.moving})
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.run_plan(
                plan, graph, lanes,
                skew=FixtureSkew(), authority=FixtureAuthority(), providers=rd.Providers(store=rd._MemoryStore(), authority=FixtureAuthority(), measurement=AllRecordsResolve()),
                source_sha=SOURCE_SHA, approvals={}, state=state,
            )
        self.assertIn("digest", str(caught.exception))

    def test_run_seals_receipt_and_records_digest_with_authority(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph = complete_fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            lanes = FixtureLanes(available={n.component for n in plan.moving})
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            entries = rd.run_plan(
                plan, graph, lanes,
                skew=FixtureSkew(), authority=authority, store=store,
                source_sha=SOURCE_SHA, approvals={}, state=state,
                providers=rd.Providers(store=store, authority=authority, measurement=AllRecordsResolve()),
            )
            self.assertEqual(set(entries), {n.component for n in plan.moving})
            kinds = {k.split(":")[0] for k in authority.recorded_ids()}
            self.assertLessEqual(
                {"plan", "staged-manifest", "transition", "receipt"},
                kinds,
                "plan, staged manifest, every transition, and the final receipt"
                " must all be anchored",
            )
            receipt_id = next(
                k for k in authority.recorded_ids() if k.startswith("receipt:")
            )
            receipt = rd.load_sealed_receipt(
                store.get(receipt_id),
                expected_digest=authority.expected_digest(receipt_id),
            )
            ok, why = rd.receipt_matches_run(receipt, plan, graph, source_sha=SOURCE_SHA)
            self.assertTrue(ok, why)
            self.assertTrue(receipt.frozen_plan_id)
            self.assertTrue(receipt.staged_manifest_id)
            self.assertTrue(
                all(e.phase == "verified" for e in receipt.entries.values())
            )

    def test_publish_failure_leaves_anchored_transitions(self) -> None:
        """Per-transition anchoring IS the durable partial state: a failure
        after the first publish leaves that transition anchored, with no
        reliance on exception handling for crash consistency."""
        import tempfile

        class FailingSecondPublish(FixtureLanes):
            def publish(self, node, staged):
                if len([c for k, c in self.calls if k == "publish"]) == 1:
                    raise RuntimeError("registry outage mid-run")
                return super().publish(node, staged)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph = complete_fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            lanes = FailingSecondPublish(
                available={n.component for n in plan.moving}
            )
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            with self.assertRaises(RuntimeError):
                rd.run_plan(
                    plan, graph, lanes,
                    skew=FixtureSkew(), authority=authority, store=store,
                    source_sha=SOURCE_SHA, approvals={}, state=state,
                    providers=rd.Providers(
                        store=store, authority=authority,
                        measurement=AllRecordsResolve(),
                    ),
                )
            transitions = [
                k
                for k in authority.recorded_ids()
                if k.startswith("transition:") and ":published:" in k
            ]
            self.assertEqual(
                len(transitions),
                1,
                "the successful first publish must be durably anchored",
            )


class ResumeTests(unittest.TestCase):
    def test_frozen_plan_resumes_without_replanning(self) -> None:
        """G4: after a partial publish, live registry state has moved; a rerun
        takes the frozen plan artifact and never recomputes from live state."""
        graph = complete_fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        frozen_bytes, frozen_id = rd.freeze_plan(plan, graph, source_sha=SOURCE_SHA, measurement=AllRecordsResolve())
        moved_state = orchestration_state(
            changed_components={"plugin": True},
        )
        restored = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
        self.assertEqual(
            [n.component for n in restored.plan.moving],
            [n.component for n in plan.moving],
            "the frozen plan is the plan; live drift must not rewrite it",
        )

    def test_tampered_frozen_plan_is_refused(self) -> None:
        graph = complete_fixture_graph()
        plan = rd.compute_plan(graph, orchestration_state())
        frozen_bytes, frozen_id = rd.freeze_plan(plan, graph, source_sha=SOURCE_SHA, measurement=AllRecordsResolve())
        tampered = frozen_bytes.replace(
            SOURCE_SHA.encode("ascii"), OTHER_SOURCE_SHA.encode("ascii")
        )
        self.assertNotEqual(tampered, frozen_bytes, "the tamper changed nothing")
        with self.assertRaises(rd.ReceiptError):
            rd.load_frozen_plan(tampered, expected_id=frozen_id)

    def test_partial_receipt_resume_skips_exact_matches_only(self) -> None:
        graph = complete_fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        done = rd.ReceiptEntry(version="1.1.0", digest="staged-client", phase="published")
        partial = {"client": done}
        remaining = rd.resume_remaining(plan, partial, observed={"client": done})
        self.assertEqual([n.component for n in remaining], ["plugin", "pointer"])
        drifted = rd.ReceiptEntry(version="1.1.0", digest="other", phase="published")
        with self.assertRaises(rd.ReceiptError):
            rd.resume_remaining(plan, partial, observed={"client": drifted})


class SealValidationTests(unittest.TestCase):
    def test_seal_refuses_pointer_node_without_pointer_state(self) -> None:
        graph = complete_fixture_graph()
        plan = rd.compute_plan(graph, orchestration_state())
        entries = {
            n.component: rd.ReceiptEntry(
                version="1.0.0",
                digest=f"d-{n.component}",
                phase="verified",
                pointer_state=None,
                delivery_proof=None,
            )
            for n in plan.moving
        }
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.seal_receipt(plan, graph, source_sha=SOURCE_SHA, entries=entries, approvals={})
        self.assertIn("pointer_state", str(caught.exception))

    def test_seal_refuses_approval_required_node_without_approvals(self) -> None:
        graph = complete_fixture_graph()
        state = orchestration_state(
            changed_components={"server": True},
            versions={"server": "3.1.0"},
            published_versions={"server": "3.0.0"},
        )
        plan = rd.compute_plan(graph, state)
        entries = {
            n.component: rd.ReceiptEntry(
                version="1.0.0",
                digest=f"d-{n.component}",
                phase="verified",
                pointer_state="ok" if n.reason.startswith("pointer:") else None,
                delivery_proof=None,
            )
            for n in plan.moving
        }
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.seal_receipt(plan, graph, source_sha=SOURCE_SHA, entries=entries, approvals={})
        self.assertIn("approval", str(caught.exception))


class G5SchemaTests(unittest.TestCase):
    def test_garbage_completion_is_refused_at_load(self) -> None:
        """alice's one-counterexample-proves-all: empty measurement id, missing
        policy, empty locators, nonsense direction must refuse to load."""
        data = fixture_graph_dict()
        data["edge"].append(
            {
                "type": "runtime-contract",
                "a": "plugin",
                "b": "server",
                "journey": "j",
                "artifacts": {"a": "", "b": ""},
                "direction": "nonsense",
                "supported": {"set": "measured:"},
            }
        )
        with self.assertRaises(rd.GraphError):
            rd.Graph.from_dict(data)

    def test_measured_set_requires_nonempty_identity_and_policy(self) -> None:
        data = fixture_graph_dict()
        for edge in data["edge"]:
            if edge["type"] == "runtime-contract":
                edge["supported"] = {"set": "measured:", "policy": "additive-only"}
        with self.assertRaises(rd.GraphError):
            rd.Graph.from_dict(data)

    def test_direction_must_be_a_known_enum_value(self) -> None:
        data = fixture_graph_dict()
        for edge in data["edge"]:
            if edge["type"] == "runtime-contract":
                edge["direction"] = "sideways"
        with self.assertRaises(rd.GraphError):
            rd.Graph.from_dict(data)


class PointerClosureTests(unittest.TestCase):
    def chain_graph(self) -> rd.Graph:
        return rd.Graph.from_dict(
            {
                "component": {
                    "a": {
                        "source_paths": ["a/"],
                        "version_source": {"type": "manifest", "path": "a/v"},
                        "tag_format": "a-v{version}",
                        "publish_lane": {"workflow": "wf/a.yml"},
                        "verify": {"command": "true"},
                    },
                    "b": {"publishable": False},
                    "c": {"publishable": False},
                },
                "edge": [
                    {"type": "pointer", "from": "a", "to": ["b"]},
                    {"type": "pointer", "from": "b", "to": ["c"]},
                ],
            }
        )

    def test_pointer_closure_is_transitive(self) -> None:
        """alice's counterexample: a->b->c must move a, b AND c."""
        plan = rd.compute_plan(
            self.chain_graph(), rd.FixtureState(changed_components={"a": True})
        )
        order = [n.component for n in plan.moving]
        self.assertEqual(order, ["a", "b", "c"])

    def test_pointer_cycle_is_refused(self) -> None:
        with self.assertRaises(rd.GraphError) as caught:
            rd.Graph.from_dict(
                {
                    "component": {
                        "a": {"publishable": False},
                        "b": {"publishable": False},
                    },
                    "edge": [
                        {"type": "pointer", "from": "a", "to": ["b"]},
                        {"type": "pointer", "from": "b", "to": ["a"]},
                    ],
                }
            )
        self.assertIn("cycle", str(caught.exception).lower())


class RegistryTruthTests(unittest.TestCase):
    def test_unknown_published_version_blocks_by_name(self) -> None:
        """alice's counterexample: published None must mean UNAVAILABLE and
        block, never read as no-published-version."""
        graph = fixture_graph()
        state = rd.FixtureState(
            changed_components={"client": True},
            versions={"client": "1.1.0"},
            published_versions={},
            registry_unavailable={"client": "fixture registry has no reader"},
        )
        plan = rd.compute_plan(graph, state)
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertTrue(
            any("registry" in p and "unavailable" in p and "client" in p for p in problems),
            f"unknown registry truth must be a named blocker, got {problems}",
        )


class RemoteIdentityTests(unittest.TestCase):
    def test_remote_forms_normalize_to_one_canonical_identity(self) -> None:
        for url in (
            "https://github.com/awebai/aweb.git",
            "https://github.com/awebai/aweb",
            "git@github.com:awebai/aweb.git",
            "ssh://git@github.com/awebai/aweb.git",
        ):
            self.assertEqual(
                rd.canonical_remote(url),
                "github.com/awebai/aweb",
                url,
            )


class GraphContractTests(unittest.TestCase):
    """The committed graph must match the repository it describes."""

    def setUp(self) -> None:
        self.graph = rd.Graph.load()

    def test_declared_source_paths_exist(self) -> None:
        for component in self.graph.components.values():
            for source_path in component.source_paths:
                self.assertTrue(
                    (REPO_ROOT / source_path).exists(),
                    f"{component.name} declares missing source path {source_path}",
                )

    def test_publishable_components_declare_lane_and_verify(self) -> None:
        for component in self.graph.components.values():
            if not component.publishable:
                continue
            self.assertTrue(
                component.publish_lane and component.publish_lane.get("workflow"),
                f"{component.name} has no publish-lane workflow declaration",
            )
            workflow = component.publish_lane["workflow"]
            self.assertTrue(
                (REPO_ROOT / workflow).is_file(),
                f"{component.name}: declared workflow {workflow} does not exist",
            )
            self.assertTrue(
                component.verify and component.verify.get("command"),
                f"{component.name} has no verify command declaration",
            )

    def test_version_sources_resolve_to_versions(self) -> None:
        import json as json_module
        import re

        for component in self.graph.components.values():
            source = component.version_source
            if source is None:
                continue
            kind = source["type"]
            if kind == "pyproject":
                text = (REPO_ROOT / source["path"]).read_text(encoding="utf-8")
                self.assertIsNotNone(
                    re.search(r'(?m)^version = "(\d+\.\d+\.\d+)"$', text),
                    f"{component.name}: no version in {source['path']}",
                )
            elif kind == "package-json":
                data = json_module.loads(
                    (REPO_ROOT / source["path"]).read_text(encoding="utf-8")
                )
                self.assertRegex(data["version"], r"^\d+\.\d+\.\d+$", component.name)
            elif kind == "tag-history":
                self.assertTrue((REPO_ROOT / source["script"]).is_file())
            else:
                self.fail(f"{component.name}: unknown version_source type {kind!r}")

    def test_sites_only_change_plans_sites(self) -> None:
        """alice's counterexample: a sites-only change planned nothing."""
        state = rd.FixtureState(changed_components={"sites": True})
        plan = rd.compute_plan(self.graph, state)
        self.assertIn("sites", {n.component for n in plan.moving})

    def _sync_skills_sources(self, package_json: Path) -> set:
        """The skill directories a package's build actually copies in."""
        scripts = json.loads(package_json.read_text())["scripts"]
        command = scripts["sync-skills"]
        return {
            "skills/" + part.rsplit("/", 1)[1]
            for part in command.split()
            if "skills/aweb-" in part
        }

    def test_bundled_skill_sources_match_what_the_packages_copy(self) -> None:
        """Root skills/ reaches users only by being copied into the Pi and
        claude-skills tarballs at build time; neither package commits one. A
        change there changes published bytes, so it has to move both consumers.
        Declared paths are compared against the copy commands so the graph
        cannot drift from the build."""
        declared = set(self.graph.components["agent-skills"].source_paths)
        self.assertTrue(declared, "the bundled skill sources must be declared")
        for consumer, package_json in (
            ("pi", REPO_ROOT / "pi-extension" / "package.json"),
            ("skills", REPO_ROOT / "packages" / "claude-skills" / "package.json"),
        ):
            with self.subTest(consumer=consumer):
                self.assertIn(
                    consumer,
                    self.graph.bundled_into.get("agent-skills", ()),
                    f"{consumer} must move when a bundled skill changes",
                )
                self.assertEqual(
                    declared,
                    self._sync_skills_sources(package_json),
                    f"{consumer} copies a different set than the graph declares",
                )

    def test_image_payload_declares_exactly_what_the_dockerfile_copies(self) -> None:
        """The published image bakes in three server paths, so those move it.
        Declaring the whole server component instead would force an immutable
        production image release for a change confined to server tests."""
        dockerfile = (REPO_ROOT / "awid" / "Dockerfile.release").read_text()
        copied = set()
        for line in dockerfile.splitlines():
            if not line.startswith("COPY "):
                continue
            # COPY <src>... <dest>: the last token is the destination.
            for token in line.split()[1:-1]:
                if token.startswith("server/"):
                    copied.add(token)
        self.assertTrue(copied, "the image no longer copies server paths")

        declared = set(self.graph.components["server-image-payload"].source_paths)
        self.assertEqual(
            declared,
            copied,
            "the declared image payload must equal what the Dockerfile copies",
        )
        self.assertIn(
            "awid-image",
            self.graph.bundled_into.get("server-image-payload", ()),
            "a change to a copied path must move the image",
        )

        # Positive control per copied input: each one is genuinely covered by a
        # declared path, so none of the three can silently stop moving the image.
        for path in sorted(copied):
            with self.subTest(copied=path):
                self.assertTrue(
                    any(path == d or path.startswith(d + "/") for d in declared),
                    f"{path} is copied into the image but not declared",
                )

        # Negative control: what the image does NOT bake in must not move it.
        # server/tests is the case that motivated naming three paths rather
        # than the whole component.
        for unrelated in ("server/tests", "server/CHANGELOG.md"):
            with self.subTest(unrelated=unrelated):
                self.assertFalse(
                    any(
                        unrelated == d or unrelated.startswith(d + "/")
                        for d in declared
                    ),
                    f"{unrelated} does not reach the image and must not move it",
                )
        self.assertNotIn(
            "awid-image",
            self.graph.bundled_into.get("server", ()),
            "the whole server component must not move the image; only its "
            "copied payload does",
        )

    def _frozen_for_sites_baseline(self, baseline: str | None):
        """Freeze the same server-only plan with sites observable or not."""
        state = rd.FixtureState(
            changed_components={"server": True},
            delivery_baselines={"sites": baseline} if baseline else {},
        )
        plan = rd.compute_plan(self.graph, state)
        self.assertNotIn("sites", {n.component for n in plan.moving})
        return rd.freeze_plan(
            plan, self.graph, source_sha=SOURCE_SHA, state=state,
            measurement=AllRecordsResolve(),
        )

    def test_delivery_observability_is_bound_into_frozen_truth(self) -> None:
        """The reviewer's counterexample: an undecidable delivery node is not in
        plan.moving, so recording baselines only for moving nodes left the
        frozen bytes identical whether sites was observable or not. A disclosure
        that exists only on transient CLI output is decoration - it cannot be
        what a later reader verifies against."""
        missing_bytes, missing_id = self._frozen_for_sites_baseline(None)
        observed_bytes, observed_id = self._frozen_for_sites_baseline("deploy-ref")

        self.assertNotEqual(
            missing_bytes, observed_bytes, "frozen bytes must record observability"
        )
        self.assertNotEqual(
            missing_id, observed_id, "the frozen id must change with it"
        )

        loaded = rd.load_frozen_plan(missing_bytes, expected_id=missing_id)
        self.assertIn(
            "sites",
            loaded.resolved.get("delivery", {}),
            "frozen truth must name the undecidable delivery node",
        )
        self.assertIsNone(loaded.resolved["delivery"]["sites"])

    def test_delivery_truth_fails_closed_without_a_capable_provider(self) -> None:
        """A provider that cannot answer is not evidence that there is nothing
        to answer. Populating delivery only when the provider implemented
        delivery_baseline made a lane component vanish from frozen truth, and
        the disclosure then reported no undecidability at all."""
        graph = rd.Graph.from_dict(
            {
                "component": {
                    "site": {
                        "source_paths": ["docs/x.md"],
                        "lane": {"command": "deploy"},
                        "publishable": False,
                    }
                }
            }
        )

        class ProviderWithoutDeliveryBaseline:
            """A state provider predating the capability."""

            def component_changed(self, component): return False
            def bundled_input_changed_for(self, bundled, consumer): return False
            def source_version(self, component): return None
            def published_version(self, component): return None
            def registry_unavailable_reason(self, component): return None
            def tag_version(self, component): return None
            def env_value(self, name): return None
            def path_exists(self, path): return False
            def pin_sha(self, pin): return None

        for label, state in (
            ("no provider at all", None),
            ("provider without the capability", ProviderWithoutDeliveryBaseline()),
        ):
            with self.subTest(case=label):
                plan = rd.compute_plan(graph, state) if state is not None else rd.Plan(
                    moving=[], runtime_contract_edges=[]
                )
                snapshot = rd._resolved_snapshot(plan, graph, state)
                self.assertIn(
                    "site", snapshot.get("delivery", {}),
                    "an undecidable lane component must be named, not omitted",
                )
                self.assertIsNone(snapshot["delivery"]["site"])
                self.assertTrue(
                    rd.delivery_disclosures(snapshot),
                    "an absent capability must disclose, not report all-clear",
                )

    def test_a_raising_observer_does_not_escape_out_of_freeze(self) -> None:
        """A moving lane component was read without the guard, so a raising
        observer propagated out of freeze_plan: no frozen truth, no disclosure,
        just the exception. Failing closed means recording None, not exploding."""
        graph = rd.Graph.from_dict(
            {
                "component": {
                    "site": {
                        "source_paths": ["docs/x.md"],
                        "lane": {"command": "deploy"},
                        "publishable": False,
                    }
                }
            }
        )

        class Raising(rd.FixtureState):
            def delivery_baseline(self, component):
                raise RuntimeError("observer failed")

        state = Raising(changed_components={"site": True})
        plan = rd.compute_plan(graph, state)
        frozen_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha=SOURCE_SHA, state=state,
        )
        loaded = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
        self.assertEqual(loaded.resolved["delivery"], {"site": None})
        self.assertTrue(rd.delivery_disclosures(loaded.resolved))

    def test_source_less_lane_components_are_in_frozen_truth(self) -> None:
        """A forced pointer node has a lane and no source paths - its movement
        is forced by an edge, not detected from a directory. Keying inclusion on
        source_paths dropped exactly those nodes, so the artifact stayed silent
        about the ones most likely to be undecidable."""
        graph = rd.Graph.from_dict(
            {
                "component": {
                    "pointer": {
                        "publishable": False,
                        "lane": {"repository": "github.com/example/plugins"},
                    }
                }
            }
        )
        snapshot = rd._resolved_snapshot(
            rd.Plan(moving=[], runtime_contract_edges=[]), graph, None
        )
        self.assertEqual(snapshot["delivery"], {"pointer": None})
        self.assertTrue(rd.delivery_disclosures(snapshot))

    def test_a_raising_provider_records_unobservable_not_an_exception(self) -> None:
        """A lookup that blows up is not evidence the node is fine."""
        graph = rd.Graph.from_dict(
            {
                "component": {
                    "site": {
                        "source_paths": ["docs/x.md"],
                        "lane": {"command": "deploy"},
                        "publishable": False,
                    }
                }
            }
        )

        class Raising:
            def delivery_baseline(self, component):
                raise RuntimeError("remote unreachable")

        snapshot = rd._resolved_snapshot(
            rd.Plan(moving=[], runtime_contract_edges=[]), graph, Raising()
        )
        self.assertEqual(snapshot["delivery"], {"site": None})

    def test_cli_disclosures_are_derived_from_frozen_truth(self) -> None:
        """What the operator reads must be the sealed value, not a second
        computation against live state that could disagree with it."""
        missing_bytes, missing_id = self._frozen_for_sites_baseline(None)
        loaded = rd.load_frozen_plan(missing_bytes, expected_id=missing_id)
        disclosures = rd.delivery_disclosures(loaded.resolved)
        self.assertTrue(any(d.startswith("sites:") for d in disclosures))

        observed_bytes, observed_id = self._frozen_for_sites_baseline("deploy-ref")
        observed = rd.load_frozen_plan(observed_bytes, expected_id=observed_id)
        # Specific to sites: the committed graph also carries marketplace-pointer,
        # a source-less lane node that is legitimately undecidable at plan time,
        # so the whole list is not expected to be empty.
        self.assertEqual(
            [d for d in rd.delivery_disclosures(observed.resolved)
             if d.startswith("sites:")],
            [],
            "an observable delivery node discloses nothing about itself",
        )

    def test_unrelated_plan_does_not_require_a_sites_baseline(self) -> None:
        """A delivery node nobody is releasing must not block someone else's
        release. sites ships without a baseline_ref, so a global check made
        every plan of every component unsatisfiable."""
        state = rd.FixtureState(changed_components={"server": True})
        plan = rd.compute_plan(self.graph, state)
        self.assertNotIn("sites", {n.component for n in plan.moving})
        problems = rd.check_declared_inputs(self.graph, plan, state)
        self.assertEqual(
            [p for p in problems if p.startswith("sites:")],
            [],
            "an unrelated plan must not demand a sites baseline",
        )

    def test_moving_sites_still_refuses_without_an_observable_baseline(self) -> None:
        """Scoping the check must not delete it: releasing sites itself still
        needs an authoritative delivered ref, and absence is never movement."""
        state = rd.FixtureState(changed_components={"sites": True})
        plan = rd.compute_plan(self.graph, state)
        self.assertIn("sites", {n.component for n in plan.moving})
        problems = rd.check_declared_inputs(self.graph, plan, state)
        self.assertTrue(
            any(p.startswith("sites:") for p in problems),
            "a sites release without a baseline must refuse",
        )

    def test_updating_the_ac_pin_needs_no_production_credentials(self) -> None:
        """Updating AC's source pointer is an effect this release performs, and
        it needs no production credentials. AC's deploy is deliberately not in
        this graph: an aweb release makes AC's pin stale and says so, it does
        not demand that AC deploy."""
        ac_pin = self.graph.components["ac-pin"]
        self.assertFalse(ac_pin.approval_required)
        self.assertFalse(ac_pin.credential_paths)
        self.assertEqual(len(ac_pin.sibling_pins), 2, "server AND awid pins declared")
        self.assertNotIn("ac-gate", self.graph.components)
        self.assertNotIn("ac-gate", self.graph.pointer_targets.get("ac-pin", ()))

    def test_a_pointer_advertises_what_its_pin_actually_holds(self) -> None:
        """ac-pin holds a git SHA for server and a package version for awid.
        Advertising a version into a git_sha field would write a value the pin
        cannot mean, so what is advertised follows the pin, not one rule."""
        state = rd.FixtureState(
            changed_components={"server": True, "awid-pypi": True},
            versions={"server": "1.26.36", "awid-pypi": "0.5.15"},
        )
        plan = rd.compute_plan(self.graph, state)
        updates = rd.pointer_updates(plan, self.graph, source_sha=SOURCE_SHA)
        self.assertEqual(
            updates["ac-pin"],
            {
                "server": {
                    "version": "1.26.36",
                    "git_ref": "server-v1.26.36",
                    "git_sha": SOURCE_SHA,
                },
                "awid-pypi": "0.5.15",
            },
            "the server pin holds one coherent release identity; the awid pin holds a version",
        )

    def test_a_version_pointer_still_advertises_the_version(self) -> None:
        state = rd.FixtureState(
            changed_components={"channel": True}, versions={"channel": "1.7.4"}
        )
        plan = rd.compute_plan(self.graph, state)
        updates = rd.pointer_updates(plan, self.graph, source_sha=SOURCE_SHA)
        self.assertEqual(updates["marketplace-pointer"], {"channel": "1.7.4"})

    def test_a_release_can_be_scoped_to_one_artifact(self) -> None:
        """Without this, shipping the channel fix also ships server, awid, aw
        and skills - nine nodes, seven version bumps and a frozen main. A
        process that can only release everything at once releases nothing."""
        state = rd.FixtureState(
            changed_components={
                "channel": True, "server": True, "awid-pypi": True, "skills": True
            },
            versions={"channel": "1.7.4", "server": "1.26.36",
                      "awid-pypi": "0.5.15", "skills": "0.2.13"},
        )
        plan = rd.compute_plan(self.graph, state)
        self.assertGreater(len(plan.moving), 4, "the unscoped plan is broad")

        scoped = rd.scope_plan(plan, self.graph, ["channel"])
        self.assertEqual(
            [n.component for n in scoped.moving],
            ["channel", "marketplace-pointer"],
            "a scoped release keeps its forced pointer and drops the rest",
        )

    def test_scoping_cannot_drop_a_forced_pointer(self) -> None:
        """The pointer is what makes the publication reach users, so it is not
        optional even when the operator names only the package."""
        state = rd.FixtureState(
            changed_components={"channel": True}, versions={"channel": "1.7.4"}
        )
        plan = rd.compute_plan(self.graph, state)
        scoped = rd.scope_plan(plan, self.graph, ["channel"])
        self.assertIn("marketplace-pointer", [n.component for n in scoped.moving])

    def test_scoping_to_something_not_moving_is_refused(self) -> None:
        """Silently releasing nothing looks exactly like success."""
        state = rd.FixtureState(
            changed_components={"channel": True}, versions={"channel": "1.7.4"}
        )
        plan = rd.compute_plan(self.graph, state)
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.scope_plan(plan, self.graph, ["server"])
        self.assertIn("server", str(caught.exception))

    def test_scoping_preserves_publication_order(self) -> None:
        state = rd.FixtureState(
            changed_components={"aw": True, "pi": True},
            versions={"aw": "1.35.0", "pi": "0.3.4"},
        )
        plan = rd.compute_plan(self.graph, state)
        scoped = rd.scope_plan(plan, self.graph, ["aw", "pi"])
        order = [n.component for n in scoped.moving]
        self.assertLess(order.index("aw"), order.index("pi"),
                        "aw is a publication prerequisite of pi")

    def test_every_forced_pointer_can_be_performed(self) -> None:
        """A forced node with no way to perform its effect is a dead end: it
        made every channel, skills, server and awid release unexecutable.

        Asserts the three things that actually blocked publication, not a proxy
        for them: an adapter exists, the node carries no delivery obligation
        nothing can satisfy, and it is not accidentally a delivery node.
        """
        import release_driver as _rd
        for source, targets in self.graph.pointer_targets.items():
            for target in targets:
                with self.subTest(pointer=f"{source}->{target}"):
                    component = self.graph.components[target]
                    if component.publish_lane:
                        continue
                    adapter = REPO_ROOT / "scripts" / f"pointer-adapter-{target}.py"
                    self.assertTrue(
                        adapter.is_file(),
                        f"{target} is forced by {source} but has no adapter at "
                        f"{adapter.name}, so no lane can perform its effect",
                    )
                    self.assertTrue(
                        os.access(adapter, os.X_OK),
                        f"{adapter.name} must be executable; the driver execs it",
                    )
                    self.assertIsNone(
                        _rd._delivery_obligation(self.graph, target),
                        f"{target} carries a delivery obligation no pointer lane "
                        "can produce, so it could never publish",
                    )

    def test_aw_lane_declares_the_reviewed_external_surface(self) -> None:
        """aweb-abbe.2.1: the aw lane points at the aw repository's reviewed
        dispatch workflow, the allowlisted provider, and exactly the three
        reviewed modes - not at this repository's checkout surface."""
        graph = rd.Graph.load(rd.GRAPH_PATH)
        lane = graph.components["aw"].publish_lane
        self.assertEqual(lane.get("repository"), "awebai/aw")
        self.assertEqual(lane.get("provider"), "github-workflow-artifacts")
        self.assertEqual(
            lane.get("modes"),
            ["stage-only", "publish-continuation", "verify-only"],
        )
        self.assertEqual(lane.get("workflow"), ".github/workflows/aw-release.yml")

    def test_pypi_and_oci_lanes_declare_the_dispatch_surface(self) -> None:
        """aweb-abbe.4: server, awid-pypi, and awid-image lanes point at the
        dispatch-only three-mode workflows; no tag-triggered publisher
        remains a lane."""
        graph = rd.Graph.load(rd.GRAPH_PATH)
        modes = ["stage-only", "publish-continuation", "verify-only"]
        for name, workflow in (
            ("server", ".github/workflows/pypi-release.yml"),
            ("awid-pypi", ".github/workflows/pypi-release.yml"),
            ("awid-image", ".github/workflows/awid-image-release.yml"),
        ):
            lane = graph.components[name].publish_lane
            self.assertEqual(lane.get("workflow"), workflow, name)
            self.assertEqual(lane.get("modes"), modes, name)
            self.assertTrue(
                (rd.REPO_ROOT / workflow).exists(), f"{workflow} must exist"
            )

    def test_ac_pin_is_a_forced_pointer_consumer_of_server_and_awid(self) -> None:
        """alice's counterexample: awid moving without ac-pin in the plan is
        the missed-consumer failure the graph exists to prevent."""
        state = rd.FixtureState(changed_components={"awid-pypi": True, "server": True})
        plan = rd.compute_plan(self.graph, state)
        order = [n.component for n in plan.moving]
        self.assertIn("ac-pin", order)
        self.assertLess(order.index("awid-pypi"), order.index("ac-pin"))
        self.assertLess(order.index("server"), order.index("ac-pin"))

    def test_known_couplings_are_declared(self) -> None:
        self.assertEqual(
            set(self.graph.bundled_into.get("channel-core", ())), {"channel", "pi"}
        )
        self.assertIn("awid-pypi", self.graph.prerequisites["server"])
        self.assertIn("aw", self.graph.prerequisites["pi"])
        self.assertEqual(
            set(self.graph.pointer_targets.get("channel", ())), {"marketplace-pointer"}
        )
        ac_pin = self.graph.components["ac-pin"]
        pins = {p["component"]: p for p in ac_pin.sibling_pins}
        self.assertEqual(set(pins), {"server", "awid-pypi"})
        self.assertEqual(pins["server"]["field"], "git_sha")
        self.assertEqual(pins["server"]["section"], "aweb")

    def test_committed_runtime_contracts_are_honestly_declared(self) -> None:
        """An edge either names a measurement backed by a resolvable record, or
        says it is incomplete. Fabricating a floor, or claiming support with no
        record behind it, is the defect. The server<->server federation journey
        is measured; the rest are honestly incomplete until they are measured."""
        self.assertTrue(self.graph.runtime_contracts, "edges must be declared")
        measured = set()
        for edge in self.graph.runtime_contracts:
            self.assertNotIn("floor", edge.supported, f"{edge.a}->{edge.b}")
            if edge.declared_incomplete:
                continue
            measured.add((edge.a, edge.b, edge.journey))
            record = edge.supported.get("record")
            self.assertIsInstance(
                record, dict, f"{edge.a}->{edge.b} claims support with no record"
            )
            self.assertTrue(
                record.get("path") and record.get("digest"),
                f"{edge.a}->{edge.b} record names no bytes to resolve",
            )

        self.assertEqual(
            measured,
            {("server", "server", "make test-federation-e2e (both request directions)")},
        )

    def test_incomplete_contracts_block_execution_but_not_the_plan(self) -> None:
        """A diagnostic plan must be freezable with incomplete edges - that is
        how an operator sees what measurement is owed. Execution is where
        measured support or an explicit recorded deferral is required."""
        state = rd.FixtureState(changed_components={"aw": True})
        plan = rd.compute_plan(self.graph, state)
        self.assertTrue(plan.moving, "diagnostic plan still computes")
        problems = rd.check_declared_inputs(self.graph, plan, state)
        self.assertFalse(
            [p for p in problems if "declared-incomplete" in p],
            "an incomplete edge is not a declared-input problem; it blocks at "
            f"execution: {problems}",
        )
        self.assertTrue(
            any(e.declared_incomplete for e in plan.runtime_contract_edges),
            "the plan must still say the edge is incomplete",
        )
        lanes = FixtureLanes(available={"aw"})
        with self.assertRaises(rd.BlockedByDeclaredInputs):
            rd.run_plan(
                plan, self.graph, lanes,
                skew=FixtureSkew(), authority=FixtureAuthority(), providers=rd.Providers(store=rd._MemoryStore(), authority=FixtureAuthority(), measurement=AllRecordsResolve()),
                source_sha=SOURCE_SHA, approvals={}, state=state,
            )
        self.assertEqual(lanes.calls, [])

    def test_deferral_requires_an_explicit_recorded_authorization(self) -> None:
        """Deferral is a human accepting a risk, so it is refused unless a
        record says who accepted it. A bare flag is not an authorization."""
        state = rd.FixtureState(changed_components={"aw": True})
        plan = rd.compute_plan(self.graph, state)
        lanes = FixtureLanes(available={"aw"})
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.run_plan(
                plan, self.graph, lanes,
                skew=FixtureSkew(), authority=FixtureAuthority(),
                providers=rd.Providers(
                    store=rd._MemoryStore(), authority=FixtureAuthority(),
                    measurement=AllRecordsResolve(), defer_g5=True,
                ),
                source_sha=SOURCE_SHA, approvals={}, state=state,
            )
        self.assertIn("authorization", str(caught.exception))
        self.assertEqual(lanes.calls, [])

    def _g5_plan(self):
        state = rd.FixtureState(changed_components={"aw": True})
        plan = rd.compute_plan(self.graph, state)
        incomplete = [
            rd.edge_identity(e)
            for e in plan.runtime_contract_edges
            if e.declared_incomplete
        ]
        self.assertTrue(incomplete, "the fixture must touch an incomplete edge")
        return plan, frozenset(incomplete)

    def _g5_record(self, **overrides):
        _, edges = self._g5_plan()
        fields = {
            "who": "juan",
            "when": "2026-08-07T00:00:00Z",
            "source_sha": SOURCE_SHA,
            "frozen_plan_id": "c" * 64,
            "edges": edges,
            "risk": "unmeasured runtime support accepted for this release",
        }
        fields.update(overrides)
        return rd.G5Authorization(**fields)

    def test_authorized_deferral_proceeds_without_declaring_support(self) -> None:
        """An authorized deferral lets execution continue; it never turns an
        unmeasured edge into a supported one."""
        plan, _ = self._g5_plan()
        rd.require_runtime_support(
            plan,
            defer_g5=True,
            authorization=self._g5_record(),
            source_sha=SOURCE_SHA,
            frozen_plan_id="c" * 64,
        )
        self.assertTrue(
            all(e.declared_incomplete for e in plan.runtime_contract_edges),
            "deferral must never declare support",
        )

    def test_runner_risk_approval_is_not_g5_acceptance(self) -> None:
        """A record that accepted an outage is not acceptance of an unmeasured
        runtime contract, however adjacent the two are in the same release."""
        plan, _ = self._g5_plan()
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.require_runtime_support(
                plan,
                defer_g5=True,
                authorization=rd.Approval(
                    who="juan", when="2026-08-07T00:00:00Z",
                    risk="runner outage", g5_deferred=True,
                ),
                source_sha=SOURCE_SHA,
            )
        self.assertIn("runner outage", str(caught.exception))

    def test_missing_g5_authorization_refuses(self) -> None:
        plan, _ = self._g5_plan()
        with self.assertRaises(rd.ReceiptError):
            rd.require_runtime_support(
                plan, defer_g5=True, authorization=None, source_sha=SOURCE_SHA
            )

    def test_g5_authorization_bound_to_another_release_refuses(self) -> None:
        """The record names one source and one frozen plan, so it cannot be
        carried to a different release."""
        plan, _ = self._g5_plan()
        for label, kwargs, call in (
            (
                "wrong source",
                {"source_sha": OTHER_SOURCE_SHA},
                {"source_sha": SOURCE_SHA, "frozen_plan_id": "c" * 64},
            ),
            (
                "wrong frozen plan",
                {"frozen_plan_id": "d" * 64},
                {"source_sha": SOURCE_SHA, "frozen_plan_id": "c" * 64},
            ),
        ):
            with self.subTest(case=label):
                with self.assertRaises(rd.ReceiptError):
                    rd.require_runtime_support(
                        plan, defer_g5=True,
                        authorization=self._g5_record(**kwargs), **call,
                    )

    def test_g5_authorization_must_name_exactly_the_deferred_edges(self) -> None:
        """Partial coverage is the dangerous case: an edge nobody read would
        ship under a record that never mentioned it."""
        plan, edges = self._g5_plan()
        for label, named in (
            ("covers nothing relevant", frozenset({"ghost<->server"})),
            ("names an unrelated extra", edges | {"ghost<->server"}),
            ("omits a deferred edge", frozenset(sorted(edges)[:-1]) if len(edges) > 1 else frozenset()),
        ):
            with self.subTest(case=label):
                with self.assertRaises(rd.ReceiptError):
                    rd.require_runtime_support(
                        plan, defer_g5=True,
                        authorization=self._g5_record(edges=named),
                        source_sha=SOURCE_SHA,
                    )

    def test_g5_authorization_reaches_run_plan_on_the_ordinary_path(self) -> None:
        """The composition control. run_providers omitted the record while
        threading the flag, so a valid operator-supplied authorization arrived
        as None and the release refused. Asserting on require_runtime_support
        alone cannot see that - the previous version of this test looped over an
        authority string it never passed anywhere, so it proved nothing."""
        graph = fixture_graph()
        state = rd.FixtureState(changed_components={"client": True})
        plan = rd.compute_plan(graph, state)
        authorization = rd.G5Authorization(
            who="juan", when="2026-08-07T00:00:00Z", source_sha=SOURCE_SHA,
            frozen_plan_id="c" * 64, edges=frozenset({"e" * 64}),
            risk="accepted",
        )
        for trust in ("github-workflow-artifacts", "local-development",
                      "local-runnerless"):
            with self.subTest(authority=trust):
                providers = rd.Providers(
                    store=rd._MemoryStore(), authority=FixtureAuthority(),
                    measurement=AllRecordsResolve(), defer_g5=True,
                    g5_authorization=authorization, authority_trust=trust,
                )
                # The record survives composition on every authority: it is the
                # same object run_plan will read.
                self.assertIs(providers.g5_authorization, authorization)

    def test_providers_default_carries_no_authorization(self) -> None:
        """A Providers built without the field must not silently look
        authorized."""
        providers = rd.Providers(
            store=rd._MemoryStore(), authority=FixtureAuthority(),
        )
        self.assertIsNone(providers.g5_authorization)

    def test_deferral_never_excuses_a_measured_edge(self) -> None:
        """Deferral partitions the set. A measured edge had nothing deferred
        about it, so its matrix must still run - gating the complete-edge checks
        on defer_g5 let one accepted gap switch off every measured matrix in the
        same plan."""
        graph = fixture_graph()  # client<->server is measured
        state = rd.FixtureState(changed_components={"client": True})
        plan = rd.compute_plan(graph, state)
        complete = [e for e in plan.runtime_contract_edges if not e.declared_incomplete]
        self.assertTrue(complete, "the fixture must touch a measured edge")

        # Complete-only plan: require_runtime_support returns early because
        # nothing is incomplete, so a bare flag must not reach the matrices.
        skew = FixtureSkew(available=False)
        with self.assertRaises(rd.SkewUnavailable):
            rd.run_plan(
                plan, graph, FixtureLanes(available={"client", "plugin", "pointer"}),
                skew=skew, authority=FixtureAuthority(),
                providers=rd.Providers(
                    store=rd._MemoryStore(), authority=FixtureAuthority(),
                    measurement=AllRecordsResolve(), defer_g5=True,
                ),
                source_sha=SOURCE_SHA, approvals={}, state=state,
            )

    def test_deferral_still_executes_the_measured_matrix(self) -> None:
        """Positive control. The previous tests proved only that an UNAVAILABLE
        matrix blocks; they never made one available and checked it ran, so the
        execute block could skip every edge under deferral and stay green."""
        graph = fixture_graph()  # client<->server is measured
        state = rd.FixtureState(changed_components={"client": True})
        plan = rd.compute_plan(graph, state)
        skew = FixtureSkew(available=True)
        rd.run_plan(
            plan, graph, FixtureLanes(available={"client", "plugin", "pointer"}),
            skew=skew, authority=FixtureAuthority(),
            providers=rd.Providers(
                store=rd._MemoryStore(), authority=FixtureAuthority(),
                measurement=AllRecordsResolve(), defer_g5=True,
            ),
            source_sha=SOURCE_SHA, approvals={}, state=state,
        )
        self.assertIn(
            ("client", "server"), skew.executed,
            "a measured edge's matrix must run even when something else was "
            "deferred; nothing about it was deferred",
        )

    def test_deferral_in_a_mixed_plan_covers_only_the_incomplete_edges(self) -> None:
        """With one measured and one unmeasured edge, an authorization for the
        unmeasured one must not silently excuse the measured one."""
        data = fixture_graph_dict()
        data["edge"].append({
            "type": "runtime-contract", "a": "plugin", "b": "server",
            "journey": "make other-journey",
            "artifacts": {"a": "registry:plugin", "b": "registry:server"},
            "direction": "both", "supported": {"policy": "additive-only"},
        })
        graph = rd.Graph.from_dict(data)
        state = rd.FixtureState(changed_components={"client": True, "plugin": True})
        plan = rd.compute_plan(graph, state)
        incomplete = [e for e in plan.runtime_contract_edges if e.declared_incomplete]
        complete = [e for e in plan.runtime_contract_edges if not e.declared_incomplete]
        self.assertTrue(incomplete and complete, "the plan must be mixed")

        authorization = rd.G5Authorization(
            who="juan", when="2026-08-07T00:00:00Z", source_sha=SOURCE_SHA,
            frozen_plan_id="c" * 64,
            edges=frozenset(rd.edge_identity(e) for e in incomplete),
            risk="unmeasured edge accepted",
        )
        # The authorization itself is accepted for exactly its edges...
        rd.require_runtime_support(
            plan, defer_g5=True, authorization=authorization,
            source_sha=SOURCE_SHA, frozen_plan_id="c" * 64,
        )
        # ...and the measured edge's matrix is still required.
        with self.assertRaises(rd.SkewUnavailable) as caught:
            rd.run_plan(
                plan, graph, FixtureLanes(available={"client", "plugin", "pointer"}),
                skew=FixtureSkew(available=False), authority=FixtureAuthority(),
                providers=rd.Providers(
                    store=rd._MemoryStore(), authority=FixtureAuthority(),
                    measurement=AllRecordsResolve(), defer_g5=True,
                    g5_authorization=authorization,
                ),
                source_sha=SOURCE_SHA, approvals={}, state=state,
            )
        self.assertIn("client<->server", str(caught.exception))
        self.assertNotIn("plugin<->server", str(caught.exception))

    def _incomplete_plan_and_receipt_parts(self):
        data = fixture_graph_dict()
        data["edge"] = [e for e in data["edge"] if e.get("type") != "runtime-contract"]
        data["edge"].append({
            "type": "runtime-contract", "a": "client", "b": "server",
            "journey": "make unmeasured-journey",
            "artifacts": {"a": "registry:client", "b": "registry:server"},
            "direction": "both", "supported": {"policy": "additive-only"},
        })
        graph = rd.Graph.from_dict(data)
        state = rd.FixtureState(changed_components={"client": True})
        plan = rd.compute_plan(graph, state)
        incomplete = frozenset(
            rd.edge_identity(e)
            for e in plan.runtime_contract_edges if e.declared_incomplete
        )
        self.assertTrue(incomplete)
        entries = {
            n.component: rd.ReceiptEntry(version="1.0.0", digest="d", phase="verified")
            for n in plan.moving
        }
        return graph, plan, incomplete, entries

    def test_an_outstanding_debt_survives_every_later_reader(self) -> None:
        """The debt was accepted at seal and rejected everywhere a finished
        receipt is later read, so a correctly sealed published-not-delivered
        receipt was unverifiable, unresumable and unrestorable. One assertion in
        one test is why three call sites went unchecked."""
        graph = rd.Graph.from_dict({
            "component": {
                "client": {
                    "source_paths": ["client/"],
                    "version_source": {"type": "manifest", "path": "v"},
                    "tag_format": "client-v{version}",
                    "publish_lane": {"workflow": "w"},
                    "verify": {"command": "true"},
                    "delivery_restart": {"proof": "restart per host"},
                },
            },
            "edge": [],
        })
        state = rd.FixtureState(
            changed_components={"client": True}, versions={"client": "1.1.0"},
            published_versions={"client": "1.0.0"},
        )
        plan = rd.compute_plan(graph, state)
        obligation = rd._delivery_obligation(graph, "client")
        entries = {
            "client": rd.ReceiptEntry(
                version="1.1.0", digest="d", phase="verified",
                delivery_outstanding=obligation,
            )
        }
        sealed, digest = rd.seal_receipt(
            plan, graph, source_sha=SOURCE_SHA, entries=entries, approvals={},
            frozen_plan_id="c" * 64, staged_manifest_id="staged",
        )
        receipt = rd.load_sealed_receipt(sealed, expected_digest=digest)
        self.assertEqual(receipt.entries["client"].delivery_outstanding, obligation)

        # The reader that rejected it.
        rd.validate_final_receipt(
            receipt, plan=plan, graph=graph, frozen_plan_id="c" * 64,
            staged_manifest_id="staged", source_sha=SOURCE_SHA,
        )

    def test_resume_carries_an_unpaid_delivery_debt_forward(self) -> None:
        """An interrupted channel or pi release is the normal resume case: the
        node published, its restart evidence could not exist yet, and adoption
        observes no proof. Dropping the old refusal without recording the debt
        only moved the failure to seal time."""
        graph = rd.Graph.from_dict({
            "component": {
                "client": {
                    "source_paths": ["client/"],
                    "version_source": {"type": "manifest", "path": "v"},
                    "tag_format": "client-v{version}",
                    "publish_lane": {"workflow": "w"},
                    "verify": {"command": "true"},
                    "delivery_restart": {"proof": "restart per host"},
                },
            },
            "edge": [],
        })
        obligation = rd._delivery_obligation(graph, "client")
        node = rd.PlanNode(component="client", reason="changed", version="1.1.0")
        manifest_entry = {"delivery_obligation": obligation}
        observed = rd.ReceiptEntry(
            version="1.1.0", digest="d", phase="published", delivery_proof=None
        )
        entry = rd.ReceiptEntry(
            version=observed.version, digest=observed.digest, phase="published",
            pointer_state=observed.pointer_state,
            delivery_proof=observed.delivery_proof,
            digest_set=observed.digest_set, lane_ref=observed.lane_ref,
            delivery_outstanding=(
                None if observed.delivery_proof
                else (manifest_entry.get("delivery_obligation")
                      or rd._delivery_obligation(graph, node.component))
            ),
        )
        self.assertEqual(
            entry.delivery_outstanding, obligation,
            "an adopted node owing delivery must carry the debt, or it seals "
            "saying neither evidence nor debt",
        )

    def test_a_delivery_node_owing_nothing_and_proving_nothing_refuses(self) -> None:
        """Accepting the debt must not become accepting silence."""
        graph = rd.Graph.from_dict({
            "component": {
                "client": {
                    "source_paths": ["client/"],
                    "version_source": {"type": "manifest", "path": "v"},
                    "tag_format": "client-v{version}",
                    "publish_lane": {"workflow": "w"},
                    "verify": {"command": "true"},
                    "delivery_restart": {"proof": "restart per host"},
                },
            },
            "edge": [],
        })
        state = rd.FixtureState(
            changed_components={"client": True}, versions={"client": "1.1.0"},
            published_versions={"client": "1.0.0"},
        )
        plan = rd.compute_plan(graph, state)
        entries = {
            "client": rd.ReceiptEntry(version="1.1.0", digest="d", phase="verified")
        }
        with self.assertRaises(rd.ReceiptError):
            rd.seal_receipt(
                plan, graph, source_sha=SOURCE_SHA, entries=entries, approvals={},
                frozen_plan_id="c" * 64, staged_manifest_id="staged",
            )

    def test_receipt_for_deferred_edges_must_carry_the_authorization(self) -> None:
        """Enforced at seal, and again on the way back in. The reviewer's
        counterexample was a final receipt for an incomplete runtime edge that
        sealed with no authorization and validated clean; sealing now refuses,
        and a receipt forged past the sealer still fails validation."""
        graph, plan, incomplete, entries = self._incomplete_plan_and_receipt_parts()

        with self.assertRaises(rd.ReceiptError) as caught:
            rd.seal_receipt(
                plan, graph, source_sha=SOURCE_SHA, entries=entries, approvals={},
                frozen_plan_id="c" * 64, staged_manifest_id="staged",
            )
        self.assertIn("G5 authorization", str(caught.exception))

        # Forged past the sealer, as a hostile or older writer would produce.
        import hashlib as _hashlib, json as _json
        authorized, _ = rd.seal_receipt(
            plan, graph, source_sha=SOURCE_SHA, entries=entries, approvals={},
            frozen_plan_id="c" * 64, staged_manifest_id="staged",
            g5_authorization=rd.G5Authorization(
                who="juan", when="t", source_sha=SOURCE_SHA,
                frozen_plan_id="c" * 64, edges=incomplete, risk="accepted",
            ),
        )
        body = _json.loads(_json.loads(authorized)["body"])
        body.pop("g5_authorization")
        forged_body = _json.dumps(body, sort_keys=True)
        forged = _json.dumps({
            "body": forged_body,
            "seal": _hashlib.sha256(forged_body.encode()).hexdigest(),
        }).encode()
        self.assertNotEqual(forged, authorized, "the forgery changed nothing")
        receipt = rd.load_sealed_receipt(
            forged, expected_digest=_hashlib.sha256(forged).hexdigest()
        )
        self.assertIsNone(receipt.g5_authorization)
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_final_receipt(
                receipt, plan=plan, graph=graph, frozen_plan_id="c" * 64,
                staged_manifest_id="staged", source_sha=SOURCE_SHA,
            )
        self.assertIn("G5 authorization", str(caught.exception))

    def test_a_sealed_entry_is_exactly_its_schema(self) -> None:
        """The loader projected known fields and dropped the rest, so bytes
        carrying an unknown field round-tripped as though they did not. A
        receipt is archive-bound evidence; what the bytes say and what a reader
        sees must be the same thing."""
        import hashlib as _h, json as _j

        graph, plan, incomplete, entries = self._incomplete_plan_and_receipt_parts()
        authorization = rd.G5Authorization(
            who="juan", when="t", source_sha=SOURCE_SHA,
            frozen_plan_id="c" * 64, edges=incomplete, risk="accepted",
        )
        sealed, digest = rd.seal_receipt(
            plan, graph, source_sha=SOURCE_SHA, entries=entries, approvals={},
            frozen_plan_id="c" * 64, staged_manifest_id="staged",
            g5_authorization=authorization,
        )
        self.assertTrue(rd.load_sealed_receipt(sealed, expected_digest=digest))

        name = sorted(entries)[0]
        for label, mutate in (
            ("unknown field", lambda e: e.update({"smuggled": "x"})),
            ("wrong type", lambda e: e.update({"pointer_state": 7})),
            ("empty required", lambda e: e.update({"version": ""})),
            ("non-object proof", lambda e: e.update({"delivery_proof": "yes"})),
        ):
            with self.subTest(case=label):
                body = _j.loads(_j.loads(sealed)["body"])
                mutate(body["entries"][name])
                raw = _j.dumps(body, sort_keys=True)
                forged = _j.dumps({
                    "body": raw,
                    "seal": _h.sha256(raw.encode()).hexdigest(),
                }).encode()
                self.assertNotEqual(forged, sealed, "the mutation changed nothing")
                with self.assertRaises(rd.ReceiptError):
                    rd.load_sealed_receipt(
                        forged, expected_digest=_h.sha256(forged).hexdigest()
                    )

    def test_sealed_record_fields_are_type_checked(self) -> None:
        """A key-set check is not a schema. who=42, when=[] and risk={} loaded
        and validated clean."""
        graph, plan, incomplete, entries = self._incomplete_plan_and_receipt_parts()
        good = {
            "who": "juan", "when": "2026-08-07T00:00:00Z",
            "source_sha": SOURCE_SHA, "frozen_plan_id": "c" * 64,
            "edges": sorted(incomplete), "risk": "accepted",
        }
        self.assertIsNotNone(rd._g5_from_record(good))
        for label, mutation in (
            ("who is a number", {"who": 42}),
            ("when is a list", {"when": []}),
            ("risk is an object", {"risk": {}}),
            ("who is blank", {"who": "   "}),
            ("source is short", {"source_sha": "s1"}),
            ("plan id is short", {"frozen_plan_id": "abc"}),
            ("edges repeat", {"edges": sorted(incomplete) * 2}),
            ("edges are display form", {"edges": ["aw<->server"]}),
        ):
            with self.subTest(case=label):
                with self.assertRaises(rd.ReceiptError):
                    rd._g5_from_record({**good, **mutation})

    def test_authorization_without_a_deferral_is_refused(self) -> None:
        """An acceptance for a deferral that did not happen is a claim about
        the release that is not true of it."""
        graph = fixture_graph()  # only a measured edge
        state = rd.FixtureState(changed_components={"client": True})
        plan = rd.compute_plan(graph, state)
        self.assertFalse(
            [e for e in plan.runtime_contract_edges if e.declared_incomplete]
        )
        entries = {
            n.component: rd.ReceiptEntry(version="1.0.0", digest="d", phase="verified")
            for n in plan.moving
        }
        with self.assertRaises(rd.ReceiptError):
            rd.seal_receipt(
                plan, graph, source_sha=SOURCE_SHA, entries=entries, approvals={},
                frozen_plan_id="c" * 64, staged_manifest_id="staged",
                g5_authorization=rd.G5Authorization(
                    who="juan", when="t", source_sha=SOURCE_SHA,
                    frozen_plan_id="c" * 64, edges=frozenset({"e" * 64}),
                    risk="unrelated",
                ),
            )

    def test_sealed_g5_authorization_round_trips_and_binds(self) -> None:
        graph, plan, incomplete, entries = self._incomplete_plan_and_receipt_parts()
        authorization = rd.G5Authorization(
            who="juan", when="2026-08-07T00:00:00Z", source_sha=SOURCE_SHA,
            frozen_plan_id="c" * 64, edges=incomplete, risk="accepted",
        )
        sealed, digest = rd.seal_receipt(
            plan, graph, source_sha=SOURCE_SHA, entries=entries, approvals={},
            frozen_plan_id="c" * 64, staged_manifest_id="staged",
            g5_authorization=authorization,
        )
        receipt = rd.load_sealed_receipt(sealed, expected_digest=digest)
        self.assertEqual(receipt.g5_authorization, authorization)
        rd.validate_final_receipt(
            receipt, plan=plan, graph=graph, frozen_plan_id="c" * 64,
            staged_manifest_id="staged", source_sha=SOURCE_SHA,
        )

        # Refused at seal, so these bytes cannot be produced by the driver...
        for label, bad in (
            ("wrong source", rd.G5Authorization(
                who="juan", when="t", source_sha=OTHER_SOURCE_SHA,
                frozen_plan_id="c" * 64, edges=incomplete, risk="x")),
            ("wrong frozen plan", rd.G5Authorization(
                who="juan", when="t", source_sha=SOURCE_SHA,
                frozen_plan_id="d" * 64, edges=incomplete, risk="x")),
            ("wrong edges", rd.G5Authorization(
                who="juan", when="t", source_sha=SOURCE_SHA,
                frozen_plan_id="c" * 64, edges=frozenset({"f" * 64}), risk="x")),
        ):
            with self.subTest(case=label, layer="seal"):
                with self.assertRaises(rd.ReceiptError):
                    rd.seal_receipt(
                        plan, graph, source_sha=SOURCE_SHA, entries=entries,
                        approvals={}, frozen_plan_id="c" * 64,
                        staged_manifest_id="staged", g5_authorization=bad,
                    )

        # ...and refused again on the way back in, for bytes forged past it.
        import hashlib as _hashlib, json as _json
        for label, record in (
            ("wrong source", {**authorization.as_record(),
                              "source_sha": OTHER_SOURCE_SHA}),
            ("wrong frozen plan", {**authorization.as_record(),
                                   "frozen_plan_id": "d" * 64}),
            ("wrong edges", {**authorization.as_record(), "edges": ["f" * 64]}),
        ):
            with self.subTest(case=label, layer="validate"):
                body = _json.loads(_json.loads(sealed)["body"])
                body["g5_authorization"] = record
                forged_body = _json.dumps(body, sort_keys=True)
                forged = _json.dumps({
                    "body": forged_body,
                    "seal": _hashlib.sha256(forged_body.encode()).hexdigest(),
                }).encode()
                self.assertNotEqual(forged, sealed, "the forgery changed nothing")
                forged_receipt = rd.load_sealed_receipt(
                    forged, expected_digest=_hashlib.sha256(forged).hexdigest()
                )
                with self.assertRaises(rd.ReceiptError):
                    rd.validate_final_receipt(
                        forged_receipt, plan=plan, graph=graph,
                        frozen_plan_id="c" * 64, staged_manifest_id="staged",
                        source_sha=SOURCE_SHA,
                    )

    def test_malformed_sealed_g5_record_is_refused_on_load(self) -> None:
        import json as _json
        graph, plan, incomplete, entries = self._incomplete_plan_and_receipt_parts()
        authorization = rd.G5Authorization(
            who="juan", when="t", source_sha=SOURCE_SHA,
            frozen_plan_id="c" * 64, edges=incomplete, risk="accepted",
        )
        sealed, digest = rd.seal_receipt(
            plan, graph, source_sha=SOURCE_SHA, entries=entries, approvals={},
            frozen_plan_id="c" * 64, staged_manifest_id="staged",
            g5_authorization=authorization,
        )
        outer = _json.loads(sealed)
        body = _json.loads(outer["body"])
        body["g5_authorization"].pop("risk")
        import hashlib as _hashlib
        new_body = _json.dumps(body, sort_keys=True)
        tampered = _json.dumps({
            "body": new_body,
            "seal": _hashlib.sha256(new_body.encode()).hexdigest(),
        }).encode()
        self.assertNotEqual(tampered, sealed, "the tamper changed nothing")
        with self.assertRaises(rd.ReceiptError):
            rd.load_sealed_receipt(
                tampered, expected_digest=_hashlib.sha256(tampered).hexdigest()
            )

    def test_a_refused_binding_leaves_no_anchor_behind(self) -> None:
        """A store write is an effect even when no lane was called. The plan
        was anchored before the first check that knew the real frozen id, so a
        run that refused still left a plan record behind - contradicting
        "every mismatch refuses before any effect"."""
        plan, edges = self._g5_plan()
        store = rd._MemoryStore()
        authority = FixtureAuthority()
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, self.graph, FixtureLanes(available={"aw"}),
                skew=FixtureSkew(), authority=authority,
                providers=rd.Providers(
                    store=store, authority=authority,
                    measurement=AllRecordsResolve(), defer_g5=True,
                    g5_authorization=self._g5_record(frozen_plan_id="d" * 64),
                ),
                source_sha=SOURCE_SHA, approvals={}, state=rd.FixtureState(
                    changed_components={"aw": True}
                ),
            )
        self.assertEqual(
            [k for k in getattr(store, "_data", {})], [],
            "no artifact may be stored by a run that refused",
        )
        self.assertEqual(
            authority.recorded, {},
            "no digest may be recorded by a run that refused",
        )

    def test_g5_authorization_parsing_refuses_malformed_records(self) -> None:
        edge_id = "e" * 64
        good = (
            f"who=juan,when=2026-08-07T00:00:00Z,source={SOURCE_SHA},"
            f"plan={'c' * 64},edges={edge_id},risk=accepted"
        )
        parsed = rd.parse_g5_authorization(good)
        self.assertEqual(parsed.edges, frozenset({edge_id}))
        self.assertEqual(parsed.source_sha, SOURCE_SHA)

        for label, value in (
            ("short source", good.replace(SOURCE_SHA, "s1")),
            ("short plan", good.replace("c" * 64, "abc")),
            ("missing risk", good.replace(",risk=accepted", "")),
            ("empty edges", good.replace(f"edges={edge_id}", "edges=")),
            ("display-form edge", good.replace(edge_id, "aw<->server")),
        ):
            with self.subTest(case=label):
                with self.assertRaises(rd.ReceiptError):
                    rd.parse_g5_authorization(value)
        self.assertIsNone(rd.parse_g5_authorization(None))


if __name__ == "__main__":
    unittest.main(verbosity=1)
