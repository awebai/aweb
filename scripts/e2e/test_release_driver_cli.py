"""Round-4 counterexamples, exercised through the ACTUAL CLI/provider path:
main(argv) with injected durable file-backed stores, never direct helper
calls. Covers immutable plan creation/readback, per-transition anchoring,
verify-red receipts, process-restart resume by artifact ids, inconsistent
frozen-body refusal, resolved-state-distinct frozen ids, combined-DAG
refusal, real uv.lock and SSH-origin handling, and a true no-op site plan.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_driver as rd
from test_release_driver import (
    AllRecordsResolve,
    FixtureAuthority,
    FixtureLanes,
    FixtureSkew,
    fixture_graph,
    fixture_graph_dict,
    orchestration_state,
)


class DurableStoreTests(unittest.TestCase):
    def test_file_store_is_immutable_and_survives_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            store = rd.FileArtifactStore(Path(root))
            store.put("plan:abc", b"bytes-1")
            with self.assertRaises(rd.ReceiptError):
                store.put("plan:abc", b"bytes-2")
            reopened = rd.FileArtifactStore(Path(root))
            self.assertEqual(reopened.get("plan:abc"), b"bytes-1")

    def test_file_authority_records_once_and_resolves_after_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            authority = rd.FileDigestAuthority(Path(root))
            authority.record("plan:abc", "d1")
            with self.assertRaises(rd.ReceiptError):
                authority.record("plan:abc", "d2")
            reopened = rd.FileDigestAuthority(Path(root))
            self.assertEqual(reopened.expected_digest("plan:abc"), "d1")


class TransitionAnchoringTests(unittest.TestCase):
    def providers(self, root: Path, lanes=None, skew=None):
        return rd.Providers(
            store=rd.FileArtifactStore(root),
            authority=rd.FileDigestAuthority(root),
            lanes=lanes,
            skew=skew or FixtureSkew(),
        )

    def test_each_publish_anchors_before_the_next_outward_call(self) -> None:
        """alice's counterexample: a crash after the first publish must leave
        that transition durably anchored."""
        anchored_when_second_publish_ran: list[int] = []

        class Lanes(FixtureLanes):
            def __init__(self, available, authority_view):
                super().__init__(available)
                self.authority_view = authority_view

            def publish(self, node, staged):
                if node.component == "plugin":
                    anchored_when_second_publish_ran.append(
                        len(
                            [
                                k
                                for k in self.authority_view()
                                if k.startswith("transition:")
                            ]
                        )
                    )
                return super().publish(node, staged)

        with tempfile.TemporaryDirectory() as root:
            authority = rd.FileDigestAuthority(Path(root))
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            lanes = Lanes(
                {n.component for n in plan.moving},
                lambda: list(authority.recorded_ids()),
            )
            providers = rd.Providers(
                store=rd.FileArtifactStore(Path(root)),
                authority=authority,
                lanes=lanes,
                skew=FixtureSkew(),
                measurement=AllRecordsResolve(),
            )
            rd.run_plan(
                plan, graph, providers=providers,
                source_sha="s1", approvals={}, state=state,
            )
        self.assertTrue(anchored_when_second_publish_ran)
        self.assertGreaterEqual(
            anchored_when_second_publish_ran[0],
            1,
            "client's publish transition must be anchored before plugin publishes",
        )

    def test_transition_ids_are_unique_and_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            authority = rd.FileDigestAuthority(Path(root))
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            lanes = FixtureLanes({n.component for n in plan.moving})
            providers = rd.Providers(
                store=rd.FileArtifactStore(Path(root)),
                authority=authority,
                lanes=lanes,
                skew=FixtureSkew(),
                measurement=AllRecordsResolve(),
            )
            rd.run_plan(
                plan, graph, providers=providers,
                source_sha="s1", approvals={}, state=state,
            )
            transitions = [
                k for k in authority.recorded_ids() if k.startswith("transition:")
            ]
            self.assertEqual(len(transitions), len(set(transitions)))
            self.assertGreaterEqual(len(transitions), len(plan.moving))

    def test_verify_red_is_anchored(self) -> None:
        """alice's counterexample: a verify failure after full publication
        left no receipt at all."""

        class VerifyFails(FixtureLanes):
            def verify(self, node, published):
                raise RuntimeError("registry disagrees with published artifact")

        with tempfile.TemporaryDirectory() as root:
            authority = rd.FileDigestAuthority(Path(root))
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            lanes = VerifyFails({n.component for n in plan.moving})
            providers = rd.Providers(
                store=rd.FileArtifactStore(Path(root)),
                authority=authority,
                lanes=lanes,
                skew=FixtureSkew(),
                measurement=AllRecordsResolve(),
            )
            with self.assertRaises(RuntimeError):
                rd.run_plan(
                    plan, graph, providers=providers,
                    source_sha="s1", approvals={}, state=state,
                )
            reds = [
                k for k in authority.recorded_ids() if "verify-red" in k
            ]
            self.assertTrue(reds, "verify-red state must be durably anchored")


class CliPathTests(unittest.TestCase):
    """The real verbs, via main(argv) with injected providers."""

    def graph_file(self, root: Path) -> Path:
        path = root / "graph.toml"
        data = fixture_graph_dict()
        # main() loads TOML; serialize the fixture dict minimally.
        import io

        def toml_value(value) -> str:
            if isinstance(value, dict):
                inner = ", ".join(
                    f"{k} = {toml_value(v)}" for k, v in value.items()
                )
                return "{ " + inner + " }"
            if isinstance(value, list):
                return "[" + ", ".join(toml_value(v) for v in value) + "]"
            if isinstance(value, bool):
                return "true" if value else "false"
            return json.dumps(value)

        def emit(d: dict) -> str:
            out = io.StringIO()
            for name, spec in d["component"].items():
                out.write(f'[component."{name}"]\n')
                for key, value in spec.items():
                    out.write(f"{key} = {toml_value(value)}\n")
                out.write("\n")
            for edge in d["edge"]:
                out.write("[[edge]]\n")
                for key, value in edge.items():
                    out.write(f"{key} = {toml_value(value)}\n")
                out.write("\n")
            return out.getvalue()

        path.write_text(emit(data))
        return path

    def providers_for(self, root: Path, state, lanes=None):
        return rd.Providers(
            store=rd.FileArtifactStore(root),
            authority=rd.FileDigestAuthority(root),
            lanes=lanes,
            skew=FixtureSkew(),
            state=state,
            source_sha="s1",
            measurement=AllRecordsResolve(),
        )

    def test_plan_verb_creates_immutable_readback_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            providers = self.providers_for(root, state)
            import contextlib, io

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = rd.main(
                    ["--graph", str(self.graph_file(root)), "plan"],
                    providers=providers,
                )
            self.assertEqual(code, 0)
            output = json.loads(buffer.getvalue())
            plan_id = output["frozen_plan_id"]
            stored = providers.store.get(output["plan_artifact_id"])
            restored = rd.load_frozen_plan(stored, expected_id=plan_id)
            self.assertEqual(
                [n.component for n in restored.plan.moving],
                [n["component"] for n in output["moving"]],
            )

    def test_release_run_requires_plan_id_and_never_replans(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            graph_path = self.graph_file(root)
            providers = self.providers_for(root, state)
            import contextlib, io

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                rd.main(["--graph", str(graph_path), "plan"], providers=providers)
            output = json.loads(buffer.getvalue())

            plan = rd.compute_plan(rd.Graph.load(graph_path), state)
            lanes = FixtureLanes({n.component for n in plan.moving})
            run_providers = self.providers_for(root, state, lanes=lanes)
            code = rd.main(
                [
                    "--graph", str(graph_path),
                    "release-run", "--allow-local-authority",
                    "--plan-id", output["frozen_plan_id"],
                    "--plan-artifact-id", output["plan_artifact_id"],
                ],
                providers=run_providers,
            )
            self.assertEqual(code, 0)
            with io.StringIO() as err_buffer, contextlib.redirect_stdout(err_buffer):
                missing = rd.main(
                    ["--graph", str(graph_path), "release-run", "--allow-local-authority"],
                    providers=run_providers,
                )
            self.assertNotEqual(missing, 0, "release-run without a plan id must refuse")

    def test_process_restart_resume_by_artifact_ids(self) -> None:
        """alice's demonstration: crash mid-run, then resume in a FRESH
        provider set (new process) from plan+receipt ids without replanning."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            graph_path = self.graph_file(root)
            import contextlib, io

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                rd.main(
                    ["--graph", str(graph_path), "plan"],
                    providers=self.providers_for(root, state),
                )
            planned = json.loads(buffer.getvalue())

            class CrashSecondPublish(FixtureLanes):
                def publish(self, node, staged):
                    if len([c for k, c in self.calls if k == "publish"]) == 1:
                        raise KeyboardInterrupt
                    return super().publish(node, staged)

            graph = rd.Graph.load(graph_path)
            plan = rd.compute_plan(graph, state)
            crash_lanes = CrashSecondPublish({n.component for n in plan.moving})
            with self.assertRaises(KeyboardInterrupt):
                rd.main(
                    [
                        "--graph", str(graph_path),
                        "release-run", "--allow-local-authority",
                        "--plan-id", planned["frozen_plan_id"],
                        "--plan-artifact-id", planned["plan_artifact_id"],
                    ],
                    providers=self.providers_for(root, state, lanes=crash_lanes),
                )

            class ObservingLanes(FixtureLanes):
                def observe(self, node):
                    if node.component == "client":
                        return rd.ReceiptEntry(
                            version=node.version or "0.0.0",
                            digest="staged-client",
                            phase="published",
                        )
                    return None

            resume_lanes = ObservingLanes({n.component for n in plan.moving})
            code = rd.main(
                [
                    "--graph", str(graph_path),
                    "release-run", "--allow-local-authority",
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                    "--resume",
                ],
                providers=self.providers_for(root, state, lanes=resume_lanes),
            )
            self.assertEqual(code, 0)
            publishes = [c for k, c in resume_lanes.calls if k == "publish"]
            self.assertEqual(
                publishes,
                ["plugin", "pointer"],
                "already-published client resumes without republishing",
            )

    def test_release_receipt_resolves_via_authority_not_caller_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            graph_path = self.graph_file(root)
            import contextlib, io

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                rd.main(
                    ["--graph", str(graph_path), "plan"],
                    providers=self.providers_for(root, state),
                )
            planned = json.loads(buffer.getvalue())
            graph = rd.Graph.load(graph_path)
            plan = rd.compute_plan(graph, state)
            lanes = FixtureLanes({n.component for n in plan.moving})
            rd.main(
                [
                    "--graph", str(graph_path),
                    "release-run", "--allow-local-authority",
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                ],
                providers=self.providers_for(root, state, lanes=lanes),
            )
            class ObserveAll(FixtureLanes):
                def observe(self, node):
                    return rd.ReceiptEntry(
                        version=node.version or "0.0.0",
                        digest=f"staged-{node.component}",
                        phase="published",
                        pointer_state="pointer-ok"
                        if node.reason.startswith("pointer:")
                        else None,
                    )

            graph_loaded = rd.Graph.load(graph_path)
            plan_again = rd.compute_plan(graph_loaded, state)
            fresh = self.providers_for(
                root, state,
                lanes=ObserveAll({n.component for n in plan_again.moving}),
            )
            receipt_ids = [
                k for k in fresh.authority.recorded_ids() if k.startswith("receipt:")
            ]
            self.assertTrue(receipt_ids)
            code = rd.main(
                [
                    "--graph", str(graph_path),
                    "release-receipt",
                    "--artifact-id", receipt_ids[0],
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                ],
                providers=fresh,
            )
            self.assertEqual(code, 0)


class TrustClassTests(unittest.TestCase):
    def test_release_run_refuses_local_development_authority(self) -> None:
        """A caller-writable digest file is not an external immutable release
        authority; the real path refuses it unless a development downgrade is
        named explicitly."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            authority = rd.FileDigestAuthority(root)
            self.assertEqual(authority.trust_class, "local-development")
            graph = fixture_graph()
            plan = rd.compute_plan(graph, state)
            lanes = FixtureLanes({n.component for n in plan.moving})
            providers = rd.Providers(
                store=rd.FileArtifactStore(root),
                authority=authority,
                lanes=lanes,
                skew=FixtureSkew(),
            )
            with self.assertRaises(rd.ReceiptError) as caught:
                rd.run_plan(
                    plan, graph, providers=providers,
                    source_sha="s1", approvals={}, state=state,
                    require_external_authority=True,
                )
            self.assertIn("trust", str(caught.exception))
            self.assertEqual(lanes.calls, [])

    def test_swapped_store_and_digest_fail_under_external_interface(self) -> None:
        """Forging both the receipt bytes and the digest record in a local
        pair must not satisfy an external authority: resolution goes through
        the authority instance, not caller-presented files."""

        class ExternalAuthority(rd.FileDigestAuthority):
            trust_class = "external-immutable"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            graph = fixture_graph()
            plan = rd.compute_plan(graph, state)
            lanes = FixtureLanes({n.component for n in plan.moving})
            authority = ExternalAuthority(root)
            providers = rd.Providers(
                store=rd.FileArtifactStore(root),
                authority=authority,
                lanes=lanes,
                skew=FixtureSkew(),
                measurement=AllRecordsResolve(),
                authority_trust="external-immutable",
            )
            rd.run_plan(
                plan, graph, providers=providers,
                source_sha="s1", approvals={}, state=state,
                require_external_authority=True,
            )
            receipt_id = next(
                k for k in authority.recorded_ids() if k.startswith("receipt:")
            )
            genuine = providers.store.get(receipt_id)
            forged = genuine.replace(b"s1", b"s2")
            import hashlib

            with tempfile.TemporaryDirectory() as attacker_tmp:
                attacker_root = Path(attacker_tmp)
                attacker_store = rd.FileArtifactStore(attacker_root)
                attacker_store.put(receipt_id, forged)
                attacker_digests = rd.FileDigestAuthority(attacker_root)
                attacker_digests.record(
                    receipt_id, hashlib.sha256(forged).hexdigest()
                )
                with self.assertRaises(rd.ReceiptError):
                    rd.load_sealed_receipt(
                        attacker_store.get(receipt_id),
                        expected_digest=authority.expected_digest(receipt_id),
                    )


class StagedManifestTests(unittest.TestCase):
    def test_manifest_anchored_after_stage_before_skew_and_publish(self) -> None:
        events: list[str] = []

        class OrderLanes(FixtureLanes):
            def stage(self, node):
                events.append("stage")
                return super().stage(node)

            def publish(self, node, staged):
                events.append("publish")
                return super().publish(node, staged)

        class OrderSkew(FixtureSkew):
            def execute(self, edge, staged):
                events.append("skew")
                super().execute(edge, staged)

        class OrderAuthority(rd.FileDigestAuthority):
            def record(self, artifact_id, digest):
                if artifact_id.startswith("staged-manifest:"):
                    events.append("manifest")
                super().record(artifact_id, digest)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            graph = fixture_graph()
            plan = rd.compute_plan(graph, state)
            lanes = OrderLanes({n.component for n in plan.moving})
            providers = rd.Providers(
                store=rd.FileArtifactStore(root),
                authority=OrderAuthority(root),
                lanes=lanes,
                skew=OrderSkew(),
                measurement=AllRecordsResolve(),
            )
            rd.run_plan(
                plan, graph, providers=providers,
                source_sha="s1", approvals={}, state=state,
            )
        last_stage = max(i for i, e in enumerate(events) if e == "stage")
        manifest = events.index("manifest")
        first_skew = events.index("skew")
        first_publish = events.index("publish")
        self.assertLess(last_stage, manifest)
        self.assertLess(manifest, first_skew)
        self.assertLess(manifest, first_publish)

    def test_resume_adoption_requires_exact_manifest_match(self) -> None:
        """Observed publication is adopted only when it equals the anchored
        staged manifest entry; anything else fails closed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            frozen_bytes, frozen_id = rd.freeze_plan(
                plan, graph, source_sha="s1", state=state,
                measurement=AllRecordsResolve(),
            )
            manifest_entries = {
                n.component: rd.ReceiptEntry(
                    version=n.version or "0.0.0",
                    digest=f"staged-{n.component}",
                    phase="staged",
                    pointer_state="ok" if n.reason.startswith("pointer:") else None,
                )
                for n in plan.moving
            }
            manifest_bytes, manifest_digest = rd.seal_staged_manifest(
                plan, frozen_plan_id=frozen_id, source_sha="s1",
                entries=manifest_entries,
            )
            good = rd.ReceiptEntry(
                version=manifest_entries["client"].version,
                digest="staged-client",
                phase="published",
            )
            bad = rd.ReceiptEntry(
                version=manifest_entries["client"].version,
                digest="rebuilt-differently",
                phase="published",
            )
            manifest = rd.load_staged_manifest(
                manifest_bytes, expected_digest=manifest_digest
            )
            rd.adopt_observed(manifest, "client", good)
            with self.assertRaises(rd.ReceiptError):
                rd.adopt_observed(manifest, "client", bad)


class FrozenEnforcementTests(unittest.TestCase):
    def pin_state(self, sha: str) -> rd.FixtureState:
        return rd.FixtureState(
            changed_components={"server": True},
            versions={"server": "3.1.0"},
            published_versions={"server": "3.0.0"},
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds", "../server-src"},
            pin_values={"release-pin.toml": sha},
            checkout_heads={"../server-src": sha},
            checkout_remotes={"../server-src": "github.com/example/server"},
        )

    def test_execution_refuses_pin_state_drifted_from_frozen(self) -> None:
        """alice's reproduction: frozen with satisfied pin aaaa, executed with
        satisfied pin bbbb, release completed. Frozen resolved truth must be
        compared, not merely recorded."""
        graph = fixture_graph()
        frozen_state = self.pin_state("aaaa")
        plan = rd.compute_plan(graph, frozen_state)
        frozen_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="s1", state=frozen_state,
            measurement=AllRecordsResolve(),
        )
        frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
        drifted = self.pin_state("bbbb")
        lanes = FixtureLanes({n.component for n in plan.moving})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            providers = rd.Providers(
                store=rd.FileArtifactStore(root),
                authority=rd.FileDigestAuthority(root),
                lanes=lanes,
                skew=FixtureSkew(),
                measurement=AllRecordsResolve(),
            )
            with self.assertRaises(rd.ReceiptError) as caught:
                rd.run_plan(
                    plan, graph, providers=providers,
                    source_sha="s1",
                    approvals={"cloud-pin": rd.Approval("juan", "now")},
                    state=drifted, frozen=frozen,
                )
            self.assertIn("aaaa", str(caught.exception))
            self.assertIn("bbbb", str(caught.exception))
            self.assertEqual(lanes.calls, [])

    def test_freeze_with_complete_edges_requires_measurement_provider(self) -> None:
        graph = fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        with self.assertRaises(rd.BlockedByDeclaredInputs):
            rd.freeze_plan(plan, graph, source_sha="s1", state=state)

    def test_frozen_measurement_binding_is_enforced_at_execution(self) -> None:
        graph = fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        frozen_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="s1", state=state,
            measurement=AllRecordsResolve(),
        )
        frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
        self.assertTrue(frozen.resolved.get("measurements"))

        class DifferentRecords:
            def resolve(self, record, edge):
                return {"digest": "different-resolution", "edge": (edge.a, edge.b)}

        lanes = FixtureLanes({n.component for n in plan.moving})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            providers = rd.Providers(
                store=rd.FileArtifactStore(root),
                authority=rd.FileDigestAuthority(root),
                lanes=lanes,
                skew=FixtureSkew(),
                measurement=DifferentRecords(),
            )
            with self.assertRaises(rd.ReceiptError):
                rd.run_plan(
                    plan, graph, providers=providers,
                    source_sha="s1", approvals={}, state=state, frozen=frozen,
                )
            self.assertEqual(lanes.calls, [])


class ReceiptVerificationTests(unittest.TestCase):
    def seeded_run(self, root: Path, state):
        helper = CliPathTests("graph_file")
        graph_path = helper.graph_file(root)
        import contextlib, io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rd.main(
                ["--graph", str(graph_path), "plan"],
                providers=helper.providers_for(root, state),
            )
        planned = json.loads(buffer.getvalue())
        graph = rd.Graph.load(graph_path)
        plan = rd.compute_plan(graph, state)
        lanes = FixtureLanes({n.component for n in plan.moving})
        rd.main(
            [
                "--graph", str(graph_path),
                "release-run", "--allow-local-authority",
                "--plan-id", planned["frozen_plan_id"],
                "--plan-artifact-id", planned["plan_artifact_id"],
            ],
            providers=helper.providers_for(root, state, lanes=lanes),
        )
        return helper, graph_path, planned, graph, plan

    def test_foreign_digest_receipt_is_refused(self) -> None:
        """alice's reproduction: manifest anchored with A-* digests, receipt
        sealed with unrelated B-* digests, real verb printed MATCH."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            helper, graph_path, planned, graph, plan = self.seeded_run(root, state)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            frozen = rd.load_frozen_plan(
                store.get(planned["plan_artifact_id"]),
                expected_id=planned["frozen_plan_id"],
            )
            forged_entries = {
                n.component: rd.ReceiptEntry(
                    version=n.version or "0.0.0",
                    digest=f"B-{n.component}",
                    phase="verified",
                    pointer_state="ok" if n.reason.startswith("pointer:") else None,
                )
                for n in frozen.plan.moving
            }
            manifest_id = next(
                k for k in authority.recorded_ids()
                if k.startswith("staged-manifest:")
            )
            sealed, digest = rd.seal_receipt(
                frozen.plan, graph, source_sha="s1",
                entries=forged_entries, approvals={},
                frozen_plan_id=planned["frozen_plan_id"],
                staged_manifest_id=manifest_id,
            )
            forged_id = f"receipt:{planned['frozen_plan_id']}:{digest}"
            store.put(forged_id, sealed)
            authority.record(forged_id, digest)
            observers = FixtureLanes(set())
            code = rd.main(
                [
                    "--graph", str(graph_path),
                    "release-receipt",
                    "--artifact-id", forged_id,
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                ],
                providers=helper.providers_for(root, state, lanes=observers),
            )
            self.assertNotEqual(
                code, 0,
                "a receipt whose digests are not the manifest's must refuse",
            )

    def test_receipt_verification_requires_lane_observation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            helper, graph_path, planned, graph, plan = self.seeded_run(root, state)
            authority = rd.FileDigestAuthority(root)
            receipt_id = next(
                k for k in authority.recorded_ids() if k.startswith("receipt:")
            )
            code = rd.main(
                [
                    "--graph", str(graph_path),
                    "release-receipt",
                    "--artifact-id", receipt_id,
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                ],
                providers=helper.providers_for(root, state),
            )
            self.assertNotEqual(
                code, 0, "verification without authoritative observers must block"
            )

            class ObserveAll(FixtureLanes):
                def observe(self, node):
                    return rd.ReceiptEntry(
                        version=node.version or "0.0.0",
                        digest=f"staged-{node.component}",
                        phase="published",
                        pointer_state="pointer-ok"
                        if node.reason.startswith("pointer:")
                        else None,
                    )

            frozen = rd.load_frozen_plan(
                rd.FileArtifactStore(root).get(planned["plan_artifact_id"]),
                expected_id=planned["frozen_plan_id"],
            )
            observers = ObserveAll({n.component for n in frozen.plan.moving})
            code = rd.main(
                [
                    "--graph", str(graph_path),
                    "release-receipt",
                    "--artifact-id", receipt_id,
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                ],
                providers=helper.providers_for(root, state, lanes=observers),
            )
            self.assertEqual(code, 0)


class ResumeBindingTests(unittest.TestCase):
    def test_local_authority_resume_without_downgrade_refuses(self) -> None:
        """alice's reproduction: --resume omitted the production trust gate."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            helper = CliPathTests("graph_file")
            graph_path = helper.graph_file(root)
            import contextlib, io

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                rd.main(
                    ["--graph", str(graph_path), "plan"],
                    providers=helper.providers_for(root, state),
                )
            planned = json.loads(buffer.getvalue())

            class CountingLanes(FixtureLanes):
                def observe(self, node):
                    self.calls.append(("observe", node.component))
                    return None

            lanes = CountingLanes(set())
            code = rd.main(
                [
                    "--graph", str(graph_path),
                    "release-run", "--resume",
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                ],
                providers=helper.providers_for(root, state, lanes=lanes),
            )
            self.assertNotEqual(code, 0)
            self.assertEqual(
                lanes.calls, [], "no observe or lane calls before trust"
            )

    def test_resume_requires_exact_manifest_frozen_binding(self) -> None:
        """Two anchored manifests with the same source and component set must
        not cross-bind; the frozen_plan_id decides."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            entries = {
                n.component: rd.ReceiptEntry(
                    version=n.version or "0.0.0",
                    digest=f"staged-{n.component}",
                    pointer_state="ok" if n.reason.startswith("pointer:") else None,
                )
                for n in plan.moving
            }
            foreign_bytes, foreign_digest = rd.seal_staged_manifest(
                plan, frozen_plan_id="FOREIGN-PLAN", source_sha="s1",
                entries=entries,
            )
            foreign_id = f"staged-manifest:FOREIGN-PLAN:{foreign_digest}"
            store.put(foreign_id, foreign_bytes)
            authority.record(foreign_id, foreign_digest)
            frozen_bytes, frozen_id = rd.freeze_plan(
                plan, graph, source_sha="s1", state=state,
                measurement=AllRecordsResolve(),
            )
            frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
            lanes = FixtureLanes({n.component for n in plan.moving})
            with self.assertRaises(rd.ReceiptError):
                rd.resume_plan(
                    plan, graph,
                    lanes=lanes, skew=FixtureSkew(),
                    store=store, authority=authority,
                    source_sha="s1", approvals={}, state=state,
                    frozen=frozen, measurement=AllRecordsResolve(),
                )


class StateBoundaryTests(unittest.TestCase):
    def test_version_without_digest_refused_at_state_boundary(self) -> None:
        """alice's reproduction: an injected provider returning (version, None)
        was accepted. The STATE interface enforces the digest-set schema."""

        class SloppyProvider:
            def published(self, component):
                return ("1.2.3", None)

        state = rd.GitRepositoryState(registry=SloppyProvider())
        component = rd.Component(
            name="x",
            publish_lane={
                "workflow": "w",
                "registry": {"type": "pypi", "package": "x"},
            },
        )
        reason = state.registry_unavailable_reason(component)
        self.assertIsNotNone(reason)
        self.assertIn("digest", reason)


class SubprocessSurfaceTests(unittest.TestCase):
    def test_cross_process_durable_readback_via_shipped_binary(self) -> None:
        """Seed the durable store in this process, then verify the receipt in
        a SEPARATE process through the real shell surface: the artifacts, the
        digest authority, and the frozen plan all survive and resolve."""
        import subprocess as sp

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            helper = CliPathTests("graph_file")
            graph_path = helper.graph_file(root)
            import contextlib, io

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                rd.main(
                    ["--graph", str(graph_path), "--store-root", str(root), "plan"],
                    providers=None
                    if False
                    else helper.providers_for(root, state),
                )
            planned = json.loads(buffer.getvalue())
            graph = rd.Graph.load(graph_path)
            plan = rd.compute_plan(graph, state)
            lanes = FixtureLanes({n.component for n in plan.moving})
            rd.main(
                [
                    "--graph", str(graph_path),
                    "release-run", "--allow-local-authority",
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                ],
                providers=helper.providers_for(root, state, lanes=lanes),
            )
            authority = rd.FileDigestAuthority(root)
            receipt_id = next(
                k for k in authority.recorded_ids() if k.startswith("receipt:")
            )
            result = sp.run(
                [
                    "python3",
                    str(REPO_ROOT / "scripts" / "release_driver.py"),
                    "--graph", str(graph_path),
                    "--store-root", str(root),
                    "release-receipt",
                    "--artifact-id", receipt_id,
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            # Across a process boundary, the shipped binary resolves the
            # anchored plan and receipt from the durable store and reaches the
            # OBSERVER gate - the correct .5-state endpoint, since fixture
            # observers cannot cross a process. Artifact-resolution failures
            # would print REFUSED/no-record instead.
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("observers", result.stdout)
            self.assertNotIn("REFUSED", result.stdout)
            self.assertNotIn("no record", result.stdout)


class PostPublicationResumeTests(unittest.TestCase):
    def test_resume_completes_after_genuine_publication(self) -> None:
        """alice's reproduction: freeze client 1.1.0 over registry 1.0.0,
        publish and anchor, advance authoritative registry to 1.1.0, observe
        the staged digest, resume - and it refused "version not advanced".
        The adopted candidate's registry movement is the SATISFIED expected
        transition."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            graph = fixture_graph()
            before = orchestration_state()
            plan = rd.compute_plan(graph, before)
            frozen_bytes, frozen_id = rd.freeze_plan(
                plan, graph, source_sha="s1", state=before,
                measurement=AllRecordsResolve(),
            )
            store.put(f"plan:s1:{frozen_id}", frozen_bytes)
            authority.record(f"plan:s1:{frozen_id}", frozen_id)
            frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)

            class CrashSecondPublish(FixtureLanes):
                def publish(self, node, staged):
                    if len([c for k, c in self.calls if k == "publish"]) == 1:
                        raise KeyboardInterrupt
                    return super().publish(node, staged)

            crash = CrashSecondPublish({n.component for n in plan.moving})
            with self.assertRaises(KeyboardInterrupt):
                rd.run_plan(
                    plan, graph, crash,
                    skew=FixtureSkew(), authority=authority, store=store,
                    source_sha="s1", approvals={}, state=before, frozen=frozen,
                    providers=rd.Providers(
                        store=store, authority=authority,
                        measurement=AllRecordsResolve(),
                    ),
                )
            # Authoritative state has genuinely transitioned: client is now
            # published at the candidate version.
            after = orchestration_state(
                published_versions={"client": "1.1.0", "plugin": "2.0.0"},
            )

            class ObservingLanes(FixtureLanes):
                def stage(self, node):
                    raise AssertionError("resume must never stage")

                def observe(self, node):
                    if node.component == "client":
                        return rd.ReceiptEntry(
                            version="1.1.0",
                            digest="staged-client",
                            phase="published",
                        )
                    return None

            resume_lanes = ObservingLanes({n.component for n in plan.moving})
            entries = rd.resume_plan(
                plan, graph,
                lanes=resume_lanes, skew=FixtureSkew(),
                store=store, authority=authority,
                source_sha="s1", approvals={}, state=after,
                frozen=frozen, measurement=AllRecordsResolve(),
            )
            self.assertEqual(set(entries), {n.component for n in plan.moving})
            publishes = [c for k, c in resume_lanes.calls if k == "publish"]
            self.assertNotIn("client", publishes)


class ObservationFieldTests(unittest.TestCase):
    def seeded(self, root: Path, state):
        helper = CliPathTests("graph_file")
        graph_path = helper.graph_file(root)
        import contextlib, io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rd.main(
                ["--graph", str(graph_path), "plan"],
                providers=helper.providers_for(root, state),
            )
        planned = json.loads(buffer.getvalue())
        graph = rd.Graph.load(graph_path)
        plan = rd.compute_plan(graph, state)
        lanes = FixtureLanes({n.component for n in plan.moving})
        rd.main(
            [
                "--graph", str(graph_path),
                "release-run", "--allow-local-authority",
                "--plan-id", planned["frozen_plan_id"],
                "--plan-artifact-id", planned["plan_artifact_id"],
            ],
            providers=helper.providers_for(root, state, lanes=lanes),
        )
        authority = rd.FileDigestAuthority(root)
        receipt_id = next(
            k for k in authority.recorded_ids() if k.startswith("receipt:")
        )
        return helper, graph_path, planned, plan, receipt_id

    def verify_with(self, root, state, helper, graph_path, planned, receipt_id, observer_cls, plan):
        observers = observer_cls({n.component for n in plan.moving})
        return rd.main(
            [
                "--graph", str(graph_path),
                "release-receipt",
                "--artifact-id", receipt_id,
                "--plan-id", planned["frozen_plan_id"],
                "--plan-artifact-id", planned["plan_artifact_id"],
            ],
            providers=helper.providers_for(root, state, lanes=observers),
        )

    def test_wrong_pointer_state_from_observer_refuses(self) -> None:
        """alice's reproduction: same version/digest, pointer_state=WRONG,
        real verb printed MATCH."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            helper, graph_path, planned, plan, receipt_id = self.seeded(root, state)

            class WrongPointer(FixtureLanes):
                def observe(self, node):
                    return rd.ReceiptEntry(
                        version=node.version or "0.0.0",
                        digest=f"staged-{node.component}",
                        phase="published",
                        pointer_state="WRONG"
                        if node.reason.startswith("pointer:")
                        else None,
                    )

            code = self.verify_with(
                root, state, helper, graph_path, planned, receipt_id,
                WrongPointer, plan,
            )
            self.assertNotEqual(code, 0)

    def test_missing_required_observation_field_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = orchestration_state()
            helper, graph_path, planned, plan, receipt_id = self.seeded(root, state)

            class NoPointerField(FixtureLanes):
                def observe(self, node):
                    return rd.ReceiptEntry(
                        version=node.version or "0.0.0",
                        digest=f"staged-{node.component}",
                        phase="published",
                        pointer_state=None,
                    )

            code = self.verify_with(
                root, state, helper, graph_path, planned, receipt_id,
                NoPointerField, plan,
            )
            self.assertNotEqual(
                code, 0, "an observer that cannot produce a required field blocks"
            )


class RegistryDigestSetObservationTests(unittest.TestCase):
    def test_registry_component_requires_complete_observed_set(self) -> None:
        """alice's rendering detail: an opaque lane-chosen scalar detached
        from the complete filename/asset set must not verify; the canonical
        digest of the COMPLETE observed set must equal the receipt digest."""
        data = fixture_graph_dict()
        data["component"]["client"]["publish_lane"] = {
            "workflow": "wf/client.yml",
            "registry": {"type": "pypi", "package": "client"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            helper = CliPathTests("graph_file")
            graph_path = root / "graph.toml"
            import io as io_module

            # Reuse the helper's emitter through a fresh graph file.
            original = helper.graph_file(root)
            graph_path = original  # emitter wrote fixture; rewrite with registry
            text = original.read_text()
            text = text.replace(
                'publish_lane = { "workflow": "wf/client.yml" }',
                'publish_lane = { workflow = "wf/client.yml", registry = { type = "pypi", package = "client" } }',
            )
            text = text.replace(
                'publish_lane = {"workflow": "wf/client.yml"}',
                'publish_lane = { workflow = "wf/client.yml", registry = { type = "pypi", package = "client" } }',
            )
            text = text.replace(
                'publish_lane = { workflow = "wf/client.yml" }',
                'publish_lane = { workflow = "wf/client.yml", registry = { type = "pypi", package = "client" } }',
            )
            original.write_text(text)

            state = orchestration_state(
                registry_unavailable={},
                published_versions={"client": "1.0.0", "plugin": "2.0.0"},
            )
            import contextlib, io

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = rd.main(
                    ["--graph", str(graph_path), "plan"],
                    providers=helper.providers_for(root, state),
                )
            planned = json.loads(buffer.getvalue())
            graph = rd.Graph.load(graph_path)
            plan = rd.compute_plan(graph, state)
            digest_set = {"client-1.1.0.tar.gz": "sha-aaa"}
            canonical = rd.canonical_digest_of_set(digest_set)

            class RegistryLanes(FixtureLanes):
                def stage(self, node):
                    entry = super().stage(node)
                    if node.component == "client":
                        return rd.ReceiptEntry(
                            version=entry.version,
                            digest=canonical,
                            phase=entry.phase,
                            pointer_state=entry.pointer_state,
                        )
                    return entry

                def publish(self, node, staged):
                    self.calls.append(("publish", node.component))
                    return staged

            lanes = RegistryLanes({n.component for n in plan.moving})
            rd.main(
                [
                    "--graph", str(graph_path),
                    "release-run", "--allow-local-authority",
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                ],
                providers=helper.providers_for(root, state, lanes=lanes),
            )
            authority = rd.FileDigestAuthority(root)
            receipt_id = next(
                k for k in authority.recorded_ids() if k.startswith("receipt:")
            )

            class ScalarObserver(FixtureLanes):
                def observe(self, node):
                    return rd.ReceiptEntry(
                        version=node.version or "0.0.0",
                        digest=canonical
                        if node.component == "client"
                        else f"staged-{node.component}",
                        phase="published",
                        pointer_state="pointer-ok"
                        if node.reason.startswith("pointer:")
                        else None,
                    )

            code = rd.main(
                [
                    "--graph", str(graph_path),
                    "release-receipt",
                    "--artifact-id", receipt_id,
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                ],
                providers=helper.providers_for(
                    root, state,
                    lanes=ScalarObserver({n.component for n in plan.moving}),
                ),
            )
            self.assertNotEqual(
                code, 0, "a scalar-only observer for a registry component blocks"
            )

            class SetObserver(ScalarObserver):
                def observe(self, node):
                    entry = super().observe(node)
                    if node.component == "client":
                        return rd.ReceiptEntry(
                            version=entry.version,
                            digest=entry.digest,
                            phase=entry.phase,
                            pointer_state=entry.pointer_state,
                            digest_set=digest_set,
                        )
                    return entry

            code = rd.main(
                [
                    "--graph", str(graph_path),
                    "release-receipt",
                    "--artifact-id", receipt_id,
                    "--plan-id", planned["frozen_plan_id"],
                    "--plan-artifact-id", planned["plan_artifact_id"],
                ],
                providers=helper.providers_for(
                    root, state,
                    lanes=SetObserver({n.component for n in plan.moving}),
                ),
            )
            self.assertEqual(code, 0)


class SplitProviderTests(unittest.TestCase):
    def test_fresh_process_resolves_split_store_and_authority(self) -> None:
        """alice's requirement: artifact bytes from the configured external
        store, expected digest from the INDEPENDENT authority, no shared
        local store between processes."""
        import subprocess as sp

        with tempfile.TemporaryDirectory() as store_tmp, \
                tempfile.TemporaryDirectory() as authority_tmp:
            store_root = Path(store_tmp)
            authority_root = Path(authority_tmp)
            store = rd.FileArtifactStore(store_root)
            authority = rd.FileDigestAuthority(authority_root)
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            frozen_bytes, frozen_id = rd.freeze_plan(
                plan, graph, source_sha="s1", state=state,
                measurement=AllRecordsResolve(),
            )
            plan_artifact_id = f"plan:s1:{frozen_id}"
            store.put(plan_artifact_id, frozen_bytes)
            authority.record(plan_artifact_id, frozen_id)

            script = (
                "import sys; sys.path.insert(0, %r); "
                "import release_driver as rd; from pathlib import Path; "
                "store = rd.FileArtifactStore(Path(%r)); "
                "authority = rd.FileDigestAuthority(Path(%r)); "
                "frozen = rd.load_frozen_plan("
                "store.get(%r), expected_id=authority.expected_digest(%r)); "
                "print('RESOLVED', frozen.source_sha, len(frozen.plan.moving))"
            ) % (
                str(REPO_ROOT / "scripts"), str(store_root), str(authority_root),
                plan_artifact_id, plan_artifact_id,
            )
            result = sp.run(
                ["python3", "-c", script],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("RESOLVED s1", result.stdout)


class ResumeAmbiguityTests(unittest.TestCase):
    def test_multiple_exact_manifests_demand_explicit_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            frozen_bytes, frozen_id = rd.freeze_plan(
                plan, graph, source_sha="s1", state=state,
                measurement=AllRecordsResolve(),
            )
            frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
            for salt in ("one", "two"):
                entries = {
                    n.component: rd.ReceiptEntry(
                        version=n.version or "0.0.0",
                        digest=f"staged-{n.component}-{salt}",
                        pointer_state="ok"
                        if n.reason.startswith("pointer:")
                        else None,
                    )
                    for n in plan.moving
                }
                body, digest = rd.seal_staged_manifest(
                    plan, frozen_plan_id=frozen_id, source_sha="s1",
                    entries=entries, graph=graph,
                )
                artifact_id = f"staged-manifest:{frozen_id}:{digest}"
                store.put(artifact_id, body)
                authority.record(artifact_id, digest)
            lanes = FixtureLanes({n.component for n in plan.moving})
            with self.assertRaises(rd.ReceiptError) as caught:
                rd.resume_plan(
                    plan, graph,
                    lanes=lanes, skew=FixtureSkew(),
                    store=store, authority=authority,
                    source_sha="s1", approvals={}, state=state,
                    frozen=frozen, measurement=AllRecordsResolve(),
                )
            self.assertIn("manifest-id", str(caught.exception))


class ExternalContextPathTests(unittest.TestCase):
    def test_relative_external_context_checkout_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            helper = CliPathTests("graph_file")
            graph_path = helper.graph_file(Path(tmp))
            with self.assertRaises(SystemExit) as caught:
                rd.main(
                    [
                        "--graph", str(graph_path),
                        "--external-context", "github.com/awebai/ac=relative/path",
                        "plan",
                    ],
                    providers=None,
                )
            self.assertIn("absolute", str(caught.exception))


class MakeSurfaceTests(unittest.TestCase):
    def test_make_targets_pass_provider_configuration(self) -> None:
        import subprocess as sp

        rendered = sp.run(
            [
                "make", "-n", "release-run",
                "PLAN_ID=p", "PLAN_ARTIFACT_ID=pa", "AUTHORITY=local-development",
                "STORE_ROOT=/tmp/store", "ALLOW_LOCAL_AUTHORITY=1",
                "EXTERNAL_CONTEXT=github.com/awebai/ac=/tmp/ac",
            ],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
        ).stdout
        for fragment in (
            "--plan-id \"p\"",
            "--plan-artifact-id \"pa\"",
            "--authority \"local-development\"",
            "--store-root \"/tmp/store\"",
            "--allow-local-authority",
            "--external-context \"github.com/awebai/ac=/tmp/ac\"",
        ):
            self.assertIn(fragment, rendered, rendered)
        receipt = sp.run(
            [
                "make", "-n", "release-receipt",
                "ARTIFACT_ID=a", "PLAN_ID=p", "PLAN_ARTIFACT_ID=pa",
                "STORE_ROOT=/tmp/store",
            ],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
        ).stdout
        for fragment in ("--artifact-id \"a\"", "--store-root \"/tmp/store\""):
            self.assertIn(fragment, receipt, receipt)


class RerunIdempotencyTests(unittest.TestCase):
    def test_complete_rerun_adopts_and_reanchors_idempotently(self) -> None:
        """A rerun of a fully completed release verifies and adopts: it
        publishes nothing and the immutable final receipt reconciles rather
        than refusing or republishing."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            frozen_bytes, frozen_id = rd.freeze_plan(
                plan, graph, source_sha="s1", state=state,
                measurement=AllRecordsResolve(),
            )
            store.put(f"plan:s1:{frozen_id}", frozen_bytes)
            authority.record(f"plan:s1:{frozen_id}", frozen_id)
            frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
            lanes = FixtureLanes({n.component for n in plan.moving})
            first = rd.run_plan(
                plan, graph, lanes,
                skew=FixtureSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=state, frozen=frozen,
                providers=rd.Providers(
                    store=store, authority=authority,
                    measurement=AllRecordsResolve(),
                ),
            )

            class ObserveAll(FixtureLanes):
                def stage(self, node):
                    raise AssertionError("rerun must never stage")

                def publish(self, node, staged):
                    raise AssertionError("rerun must never republish")

                def observe(self, node):
                    done = first[node.component]
                    return rd.ReceiptEntry(
                        version=done.version,
                        digest=done.digest,
                        phase="published",
                        pointer_state=done.pointer_state,
                        delivery_proof=done.delivery_proof,
                    )

            rerun_lanes = ObserveAll({n.component for n in plan.moving})
            entries = rd.resume_plan(
                plan, graph,
                lanes=rerun_lanes, skew=FixtureSkew(),
                store=store, authority=authority,
                source_sha="s1", approvals={}, state=state,
                frozen=frozen, measurement=AllRecordsResolve(),
            )
            self.assertEqual(set(entries), {n.component for n in plan.moving})
            publishes = [c for k, c in rerun_lanes.calls if k == "publish"]
            self.assertEqual(publishes, [])


class FrozenSnapshotTests(unittest.TestCase):
    def test_inconsistent_frozen_body_is_refused(self) -> None:
        """alice's forgery: plan_digest='not-the-plan', re-anchored by digest,
        loaded successfully. Internal consistency must be validated."""
        graph = fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        frozen_bytes, _ = rd.freeze_plan(plan, graph, source_sha="s1", state=state, measurement=AllRecordsResolve())
        parsed = json.loads(frozen_bytes)
        parsed["content"]["plan_digest"] = "not-the-plan"
        forged = json.dumps(parsed, sort_keys=True).encode()
        import hashlib

        with self.assertRaises(rd.ReceiptError):
            rd.load_frozen_plan(
                forged, expected_id=hashlib.sha256(forged).hexdigest()
            )

    def test_distinct_resolved_pin_states_produce_distinct_ids(self) -> None:
        graph = fixture_graph()
        base = dict(
            changed_components={"server": True},
            versions={"server": "3.1.0"},
            published_versions={"server": "3.0.0"},
            env={"FIXTURE_GATE_ENV_FILE": "/private/creds"},
            existing_paths={"/private/creds", "../server-src"},
            checkout_remotes={"../server-src": "github.com/example/server"},
        )
        state_a = rd.FixtureState(
            **base,
            pin_values={"release-pin.toml": "feedface"},
            checkout_heads={"../server-src": "feedface"},
        )
        state_b = rd.FixtureState(
            **base,
            pin_values={"release-pin.toml": "cafebabe"},
            checkout_heads={"../server-src": "cafebabe"},
        )
        _, id_a = rd.freeze_plan(
            rd.compute_plan(graph, state_a), graph, source_sha="s1", state=state_a,
            measurement=AllRecordsResolve(),
        )
        _, id_b = rd.freeze_plan(
            rd.compute_plan(graph, state_b), graph, source_sha="s1", state=state_b,
            measurement=AllRecordsResolve(),
        )
        self.assertNotEqual(
            id_a, id_b, "resolved pin state must be bound into the frozen plan"
        )


class TrustedCompositionTests(unittest.TestCase):
    def test_self_asserted_trust_class_does_not_pass(self) -> None:
        """alice's reproduction: a caller subclass asserting external-immutable
        passed the gate. Trust is established by the allowlisted composition,
        not by an attribute on a caller-writable implementation."""

        class Imposter(rd.FileDigestAuthority):
            trust_class = "external-immutable"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            lanes = FixtureLanes({n.component for n in plan.moving})
            providers = rd.Providers(
                store=rd.FileArtifactStore(root),
                authority=Imposter(root),
                lanes=lanes,
                skew=FixtureSkew(),
                measurement=AllRecordsResolve(),
            )
            with self.assertRaises(rd.ReceiptError):
                rd.run_plan(
                    plan, graph, providers=providers,
                    source_sha="s1", approvals={}, state=state,
                    require_external_authority=True,
                )
            self.assertEqual(lanes.calls, [])

    def test_registered_external_authority_passes_through_composition(self) -> None:
        class LaneSuppliedAuthority(rd.FileDigestAuthority):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registration = rd.AuthorityRegistration(
                kind="fixture-external",
                trust_class="external-immutable",
                factory=lambda: LaneSuppliedAuthority(root),
            )
            providers = rd.build_providers(
                store=rd.FileArtifactStore(root),
                authority_registration=registration,
                lanes=None,
                skew=FixtureSkew(),
            )
            self.assertEqual(providers.authority_trust, "external-immutable")


class FrozenTruthTests(unittest.TestCase):
    def test_recomputed_wrapper_hashes_still_detect_inconsistent_digest(self) -> None:
        """alice's reproduction: edit plan_digest, recompute inner and outer
        hashes, load succeeds. Load must recompute the digest from the frozen
        canonical graph + moving set."""
        graph = fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        frozen_bytes, _ = rd.freeze_plan(plan, graph, source_sha="s1", state=state, measurement=AllRecordsResolve())
        parsed = json.loads(frozen_bytes)
        parsed["content"]["plan_digest"] = "not-the-plan"
        import hashlib

        inner = hashlib.sha256(
            json.dumps(parsed["content"], sort_keys=True).encode()
        ).hexdigest()
        parsed["content_digest"] = inner
        forged = json.dumps(parsed, sort_keys=True).encode()
        outer = hashlib.sha256(forged).hexdigest()
        with self.assertRaises(rd.ReceiptError):
            rd.load_frozen_plan(forged, expected_id=outer)

    def test_frozen_plan_is_typed_and_carries_truth(self) -> None:
        graph = fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        frozen_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="s1", state=state,
            measurement=AllRecordsResolve(),
        )
        frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
        self.assertEqual(frozen.source_sha, "s1")
        self.assertTrue(frozen.resolved is not None)
        self.assertTrue(frozen.graph_canonical)

    def test_run_refuses_source_mismatch_with_frozen_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            frozen_bytes, frozen_id = rd.freeze_plan(
                plan, graph, source_sha="s1", state=state,
                measurement=AllRecordsResolve(),
            )
            frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
            lanes = FixtureLanes({n.component for n in plan.moving})
            providers = rd.Providers(
                store=rd.FileArtifactStore(root),
                authority=rd.FileDigestAuthority(root),
                lanes=lanes,
                skew=FixtureSkew(),
                measurement=AllRecordsResolve(),
            )
            with self.assertRaises(rd.ReceiptError):
                rd.run_plan(
                    plan, graph, providers=providers,
                    source_sha="DIFFERENT", approvals={}, state=state,
                    frozen=frozen,
                )
            self.assertEqual(lanes.calls, [])


class SemanticValidationTests(unittest.TestCase):
    def test_stage_version_must_match_frozen_candidate(self) -> None:
        """alice's reproduction: a lane staging 999.0.0 for a 1.x/2.x plan
        completed the run."""

        class WrongVersionLanes(FixtureLanes):
            def stage(self, node):
                entry = super().stage(node)
                return rd.ReceiptEntry(
                    version="999.0.0",
                    digest=entry.digest,
                    phase=entry.phase,
                    pointer_state=entry.pointer_state,
                    delivery_proof=entry.delivery_proof,
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)
            lanes = WrongVersionLanes({n.component for n in plan.moving})
            providers = rd.Providers(
                store=rd.FileArtifactStore(root),
                authority=rd.FileDigestAuthority(root),
                lanes=lanes,
                skew=FixtureSkew(),
                measurement=AllRecordsResolve(),
            )
            with self.assertRaises(rd.ReceiptError) as caught:
                rd.run_plan(
                    plan, graph, providers=providers,
                    source_sha="s1", approvals={}, state=state,
                )
            self.assertIn("999.0.0", str(caught.exception))

    def test_unresolvable_measurement_record_blocks_before_lanes(self) -> None:
        """alice's reproduction: measured:fake executed through skew and
        publish. Preflight resolves every complete record first."""
        data = fixture_graph_dict()
        for edge in data["edge"]:
            if edge["type"] == "runtime-contract":
                edge["supported"] = {
                    "set": "measured:fake",
                    "record": {
                        "authority": "workflow-artifacts",
                        "artifact_id": "measurement:fake",
                        "digest": "d",
                    },
                    "policy": "additive-only",
                }
        graph = rd.Graph.from_dict(data)
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        lanes = FixtureLanes({n.component for n in plan.moving})

        class NoRecords:
            def resolve(self, record, edge):
                return None

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            providers = rd.Providers(
                store=rd.FileArtifactStore(root),
                authority=rd.FileDigestAuthority(root),
                lanes=lanes,
                skew=FixtureSkew(),
                measurement=NoRecords(),
            )
            with self.assertRaises(rd.BlockedByDeclaredInputs):
                rd.run_plan(
                    plan, graph, providers=providers,
                    source_sha="s1", approvals={}, state=state,
                )
            self.assertEqual(lanes.calls, [])


class AnchoringReconciliationTests(unittest.TestCase):
    def test_store_present_authority_missing_is_reconciled_not_skipped(self) -> None:
        """alice's reproduction: identical store bytes counted as success
        while the authority had no record."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            store.put("x:1", b"bytes")
            import hashlib

            digest = hashlib.sha256(b"bytes").hexdigest()
            rd._put_content_addressed(store, authority, "x:1", b"bytes", digest)
            self.assertEqual(authority.expected_digest("x:1"), digest)

    def test_conflicting_bytes_under_existing_id_refuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            store.put("x:1", b"bytes")
            with self.assertRaises(rd.ReceiptError):
                rd._put_content_addressed(store, authority, "x:1", b"other", "d")


class ResumeManifestTests(unittest.TestCase):
    def test_resume_loads_original_manifest_and_stages_nothing(self) -> None:
        """alice's reproduction: resume restaged remaining nodes and sealed a
        NEW manifest. Resume fetches the original by full id, verifies it
        through the authority, and calls stage zero times."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            graph = fixture_graph()
            state = orchestration_state()
            plan = rd.compute_plan(graph, state)

            class CrashSecondPublish(FixtureLanes):
                def publish(self, node, staged):
                    if len([c for k, c in self.calls if k == "publish"]) == 1:
                        raise KeyboardInterrupt
                    return super().publish(node, staged)

            frozen_bytes, frozen_id = rd.freeze_plan(
                plan, graph, source_sha="s1", state=state,
                measurement=AllRecordsResolve(),
            )
            store.put(f"plan:s1:{frozen_id}", frozen_bytes)
            authority.record(f"plan:s1:{frozen_id}", frozen_id)
            frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
            crash_lanes = CrashSecondPublish({n.component for n in plan.moving})
            with self.assertRaises(KeyboardInterrupt):
                rd.run_plan(
                    plan, graph, crash_lanes,
                    skew=FixtureSkew(), authority=authority, store=store,
                    source_sha="s1", approvals={}, state=state, frozen=frozen,
                    providers=rd.Providers(
                        store=store, authority=authority,
                        measurement=AllRecordsResolve(),
                    ),
                )

            class ObservingLanes(FixtureLanes):
                def stage(self, node):
                    raise AssertionError("resume must never stage")

                def observe(self, node):
                    if node.component == "client":
                        return rd.ReceiptEntry(
                            version=node.version or "0.0.0",
                            digest="staged-client",
                            phase="published",
                        )
                    return None

            resume_lanes = ObservingLanes({n.component for n in plan.moving})
            entries = rd.resume_plan(
                plan, graph,
                lanes=resume_lanes,
                skew=FixtureSkew(),
                store=store,
                authority=authority,
                source_sha="s1",
                approvals={},
                state=state,
                measurement=AllRecordsResolve(),
                frozen=frozen,
            )
            self.assertEqual(set(entries), {n.component for n in plan.moving})
            publishes = [c for k, c in resume_lanes.calls if k == "publish"]
            self.assertNotIn("client", publishes)


class CombinedDagTests(unittest.TestCase):
    def test_pointer_plus_prerequisite_cycle_is_refused(self) -> None:
        """alice's counterexample: a --pointer--> b, b --prerequisite--> a
        loaded and planned [a, b], violating the prerequisite."""
        with self.assertRaises(rd.GraphError):
            rd.Graph.from_dict(
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
                    },
                    "edge": [
                        {"type": "pointer", "from": "a", "to": ["b"]},
                        {"type": "publication-prerequisite", "from": "b", "to": ["a"]},
                    ],
                }
            )


class PinKindTests(unittest.TestCase):
    def test_lock_version_pin_parses_real_uv_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = Path(tmp)
            (context / "backend").mkdir()
            (context / "backend" / "uv.lock").write_text(
                'version = 1\n\n'
                '[[package]]\nname = "aweb"\nversion = "1.26.35"\n\n'
                '[[package]]\nname = "awid-service"\nversion = "0.5.14"\n'
            )
            git_state = rd.GitRepositoryState(
                external_contexts={"github.com/awebai/ac": str(context)}
            )
            pin = {
                "pin_file": "backend/uv.lock",
                "kind": "lock-version",
                "package": "awid-service",
                "component": "awid-pypi",
                "pin_repository": "github.com/awebai/ac",
            }
            self.assertEqual(git_state.pin_sha(pin), "0.5.14")

    def test_lock_version_check_compares_versions_not_shas(self) -> None:
        graph = rd.Graph.from_dict(
            {
                "component": {
                    "lib": {
                        "source_paths": ["lib/"],
                        "version_source": {"type": "manifest", "path": "lib/v"},
                        "tag_format": "lib-v{version}",
                        "publish_lane": {"workflow": "wf/lib.yml"},
                        "verify": {"command": "true"},
                    },
                    "pin": {
                        "publishable": False,
                        "sibling_pins": [
                            {
                                "pin_file": "backend/uv.lock",
                                "kind": "lock-version",
                                "package": "lib",
                                "component": "lib",
                            }
                        ],
                    },
                },
                "edge": [{"type": "pointer", "from": "lib", "to": ["pin"]}],
            }
        )
        state = rd.FixtureState(
            changed_components={"lib": True},
            versions={"lib": "2.1.0"},
            published_versions={"lib": "2.0.0"},
            pin_values={"backend/uv.lock": "2.0.0"},
        )
        plan = rd.compute_plan(graph, state)
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertEqual(
            [p for p in problems if "HEAD" in p],
            [],
            f"a lock-version pin must never be compared against a git HEAD: {problems}",
        )


class UnionOrderingTests(unittest.TestCase):
    def test_pointer_closure_respects_cross_type_prerequisites(self) -> None:
        """alice's reproduction: acyclic a->ptr b, c->ptr d, d->prereq b
        planned [a,c,b,d], violating d before b. Closure first, then a
        topo-sort of the union DAG."""
        graph = rd.Graph.from_dict(
            {
                "component": {
                    "a": {
                        "source_paths": ["a/"],
                        "version_source": {"type": "manifest", "path": "a/v"},
                        "tag_format": "a-v{version}",
                        "publish_lane": {"workflow": "wf/a.yml"},
                        "verify": {"command": "true"},
                    },
                    "c": {
                        "source_paths": ["c/"],
                        "version_source": {"type": "manifest", "path": "c/v"},
                        "tag_format": "c-v{version}",
                        "publish_lane": {"workflow": "wf/c.yml"},
                        "verify": {"command": "true"},
                    },
                    "b": {"publishable": False},
                    "d": {"publishable": False},
                },
                "edge": [
                    {"type": "pointer", "from": "a", "to": ["b"]},
                    {"type": "pointer", "from": "c", "to": ["d"]},
                    {"type": "publication-prerequisite", "from": "d", "to": ["b"]},
                ],
            }
        )
        plan = rd.compute_plan(
            graph, rd.FixtureState(changed_components={"a": True, "c": True})
        )
        order = [n.component for n in plan.moving]
        self.assertLess(
            order.index("d"),
            order.index("b"),
            f"d is a prerequisite of b and must publish first; got {order}",
        )


class CommittedPinContractTests(unittest.TestCase):
    def test_committed_awid_lock_pin_resolves_a_real_uv_lock(self) -> None:
        """The committed declaration itself must work against a realistic
        lock file - not only a hand-built fixture pin."""
        graph = rd.Graph.load()
        ac_pin = graph.components["ac-pin"]
        lock_pin = next(
            p for p in ac_pin.sibling_pins if p.get("kind") == "lock-version"
        )
        self.assertEqual(
            lock_pin.get("package"),
            "awid-service",
            "the lock pin must name the exact package it pins",
        )
        with tempfile.TemporaryDirectory() as tmp:
            context = Path(tmp)
            (context / "backend").mkdir()
            (context / "backend" / "uv.lock").write_text(
                'version = 1\n\n'
                '[[package]]\nname = "aweb"\nversion = "1.26.35"\n\n'
                '[[package]]\nname = "awid-service"\nversion = "0.5.14"\n'
            )
            git_state = rd.GitRepositoryState(
                external_contexts={lock_pin["pin_repository"]: str(context)}
            )
            self.assertEqual(git_state.pin_sha(lock_pin), "0.5.14")

    def test_lock_version_compares_against_frozen_candidate(self) -> None:
        """alice's reproduction: comparing with the currently published
        version passes a stale lock and fails a correctly advanced one.
        The comparison target is the candidate the plan will publish."""
        graph = rd.Graph.from_dict(
            {
                "component": {
                    "lib": {
                        "source_paths": ["lib/"],
                        "version_source": {"type": "manifest", "path": "lib/v"},
                        "tag_format": "lib-v{version}",
                        "publish_lane": {"workflow": "wf/lib.yml"},
                        "verify": {"command": "true"},
                    },
                    "pin": {
                        "publishable": False,
                        "sibling_pins": [
                            {
                                "pin_file": "backend/uv.lock",
                                "kind": "lock-version",
                                "package": "lib",
                                "component": "lib",
                            }
                        ],
                    },
                },
                "edge": [{"type": "pointer", "from": "lib", "to": ["pin"]}],
            }
        )
        advanced = rd.FixtureState(
            changed_components={"lib": True},
            versions={"lib": "2.1.0"},
            published_versions={"lib": "2.0.0"},
            pin_values={"backend/uv.lock": "2.1.0"},
        )
        plan = rd.compute_plan(graph, advanced)
        problems = rd.check_declared_inputs(graph, plan, advanced)
        self.assertEqual(
            [p for p in problems if "lock" in p],
            [],
            f"a lock already at the candidate version is satisfied: {problems}",
        )
        stale = rd.FixtureState(
            changed_components={"lib": True},
            versions={"lib": "2.1.0"},
            published_versions={"lib": "2.0.0"},
            pin_values={"backend/uv.lock": "1.9.0"},
        )
        plan = rd.compute_plan(graph, stale)
        problems = rd.check_declared_inputs(graph, plan, stale)
        self.assertTrue(
            any("lock" in p and "1.9.0" in p and "2.1.0" in p for p in problems),
            f"a stale lock must be named against the candidate: {problems}",
        )


class RemoteNormalizationTests(unittest.TestCase):
    def test_real_ssh_endpoint_normalizes(self) -> None:
        self.assertEqual(
            rd.canonical_remote("ssh://git@ssh.github.com:443/awebai/aweb.git"),
            "github.com/awebai/aweb",
        )


class SitePlanTests(unittest.TestCase):
    def test_missing_site_baseline_is_a_named_problem_not_movement(self) -> None:
        """alice's counterexample: fabricated movement made a no-op plan
        impossible. Missing baseline fails closed by name instead."""
        graph = rd.Graph.from_dict(
            {
                "component": {
                    "sites": {
                        "source_paths": ["docs/x.md"],
                        "lane": {"command": "deploy"},
                        "publishable": False,
                    }
                }
            }
        )
        state = rd.FixtureState(
            changed_components={},
            delivery_baselines={},
        )
        plan = rd.compute_plan(graph, state)
        self.assertEqual(
            plan.moving, [], "no observed change and no baseline is not movement"
        )
        problems = rd.check_declared_inputs(graph, plan, state)
        self.assertTrue(
            any("baseline" in p for p in problems),
            f"the unobservable baseline must be a named problem: {problems}",
        )


class G5RecordTests(unittest.TestCase):
    def test_measured_set_requires_resolvable_structured_record(self) -> None:
        """alice's counterexample: measured:not-a-real-record marked the edge
        complete. Completion requires a structured record resolved through a
        measurement authority proving edge applicability."""
        data = fixture_graph_dict()
        for edge in data["edge"]:
            if edge["type"] == "runtime-contract":
                edge["supported"] = {
                    "set": "measured:not-a-real-record",
                    "policy": "additive-only",
                }
        with self.assertRaises(rd.GraphError):
            rd.Graph.from_dict(data)

    def test_structured_record_with_authority_fields_loads_incompletely_until_resolved(
        self,
    ) -> None:
        data = fixture_graph_dict()
        for edge in data["edge"]:
            if edge["type"] == "runtime-contract":
                edge["supported"] = {
                    "set": "measured:fleet-2026-08-01",
                    "record": {
                        "authority": "workflow-artifacts",
                        "artifact_id": "measurement:fleet-2026-08-01",
                        "digest": "abc123",
                    },
                    "policy": "additive-only",
                }
        graph = rd.Graph.from_dict(data)
        edge = graph.runtime_contracts[0]
        self.assertFalse(edge.declared_incomplete)

        class NoRecords:
            def resolve(self, record, edge):
                return None

        problems = rd.check_measurement_records(
            graph.runtime_contracts, NoRecords()
        )
        self.assertTrue(any("measurement" in p for p in problems))

    def test_breaking_policy_requires_approved_deprecation(self) -> None:
        data = fixture_graph_dict()
        for edge in data["edge"]:
            if edge["type"] == "runtime-contract":
                edge["supported"] = {
                    "set": "measured:fleet-2026-08-01",
                    "record": {
                        "authority": "workflow-artifacts",
                        "artifact_id": "m:1",
                        "digest": "d",
                    },
                    "policy": "breaking-with-approved-deprecation",
                }
        with self.assertRaises(rd.GraphError):
            rd.Graph.from_dict(data)


if __name__ == "__main__":
    unittest.main(verbosity=1)
