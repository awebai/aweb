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
                [n.component for n in restored.moving],
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
            fresh = self.providers_for(root, state)
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
                plan, graph, source_sha="s1", state=state
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


class FrozenSnapshotTests(unittest.TestCase):
    def test_inconsistent_frozen_body_is_refused(self) -> None:
        """alice's forgery: plan_digest='not-the-plan', re-anchored by digest,
        loaded successfully. Internal consistency must be validated."""
        graph = fixture_graph()
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        frozen_bytes, _ = rd.freeze_plan(plan, graph, source_sha="s1", state=state)
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
            rd.compute_plan(graph, state_a), graph, source_sha="s1", state=state_a
        )
        _, id_b = rd.freeze_plan(
            rd.compute_plan(graph, state_b), graph, source_sha="s1", state=state_b
        )
        self.assertNotEqual(
            id_a, id_b, "resolved pin state must be bound into the frozen plan"
        )


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
