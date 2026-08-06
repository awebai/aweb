"""aweb-abbe.2.1: the external workflow-artifact store/authority adapter and
the one-SHA-256 lane observers. No network: the GitHub API and downloads
arrive through injected reader callables, filled from fixtures shaped like
the real API responses measured on awebai/aw.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import unittest
import unittest.mock
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_driver as rd
from test_release_driver import (
    FixtureAuthority,
    FixtureLanes,
    fixture_graph_dict,
    orchestration_state,
)
from test_release_driver import AllRecordsResolve


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeGithubApi:
    """Answers the exact API shapes the adapter reads: artifact metadata,
    run metadata, and the raw artifact ZIP."""

    def __init__(self, *, repo="awebai/aw", run_id=30977506589,
                 artifact_id=8918869285, zip_bytes=b"zip-bytes",
                 expired=False, conclusion="success", head_repo=None,
                 owning_run=None, digest=None,
                 workflow_path=".github/workflows/aw-release.yml"):
        self.repo = repo
        self.run_id = run_id
        self.artifact_id = artifact_id
        self.zip_bytes = zip_bytes
        self.expired = expired
        self.conclusion = conclusion
        self.head_repo = head_repo or repo
        self.owning_run = owning_run if owning_run is not None else run_id
        self.digest = digest or f"sha256:{sha256(zip_bytes)}"
        self.workflow_path = workflow_path
        self.calls: list[str] = []

    def __call__(self, path: str) -> bytes:
        self.calls.append(path)
        if path == f"repos/{self.repo}/actions/artifacts/{self.artifact_id}":
            return json.dumps({
                "id": self.artifact_id,
                "workflow_run": {"id": self.owning_run},
                "expired": self.expired,
                "digest": self.digest,
            }).encode()
        if path == f"repos/{self.repo}/actions/runs/{self.run_id}":
            return json.dumps({
                "conclusion": self.conclusion,
                "head_repository": {"full_name": self.head_repo},
                "path": self.workflow_path,
            }).encode()
        if path == f"repos/{self.repo}/actions/artifacts/{self.artifact_id}/zip":
            return self.zip_bytes
        raise AssertionError(f"unexpected API path {path}")


def artifact_id_for(api: FakeGithubApi) -> str:
    return f"gh-artifact:{api.repo}:{api.run_id}:{api.artifact_id}"


class ExternalStoreTests(unittest.TestCase):
    def test_exact_artifact_bytes_are_returned(self) -> None:
        api = FakeGithubApi()
        store = rd.GithubArtifactStore(api=api)
        data = store.get(artifact_id_for(api))
        self.assertEqual(data, api.zip_bytes)

    def test_foreign_repository_is_refused(self) -> None:
        api = FakeGithubApi()
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get("gh-artifact:evil/aw:1:2")
        self.assertIn("evil/aw", str(caught.exception))

    def test_expired_artifact_is_refused(self) -> None:
        api = FakeGithubApi(expired=True)
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get(artifact_id_for(api))
        self.assertIn("expired", str(caught.exception))

    def test_unsuccessful_run_is_refused(self) -> None:
        api = FakeGithubApi(conclusion="failure")
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get(artifact_id_for(api))
        self.assertIn("success", str(caught.exception))

    def test_fork_run_is_refused(self) -> None:
        api = FakeGithubApi(head_repo="fork/aw")
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError):
            store.get(artifact_id_for(api))

    def test_artifact_of_another_run_is_refused(self) -> None:
        api = FakeGithubApi(owning_run=999)
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get(artifact_id_for(api))
        self.assertIn("belong", str(caught.exception))

    def test_wrong_workflow_path_is_refused(self) -> None:
        """alice's finding: any successful artifact-producing workflow in the
        repo was accepted. The lane binds exactly aw-release.yml."""
        api = FakeGithubApi(workflow_path=".github/workflows/other.yml")
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get(artifact_id_for(api))
        self.assertIn("aw-release.yml", str(caught.exception))

    def test_zip_digest_must_equal_api_digest(self) -> None:
        api = FakeGithubApi(digest="sha256:" + "0" * 64)
        store = rd.GithubArtifactStore(api=api)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get(artifact_id_for(api))
        self.assertIn("digest", str(caught.exception))

    def test_store_is_never_writable(self) -> None:
        store = rd.GithubArtifactStore(api=FakeGithubApi())
        with self.assertRaises(rd.ReceiptError):
            store.put("gh-artifact:awebai/aw:1:2", b"data")


class ExternalAuthorityTests(unittest.TestCase):
    def test_expected_digest_is_the_api_digest_bare_hex(self) -> None:
        api = FakeGithubApi()
        authority = rd.GithubArtifactDigestAuthority(api=api)
        self.assertEqual(
            authority.expected_digest(artifact_id_for(api)),
            sha256(api.zip_bytes),
        )

    def test_record_refuses_external_authority_is_not_caller_writable(self) -> None:
        authority = rd.GithubArtifactDigestAuthority(api=FakeGithubApi())
        with self.assertRaises(rd.ReceiptError):
            authority.record("gh-artifact:awebai/aw:1:2", "d" * 64)

    def test_foreign_repository_is_refused(self) -> None:
        authority = rd.GithubArtifactDigestAuthority(api=FakeGithubApi())
        with self.assertRaises(rd.ReceiptError):
            authority.expected_digest("gh-artifact:evil/aw:1:2")


class RegistrationTests(unittest.TestCase):
    def test_kind_is_allowlisted_external_immutable_with_own_store(self) -> None:
        registration = rd.AUTHORITY_ALLOWLIST["github-workflow-artifacts"]
        self.assertEqual(registration.trust_class, "external-immutable")
        self.assertIsNotNone(registration.store_factory)

    def test_cli_exposes_the_kind_for_a_fresh_process(self) -> None:
        self.assertIn("github-workflow-artifacts", rd.AUTHORITY_ALLOWLIST)
        providers = rd.build_providers(
            store=None,
            authority_registration=rd.AUTHORITY_ALLOWLIST["github-workflow-artifacts"],
        )
        self.assertEqual(providers.authority_trust, "external-immutable")
        self.assertIsInstance(providers.store, rd.GithubAnchorStore)
        self.assertIsInstance(providers.authority, rd.GithubAnchorDigestAuthority)


def anchor_artifact_zip(logical_id: str, body: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        zip_member(z, "record.json", json.dumps(
            {"logical_id": logical_id, "digest": sha256(body)}
        ))
        zip_member(z, "body", body)
    return buffer.getvalue()


class FakeAnchorTransport:
    """In-memory anchors backend honoring the deterministic-name contract:
    dispatch materializes a real artifact ZIP after `latency` polls, the
    listing carries API digests and expiry, and everything is enumerable."""

    def __init__(self, latency: int = 0, *, run_path=None, run_conclusion=None):
        self.artifacts: list[dict] = []
        self.dispatches: list[tuple[str, str]] = []
        self._pending: list[tuple[int, dict]] = []
        self.latency = latency
        self._next_id = 1
        self._run_path = run_path or ".github/workflows/release-anchor.yml"
        self._run_conclusion = run_conclusion or "success"

    def _materialize(self, logical_id: str, body: bytes, *, expired=False):
        digest = sha256(body)
        name = f"anchor--{sha256(logical_id.encode())}--{digest}"
        zip_bytes = anchor_artifact_zip(logical_id, body)
        entry = {
            "id": self._next_id,
            "name": name,
            "digest": f"sha256:{sha256(zip_bytes)}",
            "expired": expired,
            "workflow_run": {"id": 7000 + self._next_id},
            "_zip": zip_bytes,
        }
        self._next_id += 1
        return entry

    def anchor_run(self, run_id) -> dict:
        return {
            "path": self._run_path,
            "conclusion": self._run_conclusion,
            "head_repository": {"full_name": "awebai/aweb"},
        }

    def seed(self, logical_id: str, body: bytes, *, expired=False):
        self.artifacts.append(self._materialize(logical_id, body, expired=expired))

    def list_artifacts(self) -> list[dict]:
        still = []
        for remaining, entry in self._pending:
            if remaining <= 0:
                self.artifacts.append(entry)
            else:
                still.append((remaining - 1, entry))
        self._pending = still
        return [dict(a) for a in self.artifacts]

    def artifact_zip(self, artifact_id: int) -> bytes:
        for a in self.artifacts:
            if a["id"] == artifact_id:
                return a["_zip"]
        raise AssertionError(f"unknown artifact {artifact_id}")

    def dispatch_anchor(self, logical_id: str, digest: str, body_gzip_b64: str):
        import base64
        import gzip

        body = gzip.decompress(base64.b64decode(body_gzip_b64))
        assert sha256(body) == digest
        self.dispatches.append((logical_id, digest))
        self._pending.append((self.latency, self._materialize(logical_id, body)))


def anchor_pair(transport):
    store = rd.GithubAnchorStore(transport=transport, waiter=lambda: None)
    authority = rd.GithubAnchorDigestAuthority(transport=transport)
    return store, authority


class AnchorStoreTests(unittest.TestCase):
    def test_put_dispatches_once_and_get_returns_the_body(self) -> None:
        transport = FakeAnchorTransport(latency=1)
        store, _ = anchor_pair(transport)
        store.put("plan:s1:abc", b"body-bytes")
        self.assertEqual(len(transport.dispatches), 1)
        self.assertEqual(store.get("plan:s1:abc"), b"body-bytes")

    def test_repeated_put_reconciles_without_a_second_dispatch(self) -> None:
        transport = FakeAnchorTransport()
        store, _ = anchor_pair(transport)
        store.put("plan:s1:abc", b"body-bytes")
        store.put("plan:s1:abc", b"body-bytes")
        self.assertEqual(len(transport.dispatches), 1)

    def test_different_bytes_for_an_anchored_id_refuse(self) -> None:
        transport = FakeAnchorTransport()
        store, _ = anchor_pair(transport)
        store.put("plan:s1:abc", b"body-bytes")
        with self.assertRaises(rd.ReceiptError):
            store.put("plan:s1:abc", b"DIFFERENT")

    def test_conflicting_anchor_artifacts_refuse(self) -> None:
        transport = FakeAnchorTransport()
        transport.seed("plan:s1:abc", b"one")
        transport.artifacts.append(
            {**transport._materialize("plan:s1:abc", b"two"),
             "name": transport.artifacts[0]["name"].rsplit("--", 1)[0]
             + "--" + sha256(b"two")}
        )
        store, authority = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError):
            store.get("plan:s1:abc")
        with self.assertRaises(rd.ReceiptError):
            authority.expected_digest("plan:s1:abc")

    def test_matching_expired_identity_refuses_reads_and_writes(self) -> None:
        """An identity whose anchor expired is compromised evidence: reads
        refuse naming expiry, and put must NOT re-anchor it."""
        transport = FakeAnchorTransport()
        transport.seed("plan:s1:abc", b"body", expired=True)
        store, authority = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get("plan:s1:abc")
        self.assertIn("expired", str(caught.exception))
        with self.assertRaises(rd.ReceiptError):
            authority.expected_digest("plan:s1:abc")
        with self.assertRaises(rd.ReceiptError):
            store.put("plan:s1:abc", b"body")
        self.assertEqual(transport.dispatches, [])

    def test_anchor_from_a_foreign_workflow_refuses(self) -> None:
        transport = FakeAnchorTransport(run_path=".github/workflows/other.yml")
        transport.seed("plan:s1:abc", b"body")
        store, authority = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get("plan:s1:abc")
        self.assertIn("release-anchor.yml", str(caught.exception))
        with self.assertRaises(rd.ReceiptError):
            authority.expected_digest("plan:s1:abc")
        _, fresh = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError):
            fresh.recorded_ids()

    def test_anchor_from_a_failed_run_refuses(self) -> None:
        transport = FakeAnchorTransport(run_conclusion="failure")
        transport.seed("plan:s1:abc", b"body")
        store, _ = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError):
            store.get("plan:s1:abc")

    def test_encoded_dispatch_payload_is_bounded(self) -> None:
        """GitHub bounds the TOTAL dispatch payload at 65,535 characters; an
        incompressible body below any raw-byte bound still overflows once
        base64-encoded and must refuse BEFORE any outward dispatch."""
        import os

        transport = FakeAnchorTransport()
        store, _ = anchor_pair(transport)
        incompressible = os.urandom(60000)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.put("plan:big", incompressible)
        self.assertEqual(transport.dispatches, [])
        self.assertIn("dispatch payload", str(caught.exception))

    def test_zip_bytes_must_match_the_api_digest(self) -> None:
        transport = FakeAnchorTransport()
        transport.seed("plan:s1:abc", b"body")
        transport.artifacts[0]["digest"] = "sha256:" + "0" * 64
        store, _ = anchor_pair(transport)
        with self.assertRaises(rd.ReceiptError) as caught:
            store.get("plan:s1:abc")
        self.assertIn("digest", str(caught.exception))

    def test_record_verifies_and_never_dispatches(self) -> None:
        transport = FakeAnchorTransport()
        store, authority = anchor_pair(transport)
        store.put("plan:s1:abc", b"body-bytes")
        before = len(transport.dispatches)
        authority.record("plan:s1:abc", sha256(b"body-bytes"))
        self.assertEqual(len(transport.dispatches), before)
        with self.assertRaises(rd.ReceiptError):
            authority.record("plan:s1:abc", "0" * 64)
        with self.assertRaises(rd.ReceiptError):
            authority.record("plan:never-uploaded", sha256(b"x"))

    def test_recorded_ids_enumerate_after_a_fresh_process(self) -> None:
        transport = FakeAnchorTransport()
        store, _ = anchor_pair(transport)
        store.put("plan:s1:abc", b"one-body")
        store.put("staged-manifest:f:d", b"two-body")
        _, fresh_authority = anchor_pair(transport)
        self.assertEqual(
            sorted(fresh_authority.recorded_ids()),
            ["plan:s1:abc", "staged-manifest:f:d"],
        )

    def test_real_transport_paginates(self) -> None:
        pages = {
            1: {"artifacts": [{"id": 1, "name": "anchor--x--y",
                               "digest": "sha256:d", "expired": False}]},
            2: {"artifacts": [{"id": 2, "name": "anchor--a--b",
                               "digest": "sha256:e", "expired": False}]},
            3: {"artifacts": []},
        }

        def api(path):
            import re
            page = int(re.search(r"&page=(\d+)", path).group(1))
            return json.dumps(pages[page]).encode()

        transport = rd.GithubAnchorTransport(api=api)
        listed = transport.list_artifacts()
        self.assertEqual([a["id"] for a in listed], [1, 2])


def lane_payload_names(version="1.34.3"):
    """The real aw lane protocol: 14 basenames, members under dist/ or npm/."""
    dist = []
    for platform in ("linux_amd64", "linux_arm64", "darwin_amd64",
                     "darwin_arm64", "windows_amd64", "windows_arm64"):
        ext = "zip" if platform.startswith("windows") else "tar.gz"
        dist.append(f"aw_{version}_{platform}.{ext}")
    dist.append("checksums.txt")
    npm = [f"awebai-aw-{version}.tgz"] + [
        f"awebai-aw-{p}-{version}.tgz"
        for p in ("linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64",
                  "windows-x64", "windows-arm64")
    ]
    return dist, npm


def lane_payload_bytes(version="1.34.3"):
    dist, npm = lane_payload_names(version)
    members = {f"dist/{n}": f"bytes-of-{n}".encode() for n in dist}
    members.update({f"npm/{n}": f"bytes-of-{n}".encode() for n in npm})
    return members


ZIP_FIXTURE_STAMP = (2020, 1, 1, 0, 0, 0)


def zip_member(archive, name, data):
    """Deterministic fixture member: zipfile.writestr stamps the current
    local time into each entry, so two builds of identical content straddling
    a second boundary produce different bytes and flake any exact-digest
    comparison."""
    archive.writestr(zipfile.ZipInfo(name, date_time=ZIP_FIXTURE_STAMP), data)


def lane_zip(*, mode="stage-only", source_sha="a" * 40, version="1.34.3",
             tamper_payload=False, drop_payload=False, extra_payload=False,
             break_canonical=False, duplicate_member=False) -> bytes:
    members = lane_payload_bytes(version)
    # The REAL protocol shape (proven against the run-3 artifact): ZIP
    # members carry dist/ or npm/ prefixes, manifest files keys are the 14
    # basenames.
    files = {
        name.rsplit("/", 1)[-1]: sha256(data)
        for name, data in members.items()
    }
    canonical = sha256(json.dumps(files, sort_keys=True).encode())
    if break_canonical:
        canonical = "0" * 64
    manifest = {
        "mode": mode,
        "tag": f"v{version}",
        "candidate_version": version,
        "source_sha": source_sha,
        "files": files,
        "canonical_set_digest": canonical,
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        zip_member(z, "manifest.json", json.dumps(manifest))
        for name, data in members.items():
            if drop_payload and name == f"npm/awebai-aw-{version}.tgz":
                continue
            if tamper_payload and name.endswith("linux_amd64.tar.gz"):
                data = b"tampered"
            zip_member(z, name, data)
        if extra_payload:
            zip_member(z, "dist/uninvited.bin", b"extra")
        if duplicate_member:
            zip_member(z, "npm/checksums.txt", members["dist/checksums.txt"])
    return buffer.getvalue()


class LaneStagedArtifactTests(unittest.TestCase):
    def test_coherent_stage_only_artifact_validates(self) -> None:
        manifest = rd.validate_lane_staged_artifact(
            lane_zip(), expected_source_sha="a" * 40, expected_version="1.34.3",
        )
        self.assertEqual(manifest["mode"], "stage-only")
        self.assertEqual(len(manifest["files"]), 14)

    def test_verify_only_artifact_is_never_publishable(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(mode="verify-only"),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("stage-only", str(caught.exception))

    def test_source_and_version_must_bind(self) -> None:
        with self.assertRaises(rd.ReceiptError):
            rd.validate_lane_staged_artifact(
                lane_zip(), expected_source_sha="b" * 40, expected_version="1.34.3",
            )
        with self.assertRaises(rd.ReceiptError):
            rd.validate_lane_staged_artifact(
                lane_zip(), expected_source_sha="a" * 40, expected_version="9.9.9",
            )

    def test_payload_digest_mismatch_refuses(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(tamper_payload=True),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("linux_amd64", str(caught.exception))

    def test_duplicate_member_placement_refuses(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(duplicate_member=True),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("checksums.txt", str(caught.exception))

    def test_missing_payload_refuses(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(drop_payload=True),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("tgz", str(caught.exception))

    def test_extra_payload_refuses(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(extra_payload=True),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("uninvited", str(caught.exception))

    def test_canonical_mismatch_refuses(self) -> None:
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_lane_staged_artifact(
                lane_zip(break_canonical=True),
                expected_source_sha="a" * 40, expected_version="1.34.3",
            )
        self.assertIn("canonical", str(caught.exception))


GOOD_REF = {
    "artifact": "gh-artifact:awebai/aw:30977506589:8918869285",
    "aw_source_sha": "471400cdd011e07e17dbce092b0f837ff655af35",
    "zip_digest": "sha256:" + "8" * 64,
}


class LaneRefTests(unittest.TestCase):
    def test_well_formed_reference_validates(self) -> None:
        ref = rd.LaneRef.from_dict(GOOD_REF)
        self.assertEqual(ref.aw_source_sha, GOOD_REF["aw_source_sha"])
        self.assertEqual(ref.to_dict(), GOOD_REF)

    def test_malformed_references_refuse(self) -> None:
        for field, value in (
            ("artifact", "gh-artifact:evil/aw:1:2"),
            ("artifact", "not-a-ref"),
            ("aw_source_sha", "short"),
            ("aw_source_sha", ""),
            ("zip_digest", "8" * 64),
            ("zip_digest", "sha256:nope"),
        ):
            bad = dict(GOOD_REF)
            bad[field] = value
            with self.assertRaises(rd.ReceiptError, msg=f"{field}={value!r}"):
                rd.LaneRef.from_dict(bad)
        with self.assertRaises(rd.ReceiptError):
            rd.LaneRef.from_dict({"artifact": GOOD_REF["artifact"]})

    def test_cli_argument_parses_to_component_and_reference(self) -> None:
        component, ref = rd.parse_stage_artifact_argument(
            "component=aw,ref=" + GOOD_REF["artifact"]
            + ",source=" + GOOD_REF["aw_source_sha"]
            + ",digest=" + GOOD_REF["zip_digest"]
        )
        self.assertEqual(component, "aw")
        self.assertEqual(ref.to_dict(), GOOD_REF)
        with self.assertRaises(rd.ReceiptError):
            rd.parse_stage_artifact_argument("component=aw,ref=x")


class LaneRefThreadingTests(unittest.TestCase):
    def fixture_entries(self, plan):
        return {
            n.component: rd.ReceiptEntry(
                version=n.version or "0.0.0",
                digest=f"d-{n.component}",
                pointer_state="ok" if n.reason.startswith("pointer:") else None,
                lane_ref=GOOD_REF if n.component == "client" else None,
            )
            for n in plan.moving
        }

    def plan_and_graph(self):
        from test_release_driver import fixture_graph_dict, orchestration_state
        graph = rd.Graph.from_dict(fixture_graph_dict())
        state = orchestration_state()
        return rd.compute_plan(graph, state), graph

    def test_staged_manifest_carries_and_validates_lane_ref(self) -> None:
        plan, graph = self.plan_and_graph()
        body, digest = rd.seal_staged_manifest(
            plan, frozen_plan_id="F", source_sha="s1",
            entries=self.fixture_entries(plan), graph=graph,
        )
        manifest = rd.load_staged_manifest(body, expected_digest=digest)
        self.assertEqual(manifest["entries"]["client"]["lane_ref"], GOOD_REF)
        rd.validate_staged_manifest(
            manifest, plan=plan, graph=graph,
            frozen_plan_id="F", source_sha="s1",
        )
        manifest["entries"]["client"]["lane_ref"] = {"artifact": "not-a-ref"}
        with self.assertRaises(rd.ReceiptError):
            rd.validate_staged_manifest(
                manifest, plan=plan, graph=graph,
                frozen_plan_id="F", source_sha="s1",
            )

    def test_adoption_requires_the_exact_lane_ref(self) -> None:
        plan, graph = self.plan_and_graph()
        body, digest = rd.seal_staged_manifest(
            plan, frozen_plan_id="F", source_sha="s1",
            entries=self.fixture_entries(plan), graph=graph,
        )
        manifest = rd.load_staged_manifest(body, expected_digest=digest)
        good = rd.ReceiptEntry(
            version=manifest["entries"]["client"]["version"],
            digest=manifest["entries"]["client"]["digest"],
            lane_ref=GOOD_REF,
        )
        rd.adopt_observed(manifest, "client", good)
        tampered = dict(GOOD_REF)
        tampered["aw_source_sha"] = "b" * 40
        with self.assertRaises(rd.ReceiptError):
            rd.adopt_observed(
                manifest, "client",
                rd.ReceiptEntry(
                    version=good.version, digest=good.digest, lane_ref=tampered,
                ),
            )

    def test_receipt_round_trips_lane_ref(self) -> None:
        plan, graph = self.plan_and_graph()
        entries = {
            name: rd.ReceiptEntry(
                version=e.version, digest=e.digest, phase="verified",
                pointer_state=e.pointer_state, lane_ref=e.lane_ref,
            )
            for name, e in self.fixture_entries(plan).items()
        }
        sealed, digest = rd.seal_receipt(
            plan, graph, source_sha="s1", entries=entries, approvals={},
        )
        receipt = rd.load_sealed_receipt(sealed, expected_digest=digest)
        self.assertEqual(receipt.entries["client"].lane_ref, GOOD_REF)


class ObserverTests(unittest.TestCase):
    def test_release_observer_reports_one_sha256_per_asset(self) -> None:
        assets = {"aw_1.34.3_linux_amd64.tar.gz": b"archive-bytes"}

        def fetch(name):
            return assets.get(name)

        observer = rd.GithubReleaseObserver(fetch=fetch)
        observed = observer.observe(["aw_1.34.3_linux_amd64.tar.gz", "absent.zip"])
        self.assertEqual(
            observed,
            {"aw_1.34.3_linux_amd64.tar.gz": sha256(b"archive-bytes"),
             "absent.zip": None},
        )

    def test_npm_observer_reports_one_sha256_or_none(self) -> None:
        def fetch(package, version):
            return b"tgz-bytes" if version == "1.34.3" else None

        observer = rd.NpmRegistryObserver(fetch=fetch)
        self.assertEqual(
            observer.observe("@awebai/aw", "1.34.3"), sha256(b"tgz-bytes")
        )
        self.assertIsNone(observer.observe("@awebai/aw", "9.9.9"))

    def test_exact_remote_state_adopts_and_missing_is_identified(self) -> None:
        staged = {"a.tar.gz": sha256(b"one"), "b.tgz": sha256(b"two")}
        observed = {"a.tar.gz": sha256(b"one"), "b.tgz": None}
        adopted, missing = rd.classify_remote_state(staged, observed)
        self.assertEqual(adopted, ["a.tar.gz"])
        self.assertEqual(missing, ["b.tgz"])

    def test_mismatched_remote_bytes_refuse(self) -> None:
        staged = {"a.tar.gz": sha256(b"one")}
        observed = {"a.tar.gz": sha256(b"DIFFERENT")}
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.classify_remote_state(staged, observed)
        self.assertIn("a.tar.gz", str(caught.exception))

    def test_unobserved_evidence_refuses(self) -> None:
        staged = {"a.tar.gz": sha256(b"one")}
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.classify_remote_state(staged, {})
        self.assertIn("a.tar.gz", str(caught.exception))


class FakeAwRuns:
    """The workflow runs surface: list, dispatch, conclusion, attempt evidence."""

    def __init__(self, *, new_runs_per_dispatch=1, conclusion="success",
                 observed_attempt_artifact_id="from-dispatch"):
        self.run_ids = [100, 101]
        self.dispatched: list[dict] = []
        self.new_runs_per_dispatch = new_runs_per_dispatch
        self.conclusion = conclusion
        self.observed_attempt_artifact_id = observed_attempt_artifact_id
        self.run_attempt_artifact_ids = {}
        self._next = 200

    def list_run_ids(self):
        return list(self.run_ids)

    def high_water_run_id(self):
        run_ids = self.list_run_ids()
        return run_ids[-1] if run_ids else None

    def list_run_ids_after(self, boundary_run_id):
        run_ids = self.list_run_ids()
        if boundary_run_id is None:
            return run_ids
        boundary = str(boundary_run_id)
        for index, run_id in enumerate(run_ids):
            if str(run_id) == boundary:
                return run_ids[index + 1:]
        raise rd.ReceiptError("incomplete fake run enumeration: boundary missing")

    def dispatch(self, inputs: dict):
        self.dispatched.append(dict(inputs))
        for _ in range(self.new_runs_per_dispatch):
            run_id = self._next
            self.run_ids.append(run_id)
            observed = self.observed_attempt_artifact_id
            if observed == "from-dispatch":
                observed = inputs.get("recovery_attempt_artifact_id")
            if observed is not None:
                self.run_attempt_artifact_ids[run_id] = observed
            self._next += 1

    def run_display_title(self, run_id, *, budget=None):
        attempt_id = self.run_attempt_artifact_ids.get(run_id)
        if attempt_id is None:
            return "aweb-npm|stage-only|channel|"
        return rd.recovery_run_marker("channel", attempt_id)

    def run_conclusion(self, run_id, *, budget=None):
        return self.conclusion

    def run_attempt_artifact_id(self, run_id, *, budget=None):
        return self.run_attempt_artifact_ids.get(run_id)


class WorkflowRunAttemptEvidenceTests(unittest.TestCase):
    def evidence_zip(self, attempt_artifact_id, run_id="777"):
        body = rd.canonical_json_bytes({
            "schema": "aweb.release.recovery-continuation-attempt.v1",
            "attempt_artifact_id": attempt_artifact_id,
            "continuation_run_id": run_id,
        })
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("recovery-attempt.json", body)
        return buffer.getvalue()

    def test_reads_attempt_identity_from_run_owned_persistent_artifact(self):
        attempt_id = "adopted-preplan-attempt:" + "a" * 64 + ":channel:" + "b" * 64
        artifact_zip = self.evidence_zip(attempt_id)

        def api(path):
            if path == (
                "repos/awebai/aweb/actions/runs/777/artifacts?"
                "name=recovery-attempt-identity&per_page=100&page=1"
            ):
                return json.dumps({"total_count": 1, "artifacts": [{
                    "id": 88,
                    "name": "recovery-attempt-identity",
                    "expired": False,
                    "digest": "sha256:" + sha256(artifact_zip),
                    "workflow_run": {"id": 777},
                }]}).encode()
            if path == "repos/awebai/aweb/actions/artifacts/88/zip":
                return artifact_zip
            raise AssertionError(f"unexpected API path {path}")

        runs = rd.AwLaneRuns(api=api, repo="awebai/aweb",
                             workflow_file="npm-release.yml")
        self.assertEqual(runs.run_attempt_artifact_id(777), attempt_id)

    def test_evidence_lookup_falls_back_and_finds_page_two_after_overlap(self):
        attempt_id = "attempt:channel:page-two-evidence"
        artifact_zip = self.evidence_zip(attempt_id)
        unrelated = [
            {"id": artifact_id, "name": f"unrelated-{artifact_id}"}
            for artifact_id in range(1, 101)
        ]
        owned = {
            "id": 101,
            "name": "recovery-attempt-identity",
            "expired": False,
            "digest": "sha256:" + sha256(artifact_zip),
            "workflow_run": {"id": 777},
        }
        calls = []

        def api(path):
            calls.append(path)
            if "?name=recovery-attempt-identity" in path:
                # Simulate an endpoint which ignores the optional name filter.
                return json.dumps({
                    "total_count": 101, "artifacts": unrelated,
                }).encode()
            if path.endswith("?per_page=100&page=1"):
                return json.dumps({
                    "total_count": 101, "artifacts": unrelated,
                }).encode()
            if path.endswith("?per_page=100&page=2"):
                return json.dumps({
                    "total_count": 101,
                    "artifacts": [unrelated[-1], owned],
                }).encode()
            if path.endswith("/actions/artifacts/101/zip"):
                return artifact_zip
            raise AssertionError(f"unexpected API path {path}")

        runs = rd.AwLaneRuns(api=api, repo="awebai/aweb",
                             workflow_file="npm-release.yml")
        self.assertEqual(runs.run_attempt_artifact_id(777), attempt_id)
        self.assertEqual(
            sum(path.endswith("?per_page=100&page=2") for path in calls), 2,
            "fallback enumeration must stabilize through page two",
        )

    def test_evidence_lookup_refuses_multiple_exact_artifacts_across_pages(self):
        exact = [
            {"id": artifact_id, "name": "recovery-attempt-identity"}
            for artifact_id in range(1, 102)
        ]

        def api(path):
            if path.endswith("page=1"):
                page = exact[:100]
            else:
                page = [exact[99], exact[100]]
            return json.dumps({
                "total_count": 101, "artifacts": page,
            }).encode()

        runs = rd.AwLaneRuns(api=api, repo="awebai/aweb",
                             workflow_file="npm-release.yml")
        with self.assertRaises(rd.ReceiptError) as caught:
            runs.run_attempt_artifact_id(777)
        self.assertIn("not exactly one", str(caught.exception))

    def test_run_history_uses_high_water_and_deduplicates_page_drift(self):
        calls = []
        pages = {
            1: [300, 299, 298],
            2: [298, 297, 250, 249],
        }

        def api(path):
            calls.append(path)
            if path.endswith("?per_page=1&page=1"):
                return json.dumps({"workflow_runs": [{"id": 300}]}).encode()
            for page, run_ids in pages.items():
                if path.endswith(f"?per_page=100&page={page}"):
                    return json.dumps({
                        "workflow_runs": [{"id": item} for item in run_ids]
                    }).encode()
            raise AssertionError(f"unexpected API path {path}")

        runs = rd.AwLaneRuns(api=api, repo="awebai/aweb",
                             workflow_file="npm-release.yml")
        self.assertEqual(runs.high_water_run_id(), 300)
        self.assertEqual(
            runs.list_run_ids_after("250"),
            [300, 299, 298, 297],
        )
        self.assertEqual(
            sum(path.endswith("page=2") for path in calls), 2,
            "two complete agreeing passes must reach the boundary",
        )

    def test_run_history_retries_after_deletion_shift_hides_owned_run(self):
        calls = []
        first_page_reads = 0

        def api(path):
            nonlocal first_page_reads
            calls.append(path)
            if path.endswith("?per_page=100&page=1"):
                first_page_reads += 1
                run_ids = (
                    list(range(300, 200, -1))
                    if first_page_reads == 1
                    else list(range(299, 199, -1))
                )
            elif path.endswith("?per_page=100&page=2"):
                # Run 300 was deleted after the first page read, moving the
                # owned run 200 onto that already-read page during pass one.
                run_ids = list(range(199, 99, -1))
            else:
                raise AssertionError(f"unexpected API path {path}")
            return json.dumps({
                "workflow_runs": [{"id": item} for item in run_ids]
            }).encode()

        runs = rd.AwLaneRuns(api=api, repo="awebai/aweb",
                             workflow_file="npm-release.yml")
        observed = runs.list_run_ids_after("100")
        self.assertIn(200, observed)
        self.assertNotIn(300, observed)
        self.assertEqual(first_page_reads, 3)
        self.assertEqual(len(calls), 6)

    def test_run_history_requires_canonical_numeric_boundary(self):
        runs = rd.AwLaneRuns(
            api=lambda path: json.dumps({"workflow_runs": []}).encode(),
            repo="awebai/aweb", workflow_file="npm-release.yml",
        )
        for boundary in ("0250", "0", 0, -1, True, 250.0):
            with self.subTest(boundary=boundary):
                with self.assertRaises(rd.ReceiptError) as caught:
                    runs.list_run_ids_after(boundary)
                self.assertIn("canonical numeric ID", str(caught.exception))

    def test_run_history_refuses_order_mutation(self):
        def api(path):
            return json.dumps({"workflow_runs": [
                {"id": 300}, {"id": 298}, {"id": 299}, {"id": 250},
            ]}).encode()

        runs = rd.AwLaneRuns(api=api, repo="awebai/aweb",
                             workflow_file="npm-release.yml")
        with self.assertRaises(rd.ReceiptError) as caught:
            runs.list_run_ids_after("250")
        self.assertIn("order", str(caught.exception))
        self.assertIn("incomplete", str(caught.exception))

    def test_run_history_refuses_continuous_churn_without_agreement(self):
        calls = []

        def api(path):
            calls.append(path)
            newest = 300 + len(calls)
            return json.dumps({"workflow_runs": [
                {"id": newest}, {"id": 250},
            ]}).encode()

        runs = rd.AwLaneRuns(api=api, repo="awebai/aweb",
                             workflow_file="npm-release.yml")
        runs.MAX_RUN_HISTORY_PASSES = 3
        with self.assertRaises(rd.ReceiptError) as caught:
            runs.list_run_ids_after("250")
        self.assertIn("incomplete", str(caught.exception))
        self.assertIn("agree", str(caught.exception))
        self.assertEqual(len(calls), 3)

    def test_run_history_bounds_total_requests_and_time(self):
        for mode in ("requests", "time"):
            with self.subTest(mode=mode):
                calls = []
                ticks = iter([0.0, 0.0, 0.0, 2.0, 2.0])

                def api(path):
                    calls.append(path)
                    newest = 300 + len(calls)
                    return json.dumps({"workflow_runs": [
                        {"id": newest}, {"id": 250},
                    ]}).encode()

                runs = rd.AwLaneRuns(
                    api=api, repo="awebai/aweb",
                    workflow_file="npm-release.yml",
                    clock=(lambda: next(ticks)) if mode == "time" else None,
                )
                if mode == "requests":
                    runs.MAX_CORRELATION_REQUESTS = 2
                else:
                    runs.MAX_CORRELATION_SECONDS = 1.0
                with self.assertRaises(rd.ReceiptError) as caught:
                    runs.list_run_ids_after("250")
                self.assertIn("incomplete", str(caught.exception))
                self.assertLessEqual(len(calls), 2)

    def test_missing_boundary_and_page_cap_refuse_incomplete_enumeration(self):
        for mode in ("missing", "cap"):
            with self.subTest(mode=mode):
                calls = []

                def api(path):
                    calls.append(path)
                    if mode == "missing" and path.endswith("page=2"):
                        return json.dumps({"workflow_runs": []}).encode()
                    return json.dumps({
                        "workflow_runs": [{"id": 400 - len(calls)}]
                    }).encode()

                runs = rd.AwLaneRuns(api=api, repo="awebai/aweb",
                                     workflow_file="npm-release.yml")
                runs.MAX_RUN_HISTORY_PAGES_PER_PASS = 2
                with self.assertRaises(rd.ReceiptError) as caught:
                    runs.list_run_ids_after("250")
                self.assertIn("incomplete", str(caught.exception))
                self.assertLessEqual(len(calls), 2)

    def test_default_github_calls_receive_positive_remaining_timeout(self):
        attempt_id = "attempt:channel:timeout"
        artifact_zip = self.evidence_zip(attempt_id)
        observed_timeouts = []
        original = rd._run_gh_api

        def api(path, *, timeout):
            observed_timeouts.append(timeout)
            if "/workflows/" in path:
                return json.dumps({"workflow_runs": [
                    {"id": 777}, {"id": 100},
                ]}).encode()
            if "/artifacts?name=recovery-attempt-identity&" in path:
                return json.dumps({"total_count": 1, "artifacts": [{
                    "id": 88,
                    "name": "recovery-attempt-identity",
                    "expired": False,
                    "digest": "sha256:" + sha256(artifact_zip),
                    "workflow_run": {"id": 777},
                }]}).encode()
            if path.endswith("/artifacts/88/zip"):
                return artifact_zip
            if path.endswith("/actions/runs/777"):
                return json.dumps({"conclusion": "success"}).encode()
            raise AssertionError(f"unexpected API path {path}")

        rd._run_gh_api = api
        try:
            runs = rd.AwLaneRuns(repo="awebai/aweb",
                                 workflow_file="npm-release.yml")
            budget = runs.new_correlation_budget(
                max_seconds=3600.0, max_requests=2048
            )
            self.assertEqual(
                runs.list_run_ids_after("100", budget=budget), [777]
            )
            self.assertEqual(
                runs.run_attempt_artifact_id(777, budget=budget), attempt_id
            )
            self.assertEqual(
                runs.run_conclusion(777, budget=budget), "success"
            )
        finally:
            rd._run_gh_api = original
        self.assertEqual(len(observed_timeouts), 6)
        self.assertTrue(
            all(0 < timeout <= 30.0 for timeout in observed_timeouts)
        )

    def test_correlation_deadline_covers_evidence_list_zip_and_conclusion(self):
        attempt_id = "attempt:channel:deadline"
        artifact_zip = self.evidence_zip(attempt_id)
        for stage in ("evidence-list", "evidence-zip", "conclusion"):
            with self.subTest(stage=stage):
                now = [0.0]
                timeouts = []

                def api(path):
                    timeouts.append(path)
                    if "/artifacts?name=recovery-attempt-identity&" in path:
                        if stage == "evidence-list":
                            now[0] = 31.0
                        return json.dumps({"total_count": 1, "artifacts": [{
                            "id": 88,
                            "name": "recovery-attempt-identity",
                            "expired": False,
                            "digest": "sha256:" + sha256(artifact_zip),
                            "workflow_run": {"id": 777},
                        }]}).encode()
                    if path.endswith("/artifacts/88/zip"):
                        if stage == "evidence-zip":
                            now[0] = 31.0
                        return artifact_zip
                    if path.endswith("/actions/runs/777"):
                        now[0] = 31.0
                        return json.dumps({"conclusion": "success"}).encode()
                    raise AssertionError(f"unexpected API path {path}")

                runs = rd.AwLaneRuns(
                    api=api, repo="awebai/aweb",
                    workflow_file="npm-release.yml", clock=lambda: now[0],
                )
                budget = runs.new_correlation_budget()
                with self.assertRaises(rd.ReceiptError) as caught:
                    if stage == "conclusion":
                        runs.run_conclusion(777, budget=budget)
                    else:
                        runs.run_attempt_artifact_id(777, budget=budget)
                self.assertIn("incomplete", str(caught.exception))
                self.assertTrue(timeouts)

    def test_npm_workflow_persists_recovery_identity_before_effects(self):
        workflow = (REPO_ROOT / ".github/workflows/npm-release.yml").read_text()
        publish = workflow[workflow.index("\n  publish:\n"):]
        self.assertIn("recovery_attempt_artifact_id:", workflow)
        self.assertIn(
            "run-name: aweb-npm|${{ inputs.mode }}|${{ inputs.package }}|"
            "${{ inputs.recovery_attempt_artifact_id }}",
            workflow,
        )
        self.assertIn(
            "RECOVERY_ATTEMPT_ARTIFACT_ID: "
            "${{ inputs.recovery_attempt_artifact_id }}",
            publish,
        )
        self.assertIn("recovery-attempt.json", publish)
        self.assertIn("name: recovery-attempt-identity", publish)
        first_effect = publish.index("name: Tag - create at exact source")
        self.assertLess(
            publish.index("name: Persist recovery attempt identity"),
            first_effect,
        )
        self.assertLess(
            publish.index("name: Upload recovery attempt identity"),
            first_effect,
        )


def lane_fixture(*, zip_bytes=None, remote=None, runs=None):
    zip_bytes = zip_bytes if zip_bytes is not None else lane_zip()
    api = FakeGithubApi(zip_bytes=zip_bytes)
    remote = remote if remote is not None else {}

    def release_fetch(name, version):
        return remote.get(name)

    def npm_fetch(package, version):
        return remote.get(f"npm:{package}@{version}")

    lane = rd.AwWorkflowLane(
        reader=rd.GithubArtifactStore(api=api),
        lane_authority=rd.GithubArtifactDigestAuthority(api=api),
        refs={"aw": rd.LaneRef(
            artifact=artifact_id_for(api),
            aw_source_sha="a" * 40,
            zip_digest=f"sha256:{sha256(zip_bytes)}",
        )},
        release_fetch=release_fetch,
        npm_fetch=npm_fetch,
        runs=runs if runs is not None else FakeAwRuns(),
        waiter=lambda: None,
    )
    return lane, api, remote


def aw_node(version="1.34.3"):
    return rd.PlanNode(component="aw", reason="changed", version=version)


def remote_state(*names):
    """Remote publication state keyed the way the lane observes it: release
    assets by basename, npm tarballs by package@version."""
    dist, npm = lane_payload_names()
    full = {n: f"bytes-of-{n}".encode() for n in dist}
    for n in npm:
        stem = n.removesuffix(".tgz")
        package, _, version = stem.replace(
            "awebai-", "@awebai/", 1
        ).rpartition("-")
        full[f"npm:{package}@{version}"] = f"bytes-of-{n}".encode()
    return {k: v for k, v in full.items() if not names or k in names}


class AwWorkflowLaneTests(unittest.TestCase):
    def test_stage_builds_the_complete_entry_from_referenced_bytes(self) -> None:
        lane, _, _ = lane_fixture()
        self.assertTrue(lane.has_lane("aw"))
        self.assertFalse(lane.has_lane("server"))
        entry = lane.stage(aw_node())
        self.assertEqual(entry.version, "1.34.3")
        dist, npm = lane_payload_names()
        self.assertEqual(set(entry.digest_set), set(dist) | set(npm))
        self.assertEqual(
            entry.digest, rd.canonical_digest_of_set(entry.digest_set)
        )
        self.assertEqual(entry.lane_ref["aw_source_sha"], "a" * 40)

    def test_stage_refuses_a_caller_digest_that_does_not_match(self) -> None:
        zip_bytes = lane_zip()
        api = FakeGithubApi(zip_bytes=zip_bytes)
        lane = rd.AwWorkflowLane(
            reader=rd.GithubArtifactStore(api=api),
            lane_authority=rd.GithubArtifactDigestAuthority(api=api),
            refs={"aw": rd.LaneRef(
                artifact=artifact_id_for(api),
                aw_source_sha="a" * 40,
                zip_digest="sha256:" + "0" * 64,
            )},
            release_fetch=lambda name, version: None,
            npm_fetch=lambda p, v: None,
            runs=FakeAwRuns(),
            waiter=lambda: None,
        )
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.stage(aw_node())
        self.assertIn("caller", str(caught.exception))

    def test_independent_authority_metadata_gates_the_read(self) -> None:
        """alice's finding: blob retrieval and the expected API digest must
        be independent capabilities. A wrong independent digest refuses
        BEFORE bytes are read, even when the reader would return coherent
        bytes."""
        zip_bytes = lane_zip()
        reader_api = FakeGithubApi(zip_bytes=zip_bytes)
        wrong_meta_api = FakeGithubApi(
            zip_bytes=zip_bytes, digest="sha256:" + "1" * 64
        )
        lane = rd.AwWorkflowLane(
            reader=rd.GithubArtifactStore(api=reader_api),
            lane_authority=rd.GithubArtifactDigestAuthority(api=wrong_meta_api),
            refs={"aw": rd.LaneRef(
                artifact=artifact_id_for(reader_api),
                aw_source_sha="a" * 40,
                zip_digest=f"sha256:{sha256(zip_bytes)}",
            )},
            release_fetch=lambda name, version: None,
            npm_fetch=lambda p, v: None,
            runs=FakeAwRuns(),
            waiter=lambda: None,
        )
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.stage(aw_node())
        self.assertIn("independent", str(caught.exception))
        self.assertNotIn(
            f"repos/awebai/aw/actions/artifacts/{reader_api.artifact_id}/zip",
            reader_api.calls,
            "the blob must not be fetched when the authority refuses",
        )

    def test_stage_refuses_a_wrong_lane_source(self) -> None:
        zip_bytes = lane_zip(source_sha="c" * 40)
        api = FakeGithubApi(zip_bytes=zip_bytes)
        lane = rd.AwWorkflowLane(
            reader=rd.GithubArtifactStore(api=api),
            lane_authority=rd.GithubArtifactDigestAuthority(api=api),
            refs={"aw": rd.LaneRef(
                artifact=artifact_id_for(api),
                aw_source_sha="a" * 40,
                zip_digest=f"sha256:{sha256(zip_bytes)}",
            )},
            release_fetch=lambda name, version: None,
            npm_fetch=lambda p, v: None,
            runs=FakeAwRuns(),
            waiter=lambda: None,
        )
        with self.assertRaises(rd.ReceiptError):
            lane.stage(aw_node())

    def test_observe_reports_none_until_everything_is_published(self) -> None:
        lane, _, remote = lane_fixture(remote=remote_state("checksums.txt"))
        staged = lane.stage(aw_node())
        self.assertIsNone(lane.observe(aw_node(), staged))
        remote.update(remote_state())
        observed = lane.observe(aw_node(), staged)
        self.assertEqual(observed.digest, staged.digest)
        self.assertEqual(observed.digest_set, staged.digest_set)
        self.assertEqual(observed.lane_ref, staged.lane_ref)

    def test_observe_refuses_mismatched_remote_bytes(self) -> None:
        remote = remote_state()
        remote["checksums.txt"] = b"DIFFERENT"
        lane, _, _ = lane_fixture(remote=remote)
        staged = lane.stage(aw_node())
        with self.assertRaises(rd.ReceiptError):
            lane.observe(aw_node(), staged)

    def test_publish_dispatches_exact_continuation_inputs_and_observes(self) -> None:
        runs = FakeAwRuns()
        remote = {}
        lane, api, _ = lane_fixture(remote=remote, runs=runs)
        staged = lane.stage(aw_node())

        def fill_remote(inputs):
            remote.update(remote_state())
        runs_dispatch = runs.dispatch
        runs.dispatch = lambda inputs: (runs_dispatch(inputs), fill_remote(inputs))[0]

        published = lane.publish(aw_node(), staged)
        self.assertEqual(published.phase, "published")
        self.assertEqual(runs.dispatched, [{
            "mode": "publish-continuation",
            "version": "1.34.3",
            "source_sha": "a" * 40,
            "stage_run_id": str(api.run_id),
            "stage_artifact_id": str(api.artifact_id),
            "stage_zip_digest": f"sha256:{sha256(api.zip_bytes)}",
        }])

    def test_publish_fails_closed_on_run_correlation(self) -> None:
        for runs in (
            FakeAwRuns(new_runs_per_dispatch=0),
            FakeAwRuns(new_runs_per_dispatch=2),
        ):
            lane, _, _ = lane_fixture(remote=remote_state(), runs=runs)
            staged = lane.stage(aw_node())
            with self.assertRaises(rd.ReceiptError, msg=str(runs.new_runs_per_dispatch)):
                lane.publish(aw_node(), staged)

    def test_publish_refuses_an_unsuccessful_continuation_run(self) -> None:
        lane, _, _ = lane_fixture(
            remote=remote_state(), runs=FakeAwRuns(conclusion="failure")
        )
        staged = lane.stage(aw_node())
        with self.assertRaises(rd.ReceiptError):
            lane.publish(aw_node(), staged)

    def test_missing_after_publication_is_failure(self) -> None:
        lane, _, _ = lane_fixture(remote=remote_state("checksums.txt"))
        staged = lane.stage(aw_node())
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.publish(aw_node(), staged)
        self.assertIn("missing", str(caught.exception).lower())

    def test_verify_reobserves_the_complete_set(self) -> None:
        lane, _, remote = lane_fixture(remote=remote_state())
        staged = lane.stage(aw_node())
        published = lane.observe(aw_node(), staged)
        lane.verify(aw_node(), published)
        del remote["checksums.txt"]
        with self.assertRaises(rd.ReceiptError):
            lane.verify(aw_node(), published)


def aw_graph() -> "rd.Graph":
    return rd.Graph.from_dict({
        "component": {
            "aw": {
                "source_paths": ["cli/"],
                "version_source": {"type": "manifest", "path": "cli/version"},
                "tag_format": "aw-v{version}",
                "publish_lane": {
                    "workflow": ".github/workflows/aw-release.yml",
                    "repository": "awebai/aw",
                    "provider": "github-workflow-artifacts",
                    "modes": [
                        "stage-only", "publish-continuation", "verify-only",
                    ],
                    "registry": {"type": "github-release", "repo": "awebai/aw"},
                },
                "verify": {"command": "true"},
            },
        },
        "edge": [],
    })


class CountingLane(rd.AwWorkflowLane):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stage_calls = 0

    def stage(self, node):
        self.stage_calls += 1
        return super().stage(node)


class NoRuntimeSkew:
    def has_matrix(self, edge):
        return True

    def execute(self, edge, staged):
        pass


class EndToEndProductionCompositionTests(unittest.TestCase):
    """alice's decisive acceptance: every anchor operation runs through the
    reconstructed external production composition - no memory or file store
    anywhere on the release path."""

    def compose(self, transport, *, runs, remote):
        """A fresh production composition over the shared external state."""
        store = rd.GithubAnchorStore(transport=transport, waiter=lambda: None)
        authority = rd.GithubAnchorDigestAuthority(transport=transport)
        zip_bytes = lane_zip()
        api = FakeGithubApi(zip_bytes=zip_bytes)
        lane = CountingLane(
            reader=rd.GithubArtifactStore(api=api),
            lane_authority=rd.GithubArtifactDigestAuthority(api=api),
            refs={"aw": rd.LaneRef(
                artifact=artifact_id_for(api),
                aw_source_sha="a" * 40,
                zip_digest=f"sha256:{sha256(zip_bytes)}",
            )},
            release_fetch=lambda name, version: remote.get(name),
            npm_fetch=lambda p, v: remote.get(f"npm:{p}@{v}"),
            runs=runs,
            waiter=lambda: None,
        )
        return store, authority, lane

    def frozen_fixture(self, store, authority):
        graph = aw_graph()
        state = rd.FixtureState(
            changed_components={"aw": True},
            versions={"aw": "1.34.3"},
            published_versions={"aw": "1.34.2"},
        )
        plan = rd.compute_plan(graph, state)
        frozen_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="s1"
        )
        plan_artifact_id = f"plan:s1:{frozen_id}"
        rd._put_content_addressed(
            store, authority, plan_artifact_id, frozen_bytes, frozen_id
        )
        frozen = rd.load_frozen_plan(
            store.get(plan_artifact_id), expected_id=frozen_id
        )
        return graph, plan, frozen

    def test_anchor_run_crash_resume_continuation_and_receipt(self) -> None:
        transport = FakeAnchorTransport()
        remote: dict = {}

        # Round 1: publish fails after external staging.
        store, authority, lane = self.compose(
            transport, runs=FakeAwRuns(conclusion="failure"), remote=remote
        )
        graph, plan, frozen = self.frozen_fixture(store, authority)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane,
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        fresh_authority = rd.GithubAnchorDigestAuthority(transport=transport)
        kinds = {i.split(":")[0] for i in fresh_authority.recorded_ids()}
        self.assertIn("plan", kinds)
        self.assertIn("staged-manifest", kinds)

        # Round 2: reconstructed process resumes - zero restage, exact
        # continuation inputs, sealed receipt reloadable externally.
        runs = FakeAwRuns()
        store2, authority2, lane2 = self.compose(
            transport, runs=runs, remote=remote
        )

        def fill_remote(inputs):
            remote.update(remote_state())
        original = runs.dispatch
        runs.dispatch = lambda inputs: (original(inputs), fill_remote(inputs))[0]

        graph2, plan2, frozen2 = self.frozen_fixture(store2, authority2)
        entries = rd.resume_plan(
            plan2, graph2,
            lanes=lane2, skew=NoRuntimeSkew(),
            store=store2, authority=authority2,
            source_sha="s1", approvals={}, state=None, frozen=frozen2,
            require_external_authority=True,
            authority_trust="external-immutable",
        )
        self.assertEqual(lane2.stage_calls, 0,
                         "resume must never restage")
        self.assertEqual(len(runs.dispatched), 1)
        dispatched = runs.dispatched[0]
        self.assertEqual(dispatched["mode"], "publish-continuation")
        self.assertEqual(dispatched["source_sha"], "a" * 40)
        self.assertEqual(dispatched["stage_run_id"], "30977506589")
        self.assertEqual(dispatched["stage_artifact_id"], "8918869285")
        self.assertEqual(entries["aw"].phase, "verified")
        self.assertEqual(entries["aw"].lane_ref["aw_source_sha"], "a" * 40)

        # The sealed receipt reloads through yet another fresh composition.
        store3, authority3, _ = self.compose(
            transport, runs=FakeAwRuns(), remote=remote
        )
        receipt_ids = [
            i for i in authority3.recorded_ids() if i.startswith("receipt:")
        ]
        self.assertEqual(len(receipt_ids), 1)
        receipt = rd.load_sealed_receipt(
            store3.get(receipt_ids[0]),
            expected_digest=authority3.expected_digest(receipt_ids[0]),
        )
        ok, why = rd.receipt_matches_run(receipt, plan2, graph2, source_sha="s1")
        self.assertTrue(ok, why)
        self.assertEqual(receipt.entries["aw"].lane_ref["artifact"],
                         "gh-artifact:awebai/aw:30977506589:8918869285")
        published_transitions = [
            json.loads(store3.get(i))
            for i in authority3.recorded_ids()
            if i.startswith("transition:") and ":published:" in i
        ]
        self.assertTrue(published_transitions)
        for record in published_transitions:
            self.assertEqual(
                record["entry"]["lane_ref"]["aw_source_sha"], "a" * 40
            )
            self.assertTrue(record["entry"]["digest_set"])

    def test_resume_adopts_exact_remote_state_without_continuation(self) -> None:
        transport = FakeAnchorTransport()
        remote = remote_state()  # everything already published, exact bytes
        store, authority, lane = self.compose(
            transport, runs=FakeAwRuns(conclusion="failure"), remote={}
        )
        graph, plan, frozen = self.frozen_fixture(store, authority)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane,
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        runs = FakeAwRuns()
        store2, authority2, lane2 = self.compose(
            transport, runs=runs, remote=remote
        )
        graph2, plan2, frozen2 = self.frozen_fixture(store2, authority2)
        entries = rd.resume_plan(
            plan2, graph2,
            lanes=lane2, skew=NoRuntimeSkew(),
            store=store2, authority=authority2,
            source_sha="s1", approvals={}, state=None, frozen=frozen2,
            require_external_authority=True,
            authority_trust="external-immutable",
        )
        self.assertEqual(runs.dispatched, [],
                         "exact remote state adopts; no continuation")
        self.assertEqual(lane2.stage_calls, 0)
        self.assertEqual(entries["aw"].phase, "verified")

    def test_resume_refuses_a_tampered_published_transition(self) -> None:
        """A transition claiming publication must match the anchored staged
        manifest entry exactly; an authentic-but-wrong record refuses."""
        transport = FakeAnchorTransport()
        store, authority, lane = self.compose(
            transport, runs=FakeAwRuns(conclusion="failure"), remote={}
        )
        graph, plan, frozen = self.frozen_fixture(store, authority)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane,
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        manifest_id = next(
            i for i in authority.recorded_ids()
            if i.startswith("staged-manifest:")
        )
        forged = json.dumps({
            "frozen_plan_id": frozen.frozen_id,
            "staged_manifest_id": manifest_id,
            "sequence": 99,
            "component": "aw",
            "kind": "published",
            "entry": {
                "version": "1.34.3",
                "digest": "0" * 64,
                "phase": "published",
                "pointer_state": None,
                "delivery_proof": None,
                "lane_ref": None,
                "digest_set": {"forged": "0" * 64},
            },
        }, sort_keys=True).encode()
        forged_digest = sha256(forged)
        forged_id = (
            f"transition:{frozen.frozen_id}:099:published:aw:{forged_digest}"
        )
        rd._put_content_addressed(store, authority, forged_id, forged, forged_digest)
        runs = FakeAwRuns()
        remote = remote_state()
        store2, authority2, lane2 = self.compose(
            transport, runs=runs, remote=remote
        )
        graph2, plan2, frozen2 = self.frozen_fixture(store2, authority2)
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.resume_plan(
                plan2, graph2,
                lanes=lane2, skew=NoRuntimeSkew(),
                store=store2, authority=authority2,
                source_sha="s1", approvals={}, state=None, frozen=frozen2,
                require_external_authority=True,
                authority_trust="external-immutable",
            )
        self.assertIn("transition", str(caught.exception))

    def test_resume_refuses_exact_entry_with_wrong_manifest_identity(self) -> None:
        """A transition whose ENTRY fields are exact but whose
        staged-manifest identity is wrong must refuse: prefix filtering is
        not semantic validation of the body."""
        transport = FakeAnchorTransport()
        store, authority, lane = self.compose(
            transport, runs=FakeAwRuns(conclusion="failure"), remote={}
        )
        graph, plan, frozen = self.frozen_fixture(store, authority)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane,
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        manifest_id = next(
            i for i in authority.recorded_ids()
            if i.startswith("staged-manifest:")
        )
        manifest = json.loads(store.get(manifest_id))
        exact = dict(manifest["entries"]["aw"])
        forged = json.dumps({
            "frozen_plan_id": frozen.frozen_id,
            "staged_manifest_id": "staged-manifest:FORGED:" + "0" * 64,
            "sequence": 98,
            "component": "aw",
            "kind": "published",
            "entry": {
                "version": exact["version"],
                "digest": exact["digest"],
                "phase": "published",
                "pointer_state": exact.get("pointer_state"),
                "delivery_proof": None,
                "lane_ref": exact.get("lane_ref"),
                "digest_set": exact.get("digest_set"),
            },
        }, sort_keys=True).encode()
        forged_digest = sha256(forged)
        forged_id = (
            f"transition:{frozen.frozen_id}:098:published:aw:{forged_digest}"
        )
        rd._put_content_addressed(store, authority, forged_id, forged, forged_digest)
        remote = remote_state()
        store2, authority2, lane2 = self.compose(
            transport, runs=FakeAwRuns(), remote=remote
        )
        graph2, plan2, frozen2 = self.frozen_fixture(store2, authority2)
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.resume_plan(
                plan2, graph2,
                lanes=lane2, skew=NoRuntimeSkew(),
                store=store2, authority=authority2,
                source_sha="s1", approvals={}, state=None, frozen=frozen2,
                require_external_authority=True,
                authority_trust="external-immutable",
            )
        self.assertIn("manifest", str(caught.exception))

    def test_resume_refuses_mismatched_remote_state(self) -> None:
        transport = FakeAnchorTransport()
        store, authority, lane = self.compose(
            transport, runs=FakeAwRuns(conclusion="failure"), remote={}
        )
        graph, plan, frozen = self.frozen_fixture(store, authority)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane,
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        remote = remote_state()
        remote["checksums.txt"] = b"TAMPERED"
        store2, authority2, lane2 = self.compose(
            transport, runs=FakeAwRuns(), remote=remote
        )
        graph2, plan2, frozen2 = self.frozen_fixture(store2, authority2)
        with self.assertRaises(rd.ReceiptError):
            rd.resume_plan(
                plan2, graph2,
                lanes=lane2, skew=NoRuntimeSkew(),
                store=store2, authority=authority2,
                source_sha="s1", approvals={}, state=None, frozen=frozen2,
                require_external_authority=True,
                authority_trust="external-immutable",
            )


class MakeReleaseSurfaceTests(unittest.TestCase):
    def test_release_run_threads_stage_artifact_to_the_cli(self) -> None:
        """The repository's release target must pass every structured
        --stage-artifact value through to the Python CLI; a dry run proves
        the exact value reaches it."""
        import subprocess as sp

        value = ("component=aw,ref=gh-artifact:awebai/aw:1:2,"
                 "source=" + "a" * 40 + ",digest=sha256:" + "b" * 64)
        result = sp.run(
            ["make", "-n", "release-run",
             f"STAGE_ARTIFACT={value}",
             "PLAN_ID=p", "PLAN_ARTIFACT_ID=pa"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'--stage-artifact "{value}"', result.stdout)

    def test_duplicate_component_references_refuse(self) -> None:
        good = ("component=aw,ref=gh-artifact:awebai/aw:1:2,"
                "source=" + "a" * 40 + ",digest=sha256:" + "b" * 64)
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.parse_stage_artifact_arguments([good, good])
        self.assertIn("aw", str(caught.exception))


def pypi_lane_zip(*, package="server", pypi_name="aweb", version="1.26.36",
                  mode="stage-only", source_sha="c" * 40,
                  drop_wheel=False) -> bytes:
    normalized = pypi_name.replace("-", "_")
    members = {
        f"dist/{normalized}-{version}.tar.gz": b"sdist-bytes",
        f"dist/{normalized}-{version}-py3-none-any.whl": b"wheel-bytes",
    }
    if drop_wheel:
        members = {k: v for k, v in members.items() if not k.endswith(".whl")}
    files = {k.rsplit("/", 1)[-1]: sha256(v) for k, v in members.items()}
    canonical = sha256(json.dumps(files, sort_keys=True).encode())
    manifest = {
        "mode": mode, "package": package, "tag": f"server-v{version}",
        "candidate_version": version, "source_sha": source_sha,
        "files": files, "canonical_set_digest": canonical,
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        zip_member(z, "manifest.json", json.dumps(manifest))
        for name, data in members.items():
            zip_member(z, name, data)
    return buffer.getvalue()


def real_oci_archive(*, version="0.5.15", source_sha="d" * 40,
                     wrong_version_label=False, single_platform=False):
    """A REAL minimal two-platform labeled OCI layout tar, plus the
    identities document the reviewed inspector derives from it."""
    import tarfile

    blobs: dict[str, bytes] = {}

    def add(data: bytes) -> str:
        digest = "sha256:" + sha256(data)
        blobs[digest] = data
        return digest

    MANIFEST = "application/vnd.oci.image.manifest.v1+json"
    INDEX = "application/vnd.oci.image.index.v1+json"
    labels = {
        "org.opencontainers.image.title": "awid",
        "org.opencontainers.image.version":
            "9.9.9" if wrong_version_label else version,
        "org.opencontainers.image.revision": source_sha,
    }
    platforms = ["amd64"] if single_platform else ["amd64", "arm64"]
    entries = []
    identities = {"platforms": {}}
    for arch in platforms:
        config = add(json.dumps({"architecture": arch, "os": "linux",
                                 "config": {"Labels": labels}}).encode())
        layer = add(f"layer-bytes-{arch}".encode())
        manifest = add(json.dumps({
            "schemaVersion": 2, "mediaType": MANIFEST,
            "config": {"mediaType":
                       "application/vnd.oci.image.config.v1+json",
                       "digest": config, "size": len(blobs[config])},
            "layers": [{"mediaType":
                        "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": layer, "size": len(blobs[layer])}],
        }).encode())
        entries.append({"mediaType": MANIFEST, "digest": manifest,
                        "size": len(blobs[manifest]),
                        "platform": {"os": "linux", "architecture": arch}})
        identities["platforms"][f"linux/{arch}"] = {
            "manifest": manifest, "config": config, "layers": [layer],
        }
    index_bytes = json.dumps({
        "schemaVersion": 2, "mediaType": INDEX, "manifests": entries,
    }).encode()
    index = add(index_bytes)
    identities["index"] = index
    top = json.dumps({
        "schemaVersion": 2,
        "manifests": [{"mediaType": INDEX, "digest": index,
                       "size": len(index_bytes)}],
    }).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        def put(name, data):
            import tarfile as tf
            info = tf.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        put("oci-layout",
            json.dumps({"imageLayoutVersion": "1.0.0"}).encode())
        put("index.json", top)
        for digest, data in blobs.items():
            put("blobs/sha256/" + digest.split(":")[1], data)
    return buffer.getvalue(), identities


def image_lane_zip(*, version="0.5.15", mode="stage-only",
                   source_sha="d" * 40, archive=None, identities=None,
                   duplicate_member=False) -> bytes:
    if archive is None:
        archive, identities = real_oci_archive(
            version=version, source_sha=source_sha)
    identities_bytes = json.dumps(identities, sort_keys=True).encode()
    files = {"awid-oci.tar": sha256(archive),
             "identities.json": sha256(identities_bytes)}
    canonical = sha256(json.dumps(files, sort_keys=True).encode())
    manifest = {
        "mode": mode, "package": "awid-image", "tag": f"awid-v{version}",
        "candidate_version": version, "source_sha": source_sha,
        "files": files, "canonical_set_digest": canonical,
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        zip_member(z, "manifest.json", json.dumps(manifest))
        zip_member(z, "awid-oci.tar", archive)
        zip_member(z, "identities.json", identities_bytes)
        if duplicate_member:
            zip_member(z, "identities.json", identities_bytes)
    return buffer.getvalue()


def flattened_oci_set(identities: dict) -> dict:
    flat = {"index": identities["index"]}
    for key, ids in sorted(identities["platforms"].items()):
        flat[f"platform:{key}:manifest"] = ids["manifest"]
        flat[f"platform:{key}:config"] = ids["config"]
        for i, layer in enumerate(ids["layers"]):
            flat[f"platform:{key}:layer:{i}"] = layer
    return flat


def lane_ref_for(api, zip_bytes, source_sha) -> "rd.LaneRef":
    return rd.LaneRef(
        artifact=f"gh-artifact:{api.repo}:{api.run_id}:{api.artifact_id}",
        aw_source_sha=source_sha,
        zip_digest=f"sha256:{sha256(zip_bytes)}",
    )


class LaneSourceTests(unittest.TestCase):
    def test_each_lane_binds_its_exact_repository_and_workflow(self) -> None:
        self.assertEqual(
            rd.LANE_ARTIFACT_SOURCES["aw"],
            ("awebai/aw", ".github/workflows/aw-release.yml"),
        )
        self.assertEqual(
            rd.LANE_ARTIFACT_SOURCES["server"],
            ("awebai/aweb", ".github/workflows/pypi-release.yml"),
        )
        self.assertEqual(
            rd.LANE_ARTIFACT_SOURCES["awid-pypi"],
            ("awebai/aweb", ".github/workflows/pypi-release.yml"),
        )
        self.assertEqual(
            rd.LANE_ARTIFACT_SOURCES["awid-image"],
            ("awebai/aweb", ".github/workflows/awid-image-release.yml"),
        )

    def test_reader_refuses_the_wrong_workflow_for_its_lane(self) -> None:
        zip_bytes = pypi_lane_zip()
        api = FakeGithubApi(repo="awebai/aweb", zip_bytes=zip_bytes,
                            workflow_path=".github/workflows/aw-release.yml")
        reader = rd.GithubArtifactStore(
            api=api, repo="awebai/aweb",
            workflow_path=".github/workflows/pypi-release.yml",
        )
        with self.assertRaises(rd.ReceiptError) as caught:
            reader.get(f"gh-artifact:awebai/aweb:{api.run_id}:{api.artifact_id}")
        self.assertIn("pypi-release.yml", str(caught.exception))

    def test_reader_refuses_a_repo_outside_its_lane(self) -> None:
        api = FakeGithubApi()  # serves an awebai/aw artifact
        reader = rd.GithubArtifactStore(
            api=api, repo="awebai/aweb",
            workflow_path=".github/workflows/pypi-release.yml",
        )
        with self.assertRaises(rd.ReceiptError) as caught:
            reader.get(artifact_id_for(api))
        self.assertIn("not this lane's source", str(caught.exception))


def pypi_lane(zip_bytes, *, observer, runs=None, source_sha="c" * 40,
              version="1.26.36"):
    api = FakeGithubApi(repo="awebai/aweb", zip_bytes=zip_bytes,
                        workflow_path=".github/workflows/pypi-release.yml")
    return rd.PypiWorkflowLane(
        component="server",
        pypi_name="aweb",
        reader=rd.GithubArtifactStore(
            api=api, repo="awebai/aweb",
            workflow_path=".github/workflows/pypi-release.yml"),
        lane_authority=rd.GithubArtifactDigestAuthority(
            api=api, repo="awebai/aweb",
            workflow_path=".github/workflows/pypi-release.yml"),
        refs={"server": lane_ref_for(api, zip_bytes, source_sha)},
        pypi_observe=observer,
        runs=runs if runs is not None else FakeAwRuns(),
        waiter=lambda: None,
    ), api


class GithubApiDefaultSignatureTests(unittest.TestCase):
    """The store/authority/run-reader call their api with the path alone, and an
    injected fake has that signature. Storing _run_gh_api directly -- which
    requires a keyword-only timeout -- raised TypeError on every real use while
    every test passed, because tests inject fakes."""

    def test_default_api_is_callable_with_the_path_alone(self) -> None:
        import inspect

        for build in (
            lambda: rd.GithubArtifactStore(repo="awebai/aweb", workflow_path="w"),
            lambda: rd.GithubArtifactDigestAuthority(
                repo="awebai/aweb", workflow_path="w"),
        ):
            api = build()._api
            sig = inspect.signature(api)
            required = [
                name for name, prm in sig.parameters.items()
                if prm.default is inspect.Parameter.empty
                and prm.kind is not inspect.Parameter.VAR_KEYWORD
            ]
            self.assertEqual(required, ["path"], f"default api takes {sig}")

    def test_default_api_threads_a_timeout_to_run_gh_api(self) -> None:
        seen = {}

        def fake_run(path, *, timeout):
            seen["path"], seen["timeout"] = path, timeout
            return b"{}"

        with unittest.mock.patch.object(rd, "_run_gh_api", fake_run):
            rd._default_gh_api("repos/x/actions/runs/1")
        self.assertEqual(seen["path"], "repos/x/actions/runs/1")
        self.assertGreater(seen["timeout"], 0)

    def test_injected_api_is_still_used_unchanged(self) -> None:
        calls = []
        store = rd.GithubArtifactStore(
            lambda path: calls.append(path) or b"{}",
            repo="awebai/aweb", workflow_path="w")
        store._api("repos/x")
        self.assertEqual(calls, ["repos/x"])


class PypiWorkflowLaneTests(unittest.TestCase):
    def coherent(self):
        zip_bytes = pypi_lane_zip()
        files = {
            "aweb-1.26.36.tar.gz": sha256(b"sdist-bytes"),
            "aweb-1.26.36-py3-none-any.whl": sha256(b"wheel-bytes"),
        }
        return zip_bytes, files

    def test_stage_validates_the_pypi_payload_protocol(self) -> None:
        zip_bytes, files = self.coherent()
        lane, _ = pypi_lane(zip_bytes, observer=lambda p, v: (404, {}))
        entry = lane.stage(rd.PlanNode(
            component="server", reason="changed", version="1.26.36"))
        self.assertEqual(entry.digest_set, files)
        self.assertEqual(entry.digest, rd.canonical_digest_of_set(files))

    def test_required_mode_defaults_to_stage_only(self) -> None:
        """Every existing caller passes no mode. A verify-only artifact must
        still be refused for them, unchanged."""
        with self.assertRaisesRegex(rd.ReceiptError, "stage-only"):
            rd.validate_pypi_lane_artifact(
                pypi_lane_zip(mode="verify-only"),
                expected_source_sha="c" * 40, expected_version="1.26.36",
                package="server", pypi_name="aweb")

    def test_verify_only_mode_is_explicit_in_both_directions(self) -> None:
        """A measurement consumes verify-only, which never continues to
        publication; the same protocol governs both, so the mode is a parameter
        rather than two near-copies that can drift."""
        manifest = rd.validate_pypi_lane_artifact(
            pypi_lane_zip(mode="verify-only"),
            expected_source_sha="c" * 40, expected_version="1.26.36",
            package="server", pypi_name="aweb", required_mode="verify-only")
        self.assertEqual(manifest["mode"], "verify-only")
        with self.assertRaisesRegex(rd.ReceiptError, "verify-only"):
            rd.validate_pypi_lane_artifact(
                pypi_lane_zip(mode="stage-only"),
                expected_source_sha="c" * 40, expected_version="1.26.36",
                package="server", pypi_name="aweb",
                required_mode="verify-only")

    def test_canonical_set_digest_recomputes_in_every_mode(self) -> None:
        """The check the near-copy lacked. It must hold for verify-only too,
        or parameterizing the mode would reintroduce the same hole."""
        for mode in ("stage-only", "verify-only"):
            with self.subTest(mode=mode):
                buffer = io.BytesIO(pypi_lane_zip(mode=mode))
                with zipfile.ZipFile(buffer) as z:
                    manifest = json.loads(z.read("manifest.json"))
                    members = {n: z.read(n) for n in z.namelist()
                               if n != "manifest.json"}
                manifest["canonical_set_digest"] = "0" * 64
                forged = io.BytesIO()
                with zipfile.ZipFile(forged, "w") as z:
                    zip_member(z, "manifest.json", json.dumps(manifest))
                    for name, data in members.items():
                        zip_member(z, name, data)
                with self.assertRaisesRegex(
                    rd.ReceiptError, "canonical set digest"
                ):
                    rd.validate_pypi_lane_artifact(
                        forged.getvalue(), expected_source_sha="c" * 40,
                        expected_version="1.26.36", package="server",
                        pypi_name="aweb", required_mode=mode)

    def test_duplicate_zip_entries_refuse(self) -> None:
        """ZipFile.read resolves one of N same-named entries; membership by
        name presence would let a duplicate smuggle different bytes."""
        zip_bytes = pypi_lane_zip()
        buffer = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(buffer, "a") as z:
            zip_member(z, "manifest.json", "{}")
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.validate_pypi_lane_artifact(
                buffer.getvalue(), expected_source_sha="c" * 40,
                expected_version="1.26.36", package="server",
                pypi_name="aweb")
        self.assertIn("once", str(caught.exception))
        with self.assertRaises(rd.ReceiptError):
            rd.validate_image_lane_artifact(
                image_lane_zip(duplicate_member=True),
                expected_source_sha="d" * 40, expected_version="0.5.15")

    def test_stage_refuses_a_missing_wheel(self) -> None:
        zip_bytes = pypi_lane_zip(drop_wheel=True)
        lane, _ = pypi_lane(zip_bytes, observer=lambda p, v: (404, {}))
        with self.assertRaises(rd.ReceiptError):
            lane.stage(rd.PlanNode(
                component="server", reason="changed", version="1.26.36"))

    def test_observe_semantics_absent_partial_exact_extra_outage(self) -> None:
        zip_bytes, files = self.coherent()
        node = rd.PlanNode(component="server", reason="changed",
                           version="1.26.36")
        state = {}

        def observer(package, version):
            return state["response"]

        lane, _ = pypi_lane(zip_bytes, observer=observer)
        staged = lane.stage(node)
        state["response"] = (404, {})
        self.assertIsNone(lane.observe(node, staged))
        state["response"] = (200, {k: files[k] for k in list(files)[:1]})
        self.assertIsNone(lane.observe(node, staged), "partial continues")
        state["response"] = (200, dict(files))
        observed = lane.observe(node, staged)
        self.assertEqual(observed.digest_set, files)
        state["response"] = (200, {**files, "extra.whl": "0" * 64})
        with self.assertRaises(rd.ReceiptError):
            lane.observe(node, staged)
        bad = dict(files)
        bad[next(iter(bad))] = "0" * 64
        state["response"] = (200, bad)
        with self.assertRaises(rd.ReceiptError):
            lane.observe(node, staged)
        state["response"] = (503, {})
        with self.assertRaises(rd.ReceiptError):
            lane.observe(node, staged)

    def test_publish_dispatches_exact_continuation_inputs(self) -> None:
        zip_bytes, files = self.coherent()
        node = rd.PlanNode(component="server", reason="changed",
                           version="1.26.36")
        state = {"response": (404, {})}
        runs = FakeAwRuns()
        lane, api = pypi_lane(zip_bytes, observer=lambda p, v: state["response"],
                              runs=runs)
        staged = lane.stage(node)
        original = runs.dispatch

        def dispatch(inputs):
            original(inputs)
            state["response"] = (200, dict(files))
        runs.dispatch = dispatch
        published = lane.publish(node, staged)
        self.assertEqual(published.phase, "published")
        self.assertEqual(runs.dispatched, [{
            "package": "server",
            "mode": "publish-continuation",
            "version": "1.26.36",
            "source_sha": "c" * 40,
            "stage_run_id": str(api.run_id),
            "stage_artifact_id": str(api.artifact_id),
            "stage_zip_digest": f"sha256:{sha256(zip_bytes)}",
        }])


def image_lane(zip_bytes, *, tag_observe, runs=None, source_sha="d" * 40):
    api = FakeGithubApi(repo="awebai/aweb", zip_bytes=zip_bytes,
                        workflow_path=".github/workflows/awid-image-release.yml")
    return rd.AwidImageWorkflowLane(
        component="awid-image",
        repository="ghcr.io/awebai/awid",
        reader=rd.GithubArtifactStore(
            api=api, repo="awebai/aweb",
            workflow_path=".github/workflows/awid-image-release.yml"),
        lane_authority=rd.GithubArtifactDigestAuthority(
            api=api, repo="awebai/aweb",
            workflow_path=".github/workflows/awid-image-release.yml"),
        refs={"awid-image": lane_ref_for(api, zip_bytes, source_sha)},
        tag_observe=tag_observe,
        runs=runs if runs is not None else FakeAwRuns(),
        waiter=lambda: None,
    ), api


class AwidImageWorkflowLaneTests(unittest.TestCase):
    def test_stage_reinspects_and_binds_the_registry_identity(self) -> None:
        archive, identities = real_oci_archive()
        zip_bytes = image_lane_zip(archive=archive, identities=identities)
        lane, _ = image_lane(zip_bytes, tag_observe=lambda tag: None)
        entry = lane.stage(rd.PlanNode(
            component="awid-image", reason="changed", version="0.5.15"))
        self.assertEqual(entry.digest_set, flattened_oci_set(identities))
        self.assertEqual(
            entry.digest, rd.canonical_digest_of_set(entry.digest_set))

    def test_stage_refuses_an_invalid_archive(self) -> None:
        _, identities = real_oci_archive()
        zip_bytes = image_lane_zip(
            archive=b"oci-archive-bytes", identities=identities)
        lane, _ = image_lane(zip_bytes, tag_observe=lambda tag: None)
        with self.assertRaises(rd.ReceiptError):
            lane.stage(rd.PlanNode(
                component="awid-image", reason="changed", version="0.5.15"))

    def test_stage_refuses_a_wrong_version_label(self) -> None:
        archive, identities = real_oci_archive(wrong_version_label=True)
        zip_bytes = image_lane_zip(archive=archive, identities=identities)
        lane, _ = image_lane(zip_bytes, tag_observe=lambda tag: None)
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.stage(rd.PlanNode(
                component="awid-image", reason="changed", version="0.5.15"))
        self.assertIn("labels version", str(caught.exception))

    def test_stage_refuses_a_missing_platform(self) -> None:
        archive, identities = real_oci_archive(single_platform=True)
        zip_bytes = image_lane_zip(archive=archive, identities=identities)
        lane, _ = image_lane(zip_bytes, tag_observe=lambda tag: None)
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.stage(rd.PlanNode(
                component="awid-image", reason="changed", version="0.5.15"))
        self.assertIn("linux/arm64", str(caught.exception))

    def test_stage_refuses_tampered_identities(self) -> None:
        archive, identities = real_oci_archive()
        forged = json.loads(json.dumps(identities))
        forged["platforms"]["linux/amd64"]["config"] = "sha256:" + "0" * 64
        zip_bytes = image_lane_zip(archive=archive, identities=forged)
        lane, _ = image_lane(zip_bytes, tag_observe=lambda tag: None)
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.stage(rd.PlanNode(
                component="awid-image", reason="changed", version="0.5.15"))
        self.assertIn("identities", str(caught.exception))

    def test_observe_binds_version_immutably_and_latest_as_pointer(self) -> None:
        archive, identities = real_oci_archive()
        INDEX = identities["index"]
        zip_bytes = image_lane_zip(archive=archive, identities=identities)
        node = rd.PlanNode(component="awid-image", reason="changed",
                           version="0.5.15")
        tags = {}
        lane, _ = image_lane(zip_bytes, tag_observe=lambda tag: tags.get(tag))
        staged = lane.stage(node)
        self.assertIsNone(lane.observe(node, staged), "nothing published yet")
        tags["0.5.15"] = INDEX
        self.assertIsNone(lane.observe(node, staged),
                          "latest not yet transitioned continues")
        tags["latest"] = INDEX
        observed = lane.observe(node, staged)
        self.assertEqual(observed.digest_set, flattened_oci_set(identities))
        tags["latest"] = "sha256:" + "1" * 64
        self.assertIsNone(lane.observe(node, staged),
                          "latest is the planned mutable pointer")
        tags["0.5.15"] = "sha256:" + "1" * 64
        with self.assertRaises(rd.ReceiptError):
            lane.observe(node, staged)

    def test_unavailable_tag_observation_refuses(self) -> None:
        zip_bytes = image_lane_zip()
        node = rd.PlanNode(component="awid-image", reason="changed",
                           version="0.5.15")

        def unavailable(tag):
            raise rd.ReceiptError("listing unavailable")
        lane, _ = image_lane(zip_bytes, tag_observe=unavailable)
        staged = lane.stage(node)
        with self.assertRaises(rd.ReceiptError):
            lane.observe(node, staged)


class LaneCompositionTests(unittest.TestCase):
    def test_graph_declaration_gates_lane_composition(self) -> None:
        graph = rd.Graph.load(rd.GRAPH_PATH)
        for name in ("server", "awid-pypi", "awid-image"):
            lane = graph.components[name].publish_lane
            self.assertEqual(lane.get("provider"), "github-workflow-artifacts",
                             name)
            self.assertEqual(lane.get("repository"), "awebai/aweb", name)
        refs = {
            "server": rd.LaneRef(
                artifact="gh-artifact:awebai/aweb:1:2",
                aw_source_sha="c" * 40,
                zip_digest="sha256:" + "5" * 64),
        }
        lanes = rd.compose_workflow_lanes(graph, refs)
        self.assertTrue(lanes.has_lane("server"))
        self.assertFalse(lanes.has_lane("awid-image"))
        self.assertFalse(lanes.has_lane("sites"))

    def test_undeclared_component_reference_refuses(self) -> None:
        graph = rd.Graph.load(rd.GRAPH_PATH)
        refs = {"sites": rd.LaneRef(
            artifact="gh-artifact:awebai/aweb:1:2",
            aw_source_sha="c" * 40,
            zip_digest="sha256:" + "5" * 64)}
        with self.assertRaises(rd.ReceiptError):
            rd.compose_workflow_lanes(graph, refs)


class PypiOciEndToEndTests(unittest.TestCase):
    """The .10 acceptance: external-anchor run/crash/resume for one PyPI
    lane and the OCI lane across reconstructed compositions."""

    def graph_for(self, name, registry):
        return rd.Graph.from_dict({
            "component": {
                name: {
                    "source_paths": ["x/"],
                    "version_source": {"type": "manifest", "path": "x/v"},
                    "tag_format": name + "-v{version}",
                    "publish_lane": {
                        "workflow": ".github/workflows/x.yml",
                        "repository": "awebai/aweb",
                        "provider": "github-workflow-artifacts",
                        "modes": ["stage-only", "publish-continuation",
                                  "verify-only"],
                        "registry": registry,
                    },
                    "verify": {"command": "true"},
                },
            },
            "edge": [],
        })

    def run_crash_resume(self, *, name, version, lane_factory):
        transport = FakeAnchorTransport()
        graph = self.graph_for(
            name, {"type": "pypi", "package": name}
        )
        state = rd.FixtureState(
            changed_components={name: True},
            versions={name: version},
            published_versions={name: "0.0.1"},
        )

        def compose():
            store = rd.GithubAnchorStore(transport=transport,
                                         waiter=lambda: None)
            authority = rd.GithubAnchorDigestAuthority(transport=transport)
            return store, authority

        store, authority = compose()
        plan = rd.compute_plan(graph, state)
        frozen_bytes, frozen_id = rd.freeze_plan(plan, graph, source_sha="s1")
        rd._put_content_addressed(
            store, authority, f"plan:s1:{frozen_id}", frozen_bytes, frozen_id)
        frozen = rd.load_frozen_plan(
            store.get(f"plan:s1:{frozen_id}"), expected_id=frozen_id)

        crash_lane = lane_factory(publish_ok=False)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, crash_lane,
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )

        store2, authority2 = compose()
        resume_lane = lane_factory(publish_ok=True)
        plan2 = rd.compute_plan(graph, state)
        frozen2 = rd.load_frozen_plan(
            store2.get(f"plan:s1:{frozen_id}"), expected_id=frozen_id)
        entries = rd.resume_plan(
            plan2, graph,
            lanes=resume_lane, skew=NoRuntimeSkew(),
            store=store2, authority=authority2,
            source_sha="s1", approvals={}, state=None, frozen=frozen2,
            require_external_authority=True,
            authority_trust="external-immutable",
        )
        self.assertEqual(resume_lane.stage_calls, 0, "zero restage on resume")
        self.assertEqual(entries[name].phase, "verified")

    def test_pypi_lane_crash_resume(self) -> None:
        version = "1.26.36"
        files = {
            "aweb-1.26.36.tar.gz": sha256(b"sdist-bytes"),
            "aweb-1.26.36-py3-none-any.whl": sha256(b"wheel-bytes"),
        }

        def lane_factory(*, publish_ok):
            zip_bytes = pypi_lane_zip(package="server", version=version)
            state = {"response": (404, {})}
            runs = FakeAwRuns(
                conclusion="success" if publish_ok else "failure")
            if publish_ok:
                original = runs.dispatch

                def dispatch(inputs):
                    original(inputs)
                    state["response"] = (200, dict(files))
                runs.dispatch = dispatch
            lane, _ = pypi_lane(
                zip_bytes, observer=lambda p, v: state["response"], runs=runs)

            class Counting(type(lane)):
                pass
            lane.stage_calls = 0
            original_stage = lane.stage

            def counted_stage(node):
                lane.stage_calls += 1
                return original_stage(node)
            lane.stage = counted_stage
            return lane
        self.run_crash_resume(name="server", version=version,
                              lane_factory=lane_factory)

    def test_image_lane_crash_resume(self) -> None:
        version = "0.5.15"
        archive, identities = real_oci_archive(version=version)
        INDEX = identities["index"]

        def lane_factory(*, publish_ok):
            zip_bytes = image_lane_zip(
                version=version, archive=archive, identities=identities)
            tags = {}
            runs = FakeAwRuns(
                conclusion="success" if publish_ok else "failure")
            if publish_ok:
                original = runs.dispatch

                def dispatch(inputs):
                    original(inputs)
                    tags["0.5.15"] = INDEX
                    tags["latest"] = INDEX
                runs.dispatch = dispatch
            lane, _ = image_lane(
                zip_bytes, tag_observe=lambda tag: tags.get(tag), runs=runs)
            lane.component = "awid-image"
            lane.stage_calls = 0
            original_stage = lane.stage

            def counted_stage(node):
                lane.stage_calls += 1
                return original_stage(node)
            lane.stage = counted_stage
            return lane

        # awid-image is a registry(ghcr) component in the fixture graph
        transport = FakeAnchorTransport()
        graph = self.graph_for(
            "awid-image", {"type": "ghcr", "package": "awebai/awid"})
        state = rd.FixtureState(
            changed_components={"awid-image": True},
            versions={"awid-image": version},
            published_versions={"awid-image": "0.5.14"},
        )
        store = rd.GithubAnchorStore(transport=transport, waiter=lambda: None)
        authority = rd.GithubAnchorDigestAuthority(transport=transport)
        plan = rd.compute_plan(graph, state)
        frozen_bytes, frozen_id = rd.freeze_plan(plan, graph, source_sha="s1")
        rd._put_content_addressed(
            store, authority, f"plan:s1:{frozen_id}", frozen_bytes, frozen_id)
        frozen = rd.load_frozen_plan(
            store.get(f"plan:s1:{frozen_id}"), expected_id=frozen_id)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane_factory(publish_ok=False),
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        store2 = rd.GithubAnchorStore(transport=transport, waiter=lambda: None)
        authority2 = rd.GithubAnchorDigestAuthority(transport=transport)
        resume_lane = lane_factory(publish_ok=True)
        frozen2 = rd.load_frozen_plan(
            store2.get(f"plan:s1:{frozen_id}"), expected_id=frozen_id)
        entries = rd.resume_plan(
            rd.compute_plan(graph, state), graph,
            lanes=resume_lane, skew=NoRuntimeSkew(),
            store=store2, authority=authority2,
            source_sha="s1", approvals={}, state=None, frozen=frozen2,
            require_external_authority=True,
            authority_trust="external-immutable",
        )
        self.assertEqual(resume_lane.stage_calls, 0)
        self.assertEqual(entries["awid-image"].phase, "verified")


def skew_edge(*, a="client", b="server", direction="both",
              journey="make fixture-journey"):
    return rd.RuntimeContractEdge(
        a=a, b=b, journey=journey,
        artifacts={"a": f"registry:{a}", "b": f"registry:{b}"},
        direction=direction,
        supported={
            "set": "measured:fixture-fleet",
            "record": {"authority": "workflow-artifacts",
                       "artifact_id": "measurement:fixture-fleet",
                       "digest": "fixture-digest"},
            "policy": "additive-only",
        },
    )


def staged_entry(component, version, *, lane_ref=True):
    files = {f"{component}.bin": sha256(component.encode())}
    ref = None
    if lane_ref:
        ref = {
            "artifact": f"gh-artifact:awebai/aweb:31000:{abs(hash(component)) % 9999 + 1}",
            "aw_source_sha": "e" * 40,
            "zip_digest": "sha256:" + sha256(component.encode()),
        }
    return rd.ReceiptEntry(
        version=version, digest=rd.canonical_digest_of_set(files),
        digest_set=files, lane_ref=ref,
    )


class VersionedSupport:
    """The measured support resolution the runner consumes: an ordered
    supported published set per edge side."""

    def __init__(self, versions):
        self.versions = versions  # component -> ordered [floor, ..., latest]

    def resolve(self, record, edge):
        return {"digest": record.get("digest"),
                "supported_versions": {
                    edge.a: list(self.versions.get(edge.a, [])),
                    edge.b: list(self.versions.get(edge.b, [])),
                }}


class SkewMatrixTests(unittest.TestCase):
    def cells(self, edge, *, moving, staged, support=None, published=None):
        support = support or VersionedSupport(
            {"client": ["1.0.0", "1.1.0"], "server": ["3.0.0", "3.1.0"]})
        published = published or {"client": "1.1.0", "server": "3.1.0"}
        return rd.compute_skew_cells(
            edge, moving=moving, staged=staged,
            support=support.resolve(edge.supported["record"], edge),
            published_versions=published,
        )

    def test_both_sides_touched_produces_the_joint_spec_cells(self) -> None:
        edge = skew_edge(direction="a-to-b")
        staged = {"client": staged_entry("client", "1.2.0"),
                  "server": staged_entry("server", "3.2.0")}
        cells = self.cells(edge, moving={"client", "server"}, staged=staged)
        kinds = [(c.a_kind, c.b_kind) for c in cells]
        self.assertEqual(kinds, [
            ("candidate", "candidate"),
            ("candidate", "published-latest"),
            ("candidate", "published-floor"),
            ("published-latest", "candidate"),
            ("published-floor", "candidate"),
        ])
        self.assertTrue(all(c.direction == "a-to-b" for c in cells))
        self.assertEqual(cells[0].a["digest"], staged["client"].digest)
        self.assertEqual(cells[0].a["lane_ref"], staged["client"].lane_ref,
                         "the exact staged reference reaches the harness")
        self.assertEqual(cells[0].b["lane_ref"], staged["server"].lane_ref)
        self.assertEqual(cells[1].b["version"], "3.1.0")
        self.assertEqual(cells[2].b["version"], "3.0.0")

    def test_both_directions_double_every_cell(self) -> None:
        edge = skew_edge(direction="both")
        staged = {"client": staged_entry("client", "1.2.0"),
                  "server": staged_entry("server", "3.2.0")}
        cells = self.cells(edge, moving={"client", "server"}, staged=staged)
        self.assertEqual(len(cells), 10)
        self.assertEqual(
            [c.direction for c in cells[:2]], ["a-to-b", "b-to-a"])

    def test_persisted_same_component_uses_each_measured_version_once(self) -> None:
        edge = skew_edge(
            a="server", b="server", direction="persisted-state-both",
            journey="persisted fixture",
        )
        staged = {"server": staged_entry("server", "3.2.0")}
        cells = self.cells(
            edge, moving={"server"}, staged=staged,
            support=VersionedSupport(
                {"server": ["2.9.0", "3.0.0", "3.1.0"]}),
            published={"server": "3.1.0"},
        )
        self.assertEqual(len(cells), 6)
        self.assertEqual(
            [(c.a_kind, c.a["version"], c.b_kind, c.b["version"], c.direction)
             for c in cells],
            [
                ("candidate", "3.2.0", "published-floor", "2.9.0", "a-to-b"),
                ("candidate", "3.2.0", "published-floor", "2.9.0", "b-to-a"),
                ("candidate", "3.2.0", "published", "3.0.0", "a-to-b"),
                ("candidate", "3.2.0", "published", "3.0.0", "b-to-a"),
                ("candidate", "3.2.0", "published-latest", "3.1.0", "a-to-b"),
                ("candidate", "3.2.0", "published-latest", "3.1.0", "b-to-a"),
            ],
        )
        self.assertNotIn(
            ("candidate", "candidate"),
            [(c.a_kind, c.b_kind) for c in cells],
        )

    def test_persisted_matrix_document_recomputes_exact_cells_and_identity(self) -> None:
        edge = skew_edge(
            a="server", b="server", direction="persisted-state-both",
            journey="persisted fixture",
        )
        staged = {"server": staged_entry("server", "3.2.0")}
        support = {"supported_versions": {"server": ["3.0.0", "3.1.0"]}}
        document = rd.freeze_skew_matrix(
            edge, moving={"server"}, staged=staged, support=support,
            published_versions={"server": "3.1.0"},
            staged_manifest_digest="a" * 64,
        )
        cells = rd.validate_skew_matrix_document(document)
        self.assertEqual(
            document["preimage"]["edge_id"], rd.edge_identity(edge)
        )
        self.assertEqual(len(cells), 4)
        self.assertEqual(
            [item["cell_id"] for item in document["preimage"]["cells"]],
            [rd.skew_cell_identity(cell) for cell in cells],
        )
        self.assertEqual(
            document["matrix_id"],
            rd.canonical_json_digest(document["preimage"]),
        )
        tampered = json.loads(json.dumps(document))
        tampered["preimage"]["support"]["supported_versions"]["server"][0] = "2.0.0"
        tampered["matrix_id"] = rd.canonical_json_digest(tampered["preimage"])
        with self.assertRaisesRegex(rd.ReceiptError, "matrix"):
            rd.validate_skew_matrix_document(tampered)

    def test_one_side_touched_runs_candidate_against_the_supported_set(self) -> None:
        edge = skew_edge(direction="a-to-b")
        staged = {"client": staged_entry("client", "1.2.0")}
        cells = self.cells(edge, moving={"client"}, staged=staged)
        self.assertEqual(
            [(c.a_kind, c.b["version"]) for c in cells],
            [("candidate", "3.0.0"), ("candidate", "3.1.0")],
        )
        self.assertEqual(cells[0].a["digest"], staged["client"].digest)

    def test_single_supported_version_deduplicates_floor_and_latest(self) -> None:
        edge = skew_edge(direction="a-to-b")
        staged = {"client": staged_entry("client", "1.2.0"),
                  "server": staged_entry("server", "3.2.0")}
        cells = self.cells(
            edge, moving={"client", "server"}, staged=staged,
            support=VersionedSupport(
                {"client": ["1.1.0"], "server": ["3.1.0"]}),
        )
        kinds = [(c.a_kind, c.b_kind) for c in cells]
        self.assertEqual(kinds, [
            ("candidate", "candidate"),
            ("candidate", "published-latest"),
            ("published-latest", "candidate"),
        ])

    def test_candidate_without_a_lane_reference_refuses(self) -> None:
        """A digest-only candidate gives the child harness no way to
        retrieve and execute the exact staged bytes."""
        edge = skew_edge(direction="a-to-b")
        staged = {"client": staged_entry("client", "1.2.0", lane_ref=False),
                  "server": staged_entry("server", "3.2.0")}
        with self.assertRaises(rd.ReceiptError) as caught:
            self.cells(edge, moving={"client", "server"}, staged=staged)
        self.assertIn("lane", str(caught.exception))

    def test_stale_latest_refuses(self) -> None:
        """The measured list's last member must equal the authoritative
        published latest; caller ordering alone must never pick the cell."""
        edge = skew_edge(direction="a-to-b")
        staged = {"client": staged_entry("client", "1.2.0"),
                  "server": staged_entry("server", "3.2.0")}
        with self.assertRaises(rd.ReceiptError) as caught:
            self.cells(edge, moving={"client", "server"}, staged=staged,
                       published={"client": "1.1.0", "server": "3.5.0"})
        self.assertIn("authoritative", str(caught.exception))

    def test_missing_authoritative_latest_refuses(self) -> None:
        edge = skew_edge(direction="a-to-b")
        staged = {"client": staged_entry("client", "1.2.0"),
                  "server": staged_entry("server", "3.2.0")}
        with self.assertRaises(rd.ReceiptError):
            self.cells(edge, moving={"client", "server"}, staged=staged,
                       published={"client": "1.1.0"})

    def test_duplicate_and_invalid_support_sets_refuse(self) -> None:
        edge = skew_edge(direction="a-to-b")
        staged = {"client": staged_entry("client", "1.2.0")}
        for versions in (["3.0.0", "3.0.0"], ["3.1.0", "3.0.0"],
                         ["", "3.1.0"], ["not-a-version"]):
            with self.assertRaises(rd.ReceiptError, msg=str(versions)):
                self.cells(
                    edge, moving={"client"}, staged=staged,
                    support=VersionedSupport({"client": ["1.1.0"],
                                              "server": versions}),
                    published={"client": "1.1.0",
                               "server": versions[-1] if versions else ""},
                )

    def test_missing_staged_identity_refuses(self) -> None:
        edge = skew_edge()
        with self.assertRaises(rd.ReceiptError):
            self.cells(edge, moving={"client", "server"},
                       staged={"client": staged_entry("client", "1.2.0")})

    def test_empty_support_refuses_rather_than_inventing_floors(self) -> None:
        edge = skew_edge(direction="a-to-b")
        staged = {"client": staged_entry("client", "1.2.0")}
        with self.assertRaises(rd.ReceiptError) as caught:
            self.cells(edge, moving={"client"}, staged=staged,
                       support=VersionedSupport({"client": ["1.1.0"],
                                                 "server": []}))
        self.assertIn("floor", str(caught.exception))


class RecordingHarness:
    def __init__(self, journeys=("make fixture-journey",), fail=False):
        self.journeys = set(journeys)
        self.fail = fail
        self.cells: list = []
        self.matrices: list = []
        self.events: list = []

    def has_journey(self, edge) -> bool:
        return edge.journey in self.journeys

    def freeze_matrix(self, document) -> None:
        self.matrices.append(document)
        self.events.append(("matrix", document["matrix_id"]))

    def run(self, cell) -> None:
        self.cells.append(cell)
        self.events.append(("cell", rd.skew_cell_identity(cell)))
        if self.fail:
            raise rd.ReceiptError(f"skew red: {cell.edge_a}<->{cell.edge_b}")

    def finish_matrix(self, document) -> None:
        self.events.append(("finish", document["matrix_id"]))


class RunOnlyFreezeCompatTests(unittest.TestCase):
    """Compatibility contract: a run-only harness REFUSES at freeze time
    rather than silently executing without the frozen matrix."""

    def test_run_only_harness_refuses_at_freeze(self) -> None:
        class RunOnlyHarness:
            def __init__(self):
                self.cells = []

            def has_journey(self, edge) -> bool:
                return True

            def run(self, cell) -> None:
                self.cells.append(cell)

        harness = RunOnlyHarness()
        runner = rd.MatrixSkewRunner(
            harness=harness,
            support=VersionedSupport({"client": ["1.0.0"],
                                      "server": ["3.0.0"]}),
            published_versions={"client": "1.0.0", "server": "3.0.0"},
            moving={"client", "server"},
        )
        edge = skew_edge(direction="both")
        staged = {"client": staged_entry("client", "1.2.0"),
                  "server": staged_entry("server", "3.2.0")}
        with self.assertRaisesRegex(rd.ReceiptError, "cannot persist"):
            runner.freeze_matrix(edge, staged,
                                 staged_manifest_digest="a" * 64)
        with self.assertRaisesRegex(rd.ReceiptError, "not frozen"):
            runner.execute(edge, staged)
        self.assertEqual(harness.cells, [],
                         "no cell may execute without the frozen matrix")


class MatrixSkewRunnerTests(unittest.TestCase):
    def runner(self, harness, *, versions=None):
        return rd.MatrixSkewRunner(
            harness=harness,
            support=VersionedSupport(
                versions or {"client": ["1.0.0", "1.1.0"],
                             "server": ["3.0.0", "3.1.0"]}),
            published_versions={"client": "1.1.0", "server": "3.1.0"},
            moving={"client", "server"},
        )

    def test_ordered_cells_are_invoked_deterministically(self) -> None:
        harness = RecordingHarness()
        runner = self.runner(harness)
        edge = skew_edge(direction="both")
        staged = {"client": staged_entry("client", "1.2.0"),
                  "server": staged_entry("server", "3.2.0")}
        self.assertTrue(runner.has_matrix(edge))
        with self.assertRaisesRegex(rd.ReceiptError, "not frozen"):
            runner.execute(edge, staged)
        document = runner.freeze_matrix(
            edge, staged, staged_manifest_digest="a" * 64
        )
        runner.execute(edge, staged)
        self.assertEqual(len(harness.cells), 10)
        self.assertEqual(harness.events[0], ("matrix", document["matrix_id"]))
        self.assertTrue(all(event[0] == "cell" for event in harness.events[1:-1]))
        self.assertEqual(harness.events[-1], ("finish", document["matrix_id"]))
        first_pass = [(c.a_kind, c.b_kind, c.direction) for c in harness.cells]
        harness.cells.clear()
        harness.events.clear()
        runner.freeze_matrix(edge, staged, staged_manifest_digest="a" * 64)
        runner.execute(edge, staged)
        self.assertEqual(
            first_pass,
            [(c.a_kind, c.b_kind, c.direction) for c in harness.cells],
        )

    def test_missing_journey_capability_is_not_a_matrix(self) -> None:
        runner = self.runner(RecordingHarness(journeys=()))
        self.assertFalse(runner.has_matrix(skew_edge()))

    def test_declared_incomplete_edge_refuses_at_the_runner(self) -> None:
        edge = rd.RuntimeContractEdge(
            a="client", b="server", journey="make fixture-journey",
            artifacts={"a": "x", "b": "y"}, direction="both",
            supported={"policy": "additive-only"},
        )
        runner = self.runner(RecordingHarness())
        staged = {
            "client": staged_entry("client", "1.2.0"),
            "server": staged_entry("server", "3.2.0")}
        with self.assertRaises(rd.ReceiptError) as caught:
            runner.freeze_matrix(
                edge, staged, staged_manifest_digest="a" * 64
            )
        self.assertIn("incomplete", str(caught.exception))

    def test_skew_failure_precedes_every_lane_call(self) -> None:
        graph = rd.Graph.from_dict(fixture_graph_dict())
        state = orchestration_state()
        plan = rd.compute_plan(graph, state)
        lanes = FixtureLanes(available={n.component for n in plan.moving})
        harness = RecordingHarness(fail=True)
        runner = rd.MatrixSkewRunner(
            harness=harness,
            support=VersionedSupport(
                {"client": ["1.0.0"], "server": ["3.0.0"]}),
            published_versions={"client": "1.0.0", "server": "3.0.0"},
            moving={n.component for n in plan.moving},
        )
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lanes,
                skew=runner, authority=FixtureAuthority(),
                providers=rd.Providers(
                    store=rd._MemoryStore(), authority=FixtureAuthority(),
                    measurement=AllRecordsResolve()),
                source_sha="s1", approvals={}, state=state,
            )
        publishes = [c for k, c in lanes.calls if k == "publish"]
        self.assertEqual(publishes, [],
                         "skew failure precedes every continuation dispatch")


class ProductionSkewCompositionTests(unittest.TestCase):
    """alice's post-landing finding: the runner must be reachable from the
    REAL release path - injected-unit-only coverage is insufficient."""

    def setUp(self):
        import release_skew_harnesses
        self.registry = release_skew_harnesses
        self._saved = dict(self.registry.REGISTRY)
        self.registry.REGISTRY.clear()

    def tearDown(self):
        self.registry.REGISTRY.clear()
        self.registry.REGISTRY.update(self._saved)

    def cli_release_run(self, *, harness=None):
        """A real main(argv) release-run over a measured touched edge,
        with NO injected skew provider: the CLI must compose the matrix."""
        import tempfile

        graph = rd.Graph.from_dict(fixture_graph_dict())
        state = orchestration_state(
            published_versions={"client": "1.0.0", "plugin": "2.0.0",
                                "server": "3.0.0"})
        plan = rd.compute_plan(graph, state)

        class ReferencedLanes(FixtureLanes):
            def stage(self, node):
                entry = super().stage(node)
                return rd.ReceiptEntry(
                    version=entry.version, digest=entry.digest,
                    pointer_state=entry.pointer_state,
                    lane_ref={
                        "artifact": "gh-artifact:awebai/aweb:31000:"
                        + str(abs(hash(node.component)) % 9999 + 1),
                        "aw_source_sha": "e" * 40,
                        "zip_digest": "sha256:" + sha256(
                            node.component.encode()),
                    },
                )

        lanes = ReferencedLanes(available={n.component for n in plan.moving})
        if harness is not None:
            self.registry.register(
                "make fixture-journey", lambda: harness)

        class Support:
            def resolve(self, record, edge):
                return {"digest": record.get("digest"),
                        "supported_versions": {
                            "client": ["1.0.0"], "server": ["3.0.0"]}}

        support = Support()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            frozen_bytes, frozen_id = rd.freeze_plan(
                plan, graph, source_sha="s1", state=state, measurement=support)
            plan_artifact_id = f"plan:s1:{frozen_id}"
            rd._put_content_addressed(
                store, authority, plan_artifact_id, frozen_bytes, frozen_id)
            code = rd.main(
                ["--graph", str(rd.GRAPH_PATH), "release-run",
                 "--plan-id", frozen_id,
                 "--plan-artifact-id", plan_artifact_id,
                 "--allow-local-authority"],
                providers=rd.Providers(
                    store=store, authority=authority, lanes=lanes,
                    state=state, source_sha="s1", measurement=support,
                ),
            )
        return code, lanes

    def test_a_red_harness_exits_before_every_lane_dispatch(self) -> None:
        code, lanes = self.cli_release_run(
            harness=RecordingHarness(fail=True))
        self.assertEqual(code, 1)
        publishes = [c for k, c in lanes.calls if k == "publish"]
        self.assertEqual(publishes, [],
                         "a real CLI red must precede every lane dispatch")

    def test_a_green_harness_lets_the_run_publish(self) -> None:
        harness = RecordingHarness()
        code, lanes = self.cli_release_run(harness=harness)
        self.assertEqual(code, 0)
        self.assertTrue(harness.cells, "the matrix was reached and executed")
        publishes = [c for k, c in lanes.calls if k == "publish"]
        self.assertTrue(publishes)

    def test_missing_child_capability_refuses_not_noskew(self) -> None:
        code, lanes = self.cli_release_run(harness=None)
        self.assertEqual(code, 1)
        self.assertEqual(lanes.calls, [],
                         "an unregistered journey must refuse, never NoSkew")

    def test_duplicate_journey_registration_refuses(self) -> None:
        self.registry.register("j", lambda: None)
        with self.assertRaises(rd.ReceiptError):
            self.registry.register("j", lambda: None)


class SkewMatrixVerbTests(unittest.TestCase):
    def setUp(self):
        import release_skew_harnesses
        self.registry = release_skew_harnesses
        self._saved = dict(self.registry.REGISTRY)
        self.registry.REGISTRY.clear()

    def tearDown(self):
        self.registry.REGISTRY.clear()
        self.registry.REGISTRY.update(self._saved)

    def test_the_verb_prints_the_touched_edge_matrix(self) -> None:
        import contextlib
        import tempfile

        graph = rd.Graph.from_dict(fixture_graph_dict())
        state = orchestration_state(
            published_versions={"client": "1.0.0", "plugin": "2.0.0",
                                "server": "3.0.0"})
        plan = rd.compute_plan(graph, state)

        class Support:
            def resolve(self, record, edge):
                return {"supported_versions": {
                    "client": ["1.0.0"], "server": ["3.0.0"]}}

        support = Support()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = rd.FileArtifactStore(root)
            authority = rd.FileDigestAuthority(root)
            frozen_bytes, frozen_id = rd.freeze_plan(
                plan, graph, source_sha="s1", state=state,
                measurement=support)
            plan_artifact_id = f"plan:s1:{frozen_id}"
            rd._put_content_addressed(
                store, authority, plan_artifact_id, frozen_bytes, frozen_id)
            entries = {
                n.component: rd.ReceiptEntry(
                    version=n.version or "0.0.0",
                    digest=f"staged-{n.component}",
                    pointer_state="ok" if n.reason.startswith("pointer:")
                    else None,
                    lane_ref={
                        "artifact": "gh-artifact:awebai/aweb:1:2",
                        "aw_source_sha": "e" * 40,
                        "zip_digest": "sha256:" + "3" * 64,
                    } if n.component == "client" else None,
                )
                for n in plan.moving
            }
            body, digest = rd.seal_staged_manifest(
                plan, frozen_plan_id=frozen_id, source_sha="s1",
                entries=entries, graph=graph)
            manifest_id = f"staged-manifest:{frozen_id}:{digest}"
            rd._put_content_addressed(
                store, authority, manifest_id, body, digest)
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = rd.main(
                    ["skew-matrix",
                     "--plan-id", frozen_id,
                     "--plan-artifact-id", plan_artifact_id],
                    providers=rd.Providers(
                        store=store, authority=authority,
                        state=state, source_sha="s1", measurement=support,
                    ),
                )
        self.assertEqual(code, 0, "server is untouched: a one-side matrix")
        matrix = json.loads(buffer.getvalue())
        self.assertTrue(matrix["cells"])
        for row in matrix["cells"]:
            self.assertEqual(row["edge"], "client<->server")
            self.assertEqual(len(row["edge_id"]), 64)
            self.assertEqual(row["artifacts"],
                             {"a": "registry:client", "b": "registry:server"})
            self.assertEqual(row["declared_direction"], "both")
            self.assertEqual(row["a"]["kind"], "candidate")
            self.assertEqual(
                row["a"]["lane_ref"]["artifact"],
                "gh-artifact:awebai/aweb:1:2",
                "the exact staged reference is in the printed matrix",
            )
            self.assertEqual(row["b"]["kind"], "published")
            self.assertEqual(row["b"]["version"], "3.0.0")


def measurement_record():
    return {"authority": "workflow-artifacts",
            "artifact_id": "measurement:fixture-fleet",
            "digest": ""}


def anchor_measurement(transport, edge, *, supported=None, journey=None,
                       edge_binding=None, body=None):
    doc = {
        "edge": edge_binding or {"a": edge.a, "b": edge.b},
        "journey": journey or edge.journey,
        "artifacts": dict(edge.artifacts),
        "direction": edge.direction,
        "supported_versions": supported or {
            "client": ["1.0.0"], "server": ["3.0.0"]},
    }
    payload = body if body is not None else json.dumps(
        doc, sort_keys=True).encode()
    store = rd.GithubAnchorStore(transport=transport, waiter=lambda: None)
    store.put("measurement:fixture-fleet", payload)
    return sha256(payload)


class AnchoredMeasurementTests(unittest.TestCase):
    def adapter(self, transport):
        return rd.AnchoredMeasurementAuthority(
            store=rd.GithubAnchorStore(transport=transport,
                                       waiter=lambda: None),
            authority=rd.GithubAnchorDigestAuthority(transport=transport),
        )

    def test_a_coherent_record_resolves_to_its_schema_bound_support(self) -> None:
        transport = FakeAnchorTransport()
        edge = skew_edge()
        digest = anchor_measurement(transport, edge)
        record = {**measurement_record(), "digest": digest}
        doc = self.adapter(transport).resolve(record, edge)
        self.assertEqual(doc["supported_versions"]["server"], ["3.0.0"])

    def test_missing_record_is_unresolvable_not_invented(self) -> None:
        transport = FakeAnchorTransport()
        record = {**measurement_record(), "digest": "0" * 64}
        self.assertIsNone(self.adapter(transport).resolve(record, skew_edge()))

    def test_malformed_record_schema_refuses(self) -> None:
        adapter = self.adapter(FakeAnchorTransport())
        for record in ({}, {"authority": "elsewhere", "artifact_id": "x",
                            "digest": "d"},
                       {"authority": "workflow-artifacts",
                        "artifact_id": "", "digest": "d"}):
            with self.assertRaises(rd.ReceiptError, msg=str(record)):
                adapter.resolve(record, skew_edge())

    def test_record_digest_must_equal_the_authority(self) -> None:
        transport = FakeAnchorTransport()
        edge = skew_edge()
        anchor_measurement(transport, edge)
        record = {**measurement_record(), "digest": "0" * 64}
        with self.assertRaises(rd.ReceiptError):
            self.adapter(transport).resolve(record, edge)

    def test_wrong_edge_binding_refuses(self) -> None:
        transport = FakeAnchorTransport()
        edge = skew_edge()
        digest = anchor_measurement(
            transport, edge, edge_binding={"a": "other", "b": "server"})
        record = {**measurement_record(), "digest": digest}
        with self.assertRaises(rd.ReceiptError) as caught:
            self.adapter(transport).resolve(record, edge)
        self.assertIn("edge", str(caught.exception))

    def test_wrong_journey_and_bad_support_schema_refuse(self) -> None:
        for kwargs in ({"journey": "another journey"},
                       {"supported": {"client": "not-a-list"}},
                       {"body": b"not json"}):
            transport = FakeAnchorTransport()
            edge = skew_edge()
            digest = anchor_measurement(transport, edge, **kwargs)
            record = {**measurement_record(), "digest": digest}
            with self.assertRaises(rd.ReceiptError, msg=str(kwargs)):
                self.adapter(transport).resolve(record, edge)


class FrozenTruthSkewTests(unittest.TestCase):
    """Execution never substitutes live values for frozen truth."""

    def freeze(self, *, support_versions=None):
        graph = rd.Graph.from_dict(fixture_graph_dict())
        state = orchestration_state(
            published_versions={"client": "1.0.0", "plugin": "2.0.0",
                                "server": "3.0.0"})
        plan = rd.compute_plan(graph, state)

        class Support:
            def __init__(self, versions):
                self.versions = versions
                self.calls = 0

            def resolve(self, record, edge):
                self.calls += 1
                return {"supported_versions": dict(self.versions)}

        live = Support(support_versions or {"client": ["1.0.0"],
                                            "server": ["3.0.0"]})
        frozen_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="s1", state=state, measurement=live)
        frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
        return frozen, state, live

    def test_frozen_snapshot_binds_every_touched_endpoint_version(self) -> None:
        frozen, _, _ = self.freeze()
        self.assertEqual(
            frozen.resolved["runtime_published"],
            {"client": "1.0.0", "server": "3.0.0"},
            "the untouched server endpoint is bound too",
        )

    def test_live_measurement_drift_refuses_before_any_harness(self) -> None:
        frozen, state, live = self.freeze()
        live.versions = {"client": ["1.0.0"], "server": ["9.9.9"]}
        harness = RecordingHarness()
        with self.assertRaises(rd.ReceiptError) as caught:
            runner = rd.build_production_skew(
                frozen, state=state, measurement=live, harness=harness)
            for edge in frozen.plan.runtime_contract_edges:
                runner.execute(edge, {})
        self.assertIn("frozen", str(caught.exception))
        self.assertEqual(harness.cells, [])

    def test_live_published_drift_refuses_before_any_harness(self) -> None:
        frozen, _, live = self.freeze()
        drifted = orchestration_state(
            published_versions={"client": "1.0.0", "plugin": "2.0.0",
                                "server": "3.5.0"})
        harness = RecordingHarness()
        with self.assertRaises(rd.ReceiptError):
            rd.build_production_skew(
                frozen, state=drifted, measurement=live, harness=harness)
        self.assertEqual(harness.cells, [])

    def test_the_exact_frozen_record_drives_the_cells(self) -> None:
        frozen, state, live = self.freeze()
        harness = RecordingHarness()
        runner = rd.build_production_skew(
            frozen, state=state, measurement=live, harness=harness)
        # Mutating the live resolver AFTER composition must not change the
        # matrix: cells come from the frozen sealed record.
        live.versions = {"client": ["8.8.8"], "server": ["9.9.9"]}
        staged = {"client": staged_entry("client", "1.1.0"),
                  "plugin": staged_entry("plugin", "2.1.0")}
        for edge in frozen.plan.runtime_contract_edges:
            runner.freeze_matrix(
                edge, staged, staged_manifest_digest="a" * 64
            )
            runner.execute(edge, staged)
        self.assertTrue(harness.cells)
        for cell in harness.cells:
            if cell.b_kind == "published":
                self.assertEqual(cell.b["version"], "3.0.0",
                                 "frozen support, not the mutated live set")


def two_edge_graph_dict():
    """Two DISTINCT server<->server runtime edges - federation and
    persisted-state - mirroring the checked-in graph's pair."""
    data = fixture_graph_dict()
    data["edge"] = [e for e in data["edge"]
                    if e.get("type") != "runtime-contract"]
    for journey, direction, artifact_id in (
        ("make federation-journey", "both", "measurement:federation"),
        ("persisted-state fixture", "persisted-state-both",
         "measurement:persisted"),
    ):
        data["edge"].append({
            "type": "runtime-contract",
            "a": "server", "b": "server",
            "journey": journey,
            "artifacts": {"a": "pypi:server", "b": "pypi:server"},
            "direction": direction,
            "supported": {
                "set": "measured:fixture-fleet",
                "record": {"authority": "workflow-artifacts",
                           "artifact_id": artifact_id,
                           "digest": "d"},
                "policy": "additive-only",
            },
        })
    return data


class EdgeIdentityTests(unittest.TestCase):
    def edges(self):
        graph = rd.Graph.from_dict(two_edge_graph_dict())
        state = orchestration_state(
            changed_components={"server": True},
            versions={"server": "3.1.0"},
            published_versions={"server": "3.0.0"},
        )
        plan = rd.compute_plan(graph, state)
        contracts = plan.runtime_contract_edges
        self.assertEqual(len(contracts), 2)
        return graph, state, plan, contracts

    def support_for(self, versions_by_journey):
        class Support:
            def resolve(self, record, edge):
                return {
                    "journey": edge.journey,
                    "supported_versions":
                        dict(versions_by_journey[edge.journey]),
                }
        return Support()

    def test_identities_are_distinct_and_content_bound(self) -> None:
        _, _, _, contracts = self.edges()
        a, b = contracts
        self.assertNotEqual(rd.edge_identity(a), rd.edge_identity(b))
        self.assertEqual(rd.edge_identity(a), rd.edge_identity(a))

    def test_freeze_retains_one_record_per_edge(self) -> None:
        graph, state, plan, contracts = self.edges()
        support = self.support_for({
            "make federation-journey": {"server": ["3.0.0"]},
            "persisted-state fixture": {"server": ["2.9.0", "3.0.0"]},
        })
        frozen_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="s1", state=state, measurement=support)
        frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
        sealed = frozen.resolved["measurements"]
        self.assertEqual(len(sealed), 2, "one sealed record per edge")
        for edge in contracts:
            self.assertEqual(
                sealed[rd.edge_identity(edge)]["journey"], edge.journey)

    def test_each_edge_compares_and_renders_its_own_record(self) -> None:
        graph, state, plan, contracts = self.edges()
        versions = {
            "make federation-journey": {"server": ["3.0.0"]},
            "persisted-state fixture": {"server": ["2.9.0", "3.0.0"]},
        }
        support = self.support_for(versions)
        frozen_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="s1", state=state, measurement=support)
        frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
        harness = RecordingHarness(
            journeys=("make federation-journey", "persisted-state fixture"))
        runner = rd.build_production_skew(
            frozen, state=state, measurement=support, harness=harness)
        staged = {"server": staged_entry("server", "3.1.0")}
        for edge in contracts:
            runner.freeze_matrix(
                edge, staged, staged_manifest_digest="a" * 64
            )
            runner.execute(edge, staged)
        persisted = [c for c in harness.cells
                     if c.journey == "persisted-state fixture"
                     and c.b_kind == "published-floor"]
        self.assertTrue(persisted, "the persisted edge used ITS OWN floor")
        self.assertTrue(all(c.b["version"] == "2.9.0" for c in persisted))
        federation = [c for c in harness.cells
                      if c.journey == "make federation-journey"]
        self.assertTrue(all(
            c.b_kind != "published-floor" for c in federation
        ), "the federation edge's single-version set has no separate floor")

    def test_mutating_one_edge_refuses_without_aliasing_the_other(self) -> None:
        graph, state, plan, contracts = self.edges()
        versions = {
            "make federation-journey": {"server": ["3.0.0"]},
            "persisted-state fixture": {"server": ["2.9.0", "3.0.0"]},
        }
        support = self.support_for(versions)
        frozen_bytes, frozen_id = rd.freeze_plan(
            plan, graph, source_sha="s1", state=state, measurement=support)
        frozen = rd.load_frozen_plan(frozen_bytes, expected_id=frozen_id)
        versions["make federation-journey"] = {"server": ["9.9.9"]}
        harness = RecordingHarness(
            journeys=("make federation-journey", "persisted-state fixture"))
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.build_production_skew(
                frozen, state=state, measurement=support, harness=harness)
        self.assertIn("federation", str(caught.exception))
        self.assertNotIn("persisted", str(caught.exception))

    def test_duplicate_exact_edge_refuses_at_the_graph(self) -> None:
        data = two_edge_graph_dict()
        data["edge"].append(dict(data["edge"][-1]))
        with self.assertRaises(rd.GraphError):
            rd.Graph.from_dict(data)

    def test_measurement_binds_artifacts_and_direction(self) -> None:
        edge = skew_edge()
        for override in (
            {"artifacts": {"a": "other:client", "b": "registry:server"}},
            {"direction": "a-to-b"},
        ):
            doc = {
                "edge": {"a": edge.a, "b": edge.b},
                "journey": edge.journey,
                "artifacts": override.get("artifacts", dict(edge.artifacts)),
                "direction": override.get("direction", edge.direction),
                "supported_versions": {"client": ["1.0.0"]},
            }
            payload = json.dumps(doc, sort_keys=True).encode()
            fresh = FakeAnchorTransport()
            store = rd.GithubAnchorStore(transport=fresh, waiter=lambda: None)
            store.put("measurement:fixture-fleet", payload)
            adapter = rd.AnchoredMeasurementAuthority(
                store=rd.GithubAnchorStore(transport=fresh,
                                           waiter=lambda: None),
                authority=rd.GithubAnchorDigestAuthority(transport=fresh),
            )
            record = {**measurement_record(), "digest": sha256(payload)}
            with self.assertRaises(rd.ReceiptError, msg=str(override)):
                adapter.resolve(record, edge)


class CellIdentityTests(unittest.TestCase):
    """The canonical identity and immutable edge preimage reach every
    cell, the harness, and the rendered matrix."""

    def test_cells_carry_the_identity_and_preimage(self) -> None:
        edge = skew_edge(direction="both")
        staged = {"client": staged_entry("client", "1.2.0"),
                  "server": staged_entry("server", "3.2.0")}
        cells = rd.compute_skew_cells(
            edge, moving={"client", "server"}, staged=staged,
            support={"supported_versions": {"client": ["1.1.0"],
                                            "server": ["3.1.0"]}},
            published_versions={"client": "1.1.0", "server": "3.1.0"},
        )
        for cell in cells:
            self.assertEqual(cell.edge_id, rd.edge_identity(edge))
            self.assertEqual(cell.artifacts, edge.artifacts)
            self.assertEqual(cell.declared_direction, "both")
            self.assertIn(cell.direction, ("a-to-b", "b-to-a"))

    def test_same_endpoints_and_journey_distinct_artifacts_direction(self) -> None:
        data = fixture_graph_dict()
        data["edge"] = [e for e in data["edge"]
                        if e.get("type") != "runtime-contract"]
        for artifacts, direction, artifact_id in (
            ({"a": "pypi:server", "b": "pypi:server"}, "both",
             "measurement:one"),
            ({"a": "ghcr:server", "b": "ghcr:server"}, "a-to-b",
             "measurement:two"),
        ):
            data["edge"].append({
                "type": "runtime-contract",
                "a": "server", "b": "server",
                "journey": "make same-journey",
                "artifacts": artifacts,
                "direction": direction,
                "supported": {
                    "set": "measured:fixture-fleet",
                    "record": {"authority": "workflow-artifacts",
                               "artifact_id": artifact_id, "digest": "d"},
                    "policy": "additive-only",
                },
            })
        graph = rd.Graph.from_dict(data)  # both accepted
        state = orchestration_state(
            changed_components={"server": True},
            versions={"server": "3.1.0"},
            published_versions={"server": "3.0.0"},
        )
        plan = rd.compute_plan(graph, state)
        edges = plan.runtime_contract_edges
        self.assertEqual(len(edges), 2)
        self.assertNotEqual(rd.edge_identity(edges[0]),
                            rd.edge_identity(edges[1]))
        staged = {"server": staged_entry("server", "3.1.0")}
        support = {"supported_versions": {"server": ["3.0.0"]}}
        for edge in edges:
            cells = rd.compute_skew_cells(
                edge, moving={"server"}, staged=staged, support=support,
                published_versions={"server": "3.0.0"},
            )
            for cell in cells:
                self.assertEqual(cell.edge_id, rd.edge_identity(edge))
                self.assertEqual(cell.artifacts, edge.artifacts,
                                 "the harness selects the declared "
                                 "published artifact without guessing")
                self.assertEqual(cell.declared_direction, edge.direction)


def channel_tgz(*, version="1.7.3", plugin_version=None, sentinel=True):
    """A tgz satisfying the reviewed .3 channel profile."""
    import tarfile

    markers = "\n".join([
        "const stableID = certificateStableID || identityStableID",
        'case "app_event"', 'kind: "app"',
        "stableIdentityStateHash",
        "seq>1 requires rotate_key operation",
        "did:aw not derived from genesis key",
        "verifyStableIdentityViaFullLog",
        "pin store is empty or has no document",
        "msg.encrypted_envelope != null",
        "msg.subject = decrypted.subject",
        "msg.body = decrypted.body",
        '["--team", options.teamID.trim()]',
        "selected active team ${config.teamID} is missing certificate signing authentication",
        '{ name: "aweb-channel", version: "0.1.0" }',
    ])
    if sentinel:
        markers += ("\naweb-channel-core-security/"
                    "did-log-genesis-bound-v2+full-log-v1+"
                    "pinstore-fail-closed-v1")
    files = {
        "package/package.json": json.dumps({
            "name": "@awebai/claude-channel", "version": version,
            "main": "./dist/index.js",
            "files": ["dist", ".mcp.json", ".claude-plugin"],
        }),
        "package/dist/index.js": markers,
        "package/.mcp.json": json.dumps(
            {"mcpServers": {"aweb-channel": {"command": "node"}}}),
        "package/.claude-plugin/plugin.json": json.dumps(
            {"name": "channel", "version": plugin_version or version}),
    }
    import gzip

    buffer = io.BytesIO()
    # gzip stamps the current time into its header; mtime=0 keeps two
    # builds of identical content byte-identical.
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            for name, content in files.items():
                data = content.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def npm_lane_zip(*, package="channel", version="1.7.3", mode="stage-only",
                 source_sha="f" * 40, tgz=None):
    tgz = tgz if tgz is not None else channel_tgz(version=version)
    tgz_name = f"awebai-claude-channel-{version}.tgz"
    files = {tgz_name: sha256(tgz)}
    canonical = sha256(json.dumps(files, sort_keys=True).encode())
    manifest = {
        "mode": mode, "package": package, "tag": f"channel-v{version}",
        "candidate_version": version, "source_sha": source_sha,
        "files": files, "canonical_set_digest": canonical,
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        zip_member(z, "manifest.json", json.dumps(manifest))
        zip_member(z, tgz_name, tgz)
    return buffer.getvalue()


GOOD_PROOF = {"obligation": "delivery-restart-proof",
              "evidence_id": "restart:host-1:pid-9", "digest": "sha-evidence"}


def npm_lane(zip_bytes, *, observer, runs=None, source_sha="f" * 40,
             delivery_proofs=None, expected_obligation="delivery-restart-proof"):
    api = FakeGithubApi(repo="awebai/aweb", zip_bytes=zip_bytes,
                        workflow_path=".github/workflows/npm-release.yml")
    return rd.NpmWorkflowLane(
        component="channel",
        npm_name="@awebai/claude-channel",
        expected_obligation=expected_obligation,
        reader=rd.GithubArtifactStore(
            api=api, repo="awebai/aweb",
            workflow_path=".github/workflows/npm-release.yml"),
        lane_authority=rd.GithubArtifactDigestAuthority(
            api=api, repo="awebai/aweb",
            workflow_path=".github/workflows/npm-release.yml"),
        refs={"channel": lane_ref_for(api, zip_bytes, source_sha)},
        npm_observe=observer,
        runs=runs if runs is not None else FakeAwRuns(),
        delivery_proofs=delivery_proofs or {},
        waiter=lambda: None,
    ), api


class NpmWorkflowLaneTests(unittest.TestCase):
    def node(self):
        return rd.PlanNode(component="channel", reason="changed",
                           version="1.7.3")

    def test_stage_validates_the_lane_and_channel_profile(self) -> None:
        zip_bytes = npm_lane_zip()
        lane, _ = npm_lane(zip_bytes, observer=lambda p, v: None)
        entry = lane.stage(self.node())
        self.assertEqual(list(entry.digest_set),
                         ["awebai-claude-channel-1.7.3.tgz"])
        self.assertEqual(entry.digest,
                         rd.canonical_digest_of_set(entry.digest_set))

    def test_adopt_preplan_revalidates_without_calling_stage(self) -> None:
        zip_bytes = npm_lane_zip()
        lane, _ = npm_lane(zip_bytes, observer=lambda p, v: None)
        lane.stage = lambda node: self.fail("adoption called normal stage()")
        adopted = lane.adopt_preplan(self.node())
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            expected_manifest = "sha256:" + sha256(archive.read("manifest.json"))
        self.assertEqual(adopted.manifest_digest, expected_manifest)
        self.assertEqual(adopted.entry.lane_ref,
                         lane._refs["channel"].to_dict())

    def test_adopt_preplan_requires_independent_zip_authority(self) -> None:
        zip_bytes = npm_lane_zip()
        lane, _ = npm_lane(zip_bytes, observer=lambda p, v: None)

        class WrongAuthority:
            def expected_digest(self, artifact):
                return "0" * 64

        lane._lane_authority = WrongAuthority()
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.adopt_preplan(self.node())
        self.assertIn("independent", str(caught.exception))

    def test_recovery_continuation_uses_persisted_snapshot_and_returns_run(self) -> None:
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        state = {"value": None}
        runs = FakeAwRuns()
        lane, _ = npm_lane(
            zip_bytes, observer=lambda p, v: state["value"], runs=runs,
            delivery_proofs={"channel": dict(GOOD_PROOF)})
        adopted = lane.adopt_preplan(self.node())
        before = lane.continuation_snapshot(self.node())
        self.assertEqual(before, ["101"], "persist only the stable high-water run")
        original = runs.dispatch

        def dispatch(inputs):
            original(inputs)
            state["value"] = sha256(tgz)
        runs.dispatch = dispatch
        result = lane.publish_recovery(
            self.node(), adopted.entry, before_run_ids=before,
            attempt_artifact_id="attempt:channel:one")
        self.assertEqual(result.continuation_run_id, str(runs.run_ids[-1]))
        self.assertEqual(result.attempt_artifact_id, "attempt:channel:one")
        self.assertEqual(
            runs.dispatched[0]["recovery_attempt_artifact_id"],
            "attempt:channel:one",
        )
        self.assertEqual(result.entry.digest_set, adopted.entry.digest_set)

    def test_recovery_publish_ignores_unrelated_run_until_owned_run_appears(self) -> None:
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        state = {"value": None}

        class InterleavedRuns(FakeAwRuns):
            def __init__(self):
                super().__init__(new_runs_per_dispatch=0)
                self.dispatch_started = False
                self.polls = 0
                self.expected_attempt = None

            def dispatch(self, inputs):
                self.dispatched.append(dict(inputs))
                self.expected_attempt = inputs["recovery_attempt_artifact_id"]
                self.dispatch_started = True
                state["value"] = sha256(tgz)

            def list_run_ids(self):
                if self.dispatch_started:
                    self.polls += 1
                    if self.polls == 1:
                        self.run_ids.append(200)
                        self.run_attempt_artifact_ids[200] = "unrelated-attempt"
                    elif self.polls == 2:
                        self.run_ids.append(201)
                        self.run_attempt_artifact_ids[201] = self.expected_attempt
                return list(self.run_ids)

        runs = InterleavedRuns()
        lane, _ = npm_lane(
            zip_bytes, observer=lambda p, v: state["value"], runs=runs,
            delivery_proofs={"channel": dict(GOOD_PROOF)})
        adopted = lane.adopt_preplan(self.node())
        before = lane.continuation_snapshot(self.node())
        recovered = lane.publish_recovery(
            self.node(), adopted.entry, before_run_ids=before,
            attempt_artifact_id="attempt:channel:expected")
        self.assertEqual(recovered.continuation_run_id, "201")
        self.assertEqual(recovered.attempt_artifact_id,
                         "attempt:channel:expected")
        self.assertEqual(len(runs.dispatched), 1)

    def test_recovery_publish_refuses_run_with_different_attempt_evidence(self) -> None:
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        state = {"value": None}
        runs = FakeAwRuns(observed_attempt_artifact_id="different-attempt")
        lane, _ = npm_lane(
            zip_bytes, observer=lambda p, v: state["value"], runs=runs,
            delivery_proofs={"channel": dict(GOOD_PROOF)})
        adopted = lane.adopt_preplan(self.node())
        before = lane.continuation_snapshot(self.node())
        original = runs.dispatch

        def dispatch(inputs):
            original(inputs)
            state["value"] = sha256(tgz)
        runs.dispatch = dispatch
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.publish_recovery(
                self.node(), adopted.entry, before_run_ids=before,
                attempt_artifact_id="attempt:channel:expected")
        self.assertIn("attempt", str(caught.exception))

    def test_recovery_attempt_correlates_one_exact_success_without_dispatch(self) -> None:
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        state = {"value": None}
        runs = FakeAwRuns()
        lane, _ = npm_lane(
            zip_bytes, observer=lambda p, v: state["value"], runs=runs,
            delivery_proofs={"channel": dict(GOOD_PROOF)})
        adopted = lane.adopt_preplan(self.node())
        before = lane.continuation_snapshot(self.node())
        runs.run_ids.append(777)
        runs.conclusion = "success"
        runs.run_attempt_artifact_ids[777] = "attempt:channel:two"
        state["value"] = sha256(tgz)
        recovered = lane.recover_recovery_attempt(
            self.node(), adopted.entry, before_run_ids=before,
            attempt_artifact_id="attempt:channel:two")
        self.assertEqual(recovered.continuation_run_id, "777")
        self.assertEqual(recovered.attempt_artifact_id, "attempt:channel:two")
        self.assertEqual(runs.dispatched, [])

    def test_recovery_finds_owned_run_beyond_first_history_page(self) -> None:
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        state = {"value": sha256(tgz)}
        attempt_id = "attempt:channel:beyond-page-one"
        owned_run_id = 1101
        boundary_run_id = 1000
        unrelated = list(range(1201, 1101, -1))
        evidence_body = rd.canonical_json_bytes({
            "schema": "aweb.release.recovery-continuation-attempt.v1",
            "attempt_artifact_id": attempt_id,
            "continuation_run_id": str(owned_run_id),
        })
        evidence_buffer = io.BytesIO()
        with zipfile.ZipFile(evidence_buffer, "w") as archive:
            archive.writestr("recovery-attempt.json", evidence_body)
        evidence_zip = evidence_buffer.getvalue()
        calls = []
        prefix = "repos/awebai/aweb/actions/workflows/npm-release.yml/runs"

        def runs_api(path):
            calls.append(path)
            if path == prefix + "?per_page=100&page=1":
                return json.dumps({
                    "workflow_runs": [{"id": item} for item in unrelated]
                }).encode()
            if path == prefix + "?per_page=100&page=2":
                return json.dumps({"workflow_runs": [
                    {"id": owned_run_id}, {"id": boundary_run_id},
                ]}).encode()
            if path == (
                f"repos/awebai/aweb/actions/runs/{owned_run_id}/artifacts?"
                "name=recovery-attempt-identity&per_page=100&page=1"
            ):
                return json.dumps({"total_count": 1, "artifacts": [{
                    "id": 88,
                    "name": "recovery-attempt-identity",
                    "expired": False,
                    "digest": "sha256:" + sha256(evidence_zip),
                    "workflow_run": {"id": owned_run_id},
                }]}).encode()
            if path == "repos/awebai/aweb/actions/artifacts/88/zip":
                return evidence_zip
            if path == f"repos/awebai/aweb/actions/runs/{owned_run_id}":
                return json.dumps({
                    "display_title": rd.recovery_run_marker(
                        "channel", attempt_id
                    ),
                    "conclusion": "success",
                }).encode()
            if path.startswith("repos/awebai/aweb/actions/runs/"):
                return json.dumps({
                    "display_title": "aweb-npm|stage-only|channel|",
                    "conclusion": "success",
                }).encode()
            raise AssertionError(f"unexpected API path {path}")

        runs = rd.AwLaneRuns(api=runs_api, repo="awebai/aweb",
                             workflow_file="npm-release.yml")
        lane, _ = npm_lane(
            zip_bytes, observer=lambda p, v: state["value"], runs=runs,
            delivery_proofs={"channel": dict(GOOD_PROOF)})
        adopted = lane.adopt_preplan(self.node())
        recovered = lane.recover_recovery_attempt(
            self.node(), adopted.entry,
            before_run_ids=[str(boundary_run_id)],
            attempt_artifact_id=attempt_id)
        self.assertEqual(recovered.continuation_run_id, str(owned_run_id))
        self.assertEqual(recovered.attempt_artifact_id, attempt_id)
        self.assertIn(prefix + "?per_page=100&page=2", calls)

    def test_sync_and_crash_correlation_bound_every_owned_run_request(self):
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        attempt_id = "attempt:channel:bounded"
        evidence_body = rd.canonical_json_bytes({
            "schema": "aweb.release.recovery-continuation-attempt.v1",
            "attempt_artifact_id": attempt_id,
            "continuation_run_id": "777",
        })
        evidence_buffer = io.BytesIO()
        with zipfile.ZipFile(evidence_buffer, "w") as archive:
            archive.writestr("recovery-attempt.json", evidence_body)
        evidence_zip = evidence_buffer.getvalue()
        history = (
            "repos/awebai/aweb/actions/workflows/npm-release.yml/runs"
            "?per_page=100&page=1"
        )

        for operation in ("sync", "crash"):
            for hanging in ("evidence-list", "evidence-zip", "conclusion"):
                with self.subTest(operation=operation, hanging=hanging):
                    now = [0.0]
                    run_reads = 0

                    def api(path):
                        nonlocal run_reads
                        if path == history:
                            return json.dumps({"workflow_runs": [
                                {"id": 777}, {"id": 100},
                            ]}).encode()
                        if (
                            "/actions/runs/777/artifacts?"
                            "name=recovery-attempt-identity&" in path
                        ):
                            if hanging == "evidence-list":
                                now[0] = 31.0
                            return json.dumps({
                                "total_count": 1, "artifacts": [{
                                "id": 88,
                                "name": "recovery-attempt-identity",
                                "expired": False,
                                "digest": "sha256:" + sha256(evidence_zip),
                                "workflow_run": {"id": 777},
                            }]}).encode()
                        if path.endswith("/actions/artifacts/88/zip"):
                            if hanging == "evidence-zip":
                                now[0] = 31.0
                            return evidence_zip
                        if path.endswith("/actions/runs/777"):
                            run_reads += 1
                            if hanging == "conclusion" and run_reads == 2:
                                now[0] = 31.0
                            return json.dumps({
                                "display_title": rd.recovery_run_marker(
                                    "channel", attempt_id
                                ),
                                "conclusion": "success",
                            }).encode()
                        raise AssertionError(f"unexpected API path {path}")

                    runs = rd.AwLaneRuns(
                        api=api, repo="awebai/aweb",
                        workflow_file="npm-release.yml",
                        clock=lambda: now[0],
                    )
                    lane, _ = npm_lane(
                        zip_bytes, observer=lambda p, v: sha256(tgz),
                        runs=runs,
                        delivery_proofs={"channel": dict(GOOD_PROOF)},
                    )
                    adopted = lane.adopt_preplan(self.node())
                    with self.assertRaises(rd.ReceiptError) as caught:
                        if operation == "sync":
                            lane._wait_for_continuation(
                                ["100"],
                                expected_attempt_artifact_id=attempt_id,
                            )
                        else:
                            lane.recover_recovery_attempt(
                                self.node(), adopted.entry,
                                before_run_ids=["100"],
                                attempt_artifact_id=attempt_id,
                            )
                    self.assertIn("incomplete", str(caught.exception))

    def test_sync_and_crash_refuse_many_unrelated_candidate_exhaustion(self):
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        run_ids = list(range(1000, 700, -1))
        history_prefix = (
            "repos/awebai/aweb/actions/workflows/npm-release.yml/runs"
        )

        for operation in ("sync", "crash"):
            with self.subTest(operation=operation):
                calls = []

                def api(path):
                    calls.append(path)
                    if path == history_prefix + "?per_page=100&page=1":
                        page = run_ids[:100]
                        return json.dumps({"workflow_runs": [
                            {"id": run_id} for run_id in page
                        ]}).encode()
                    if path == history_prefix + "?per_page=100&page=2":
                        page = run_ids[100:200]
                        return json.dumps({"workflow_runs": [
                            {"id": run_id} for run_id in page
                        ]}).encode()
                    if path == history_prefix + "?per_page=100&page=3":
                        page = run_ids[200:]
                        return json.dumps({"workflow_runs": [
                            {"id": run_id} for run_id in page
                        ]}).encode()
                    if path == history_prefix + "?per_page=100&page=4":
                        return json.dumps({"workflow_runs": [
                            {"id": 600},
                        ]}).encode()
                    if "/actions/runs/" in path:
                        return json.dumps({
                            "display_title": "aweb-npm|stage-only|channel|",
                            "conclusion": "success",
                        }).encode()
                    raise AssertionError(f"unexpected API path {path}")

                runs = rd.AwLaneRuns(
                    api=api, repo="awebai/aweb",
                    workflow_file="npm-release.yml",
                )
                lane, _ = npm_lane(
                    zip_bytes, observer=lambda p, v: sha256(tgz), runs=runs,
                    delivery_proofs={"channel": dict(GOOD_PROOF)},
                )
                if operation == "sync":
                    lane.SYNC_CORRELATION_REQUESTS = 256
                adopted = lane.adopt_preplan(self.node())
                with self.assertRaises(rd.ReceiptError) as caught:
                    if operation == "sync":
                        lane._wait_for_continuation(
                            ["600"],
                            expected_attempt_artifact_id="attempt:missing",
                        )
                    else:
                        lane.recover_recovery_attempt(
                            self.node(), adopted.entry,
                            before_run_ids=["600"],
                            attempt_artifact_id="attempt:missing",
                        )
                self.assertIn("incomplete", str(caught.exception))
                self.assertLessEqual(
                    len(calls), runs.MAX_CORRELATION_REQUESTS
                )

    def test_synchronous_polling_shares_one_correlation_budget(self):
        tgz = channel_tgz()
        history = (
            "repos/awebai/aweb/actions/workflows/npm-release.yml/runs"
            "?per_page=100&page=1"
        )
        calls = []

        def api(path):
            calls.append(path)
            if path == history:
                return json.dumps({"workflow_runs": [
                    {"id": 777}, {"id": 100},
                ]}).encode()
            if "/artifacts?name=recovery-attempt-identity&" in path:
                return json.dumps({
                    "total_count": 0, "artifacts": [],
                }).encode()
            if path.endswith("/actions/runs/777"):
                return json.dumps({
                    "display_title": rd.recovery_run_marker(
                        "channel", "attempt:missing"
                    ),
                    "conclusion": "success",
                }).encode()
            raise AssertionError(f"unexpected API path {path}")

        runs = rd.AwLaneRuns(api=api, repo="awebai/aweb",
                             workflow_file="npm-release.yml")
        lane, _ = npm_lane(
            npm_lane_zip(tgz=tgz), observer=lambda p, v: None, runs=runs,
            delivery_proofs={"channel": dict(GOOD_PROOF)},
        )
        lane.POLL_ATTEMPTS = 10
        lane.SYNC_CORRELATION_REQUESTS = 8
        with self.assertRaises(rd.ReceiptError) as caught:
            lane._wait_for_continuation(
                ["100"], expected_attempt_artifact_id="attempt:missing"
            )
        self.assertIn("incomplete", str(caught.exception))
        self.assertLessEqual(len(calls), 8)

    def test_sync_ordinary_and_adopted_survive_45_seconds_pending(self):
        tgz = channel_tgz()
        attempt_id = "attempt:channel:long-pending"
        evidence_body = rd.canonical_json_bytes({
            "schema": "aweb.release.recovery-continuation-attempt.v1",
            "attempt_artifact_id": attempt_id,
            "continuation_run_id": "777",
        })
        evidence_buffer = io.BytesIO()
        with zipfile.ZipFile(evidence_buffer, "w") as archive:
            archive.writestr("recovery-attempt.json", evidence_body)
        evidence_zip = evidence_buffer.getvalue()

        for mode in ("ordinary", "adopted"):
            with self.subTest(mode=mode):
                now = [0.0]
                conclusion_calls = 0

                def waiter():
                    now[0] += 15.0

                def api(path):
                    nonlocal conclusion_calls
                    if "/workflows/npm-release.yml/runs?" in path:
                        return json.dumps({"workflow_runs": [
                            {"id": 777}, {"id": 100},
                        ]}).encode()
                    if path.endswith("/actions/runs/777"):
                        if mode == "ordinary":
                            conclusion_calls += 1
                            conclusion = (
                                "success" if conclusion_calls == 4 else None
                            )
                        else:
                            conclusion = "success"
                        return json.dumps({
                            "display_title": rd.recovery_run_marker(
                                "channel", attempt_id
                            ),
                            "conclusion": conclusion,
                        }).encode()
                    if "/runs/777/artifacts?name=" in path:
                        artifacts = [] if now[0] < 45.0 else [{
                            "id": 88,
                            "name": "recovery-attempt-identity",
                            "expired": False,
                            "digest": "sha256:" + sha256(evidence_zip),
                            "workflow_run": {"id": 777},
                        }]
                        return json.dumps({
                            "total_count": len(artifacts),
                            "artifacts": artifacts,
                        }).encode()
                    if path.endswith("/actions/artifacts/88/zip"):
                        return evidence_zip
                    raise AssertionError(f"unexpected API path {path}")

                runs = rd.AwLaneRuns(
                    api=api, repo="awebai/aweb",
                    workflow_file="npm-release.yml", clock=lambda: now[0],
                )
                lane, _ = npm_lane(
                    npm_lane_zip(tgz=tgz), observer=lambda p, v: sha256(tgz),
                    runs=runs, delivery_proofs={"channel": dict(GOOD_PROOF)},
                )
                lane._waiter = waiter
                run_id, observed_attempt = lane._wait_for_continuation(
                    ["100"],
                    expected_attempt_artifact_id=(
                        attempt_id if mode == "adopted" else None
                    ),
                )
                self.assertEqual(run_id, "777")
                self.assertEqual(
                    observed_attempt,
                    attempt_id if mode == "adopted" else None,
                )
                self.assertEqual(now[0], 45.0)

    def test_sync_polling_uses_exact_max_attempts_without_final_sleep(self):
        tgz = channel_tgz()
        for outcome in ("success-at-limit", "exhausted"):
            with self.subTest(outcome=outcome):
                conclusion_calls = 0
                waits = 0

                def waiter():
                    nonlocal waits
                    waits += 1

                def api(path):
                    nonlocal conclusion_calls
                    if "/workflows/npm-release.yml/runs?" in path:
                        return json.dumps({"workflow_runs": [
                            {"id": 777}, {"id": 100},
                        ]}).encode()
                    if path.endswith("/actions/runs/777"):
                        conclusion_calls += 1
                        conclusion = (
                            "success"
                            if outcome == "success-at-limit"
                            and conclusion_calls == 3
                            else None
                        )
                        return json.dumps({
                            "conclusion": conclusion,
                        }).encode()
                    raise AssertionError(f"unexpected API path {path}")

                runs = rd.AwLaneRuns(api=api, repo="awebai/aweb",
                                     workflow_file="npm-release.yml")
                lane, _ = npm_lane(
                    npm_lane_zip(tgz=tgz), observer=lambda p, v: None,
                    runs=runs,
                    delivery_proofs={"channel": dict(GOOD_PROOF)},
                )
                lane.POLL_ATTEMPTS = 3
                lane._waiter = waiter
                if outcome == "success-at-limit":
                    self.assertEqual(
                        lane._wait_for_continuation(["100"]), ("777", None)
                    )
                else:
                    with self.assertRaises(rd.ReceiptError) as caught:
                        lane._wait_for_continuation(["100"])
                    self.assertIn("uncertain", str(caught.exception))
                self.assertEqual(conclusion_calls, 3)
                self.assertEqual(waits, 2)

    def test_sync_lifecycle_deadline_exhaustion_refuses_uncertain(self):
        tgz = channel_tgz()
        attempt_id = "attempt:channel:lifecycle-exhaustion"
        now = [0.0]

        def api(path):
            if "/workflows/npm-release.yml/runs?" in path:
                return json.dumps({"workflow_runs": [
                    {"id": 777}, {"id": 100},
                ]}).encode()
            if path.endswith("/actions/runs/777"):
                return json.dumps({
                    "display_title": rd.recovery_run_marker(
                        "channel", attempt_id
                    ),
                    "conclusion": "success",
                }).encode()
            if "/runs/777/artifacts?name=" in path:
                return json.dumps({
                    "total_count": 0, "artifacts": [],
                }).encode()
            raise AssertionError(f"unexpected API path {path}")

        runs = rd.AwLaneRuns(
            api=api, repo="awebai/aweb", workflow_file="npm-release.yml",
            clock=lambda: now[0],
        )
        lane, _ = npm_lane(
            npm_lane_zip(tgz=tgz), observer=lambda p, v: None, runs=runs,
            delivery_proofs={"channel": dict(GOOD_PROOF)},
        )
        lane.POLL_ATTEMPTS = 3
        lane.POLL_INTERVAL_SECONDS = 10.0
        lane._waiter = lambda: now.__setitem__(0, now[0] + 31.0)
        with self.assertRaises(rd.ReceiptError) as caught:
            lane._wait_for_continuation(
                ["100"], expected_attempt_artifact_id=attempt_id
            )
        self.assertIn("uncertain", str(caught.exception))
        self.assertEqual(now[0], 62.0)

    def test_terminal_exact_marker_evidence_appearing_next_poll_succeeds(self):
        tgz = channel_tgz()
        attempt_id = "attempt:channel:eventual-evidence"
        evidence_body = rd.canonical_json_bytes({
            "schema": "aweb.release.recovery-continuation-attempt.v1",
            "attempt_artifact_id": attempt_id,
            "continuation_run_id": "777",
        })
        evidence_buffer = io.BytesIO()
        with zipfile.ZipFile(evidence_buffer, "w") as archive:
            archive.writestr("recovery-attempt.json", evidence_body)
        evidence_zip = evidence_buffer.getvalue()

        for operation in ("sync", "crash"):
            with self.subTest(operation=operation):
                evidence_lists = 0

                def api(path):
                    nonlocal evidence_lists
                    if "/workflows/npm-release.yml/runs?" in path:
                        return json.dumps({"workflow_runs": [
                            {"id": 777}, {"id": 100},
                        ]}).encode()
                    if path.endswith("/actions/runs/777"):
                        return json.dumps({
                            "display_title": rd.recovery_run_marker(
                                "channel", attempt_id
                            ),
                            "conclusion": "success",
                        }).encode()
                    if "/runs/777/artifacts?name=" in path:
                        evidence_lists += 1
                        artifacts = [] if evidence_lists <= 2 else [{
                            "id": 88,
                            "name": "recovery-attempt-identity",
                            "expired": False,
                            "digest": "sha256:" + sha256(evidence_zip),
                            "workflow_run": {"id": 777},
                        }]
                        return json.dumps({
                            "total_count": len(artifacts),
                            "artifacts": artifacts,
                        }).encode()
                    if path.endswith("/actions/artifacts/88/zip"):
                        return evidence_zip
                    raise AssertionError(f"unexpected API path {path}")

                runs = rd.AwLaneRuns(
                    api=api, repo="awebai/aweb",
                    workflow_file="npm-release.yml",
                )
                lane, _ = npm_lane(
                    npm_lane_zip(tgz=tgz),
                    observer=lambda p, v: sha256(tgz), runs=runs,
                    delivery_proofs={"channel": dict(GOOD_PROOF)},
                )
                if operation == "sync":
                    run_id, observed_attempt = lane._wait_for_continuation(
                        ["100"], expected_attempt_artifact_id=attempt_id
                    )
                else:
                    recovered = lane.recover_recovery_attempt(
                        self.node(), lane.adopt_preplan(self.node()).entry,
                        before_run_ids=["100"],
                        attempt_artifact_id=attempt_id,
                    )
                    run_id = recovered.continuation_run_id
                    observed_attempt = recovered.attempt_artifact_id
                self.assertEqual(
                    (run_id, observed_attempt), ("777", attempt_id)
                )
                self.assertEqual(evidence_lists, 4)

    def test_exact_marker_without_evidence_refuses_uncertain_sync_and_crash(self):
        tgz = channel_tgz()
        attempt_id = "attempt:channel:never-evidence"

        for operation in ("sync", "crash"):
            with self.subTest(operation=operation):
                calls = []

                def api(path):
                    calls.append(path)
                    if "/workflows/npm-release.yml/runs?" in path:
                        return json.dumps({"workflow_runs": [
                            {"id": 777}, {"id": 100},
                        ]}).encode()
                    if path.endswith("/actions/runs/777"):
                        return json.dumps({
                            "display_title": rd.recovery_run_marker(
                                "channel", attempt_id
                            ),
                            "conclusion": "success",
                        }).encode()
                    if "/runs/777/artifacts?name=" in path:
                        return json.dumps({
                            "total_count": 0, "artifacts": [],
                        }).encode()
                    raise AssertionError(f"unexpected API path {path}")

                runs = rd.AwLaneRuns(
                    api=api, repo="awebai/aweb",
                    workflow_file="npm-release.yml",
                )
                runs.MAX_CORRELATION_REQUESTS = 16
                lane, _ = npm_lane(
                    npm_lane_zip(tgz=tgz),
                    observer=lambda p, v: sha256(tgz), runs=runs,
                    delivery_proofs={"channel": dict(GOOD_PROOF)},
                )
                if operation == "sync":
                    lane.SYNC_CORRELATION_REQUESTS = 16
                adopted = lane.adopt_preplan(self.node())
                with self.assertRaises(rd.ReceiptError) as caught:
                    if operation == "sync":
                        lane._wait_for_continuation(
                            ["100"],
                            expected_attempt_artifact_id=attempt_id,
                        )
                    else:
                        lane.recover_recovery_attempt(
                            self.node(), adopted.entry,
                            before_run_ids=["100"],
                            attempt_artifact_id=attempt_id,
                        )
                self.assertIn("uncertain", str(caught.exception))
                self.assertLessEqual(len(calls), 16)

    def test_multiple_exact_run_markers_refuse_before_evidence(self):
        tgz = channel_tgz()
        attempt_id = "attempt:channel:duplicate-marker"

        def api(path):
            if "/workflows/npm-release.yml/runs?" in path:
                return json.dumps({"workflow_runs": [
                    {"id": 778}, {"id": 777}, {"id": 100},
                ]}).encode()
            if path.endswith("/actions/runs/778") or path.endswith(
                "/actions/runs/777"
            ):
                return json.dumps({
                    "display_title": rd.recovery_run_marker(
                        "channel", attempt_id
                    ),
                    "conclusion": "success",
                }).encode()
            raise AssertionError(
                "multiple exact markers must refuse before evidence lookup"
            )

        runs = rd.AwLaneRuns(api=api, repo="awebai/aweb",
                             workflow_file="npm-release.yml")
        lane, _ = npm_lane(
            npm_lane_zip(tgz=tgz), observer=lambda p, v: sha256(tgz),
            runs=runs, delivery_proofs={"channel": dict(GOOD_PROOF)},
        )
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.recover_recovery_attempt(
                self.node(), lane.adopt_preplan(self.node()).entry,
                before_run_ids=["100"], attempt_artifact_id=attempt_id,
            )
        self.assertIn("marker", str(caught.exception))

    def test_recovery_attempt_selects_owned_run_amid_unrelated_run(self) -> None:
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        state = {"value": None}
        runs = FakeAwRuns()
        lane, _ = npm_lane(
            zip_bytes, observer=lambda p, v: state["value"], runs=runs,
            delivery_proofs={"channel": dict(GOOD_PROOF)})
        adopted = lane.adopt_preplan(self.node())
        before = lane.continuation_snapshot(self.node())
        runs.run_ids.extend([777, 778])
        runs.run_attempt_artifact_ids.update({
            777: "unrelated-attempt",
            778: "attempt:channel:expected",
        })
        state["value"] = sha256(tgz)

        recovered = lane.recover_recovery_attempt(
            self.node(), adopted.entry, before_run_ids=before,
            attempt_artifact_id="attempt:channel:expected")
        self.assertEqual(recovered.continuation_run_id, "778")
        self.assertEqual(recovered.attempt_artifact_id,
                         "attempt:channel:expected")
        self.assertEqual(runs.dispatched, [])

    def test_recovery_attempt_refuses_multiple_owned_runs(self) -> None:
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        state = {"value": sha256(tgz)}
        runs = FakeAwRuns()
        lane, _ = npm_lane(
            zip_bytes, observer=lambda p, v: state["value"], runs=runs,
            delivery_proofs={"channel": dict(GOOD_PROOF)})
        adopted = lane.adopt_preplan(self.node())
        before = lane.continuation_snapshot(self.node())
        runs.run_ids.extend([777, 778])
        runs.run_attempt_artifact_ids.update({
            777: "attempt:channel:expected",
            778: "attempt:channel:expected",
        })

        with self.assertRaises(rd.ReceiptError) as caught:
            lane.recover_recovery_attempt(
                self.node(), adopted.entry, before_run_ids=before,
                attempt_artifact_id="attempt:channel:expected")
        self.assertIn("exactly one", str(caught.exception))
        self.assertEqual(runs.dispatched, [])

    def test_recovery_attempt_ignores_unowned_success_without_dispatch(self) -> None:
        for observed_attempt_id in (None, "different-attempt"):
            with self.subTest(observed_attempt_id=observed_attempt_id):
                tgz = channel_tgz()
                zip_bytes = npm_lane_zip(tgz=tgz)
                state = {"value": None}
                runs = FakeAwRuns()
                lane, _ = npm_lane(
                    zip_bytes, observer=lambda p, v: state["value"], runs=runs,
                    delivery_proofs={"channel": dict(GOOD_PROOF)})
                adopted = lane.adopt_preplan(self.node())
                before = lane.continuation_snapshot(self.node())
                runs.run_ids.append(777)
                runs.conclusion = "success"
                if observed_attempt_id is not None:
                    runs.run_attempt_artifact_ids[777] = observed_attempt_id
                state["value"] = sha256(tgz)

                recovered = lane.recover_recovery_attempt(
                    self.node(), adopted.entry, before_run_ids=before,
                    attempt_artifact_id="attempt:channel:expected")
                self.assertIsNone(recovered)
                self.assertEqual(runs.dispatched, [])

    def test_stage_refuses_a_profile_violation_in_the_tgz(self) -> None:
        zip_bytes = npm_lane_zip(tgz=channel_tgz(sentinel=False))
        lane, _ = npm_lane(zip_bytes, observer=lambda p, v: None)
        with self.assertRaises(rd.ReceiptError):
            lane.stage(self.node())
        zip_bytes = npm_lane_zip(tgz=channel_tgz(plugin_version="9.9.9"))
        lane, _ = npm_lane(zip_bytes, observer=lambda p, v: None)
        with self.assertRaises(rd.ReceiptError):
            lane.stage(self.node())

    def test_observation_absent_exact_mismatch_outage(self) -> None:
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        tgz_digest = sha256(tgz)
        node = self.node()
        state = {"value": None}

        def observer(package, version):
            if state["value"] == "outage":
                raise rd.ReceiptError("registry unavailable")
            return state["value"]

        lane, _ = npm_lane(zip_bytes, observer=observer,
                           delivery_proofs={"channel": dict(GOOD_PROOF)})
        staged = lane.stage(node)
        self.assertIsNone(lane.observe(node, staged), "absent continues")
        state["value"] = tgz_digest
        observed = lane.observe(node, staged)
        self.assertEqual(observed.digest_set, staged.digest_set)
        self.assertEqual(observed.delivery_proof, GOOD_PROOF)
        state["value"] = "0" * 64
        with self.assertRaises(rd.ReceiptError):
            lane.observe(node, staged)
        state["value"] = "outage"
        with self.assertRaises(rd.ReceiptError):
            lane.observe(node, staged)

    def test_publish_dispatches_package_inputs_and_attaches_proof(self) -> None:
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        tgz_digest = sha256(tgz)
        runs = FakeAwRuns()
        state = {"value": None}
        lane, api = npm_lane(
            zip_bytes, observer=lambda p, v: state["value"], runs=runs,
            delivery_proofs={"channel": dict(GOOD_PROOF)})
        staged = lane.stage(self.node())
        original = runs.dispatch

        def dispatch(inputs):
            original(inputs)
            state["value"] = tgz_digest
        runs.dispatch = dispatch
        published = lane.publish(self.node(), staged)
        self.assertEqual(published.delivery_proof, GOOD_PROOF)
        self.assertEqual(runs.dispatched[0]["package"], "channel")
        self.assertEqual(runs.dispatched[0]["mode"], "publish-continuation")
        self.assertEqual(runs.dispatched[0]["stage_run_id"], str(api.run_id))

    def refusal_dispatches_nothing(self, *, delivery_proofs,
                                   expected_obligation, needle):
        """Missing/wrong delivery evidence precedes every outward call."""
        zip_bytes = npm_lane_zip()
        runs = FakeAwRuns()
        lane, _ = npm_lane(
            zip_bytes, observer=lambda p, v: None, runs=runs,
            delivery_proofs=delivery_proofs,
            expected_obligation=expected_obligation)
        staged = lane.stage(self.node())
        with self.assertRaises(rd.ReceiptError) as caught:
            lane.publish(self.node(), staged)
        self.assertIn(needle, str(caught.exception))
        self.assertEqual(runs.dispatched, [],
                         "the refusal must precede the dispatch")

    def test_missing_proof_for_an_obligated_component_refuses_before_dispatch(
            self) -> None:
        self.refusal_dispatches_nothing(
            delivery_proofs={},
            expected_obligation="delivery-restart-proof",
            needle="delivery")

    def test_malformed_proof_refuses_before_dispatch(self) -> None:
        self.refusal_dispatches_nothing(
            delivery_proofs={"channel": {
                "obligation": "delivery-restart-proof",
                "evidence_id": 7, "digest": "d"}},
            expected_obligation="delivery-restart-proof",
            needle="nonempty string")

    def test_wrong_obligation_refuses_before_dispatch(self) -> None:
        self.refusal_dispatches_nothing(
            delivery_proofs={"channel": {
                "obligation": "delivery-lane-proof",
                "evidence_id": "e", "digest": "d"}},
            expected_obligation="delivery-restart-proof",
            needle="obligation")

    def test_unobligated_component_rejects_an_unexpected_proof(self) -> None:
        self.refusal_dispatches_nothing(
            delivery_proofs={"channel": dict(GOOD_PROOF)},
            expected_obligation=None,
            needle="no delivery obligation")

    def test_exact_existing_registry_bytes_adopt_without_dispatch(self) -> None:
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        runs = FakeAwRuns()
        lane, _ = npm_lane(
            zip_bytes, observer=lambda p, v: sha256(tgz),
            runs=runs, delivery_proofs={"channel": dict(GOOD_PROOF)})
        staged = lane.stage(self.node())
        published = lane.publish(self.node(), staged)
        self.assertEqual(published.phase, "published")
        self.assertEqual(runs.dispatched, [],
                         "exact adoption dispatches zero runs")


class WorkflowRecoveryObservationTests(unittest.TestCase):
    def test_combines_exact_tag_and_registry_observations_without_expectations(self):
        tgz = channel_tgz()
        zip_bytes = npm_lane_zip(tgz=tgz)
        registry = {"value": None}
        tag = {"value": None}
        lane, _ = npm_lane(
            zip_bytes, observer=lambda p, v: registry["value"],
            delivery_proofs={"channel": dict(GOOD_PROOF)})
        lanes = rd.WorkflowLanes(
            {"channel": lane},
            recovery_tag_names={"channel": "channel-v1.7.3"},
            recovery_tag_observe=lambda name: tag["value"],
        )
        node = rd.PlanNode(component="channel", reason="adopted-preplan",
                           version="1.7.3")
        staged = lane.adopt_preplan(node).entry
        absent = lanes.observe_recovery(node, staged)
        self.assertEqual(absent.public, {
            "tag": {"name": "channel-v1.7.3", "status": "absent",
                    "source_sha": None},
            "registry": {"status": "absent", "digest_set": None},
        })
        self.assertIsNone(absent.entry)

        tag["value"] = "f" * 40
        registry["value"] = sha256(tgz)
        exact = lanes.observe_recovery(node, staged)
        self.assertEqual(exact.public["tag"]["source_sha"], "f" * 40)
        self.assertEqual(exact.public["registry"]["digest_set"],
                         staged.digest_set)
        self.assertEqual(exact.entry.digest, staged.digest)


class NpmRegistryClassifierTests(unittest.TestCase):
    """The PRODUCTION classifier: only 404 proves absence."""

    def classify(self, responses):
        def http(url):
            return responses.pop(0)
        return rd._observe_npm_registry(
            "@awebai/claude-channel", "1.7.3", http=http)

    def test_404_proves_absence(self) -> None:
        self.assertIsNone(self.classify([(404, b"")]))

    def test_present_returns_the_tarball_digest(self) -> None:
        meta = json.dumps({"dist": {
            "tarball": "https://registry.npmjs.org/x/-/x-1.7.3.tgz"}}).encode()
        digest = self.classify([(200, meta), (200, b"tgz-bytes")])
        self.assertEqual(digest, sha256(b"tgz-bytes"))

    def test_outage_and_malformed_block(self) -> None:
        for responses in ([(503, b"")], [(200, b"not json")],
                          [(200, json.dumps({}).encode())],
                          [(200, json.dumps({"dist": {"tarball": "u"}}).encode()),
                           (500, b"")]):
            with self.assertRaises(rd.ReceiptError, msg=str(responses)):
                self.classify(list(responses))


class ComposedProofConsumptionTests(unittest.TestCase):
    """Every supplied proof key is validated centrally at composition: it
    must name a composed component whose graph-derived delivery obligation
    is nonempty AND whose composed lane consumes delivery evidence. No
    caller-supplied proof may be accepted and ignored."""

    @staticmethod
    def ref():
        return rd.LaneRef(
            artifact="gh-artifact:awebai/aweb:1:2",
            aw_source_sha="f" * 40,
            zip_digest="sha256:" + "6" * 64)

    def refuse(self, component, proof, needle, graph=None):
        graph = graph or rd.Graph.load(rd.GRAPH_PATH)
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.compose_workflow_lanes(
                graph, {component: self.ref()},
                delivery_proofs={component: proof})
        self.assertIn(component, str(caught.exception))
        self.assertIn(needle, str(caught.exception))

    def test_unobligated_composed_components_refuse_a_proof(self) -> None:
        for component in ("server", "awid-image", "skills"):
            self.refuse(component, dict(GOOD_PROOF),
                        "no delivery obligation")

    def test_obligated_component_on_nonconsuming_lane_refuses(self) -> None:
        graph = rd.Graph.load(rd.GRAPH_PATH)
        raw = dict(graph.canonical)
        raw["component"] = dict(raw["component"])
        raw["component"]["server"] = dict(raw["component"]["server"])
        raw["component"]["server"]["delivery_restart"] = {
            "proof": "restart per host"}
        self.refuse("server", dict(GOOD_PROOF),
                    "does not consume delivery evidence",
                    graph=rd.Graph.from_dict(raw))

    def test_malformed_proof_refuses_at_composition(self) -> None:
        bad = dict(GOOD_PROOF)
        bad["obligation"] = "delivery-lane-proof"
        self.refuse("channel", bad, "obligation")

    def test_valid_channel_and_pi_proofs_compose(self) -> None:
        graph = rd.Graph.load(rd.GRAPH_PATH)
        lanes = rd.compose_workflow_lanes(
            graph, {"channel": self.ref(), "pi": self.ref()},
            delivery_proofs={"channel": dict(GOOD_PROOF),
                             "pi": dict(GOOD_PROOF)})
        self.assertTrue(lanes.has_lane("channel"))
        self.assertTrue(lanes.has_lane("pi"))


class ForeignProofKeyTests(unittest.TestCase):
    def test_proofs_for_uncomposed_components_refuse(self) -> None:
        graph = rd.Graph.load(rd.GRAPH_PATH)
        refs = {"channel": rd.LaneRef(
            artifact="gh-artifact:awebai/aweb:1:2",
            aw_source_sha="f" * 40,
            zip_digest="sha256:" + "6" * 64)}
        with self.assertRaises(rd.ReceiptError) as caught:
            rd.compose_workflow_lanes(
                graph, refs,
                delivery_proofs={"pi": dict(GOOD_PROOF)})
        self.assertIn("pi", str(caught.exception))


class DeliveryProofArgumentTests(unittest.TestCase):
    def test_well_formed_proof_parses_and_malformed_refuses(self) -> None:
        proofs = rd.parse_delivery_proof_arguments([
            "component=channel,obligation=delivery-restart-proof,"
            "evidence_id=restart:h1:p9,digest=sha-evidence",
        ])
        self.assertEqual(proofs["channel"]["obligation"],
                         "delivery-restart-proof")
        for bad in ("component=channel,obligation=,evidence_id=e,digest=d",
                    "component=channel",
                    "component=channel,obligation=o,evidence_id=e,digest=d,"
                    "component=again"):
            with self.assertRaises(rd.ReceiptError, msg=bad):
                rd.parse_delivery_proof_arguments([bad])
        with self.assertRaises(rd.ReceiptError):
            rd.parse_delivery_proof_arguments([
                "component=channel,obligation=o,evidence_id=e,digest=d",
                "component=channel,obligation=o,evidence_id=e,digest=d",
            ])


class NpmLaneEndToEndTests(unittest.TestCase):
    def test_channel_crash_resume_zero_restage_with_proof(self) -> None:
        transport = FakeAnchorTransport()
        version = "1.7.3"
        graph = rd.Graph.from_dict({
            "component": {
                "channel": {
                    "source_paths": ["x/"],
                    "version_source": {"type": "manifest", "path": "x/v"},
                    "tag_format": "channel-v{version}",
                    "publish_lane": {
                        "workflow": ".github/workflows/npm-release.yml",
                        "repository": "awebai/aweb",
                        "provider": "github-workflow-artifacts",
                        "modes": ["stage-only", "publish-continuation",
                                  "verify-only"],
                        "registry": {"type": "npm",
                                     "package": "@awebai/claude-channel"},
                    },
                    "verify": {"command": "true"},
                    "delivery_restart": {"proof": "restart per host"},
                },
            },
            "edge": [],
        })
        state = rd.FixtureState(
            changed_components={"channel": True},
            versions={"channel": version},
            published_versions={"channel": "1.7.1"},
        )
        tgz = channel_tgz(version=version)
        registry = {"value": None}

        def lane_factory(*, publish_ok):
            zip_bytes = npm_lane_zip(version=version, tgz=tgz)
            runs = FakeAwRuns(
                conclusion="success" if publish_ok else "failure")
            if publish_ok:
                original = runs.dispatch

                def dispatch(inputs):
                    original(inputs)
                    registry["value"] = sha256(tgz)
                runs.dispatch = dispatch
            lane, _ = npm_lane(
                zip_bytes, observer=lambda p, v: registry["value"],
                runs=runs,
                delivery_proofs={"channel": dict(GOOD_PROOF)})
            lane.stage_calls = 0
            original_stage = lane.stage

            def counted(node):
                lane.stage_calls += 1
                return original_stage(node)
            lane.stage = counted
            return lane

        store = rd.GithubAnchorStore(transport=transport, waiter=lambda: None)
        authority = rd.GithubAnchorDigestAuthority(transport=transport)
        plan = rd.compute_plan(graph, state)
        frozen_bytes, frozen_id = rd.freeze_plan(plan, graph, source_sha="s1")
        rd._put_content_addressed(
            store, authority, f"plan:s1:{frozen_id}", frozen_bytes, frozen_id)
        frozen = rd.load_frozen_plan(
            store.get(f"plan:s1:{frozen_id}"), expected_id=frozen_id)
        with self.assertRaises(rd.ReceiptError):
            rd.run_plan(
                plan, graph, lane_factory(publish_ok=False),
                skew=NoRuntimeSkew(), authority=authority, store=store,
                source_sha="s1", approvals={}, state=None, frozen=frozen,
                providers=rd.Providers(store=store, authority=authority),
            )
        store2 = rd.GithubAnchorStore(transport=transport, waiter=lambda: None)
        authority2 = rd.GithubAnchorDigestAuthority(transport=transport)
        resume_lane = lane_factory(publish_ok=True)
        frozen2 = rd.load_frozen_plan(
            store2.get(f"plan:s1:{frozen_id}"), expected_id=frozen_id)
        entries = rd.resume_plan(
            rd.compute_plan(graph, state), graph,
            lanes=resume_lane, skew=NoRuntimeSkew(),
            store=store2, authority=authority2,
            source_sha="s1", approvals={}, state=None, frozen=frozen2,
            require_external_authority=True,
            authority_trust="external-immutable",
        )
        self.assertEqual(resume_lane.stage_calls, 0, "zero restage")
        self.assertEqual(entries["channel"].phase, "verified")
        self.assertEqual(entries["channel"].delivery_proof, GOOD_PROOF)


class NpmLaneCompositionTests(unittest.TestCase):
    def test_graph_declares_the_npm_lane_surface(self) -> None:
        graph = rd.Graph.load(rd.GRAPH_PATH)
        for name in ("channel", "pi", "skills"):
            lane = graph.components[name].publish_lane
            self.assertEqual(lane.get("provider"),
                             "github-workflow-artifacts", name)
            self.assertEqual(lane.get("repository"), "awebai/aweb", name)
            self.assertEqual(
                rd.LANE_ARTIFACT_SOURCES[name],
                ("awebai/aweb", ".github/workflows/npm-release.yml"),
            )
        refs = {"channel": rd.LaneRef(
            artifact="gh-artifact:awebai/aweb:1:2",
            aw_source_sha="f" * 40,
            zip_digest="sha256:" + "6" * 64)}
        lanes = rd.compose_workflow_lanes(graph, refs)
        self.assertTrue(lanes.has_lane("channel"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
