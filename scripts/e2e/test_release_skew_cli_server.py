#!/usr/bin/env python3
"""Focused contract tests for the CLI/server skew child harness."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import release_driver as rd


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def archive_with_aw(binary: bytes) -> bytes:
    body = io.BytesIO()
    with tarfile.open(fileobj=body, mode="w:gz") as archive:
        info = tarfile.TarInfo("aw")
        info.mode = 0o755
        info.size = len(binary)
        archive.addfile(info, io.BytesIO(binary))
    return body.getvalue()


def staged_aw_zip(version="1.35.0", source="a" * 40):
    dist, npm = rd.expected_lane_payload_names(version)
    payloads = {}
    for name in dist:
        payloads[name] = (
            archive_with_aw(b"candidate-aw")
            if name == f"aw_{version}_darwin_arm64.tar.gz"
            else (b"checksums" if name == "checksums.txt" else name.encode())
        )
    payloads.update({name: name.encode() for name in npm})
    files = {name: sha(body) for name, body in payloads.items()}
    manifest = {
        "mode": "stage-only",
        "candidate_version": version,
        "source_sha": source,
        "files": files,
        "canonical_set_digest": rd.canonical_digest_of_set(files),
    }
    body = io.BytesIO()
    with zipfile.ZipFile(body, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, payload in payloads.items():
            prefix = "npm" if name.endswith(".tgz") else "dist"
            archive.writestr(f"{prefix}/{name}", payload)
    return body.getvalue(), manifest


def staged_server_zip(version="1.26.36", source="b" * 40):
    wheel = f"aweb-{version}-py3-none-any.whl"
    sdist = f"aweb-{version}.tar.gz"
    payloads = {wheel: b"candidate-wheel", sdist: b"candidate-sdist"}
    files = {name: sha(body) for name, body in payloads.items()}
    manifest = {
        "mode": "stage-only",
        "package": "server",
        "candidate_version": version,
        "source_sha": source,
        "files": files,
        "canonical_set_digest": rd.canonical_digest_of_set(files),
    }
    body = io.BytesIO()
    with zipfile.ZipFile(body, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, payload in payloads.items():
            archive.writestr(f"dist/{name}", payload)
    return body.getvalue(), manifest


class FakeAuthority:
    def __init__(self, digest):
        self.digest = digest
        self.calls = []

    def expected_digest(self, artifact):
        self.calls.append(artifact)
        return self.digest


class FakeStore:
    def __init__(self, body):
        self.body = body
        self.calls = []

    def get(self, artifact):
        self.calls.append(artifact)
        return self.body


def candidate_side(component, version, body, manifest, source):
    return {
        "component": component,
        "version": version,
        "digest": manifest["canonical_set_digest"],
        "digest_set": manifest["files"],
        "lane_ref": {
            "artifact": (
                "gh-artifact:awebai/aw:11:22"
                if component == "aw"
                else "gh-artifact:awebai/aweb:33:44"
            ),
            "aw_source_sha": source,
            "zip_digest": f"sha256:{sha(body)}",
        },
    }


def edge():
    return rd.RuntimeContractEdge(
        a="aw",
        b="server",
        journey="make cli-e2e",
        artifacts={"a": "github-release:awebai/aw", "b": "pypi:aweb"},
        direction="both",
        supported={"policy": "additive-only"},
    )


def cell(a, b, *, a_kind="candidate", b_kind="candidate", direction="a-to-b"):
    contract = edge()
    return rd.SkewCell(
        edge_id=rd.edge_identity(contract),
        edge_a=contract.a,
        edge_b=contract.b,
        journey=contract.journey,
        artifacts=contract.artifacts,
        declared_direction=contract.direction,
        direction=direction,
        a_kind=a_kind,
        b_kind=b_kind,
        a=a,
        b=b,
    )


class ArtifactResolutionTests(unittest.TestCase):
    def resolver(self, *, staged=None, release=None, release_digest=None, pypi=None, url=None):
        import release_skew_cli_server as subject

        def staged_capabilities(component):
            body = staged[component]
            return FakeStore(body), FakeAuthority(sha(body))

        return subject.CliServerArtifactResolver(
            staged_capabilities=staged_capabilities,
            github_release_fetch=release or (lambda version, name: None),
            github_release_digest=release_digest or (lambda version, name: None),
            pypi_metadata_fetch=pypi or (lambda version: None),
            url_fetch=url or (lambda value: b""),
            platform_name=lambda: "darwin_arm64",
        )

    def test_candidate_lane_refs_resolve_exact_staged_binary_and_wheel(self):
        aw_zip, aw_manifest = staged_aw_zip()
        server_zip, server_manifest = staged_server_zip()
        resolver = self.resolver(staged={"aw": aw_zip, "server": server_zip})
        aw_side = candidate_side("aw", "1.35.0", aw_zip, aw_manifest, "a" * 40)
        server_side = candidate_side(
            "server", "1.26.36", server_zip, server_manifest, "b" * 40
        )
        with tempfile.TemporaryDirectory() as tmp:
            aw = resolver.resolve(aw_side, "candidate", "github-release:awebai/aw", Path(tmp))
            server = resolver.resolve(server_side, "candidate", "pypi:aweb", Path(tmp))
            self.assertEqual(aw.path.read_bytes(), b"candidate-aw")
            self.assertTrue(aw.path.stat().st_mode & stat.S_IXUSR)
            self.assertEqual(server.path.read_bytes(), b"candidate-wheel")
        self.assertEqual(aw.evidence["outer_sha256"], sha(aw_zip))
        self.assertEqual(aw.evidence["payload_sha256"], sha(b"candidate-aw"))
        self.assertEqual(server.evidence["outer_sha256"], sha(server_zip))
        self.assertEqual(server.evidence["payload_sha256"], sha(b"candidate-wheel"))
        self.assertEqual(aw.evidence["lane_ref"], aw_side["lane_ref"])

    def test_rejected_dirty_aw_release_cannot_be_candidate_provenance(self):
        aw_zip, manifest = staged_aw_zip(version="1.34.2")
        resolver = self.resolver(staged={"aw": aw_zip})
        side = candidate_side("aw", "1.34.2", aw_zip, manifest, "a" * 40)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rd.ReceiptError, "rejected dirty.*candidate"):
                resolver.resolve(side, "candidate", "github-release:awebai/aw", Path(tmp))

    def test_candidate_ref_digest_mismatch_refuses_before_extraction(self):
        import release_skew_cli_server as subject

        aw_zip, manifest = staged_aw_zip()
        side = candidate_side("aw", "1.35.0", aw_zip, manifest, "a" * 40)
        side["lane_ref"]["zip_digest"] = "sha256:" + "0" * 64
        resolver = subject.CliServerArtifactResolver(
            staged_capabilities=lambda component: (
                FakeStore(aw_zip), FakeAuthority(sha(aw_zip))
            ),
            github_release_fetch=lambda version, name: None,
            github_release_digest=lambda version, name: None,
            pypi_metadata_fetch=lambda version: None,
            url_fetch=lambda value: b"",
            platform_name=lambda: "darwin_arm64",
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rd.ReceiptError, "independent authority"):
                resolver.resolve(side, "candidate", "github-release:awebai/aw", Path(tmp))
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_published_dirty_aw_floor_is_digest_bound_compatibility_only(self):
        archive = archive_with_aw(b"published-aw")
        calls = []

        def fetch(version, name):
            calls.append((version, name))
            if name == "checksums.txt":
                return f"{sha(archive)}  aw_1.34.2_darwin_arm64.tar.gz\n".encode()
            return archive

        resolver = self.resolver(
            staged={}, release=fetch,
            release_digest=lambda version, name: sha(
                fetch(version, name)
            ),
        )
        side = {"component": "aw", "version": "1.34.2", "kind": "published-floor"}
        with tempfile.TemporaryDirectory() as tmp:
            result = resolver.resolve(
                side, "published-floor", "github-release:awebai/aw", Path(tmp)
            )
            self.assertEqual(result.path.read_bytes(), b"published-aw")
        self.assertEqual(
            calls,
            [
                ("1.34.2", "checksums.txt"),
                ("1.34.2", "aw_1.34.2_darwin_arm64.tar.gz"),
                ("1.34.2", "checksums.txt"),
                ("1.34.2", "aw_1.34.2_darwin_arm64.tar.gz"),
            ],
        )
        self.assertEqual(result.evidence["outer_sha256"], sha(archive))
        self.assertEqual(result.evidence["registry_sha256"], sha(archive))
        self.assertEqual(result.evidence["checksums_recorded_sha256"], sha(archive))
        self.assertEqual(result.evidence["payload_sha256"], sha(b"published-aw"))
        self.assertEqual(result.evidence["provenance_status"], "rejected-dirty")
        self.assertEqual(result.evidence["use"], "installed-fleet-compatibility-only")

    def test_published_aw_api_digest_mismatch_refuses(self):
        archive = archive_with_aw(b"published-aw")

        def fetch(version, name):
            if name == "checksums.txt":
                return f"{sha(archive)}  aw_1.34.3_darwin_arm64.tar.gz\n".encode()
            return archive

        resolver = self.resolver(
            staged={}, release=fetch,
            release_digest=lambda version, name: "0" * 64,
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rd.ReceiptError, "GitHub API records"):
                resolver.resolve(
                    {"component": "aw", "version": "1.34.3"},
                    "published-latest",
                    "github-release:awebai/aw",
                    Path(tmp),
                )

    def test_published_pypi_wheel_uses_registry_digest(self):
        wheel = b"published-wheel"
        metadata = {
            "urls": [{
                "filename": "aweb-1.26.35-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "yanked": False,
                "url": "https://files.example/aweb.whl",
                "digests": {"sha256": sha(wheel)},
            }]
        }
        resolver = self.resolver(
            staged={}, pypi=lambda version: metadata, url=lambda value: wheel
        )
        side = {"component": "server", "version": "1.26.35", "kind": "published"}
        with tempfile.TemporaryDirectory() as tmp:
            result = resolver.resolve(side, "published", "pypi:aweb", Path(tmp))
            self.assertEqual(result.path.read_bytes(), wheel)
        self.assertEqual(result.evidence["outer_sha256"], sha(wheel))
        self.assertEqual(result.evidence["registry_sha256"], sha(wheel))

    def test_published_pypi_digest_mismatch_refuses(self):
        metadata = {
            "urls": [{
                "filename": "aweb-1.26.35-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "yanked": False,
                "url": "https://files.example/aweb.whl",
                "digests": {"sha256": "0" * 64},
            }]
        }
        resolver = self.resolver(
            staged={}, pypi=lambda version: metadata, url=lambda value: b"wrong"
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rd.ReceiptError, "PyPI records"):
                resolver.resolve(
                    {"component": "server", "version": "1.26.35"},
                    "published",
                    "pypi:aweb",
                    Path(tmp),
                )


class HarnessTests(unittest.TestCase):
    def test_known_control_failure_summary_drops_stack_output(self):
        import release_skew_cli_server as subject

        summary = subject._summarize_journey_failure(
            2,
            "docker noise\nworkspace and agent identifiers were not distinct: secret-path\nFAIL",
            "container noise",
        )
        self.assertEqual(
            summary,
            "real-stack journey exited 2: workspace and agent identifiers were not distinct",
        )
        self.assertNotIn("secret-path", summary)

    def test_registered_exact_journey_runs_each_cell_direction_unchanged(self):
        import release_skew_cli_server as subject
        import release_skew_harnesses as registry

        self.assertIs(registry.REGISTRY["make cli-e2e"], subject.CliServerSkewHarness)
        calls = []

        class Resolver:
            def resolve(self, side, kind, locator, root):
                path = root / side["component"]
                path.write_bytes(side["component"].encode())
                return subject.ResolvedArtifact(
                    component=side["component"], version=side["version"], path=path,
                    evidence={"component": side["component"], "payload_sha256": sha(path.read_bytes())},
                )

        def journey(aw, server, direction):
            calls.append((aw.path.name, server.path.name, direction))

        harness = subject.CliServerSkewHarness(
            resolver=Resolver(), journey=journey, evidence_root=None
        )
        for direction in ("a-to-b", "b-to-a"):
            evidence = harness.run_evidenced(cell(
                {"component": "aw", "version": "1.35.0"},
                {"component": "server", "version": "1.26.36"},
                direction=direction,
            ))
            self.assertEqual(evidence["cell"]["direction"], direction)
            self.assertEqual(evidence["outcome"], "green")
        self.assertEqual(calls, [("aw", "server", "a-to-b"), ("aw", "server", "b-to-a")])

    def test_wrong_edge_preimage_refuses_before_artifact_resolution(self):
        import release_skew_cli_server as subject

        class Resolver:
            def resolve(self, *args):
                self.fail("resolver must not run")

        bad = cell(
            {"component": "aw", "version": "1"},
            {"component": "server", "version": "1"},
        )
        bad = rd.SkewCell(**{**bad.__dict__, "artifacts": {"a": "wrong", "b": "pypi:aweb"}})
        harness = subject.CliServerSkewHarness(
            resolver=Resolver(), journey=lambda *args: None, evidence_root=None
        )
        with self.assertRaisesRegex(rd.ReceiptError, "exact CLI/server edge"):
            harness.run(bad)

    def test_red_journey_preserves_exact_digests_in_failure_evidence(self):
        import release_skew_cli_server as subject

        class Resolver:
            def resolve(self, side, kind, locator, root):
                path = root / side["component"]
                path.write_bytes(b"bytes")
                return subject.ResolvedArtifact(
                    side["component"], side["version"], path,
                    {"component": side["component"], "outer_sha256": "1" * 64, "payload_sha256": "2" * 64},
                )

        def red(*args):
            raise RuntimeError("required agent_id absent")

        harness = subject.CliServerSkewHarness(
            resolver=Resolver(), journey=red, evidence_root=None
        )
        with self.assertRaises(subject.SkewJourneyFailure) as caught:
            harness.run_evidenced(cell(
                {"component": "aw", "version": "1.35.0"},
                {"component": "server", "version": "1.26.31"},
                b_kind="published",
            ))
        evidence = caught.exception.evidence
        self.assertEqual(evidence["outcome"], "red")
        self.assertEqual(evidence["artifacts"][0]["outer_sha256"], "1" * 64)
        self.assertIn("agent_id absent", evidence["error"])


class MeasurementTests(unittest.TestCase):
    def test_negative_control_must_be_red_and_supported_matrix_green(self):
        import release_skew_cli_server as subject

        aw_zip, aw_manifest = staged_aw_zip()
        server_zip, server_manifest = staged_server_zip()
        staged = {
            "aw": rd.ReceiptEntry(
                version="1.35.0", digest=aw_manifest["canonical_set_digest"],
                phase="staged", digest_set=aw_manifest["files"],
                lane_ref=candidate_side("aw", "1.35.0", aw_zip, aw_manifest, "a" * 40)["lane_ref"],
            ),
            "server": rd.ReceiptEntry(
                version="1.26.36", digest=server_manifest["canonical_set_digest"],
                phase="staged", digest_set=server_manifest["files"],
                lane_ref=candidate_side("server", "1.26.36", server_zip, server_manifest, "b" * 40)["lane_ref"],
            ),
        }

        class Harness:
            def run_evidenced(self, value):
                if value.b.get("version") == "1.26.31":
                    evidence = {"outcome": "red", "cell": subject.cell_document(value), "artifacts": [{"payload_sha256": "a" * 64}]}
                    evidence["error"] = "server status locks = [], want one lock"
                    raise subject.SkewJourneyFailure(evidence["error"], evidence)
                artifacts = [{"payload_sha256": "b" * 64}]
                for side in (value.a, value.b):
                    if side.get("component") == "aw" and side.get("version") == "1.34.2":
                        artifacts.append({
                            "component": "aw",
                            "version": "1.34.2",
                            "kind": "published-floor",
                            "outer_sha256": "c" * 64,
                            "registry_sha256": "c" * 64,
                            "checksums_recorded_sha256": "c" * 64,
                            "checksums_sha256": "e" * 64,
                            "checksums_registry_sha256": "e" * 64,
                            "payload_sha256": "d" * 64,
                            "provenance_status": "rejected-dirty",
                            "use": "installed-fleet-compatibility-only",
                        })
                return {"outcome": "green", "cell": subject.cell_document(value), "artifacts": artifacts}

        document = subject.measure_support(
            staged=staged,
            supported_versions={"aw": ["1.34.2", "1.34.3"], "server": ["1.26.35"]},
            published_versions={"aw": "1.34.3", "server": "1.26.35"},
            negative_server="1.26.31",
            harness=Harness(),
        )
        self.assertEqual(document["edge"], {"a": "aw", "b": "server"})
        self.assertEqual(document["journey"], "make cli-e2e")
        self.assertEqual(document["direction"], "both")
        self.assertEqual(document["supported_versions"]["aw"], ["1.34.2", "1.34.3"])
        self.assertEqual(document["support_basis"]["server"]["first_supported"], "1.26.35")
        self.assertEqual(document["support_basis"]["server"]["negative_only"], "1.26.31")
        self.assertEqual(
            document["support_basis"]["aw"]["1.34.2"]["provenance_status"],
            "rejected-dirty",
        )
        self.assertEqual({row["outcome"] for row in document["negative_control"]}, {"red"})
        self.assertEqual({row["outcome"] for row in document["evidence"]}, {"green"})
        self.assertEqual(
            {row["cell"]["direction"] for row in document["evidence"]},
            {"a-to-b", "b-to-a"},
        )

    def test_negative_server_version_cannot_enter_supported_versions(self):
        import release_skew_cli_server as subject

        with self.assertRaisesRegex(rd.ReceiptError, "negative-only.*supported_versions"):
            subject.measure_support(
                staged={},
                supported_versions={"aw": ["1.34.2", "1.34.3"], "server": ["1.26.31", "1.26.35"]},
                published_versions={"aw": "1.34.3", "server": "1.26.35"},
                negative_server="1.26.31",
                harness=None,
            )

    def test_unrelated_negative_failure_refuses_measurement(self):
        import release_skew_cli_server as subject

        class BrokenDownload:
            def run_evidenced(self, value):
                evidence = {
                    "outcome": "red",
                    "cell": subject.cell_document(value),
                    "artifacts": [],
                    "error": "network timeout",
                }
                raise subject.SkewJourneyFailure("network timeout", evidence)

        staged = {
            name: rd.ReceiptEntry(
                version="9.0.0", digest="d", phase="staged", digest_set={"x": "y"},
                lane_ref={"artifact": "gh-artifact:awebai/aw:1:2" if name == "aw" else "gh-artifact:awebai/aweb:1:2", "aw_source_sha": "a" * 40, "zip_digest": "sha256:" + "b" * 64},
            )
            for name in ("aw", "server")
        }
        with self.assertRaisesRegex(rd.ReceiptError, "did not fail on the required.*feature"):
            subject.measure_support(
                staged=staged,
                supported_versions={"aw": ["1.34.3"], "server": ["1.26.35"]},
                published_versions={"aw": "1.34.3", "server": "1.26.35"},
                negative_server="1.26.31",
                harness=BrokenDownload(),
            )

    def test_green_negative_control_refuses_measurement(self):
        import release_skew_cli_server as subject

        class Green:
            def run_evidenced(self, value):
                return {"outcome": "green", "cell": subject.cell_document(value), "artifacts": []}

        staged = {
            name: rd.ReceiptEntry(
                version="9.0.0", digest="d", phase="staged", digest_set={"x": "y"},
                lane_ref={"artifact": "gh-artifact:awebai/aw:1:2" if name == "aw" else "gh-artifact:awebai/aweb:1:2", "aw_source_sha": "a" * 40, "zip_digest": "sha256:" + "b" * 64},
            )
            for name in ("aw", "server")
        }
        with self.assertRaisesRegex(rd.ReceiptError, "negative control.*green"):
            subject.measure_support(
                staged=staged,
                supported_versions={"aw": ["1.34.3"], "server": ["1.26.35"]},
                published_versions={"aw": "1.34.3", "server": "1.26.35"},
                negative_server="1.26.31",
                harness=Green(),
            )


if __name__ == "__main__":
    unittest.main()
