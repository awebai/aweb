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


def aw_version_proof(version: str, *, module_version: str | None = None):
    return {
        "version_output": (
            f"aw {version}\n"
            f"  commit: {'c' * 40} (github.com/awebai/aw)\n"
            "  built:  2026-08-04T00:00:00Z\n"
        ),
        "module_version": module_version or f"v{version}",
    }


def github_release_fixture(version: str, selected_archive: bytes):
    platform_name = f"aw_{version}_darwin_arm64.tar.gz"
    names = rd.expected_lane_payload_names(version)[0]
    bodies = {
        name: (selected_archive if name == platform_name else name.encode())
        for name in names if name != "checksums.txt"
    }
    checksums = "".join(
        f"{sha(body)}  {name}\n" for name, body in sorted(bodies.items())
    ).encode()
    bodies["checksums.txt"] = checksums
    metadata = {
        "tag_name": f"v{version}",
        "assets": [
            {"name": name, "digest": f"sha256:{sha(body)}"}
            for name, body in sorted(bodies.items())
        ],
    }
    return bodies, metadata


def pypi_fixture(version: str, wheel: bytes, sdist: bytes = b"sdist"):
    wheel_name = f"aweb-{version}-py3-none-any.whl"
    sdist_name = f"aweb-{version}.tar.gz"
    return {
        "info": {"version": version},
        "urls": [
            {
                "filename": wheel_name,
                "packagetype": "bdist_wheel",
                "yanked": False,
                "url": f"https://files.pythonhosted.org/{wheel_name}",
                "digests": {"sha256": sha(wheel)},
            },
            {
                "filename": sdist_name,
                "packagetype": "sdist",
                "yanked": False,
                "url": f"https://files.pythonhosted.org/{sdist_name}",
                "digests": {"sha256": sha(sdist)},
            },
        ],
    }


def runtime_proof(server_version, wheel_sha, identity, *, aweb_override=None):
    import release_skew_cli_server as subject

    inventory = {
        "aweb": aweb_override or server_version,
        "mcp": subject.locked_mcp_version(),
        "starlette": "0.52.1",
    }
    return {
        "cell_identity_sha256": sha(subject._canonical_json(identity)),
        "container_id": "a" * 64,
        "image_id": "sha256:" + "b" * 64,
        "installed_distributions": inventory,
        "installed_distributions_sha256": sha(subject._canonical_json(inventory)),
        "mcp_version": subject.locked_mcp_version(),
        "ports": {
            "aweb": 38000, "awid": 38010,
            "library": 38765, "postgres": 35432,
        },
        "project": f"aweb-skew-{sha(subject._canonical_json(identity))[:20]}-{'c' * 16}",
        "server_version": server_version,
        "wheel_sha256": wheel_sha,
    }


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
    def resolver(
        self, *, staged=None, release=None, release_metadata=None, pypi=None,
        url=None, aw_probe=None,
    ):
        import release_skew_cli_server as subject

        def staged_capabilities(component):
            body = staged[component]
            return FakeStore(body), FakeAuthority(sha(body))

        return subject.CliServerArtifactResolver(
            staged_capabilities=staged_capabilities,
            github_release_fetch=release or (lambda version, name: None),
            github_release_metadata_fetch=(
                release_metadata or (lambda version: None)
            ),
            pypi_metadata_fetch=pypi or (lambda version: None),
            url_fetch=url or (lambda value: b""),
            platform_name=lambda: "darwin_arm64",
            aw_version_probe=aw_probe or (lambda path: aw_version_proof("1.35.0")),
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
            github_release_metadata_fetch=lambda version: None,
            pypi_metadata_fetch=lambda version: None,
            url_fetch=lambda value: b"",
            platform_name=lambda: "darwin_arm64",
            aw_version_probe=lambda path: aw_version_proof("1.35.0"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rd.ReceiptError, "independent authority"):
                resolver.resolve(side, "candidate", "github-release:awebai/aw", Path(tmp))
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_published_dirty_aw_floor_is_digest_bound_compatibility_only(self):
        archive = archive_with_aw(b"published-aw")
        bodies, metadata = github_release_fixture("1.34.2", archive)
        calls = []

        def fetch(version, name):
            calls.append((version, name))
            return bodies.get(name)

        resolver = self.resolver(
            staged={}, release=fetch, release_metadata=lambda version: metadata,
            aw_probe=lambda path: aw_version_proof(
                "1.34.2", module_version="v1.34.2+dirty"
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
            ],
        )
        self.assertEqual(result.evidence["outer_sha256"], sha(archive))
        self.assertEqual(result.evidence["registry_sha256"], sha(archive))
        self.assertEqual(result.evidence["checksums_recorded_sha256"], sha(archive))
        self.assertEqual(result.evidence["payload_sha256"], sha(b"published-aw"))
        self.assertEqual(
            result.evidence["registry_set_digest"],
            rd.canonical_digest_of_set(result.evidence["registry_digest_set"]),
        )
        self.assertEqual(result.evidence["module_version"], "v1.34.2+dirty")
        self.assertEqual(result.evidence["provenance_status"], "rejected-dirty")
        self.assertEqual(result.evidence["use"], "installed-fleet-compatibility-only")

    def test_published_aw_api_digest_mismatch_refuses(self):
        archive = archive_with_aw(b"published-aw")
        bodies, metadata = github_release_fixture("1.34.3", archive)
        for asset in metadata["assets"]:
            if asset["name"] == "checksums.txt":
                asset["digest"] = "sha256:" + "0" * 64
        resolver = self.resolver(
            staged={}, release=lambda version, name: bodies.get(name),
            release_metadata=lambda version: metadata,
            aw_probe=lambda path: aw_version_proof("1.34.3"),
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
        metadata = pypi_fixture("1.26.35", wheel)
        resolver = self.resolver(
            staged={}, pypi=lambda version: metadata, url=lambda value: wheel
        )
        side = {"component": "server", "version": "1.26.35", "kind": "published"}
        with tempfile.TemporaryDirectory() as tmp:
            result = resolver.resolve(side, "published", "pypi:aweb", Path(tmp))
            self.assertEqual(result.path.read_bytes(), wheel)
        self.assertEqual(result.evidence["outer_sha256"], sha(wheel))
        self.assertEqual(result.evidence["registry_sha256"], sha(wheel))
        self.assertEqual(len(result.evidence["registry_digest_set"]), 2)
        self.assertEqual(
            result.evidence["registry_set_digest"],
            rd.canonical_digest_of_set(result.evidence["registry_digest_set"]),
        )

    def test_published_aw_complete_asset_set_and_binary_version_are_required(self):
        archive = archive_with_aw(b"published-aw")
        bodies, clean = github_release_fixture("1.34.3", archive)
        mutations = []
        missing = json.loads(json.dumps(clean))
        missing["assets"].pop()
        mutations.append((missing, aw_version_proof("1.34.3"), "asset set is not exact"))
        extra = json.loads(json.dumps(clean))
        extra["assets"].append({"name": "extra.txt", "digest": "sha256:" + "d" * 64})
        mutations.append((extra, aw_version_proof("1.34.3"), "asset set is not exact"))
        mutations.append((clean, aw_version_proof("9.9.9"), "version output"))
        mutations.append((clean, aw_version_proof("1.34.3", module_version="v1.34.3+dirty"), "module version"))
        for metadata, proof, marker in mutations:
            with self.subTest(marker=marker):
                resolver = self.resolver(
                    staged={}, release=lambda version, name: bodies.get(name),
                    release_metadata=lambda version, value=metadata: value,
                    aw_probe=lambda path, value=proof: value,
                )
                with tempfile.TemporaryDirectory() as tmp:
                    with self.assertRaisesRegex(rd.ReceiptError, marker):
                        resolver.resolve(
                            {"component": "aw", "version": "1.34.3"},
                            "published", "github-release:awebai/aw", Path(tmp),
                        )

    def test_published_pypi_metadata_version_and_complete_set_are_required(self):
        wheel = b"published-wheel"
        valid = pypi_fixture("1.26.35", wheel)
        mutations = []
        wrong_version = json.loads(json.dumps(valid))
        wrong_version["info"]["version"] = "1.26.31"
        mutations.append((wrong_version, "info.version"))
        unsafe_url = json.loads(json.dumps(valid))
        unsafe_url["urls"][0]["url"] = "https://attacker.example/aweb-1.26.35-py3-none-any.whl"
        mutations.append((unsafe_url, "unsafe or mismatched URL"))
        missing = json.loads(json.dumps(valid))
        missing["urls"].pop()
        mutations.append((missing, "release file set is not exact"))
        extra = json.loads(json.dumps(valid))
        extra["urls"].append({
            "filename": "extra-1.26.35.tar.gz", "packagetype": "sdist",
            "yanked": False, "url": "https://files.pythonhosted.org/extra-1.26.35.tar.gz",
            "digests": {"sha256": "e" * 64},
        })
        mutations.append((extra, "release file set is not exact"))
        for metadata, marker in mutations:
            with self.subTest(marker=marker):
                resolver = self.resolver(
                    staged={}, pypi=lambda version, value=metadata: value,
                    url=lambda value: wheel,
                )
                with tempfile.TemporaryDirectory() as tmp:
                    with self.assertRaisesRegex(rd.ReceiptError, marker):
                        resolver.resolve(
                            {"component": "server", "version": "1.26.35"},
                            "published", "pypi:aweb", Path(tmp),
                        )

    def test_published_pypi_digest_mismatch_refuses(self):
        metadata = pypi_fixture("1.26.35", b"expected")
        metadata["urls"][0]["digests"]["sha256"] = "0" * 64
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

        def journey(aw, server, direction, identity):
            calls.append((aw.path.name, server.path.name, direction, identity))
            return runtime_proof(
                server.version, server.evidence["payload_sha256"], identity
            )

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
            self.assertEqual(evidence["runtime"]["server_version"], "1.26.36")
            self.assertEqual(evidence["runtime"]["wheel_sha256"], sha(b"server"))
        self.assertEqual(
            [(left, right, direction) for left, right, direction, _ in calls],
            [("aw", "server", "a-to-b"), ("aw", "server", "b-to-a")],
        )
        self.assertEqual(calls[0][3]["direction"], "a-to-b")
        self.assertEqual(calls[1][3]["direction"], "b-to-a")

    def test_frozen_lifecycle_persists_first_and_finishes_incomplete(self):
        import release_skew_cli_server as subject

        server_zip, server_manifest = staged_server_zip()
        server_entry = rd.ReceiptEntry(
            version="1.26.36", digest=server_manifest["canonical_set_digest"],
            digest_set=server_manifest["files"],
            lane_ref=candidate_side(
                "server", "1.26.36", server_zip, server_manifest, "b" * 40
            )["lane_ref"],
        )
        document = rd.freeze_skew_matrix(
            edge(), moving={"server"}, staged={"server": server_entry},
            support={"supported_versions": {
                "aw": ["1.34.3"], "server": ["1.26.35"],
            }},
            published_versions={"aw": "1.34.3", "server": "1.26.35"},
            staged_manifest_digest="f" * 64,
        )
        cells = rd.validate_skew_matrix_document(document)
        calls = []

        class Resolver:
            def resolve(self, side, kind, locator, root):
                component = side["component"]
                path = root / ("aw" if component == "aw" else "server.whl")
                path.write_bytes(component.encode())
                if component == "server":
                    wheel_name = next(
                        name for name in side["digest_set"] if name.endswith(".whl")
                    )
                    evidence = {
                        "component": "server", "version": side["version"],
                        "kind": "candidate", "lane_ref": side["lane_ref"],
                        "outer_sha256": side["lane_ref"]["zip_digest"].removeprefix("sha256:"),
                        "digest_set": side["digest_set"],
                        "payload_name": wheel_name,
                        "payload_sha256": side["digest_set"][wheel_name],
                        "archive_payload_sha256": side["digest_set"][wheel_name],
                    }
                else:
                    names = rd.expected_lane_payload_names(side["version"])[0]
                    selected = f"aw_{side['version']}_darwin_arm64.tar.gz"
                    registry = {name: ("a" * 64) for name in names}
                    evidence = {
                        "component": "aw", "version": side["version"],
                        "kind": kind, "registry": "github-release:awebai/aw",
                        "tag": f"v{side['version']}",
                        "registry_digest_set": registry,
                        "registry_set_digest": rd.canonical_digest_of_set(registry),
                        "checksums_sha256": registry["checksums.txt"],
                        "checksums_registry_sha256": registry["checksums.txt"],
                        "payload_name": selected, "outer_sha256": registry[selected],
                        "registry_sha256": registry[selected],
                        "checksums_recorded_sha256": registry[selected],
                        "payload_sha256": sha(b"aw"),
                        **aw_version_proof(side["version"]),
                    }
                return subject.ResolvedArtifact(
                    component, side["version"], path, evidence
                )

        def journey(aw, server, direction, identity):
            calls.append(direction)
            return runtime_proof(
                server.version, server.evidence["payload_sha256"], identity
            )

        with tempfile.TemporaryDirectory() as tmp:
            harness = subject.CliServerSkewHarness(
                resolver=Resolver(), journey=journey, evidence_root=Path(tmp)
            )
            with self.assertRaisesRegex(rd.ReceiptError, "before.*matrix"):
                harness.run(cells[0])
            matrix_path = harness.freeze_matrix(document)
            self.assertTrue(matrix_path.is_file())
            self.assertEqual(calls, [])
            for value in cells:
                harness.run(value)
            aggregate_path = harness.finish_matrix(document)
            aggregate = json.loads(aggregate_path.read_text())
            self.assertEqual(aggregate["status"], "incomplete-unanchored")
            self.assertFalse(aggregate["support_complete"])
            self.assertIsNone(aggregate["anchor"])
            self.assertEqual(aggregate["matrix_id"], document["matrix_id"])
            cell_path = next((Path(tmp) / "cells").iterdir())
            original = cell_path.read_bytes()
            tampered = json.loads(original)
            tampered["runtime"]["server_version"] = "9.9.9"
            tampered["report_id"] = rd.canonical_json_digest({
                key: value for key, value in tampered.items() if key != "report_id"
            })
            cell_path.write_text(json.dumps(
                tampered, sort_keys=True, separators=(",", ":")
            ))
            with self.assertRaisesRegex(rd.ReceiptError, "runtime"):
                subject.aggregate_frozen_matrix(matrix_path, Path(tmp))
            cell_path.write_bytes(original)
            tampered = json.loads(original)
            artifact = tampered["artifacts"][0]
            registry = {name: "0" * 64 for name in artifact["registry_digest_set"]}
            artifact["registry_digest_set"] = registry
            artifact["registry_set_digest"] = rd.canonical_digest_of_set(registry)
            artifact["outer_sha256"] = registry[artifact["payload_name"]]
            artifact["registry_sha256"] = artifact["outer_sha256"]
            artifact["checksums_recorded_sha256"] = artifact["outer_sha256"]
            artifact["checksums_sha256"] = registry["checksums.txt"]
            artifact["checksums_registry_sha256"] = registry["checksums.txt"]
            tampered["report_id"] = rd.canonical_json_digest({
                key: value for key, value in tampered.items() if key != "report_id"
            })
            cell_path.write_text(json.dumps(
                tampered, sort_keys=True, separators=(",", ":")
            ))
            with self.assertRaisesRegex(rd.ReceiptError, "published.*differs"):
                subject.aggregate_frozen_matrix(matrix_path, Path(tmp))
            cell_path.write_bytes(original)
            extra = Path(tmp) / "cells" / "stale.json"
            extra.write_text("{}")
            with self.assertRaisesRegex(rd.ReceiptError, "file set"):
                subject.aggregate_frozen_matrix(matrix_path, Path(tmp))

    def test_runtime_server_proof_refuses_version_or_wheel_mismatch(self):
        import release_skew_cli_server as subject

        artifact = subject.ResolvedArtifact(
            component="server", version="1.26.35", path=Path("server.whl"),
            evidence={"payload_sha256": "a" * 64},
        )
        identity = subject.cell_document(cell(
            {"component": "aw", "version": "1.34.3"},
            {"component": "server", "version": "1.26.35"},
            a_kind="published", b_kind="published",
        ))
        base = runtime_proof("1.26.35", "a" * 64, identity)
        self.assertEqual(subject.validate_runtime_proof(base, artifact, identity), base)
        for field, value in (("server_version", "1.26.31"), ("wheel_sha256", "d" * 64)):
            with self.subTest(field=field):
                with self.assertRaisesRegex(rd.ReceiptError, "runtime server proof"):
                    subject.validate_runtime_proof(
                        {**base, field: value}, artifact, identity
                    )

        wrong_project = {
            **base,
            "project": f"aweb-skew-{'f' * 20}-{'e' * 16}",
        }
        with self.assertRaisesRegex(rd.ReceiptError, "runtime server proof"):
            subject.validate_runtime_proof(wrong_project, artifact, identity)

        port_mutations = {
            "wrong": {**base["ports"], "aweb": 70000},
            "duplicate": {**base["ports"], "aweb": base["ports"]["awid"]},
            "missing": {
                name: value for name, value in base["ports"].items()
                if name != "postgres"
            },
        }
        for label, ports in port_mutations.items():
            with self.subTest(ports=label):
                with self.assertRaisesRegex(rd.ReceiptError, "runtime server proof"):
                    subject.validate_runtime_proof(
                        {**base, "ports": ports}, artifact, identity
                    )

    def test_outer_artifact_cleanup_failure_cannot_publish_green(self):
        import release_skew_cli_server as subject

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            artifact_root = root / "artifacts"
            artifact_root.mkdir()
            evidence_root = root / "evidence"

            class CleanupFails:
                def __init__(self, **kwargs):
                    pass

                def __enter__(self):
                    return str(artifact_root)

                def __exit__(self, exc_type, exc, traceback):
                    raise OSError("controlled outer cleanup failure")

            class Resolver:
                def resolve(self, side, kind, locator, output_root):
                    path = output_root / side["component"]
                    path.write_bytes(b"bytes")
                    return subject.ResolvedArtifact(
                        side["component"], side["version"], path,
                        {"component": side["component"], "payload_sha256": "a" * 64},
                    )

            def journey(aw, server, direction, identity):
                return runtime_proof(server.version, "a" * 64, identity)

            harness = subject.CliServerSkewHarness(
                resolver=Resolver(), journey=journey,
                evidence_root=evidence_root,
                temporary_directory=CleanupFails,
            )
            with self.assertRaisesRegex(
                subject.SkewJourneyFailure, "outer cleanup failure"
            ) as caught:
                harness.run_evidenced(cell(
                    {"component": "aw", "version": "1.35.0"},
                    {"component": "server", "version": "1.26.36"},
                ))
            self.assertEqual(caught.exception.evidence["outcome"], "red")
            reports = [json.loads(path.read_text()) for path in evidence_root.glob("*.json")]
            self.assertEqual(len(reports), 1)
            self.assertEqual({report["outcome"] for report in reports}, {"red"})

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
            harness.run_evidenced(bad)

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

        def red(aw, server, direction, identity):
            raise subject.JourneyExecutionFailure(
                "required agent_id absent",
                runtime_proof(
                    server.version, server.evidence["payload_sha256"], identity
                ),
            )

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
        self.assertEqual(evidence["runtime"]["server_version"], "1.26.31")
        self.assertEqual(evidence["runtime"]["wheel_sha256"], "2" * 64)
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
            def __init__(self):
                self.root = tempfile.TemporaryDirectory()
                self.events = []

            def freeze_matrix(self, document):
                self.events.append("freeze")

            def finish_matrix(self, document):
                self.events.append("finish")
                path = Path(self.root.name) / "aggregate.json"
                path.write_text(json.dumps({
                    "schema": "aweb.release.runtime-support-measurement.v1",
                    "status": "incomplete-unanchored",
                    "support_complete": False,
                    "anchor": None,
                    "matrix_id": document["matrix_id"],
                    "edge": {"a": "aw", "b": "server"},
                    "journey": "make cli-e2e",
                    "direction": "both",
                }))
                return path

            def run(self, value):
                self.events.append("run")
                return self._evidence(value)

            def run_evidenced(self, value):
                self.events.append("control")
                return self._evidence(value)

            def _evidence(self, value):
                identity = subject.cell_document(value)
                runtime = runtime_proof(
                    value.b["version"], "a" * 64, identity
                )
                if value.b.get("version") == "1.26.31":
                    evidence = {
                        "outcome": "red", "cell": identity,
                        "artifacts": [{"payload_sha256": "a" * 64}],
                        "runtime": runtime,
                    }
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
                            "registry_digest_set": {"asset": "f" * 64},
                            "registry_set_digest": rd.canonical_digest_of_set({"asset": "f" * 64}),
                            **aw_version_proof(
                                "1.34.2", module_version="v1.34.2+dirty"
                            ),
                            "provenance_status": "rejected-dirty",
                            "use": "installed-fleet-compatibility-only",
                        })
                return {
                    "outcome": "green", "cell": identity,
                    "artifacts": artifacts, "runtime": runtime,
                }

        harness = Harness()
        document = subject.measure_support(
            staged=staged,
            staged_manifest_digest="f" * 64,
            supported_versions={"aw": ["1.34.2", "1.34.3"], "server": ["1.26.35"]},
            published_versions={"aw": "1.34.3", "server": "1.26.35"},
            negative_server="1.26.31",
            harness=harness,
        )
        self.assertEqual(harness.events[0], "freeze")
        self.assertEqual(document["status"], "incomplete-unanchored")
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
        self.assertEqual({row["outcome"] for row in document["cell_evidence"]}, {"green"})
        self.assertEqual(
            {row["cell"]["direction"] for row in document["cell_evidence"]},
            {"a-to-b", "b-to-a"},
        )
        harness.root.cleanup()

    def test_controls_refuse_dependency_resolution_drift_beyond_server_wheel(self):
        import release_skew_cli_server as subject

        base = {
            "cell": {"direction": "a-to-b"},
            "runtime": {"installed_distributions": {
                "aweb": "1.26.31", "mcp": subject.locked_mcp_version(),
                "starlette": "0.52.1",
            }},
        }
        changed = {
            "cell": {"direction": "b-to-a"},
            "runtime": {"installed_distributions": {
                "aweb": "1.26.35", "mcp": subject.locked_mcp_version(),
                "starlette": "0.53.0",
            }},
        }
        with self.assertRaisesRegex(rd.ReceiptError, "differ in dependency resolution"):
            subject._require_uniform_dependency_posture([base, changed])

    def test_negative_server_version_cannot_enter_supported_versions(self):
        import release_skew_cli_server as subject

        with self.assertRaisesRegex(rd.ReceiptError, "negative-only.*supported_versions"):
            subject.measure_support(
                staged={}, staged_manifest_digest="f" * 64,
                supported_versions={"aw": ["1.34.2", "1.34.3"], "server": ["1.26.31", "1.26.35"]},
                published_versions={"aw": "1.34.3", "server": "1.26.35"},
                negative_server="1.26.31",
                harness=None,
            )

    def test_unrelated_negative_failure_refuses_measurement(self):
        import release_skew_cli_server as subject

        class BrokenDownload:
            def freeze_matrix(self, document):
                pass

            def finish_matrix(self, document):
                raise AssertionError("negative control must refuse first")

            def run(self, value):
                raise AssertionError("negative control must refuse first")

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
                staged=staged, staged_manifest_digest="f" * 64,
                supported_versions={"aw": ["1.34.3"], "server": ["1.26.35"]},
                published_versions={"aw": "1.34.3", "server": "1.26.35"},
                negative_server="1.26.31",
                harness=BrokenDownload(),
            )

    def test_green_negative_control_refuses_measurement(self):
        import release_skew_cli_server as subject

        class Green:
            def freeze_matrix(self, document):
                pass

            def finish_matrix(self, document):
                raise AssertionError("negative control must refuse first")

            def run(self, value):
                raise AssertionError("negative control must refuse first")

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
                staged=staged, staged_manifest_digest="f" * 64,
                supported_versions={"aw": ["1.34.3"], "server": ["1.26.35"]},
                published_versions={"aw": "1.34.3", "server": "1.26.35"},
                negative_server="1.26.31",
                harness=Green(),
            )


if __name__ == "__main__":
    unittest.main()
