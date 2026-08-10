#!/usr/bin/env python3
"""Channel/Pi ↔ server skew child harness contract tests (tmux-free)."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import release_driver as rd  # noqa: E402
import release_channel_pi_skew as skew  # noqa: E402


def sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def npm_tgz(package: str, version: str) -> bytes:
    import gzip
    import tarfile

    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            body = json.dumps({"name": package, "version": version}).encode()
            info = tarfile.TarInfo("package/package.json")
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


def lane_zip(component: str, version: str = "1.2.3"):
    if component in {"channel", "pi"}:
        name = (
            f"awebai-claude-channel-{version}.tgz"
            if component == "channel" else f"awebai-pi-{version}.tgz"
        )
        payload = f"exact-{component}-tgz".encode()
        member = name
    else:
        name = f"aweb-{version}-py3-none-any.whl"
        payload = b"exact-server-wheel"
        member = f"dist/{name}"
    files = {name: sha(payload)}
    if component == "server":
        sdist = f"aweb-{version}.tar.gz"
        files[sdist] = sha(b"exact-server-sdist")
    manifest = {
        "mode": "stage-only",
        "package": component,
        "source_sha": "a" * 40,
        "candidate_version": version,
        "files": files,
        "canonical_set_digest": sha(json.dumps(files, sort_keys=True).encode()),
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr(member, payload)
        if component == "server":
            archive.writestr(f"dist/{sdist}", b"exact-server-sdist")
    return output.getvalue(), name, payload, files, manifest


class BytesStore:
    def __init__(self, body):
        self.body = body
        self.requests = []

    def get(self, artifact_id):
        self.requests.append(artifact_id)
        return self.body


class DigestAuthority:
    def __init__(self, digest):
        self.digest = digest
        self.requests = []

    def expected_digest(self, artifact_id):
        self.requests.append(artifact_id)
        return self.digest


class CandidateArtifactTests(unittest.TestCase):
    def resolver(self, body, authority_digest=None, validator=None):
        self.store = BytesStore(body)
        self.authority = DigestAuthority(authority_digest or sha(body))
        self.validated = []

        def validate(data, **kwargs):
            self.validated.append((data, kwargs))
            if validator:
                return validator(data, **kwargs)
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                tgz = next(name for name in manifest["files"] if name.endswith(".tgz"))
                return manifest, tgz, archive.read(tgz)

        return skew.ArtifactResolver(
            staged_store_factory=lambda component: self.store,
            staged_authority_factory=lambda component: self.authority,
            npm_lane_validator=validate,
        )

    def side(self, component, body, files, version="1.2.3"):
        return {
            "component": component,
            "version": version,
            "digest": rd.canonical_digest_of_set(files),
            "digest_set": files,
            "lane_ref": {
                "artifact": "gh-artifact:awebai/aweb:17:23",
                "aw_source_sha": "a" * 40,
                "zip_digest": "sha256:" + sha(body),
            },
        }

    def test_candidate_npm_uses_separate_authority_then_exact_store_and_profile(self):
        body, name, tgz, files, _ = lane_zip("channel")
        artifact = self.resolver(body).resolve(
            "candidate", self.side("channel", body, files),
            "npm:@awebai/claude-channel",
        )
        ref = "gh-artifact:awebai/aweb:17:23"
        self.assertEqual(self.authority.requests, [ref])
        self.assertEqual(self.store.requests, [ref])
        self.assertEqual(artifact.filename, name)
        self.assertEqual(artifact.bytes, tgz)
        self.assertEqual(artifact.sha256, files[name])
        self.assertEqual(self.validated[0][1]["profile"], "channel")
        self.assertEqual(artifact.source["lane_ref"]["artifact"], ref)

    def test_candidate_server_uses_complete_lane_set_and_exact_wheel(self):
        body, name, wheel, files, _ = lane_zip("server")
        artifact = self.resolver(body).resolve(
            "candidate", self.side("server", body, files), "pypi:aweb"
        )
        self.assertEqual(artifact.filename, name)
        self.assertEqual(artifact.bytes, wheel)
        self.assertEqual(artifact.sha256, files[name])
        self.assertEqual(artifact.source["digest_set"], files)

    def test_authority_mismatch_refuses_before_store_read(self):
        body, _, _, files, _ = lane_zip("pi")
        resolver = self.resolver(body, authority_digest="0" * 64)
        with self.assertRaisesRegex(rd.ReceiptError, "independent authority"):
            resolver.resolve(
                "candidate", self.side("pi", body, files), "npm:@awebai/pi"
            )
        self.assertEqual(self.store.requests, [])

    def test_candidate_changed_complete_set_or_missing_lane_ref_refuses(self):
        body, _, _, files, _ = lane_zip("channel")
        resolver = self.resolver(body)
        side = self.side("channel", body, files)
        with self.assertRaisesRegex(rd.ReceiptError, "lane reference"):
            resolver.resolve("candidate", {**side, "lane_ref": None},
                             "npm:@awebai/claude-channel")
        with self.assertRaisesRegex(rd.ReceiptError, "complete set"):
            resolver.resolve(
                "candidate", {**side, "digest_set": {"other.tgz": "0" * 64}},
                "npm:@awebai/claude-channel",
            )


class PublishedArtifactTests(unittest.TestCase):
    def test_published_npm_reuses_404_outage_classifier_and_exact_profile(self):
        tgz = npm_tgz("@awebai/claude-channel", "1.7.1")
        metadata_url = "https://registry.npmjs.org/@awebai%2Fclaude-channel/1.7.1"
        tarball_url = "https://registry.example/channel.tgz"
        metadata = json.dumps({"dist": {"tarball": tarball_url}}).encode()
        responses = {
            metadata_url: (200, metadata),
            tarball_url: (200, tgz),
        }
        checked = []
        resolver = skew.ArtifactResolver(
            http_get=lambda url: responses[url],
            npm_profile_check=lambda body, component, version: checked.append(
                (body, component, version)
            ),
        )
        artifact = resolver.resolve(
            "published-latest", {"component": "channel", "version": "1.7.1"},
            "npm:@awebai/claude-channel",
        )
        self.assertEqual(artifact.bytes, tgz)
        self.assertEqual(artifact.sha256, sha(tgz))
        self.assertEqual(checked, [(tgz, "channel", "1.7.1")])

        absent = skew.ArtifactResolver(http_get=lambda url: (404, b""))
        with self.assertRaisesRegex(rd.ReceiptError, "404.*absent"):
            absent.resolve(
                "published-floor", {"component": "pi", "version": "0.3.0"},
                "npm:@awebai/pi",
            )
        outage = skew.ArtifactResolver(http_get=lambda url: (503, b""))
        with self.assertRaisesRegex(rd.ReceiptError, "outage is never proof"):
            outage.resolve(
                "published-floor", {"component": "pi", "version": "0.3.0"},
                "npm:@awebai/pi",
            )

    def test_published_server_reuses_pypi_status_and_digest_set(self):
        bodies, metadata_document = published_registry_fixture("1.26.34")
        wheel_name = "aweb-1.26.34-py3-none-any.whl"
        wheel = bodies[wheel_name]
        metadata_url = "https://pypi.org/pypi/aweb/1.26.34/json"
        metadata = json.dumps(metadata_document).encode()
        observed_set = {name: sha(body) for name, body in bodies.items()}
        resolver = skew.ArtifactResolver(
            pypi_observe=lambda package, version: (200, observed_set),
            http_get=lambda url: (
                (200, metadata) if url == metadata_url
                else (200, bodies[url.rsplit("/", 1)[-1]])
            ),
        )
        artifact = resolver.resolve(
            "published", {"component": "server", "version": "1.26.34"},
            "pypi:aweb",
        )
        self.assertEqual(artifact.bytes, wheel)
        self.assertEqual(artifact.sha256, sha(wheel))
        self.assertEqual(artifact.source["registry"], "pypi:aweb")

        for status, needle in ((404, "404.*absent"), (503, "unavailability")):
            resolver = skew.ArtifactResolver(
                pypi_observe=lambda package, version, status=status: (status, {})
            )
            with self.assertRaisesRegex(rd.ReceiptError, needle):
                resolver.resolve(
                    "published", {"component": "server", "version": "1.26.34"},
                    "pypi:aweb",
                )


class FakeResolver:
    def __init__(self):
        self.calls = []

    def resolve(self, kind, side, locator):
        self.calls.append((kind, side["component"], side["version"], locator))
        body = f"{side['component']}:{side['version']}".encode()
        source = {"kind": "candidate" if kind == "candidate" else "published"}
        if kind != "candidate":
            filename = f"{side['component']}.artifact"
            digest_set = {filename: sha(body)}
            source.update(
                registry=locator,
                metadata_url=(
                    f"https://registry.npmjs.org/"
                    f"{skew.CLIENT_ARTIFACTS[side['component']].removeprefix('npm:').replace('/', '%2F')}/"
                    f"{side['version']}"
                    if side["component"] in {"channel", "pi"} else
                    f"https://pypi.org/pypi/aweb/{side['version']}/json"
                ),
                digest_set=digest_set,
                canonical_set_digest=rd.canonical_digest_of_set(digest_set),
            )
            source[
                "tarball_url" if side["component"] in {"channel", "pi"}
                else "download_url"
            ] = (
                f"https://registry.npmjs.org/{filename}"
                if side["component"] in {"channel", "pi"} else
                f"https://files.pythonhosted.org/{filename}"
            )
        if kind == "candidate":
            source.update(
                lane_ref=side["lane_ref"],
                outer_zip_sha256=side["lane_ref"]["zip_digest"].removeprefix("sha256:"),
                digest_set=side["digest_set"],
                canonical_set_digest=sha(
                    json.dumps(side["digest_set"], sort_keys=True).encode()
                ),
            )
        filename = f"{side['component']}.artifact"
        digest = (
            side["digest_set"][filename]
            if kind == "candidate" else sha(body)
        )
        return skew.PackageArtifact(
            component=side["component"], filename=filename,
            version=side["version"], sha256=digest, bytes=body,
            source=source,
        )


def runtime_proof(server_version="1.26.34", *, extra=None):
    _, constraints_digest, constraints = skew.server_runtime_constraints()
    distributions = [
        {"name": "aweb", "version": server_version},
        {"name": "mcp", "version": constraints["mcp"]},
        {"name": "pip", "version": "25.0"},
    ]
    if extra:
        distributions.extend(extra)
    distributions.sort(key=lambda item: (item["name"], item["version"]))
    preimage = {
        "constraints_sha256": constraints_digest,
        "python_version": "3.12.12",
        "distributions": distributions,
    }
    return {
        "schema": "aweb.server-runtime-inventory.v1",
        **preimage,
        "sha256": sha(json.dumps(
            preimage, sort_keys=True, separators=(",", ":")
        ).encode()),
    }


class FakeJourney:
    def __init__(self, control=(200, 422), close_error=None):
        self.events = []
        self.control = control
        self.close_error = close_error

    @staticmethod
    def observation(component, direction):
        if (component, direction) == ("channel", "a-to-b"):
            operation, result = "chat-mark-read", "removed-from-pending"
        elif (component, direction) == ("channel", "b-to-a"):
            operation, result = "sse-chat-presentation", "presented"
        elif (component, direction) == ("pi", "a-to-b"):
            operation, result = "resident-mail-reply", "observer-verified"
        else:
            operation, result = "resident-mail-wake", "session-observed"
        return {
            "schema": "aweb.channel-pi-skew-observation.v1",
            "component": component,
            "direction": direction,
            "operation": operation,
            "result": result,
            "message_id": "message-1",
            "conversation_id": "conversation-1",
            "server_runtime": runtime_proof(),
        }

    @staticmethod
    def bind_server_version(observation, server_version):
        runtime = observation["server_runtime"]
        next(row for row in runtime["distributions"] if row["name"] == "aweb")[
            "version"
        ] = server_version
        preimage = {
            key: runtime[key]
            for key in ("constraints_sha256", "python_version", "distributions")
        }
        runtime["sha256"] = sha(json.dumps(
            preimage, sort_keys=True, separators=(",", ":")
        ).encode())
        return observation

    def run_client_request(self, client, server, cell):
        self.events.append(("request", client.component, server.component, cell.direction))
        return self.bind_server_version(
            self.observation(client.component, cell.direction), server.version
        )

    def run_server_event(self, client, server, cell):
        self.events.append(("event", server.component, client.component, cell.direction))
        return self.bind_server_version(
            self.observation(client.component, cell.direction), server.version
        )

    def run_mark_read_control(self, payload):
        self.events.append(("control", payload))
        return {
            "unmutated_status": self.control[0],
            "mutated_status": self.control[1],
            "mutation_subject": "disposable required-field server",
        }

    def close(self):
        self.events.append(("close",))
        if self.close_error:
            raise rd.ReceiptError(self.close_error)


class Reports:
    def __init__(self):
        self.items = []

    def write(self, report):
        self.items.append(report)


def cell(client="channel", direction="a-to-b", a_kind="candidate",
         b_kind="published-latest"):
    locator = (
        "npm:@awebai/claude-channel" if client == "channel" else "npm:@awebai/pi"
    )
    journey = skew.CHANNEL_JOURNEY if client == "channel" else skew.PI_JOURNEY
    def side(component, version):
        body = f"{component}:{version}".encode()
        files = {f"{component}.artifact": sha(body)}
        return {
            "component": component,
            "version": version,
            "digest": rd.canonical_digest_of_set(files),
            "digest_set": files,
            "lane_ref": {
                "artifact": "gh-artifact:awebai/aweb:17:23",
                "aw_source_sha": "a" * 40,
                "zip_digest": "sha256:" + "1" * 64,
            },
        }
    return rd.SkewCell(
        edge_id=f"edge-{client}", edge_a=client, edge_b="server",
        journey=journey, artifacts={"a": locator, "b": "pypi:aweb"},
        declared_direction="both", direction=direction,
        a_kind=a_kind, b_kind=b_kind,
        a=side(client, "1.2.3"),
        b=side("server", "1.26.34"),
    )


def prime_harness(harness, value, matrix_id=None):
    harness._matrix = {"matrix_id": matrix_id}
    harness._cells = {rd.skew_cell_identity(value): value}
    return harness


class ChildHarnessTests(unittest.TestCase):
    def run_cell(self, value, *, journey=None):
        reports = Reports()
        journey = journey or FakeJourney()
        harness = skew.ChannelPiHarness(
            resolver=FakeResolver(), journey=journey, evidence=reports,
        )
        prime_harness(harness, value)
        harness.run(value)
        return journey, reports.items[0]

    def test_request_and_event_directions_execute_distinct_observed_assertions(self):
        request_journey, request = self.run_cell(cell(direction="a-to-b"))
        event_journey, event = self.run_cell(cell(direction="b-to-a"))
        self.assertEqual(request_journey.events[0][0], "request")
        self.assertEqual(event_journey.events[0][0], "event")
        self.assertEqual(set(request["observation"]), {"request"})
        self.assertEqual(set(event["observation"]), {"event"})
        self.assertEqual(request["observation"]["request"]["operation"], "chat-mark-read")
        self.assertEqual(event["observation"]["event"]["operation"], "sse-chat-presentation")
        self.assertNotEqual(request["cell_id"], event["cell_id"])
        self.assertEqual(request["edge_id"], "edge-channel")
        self.assertEqual(request["server_runtime"], runtime_proof())
        self.assertEqual(request["artifacts"], {
            "a": "npm:@awebai/claude-channel", "b": "pypi:aweb",
        })

    def test_required_field_control_is_separate_from_candidate_evidence(self):
        journey, report = self.run_cell(cell(
            client="pi", direction="a-to-b",
            a_kind="published-floor", b_kind="candidate",
        ))
        self.assertFalse(any(event[0] == "control" for event in journey.events))
        self.assertNotIn("negative_control", report)
        self.assertNotIn("mutation_subject", report["server_artifact"])

    def test_control_is_not_hidden_in_ordinary_cells(self):
        journey, _ = self.run_cell(
            cell(a_kind="published-latest", b_kind="candidate"),
            journey=FakeJourney(control=(500, 500)),
        )
        self.assertFalse(any(event[0] == "control" for event in journey.events))

    def test_each_invocation_has_a_bounded_noncolliding_compose_project(self):
        first = skew.compose_project_name(Path("/tmp/channel-skew-run-a"), cell())
        second = skew.compose_project_name(Path("/tmp/channel-skew-run-b"), cell())
        self.assertNotEqual(first, second)
        for project in (first, second):
            self.assertRegex(project, r"^[a-z0-9][a-z0-9_.-]{0,62}$")

    def test_free_form_direction_label_cannot_become_green_evidence(self):
        class LabelOnlyJourney(FakeJourney):
            def run_client_request(self, client, server, value):
                observation = super().run_client_request(client, server, value)
                observation["result"] = "anything"
                return observation

        reports = Reports()
        with self.assertRaisesRegex(rd.ReceiptError, "structured"):
            harness = skew.ChannelPiHarness(
                resolver=FakeResolver(), journey=LabelOnlyJourney(), evidence=reports
            )
            value = cell()
            prime_harness(harness, value)
            harness.run(value)
        self.assertEqual(reports.items, [])

    def test_cleanup_failure_blocks_and_writes_no_green_evidence(self):
        reports = Reports()
        with self.assertRaisesRegex(rd.ReceiptError, "cleanup refused"):
            harness = skew.ChannelPiHarness(
                resolver=FakeResolver(),
                journey=FakeJourney(close_error="cleanup refused"),
                evidence=reports,
            )
            value = cell()
            prime_harness(harness, value)
            harness.run(value)
        self.assertEqual(reports.items, [])

    def test_runtime_inventory_must_bind_lock_and_exact_server(self):
        reports = Reports()
        journey = FakeJourney()
        original = journey.observation

        def wrong_runtime(component, direction):
            observed = original(component, direction)
            observed["server_runtime"]["constraints_sha256"] = "0" * 64
            return observed

        journey.observation = wrong_runtime
        with self.assertRaisesRegex(rd.ReceiptError, "runtime inventory"):
            harness = skew.ChannelPiHarness(
                resolver=FakeResolver(), journey=journey, evidence=reports,
            )
            value = cell()
            prime_harness(harness, value)
            harness.run(value)
        self.assertEqual(reports.items, [])

        with self.assertRaisesRegex(rd.ReceiptError, "unlocked distribution"):
            skew.validate_server_runtime(
                runtime_proof(extra=[{"name": "surprise", "version": "9.9"}]),
                "1.26.34",
            )

    def test_other_edges_and_labels_refuse(self):
        wrong = cell()
        wrong = rd.SkewCell(**{**wrong.__dict__, "artifacts": {"a": "x", "b": "y"}})
        with self.assertRaisesRegex(rd.ReceiptError, "channel/Pi-server edge"):
            self.run_cell(wrong)

    def test_journey_closes_when_artifact_resolution_refuses(self):
        class RefusingResolver:
            def resolve(self, kind, side, locator):
                raise rd.ReceiptError("artifact refused")

        journey = FakeJourney()
        with self.assertRaisesRegex(rd.ReceiptError, "artifact refused"):
            harness = skew.ChannelPiHarness(
                resolver=RefusingResolver(), journey=journey, evidence=Reports()
            )
            value = cell()
            prime_harness(harness, value)
            harness.run(value)
        self.assertEqual(journey.events, [("close",)])


class MatrixCoverageTests(unittest.TestCase):
    @staticmethod
    def staged(component, version):
        files = {f"{component}.artifact": sha(component.encode())}
        return rd.ReceiptEntry(
            version=version,
            digest=rd.canonical_digest_of_set(files),
            digest_set=files,
            lane_ref={
                "artifact": "gh-artifact:awebai/aweb:17:23",
                "aw_source_sha": "a" * 40,
                "zip_digest": "sha256:" + "1" * 64,
            },
        )

    def matrix(self, client, moving):
        edge = rd.RuntimeContractEdge(
            a=client, b="server",
            journey=(skew.CHANNEL_JOURNEY if client == "channel" else skew.PI_JOURNEY),
            artifacts={"a": skew.CLIENT_ARTIFACTS[client], "b": "pypi:aweb"},
            direction="both", supported={"policy": "additive-only"},
        )
        staged = {}
        if client in moving:
            staged[client] = self.staged(client, "1.2.3")
        if "server" in moving:
            staged["server"] = self.staged("server", "1.26.35")
        return rd.compute_skew_cells(
            edge,
            moving=set(moving),
            staged=staged,
            support={"supported_versions": {
                client: ["1.2.1", "1.2.2"],
                "server": ["1.26.33", "1.26.34"],
            }},
            published_versions={client: "1.2.2", "server": "1.26.34"},
        )

    def test_both_clients_evidence_the_full_both_side_matrix_per_exact_cell(self):
        for client in ("channel", "pi"):
            cells = self.matrix(client, {client, "server"})
            self.assertEqual(len(cells), 10)
            reports = Reports()
            for value in cells:
                harness = skew.ChannelPiHarness(
                    resolver=FakeResolver(), journey=FakeJourney(), evidence=reports,
                )
                prime_harness(harness, value)
                harness.run(value)
            self.assertEqual(len({item["cell_id"] for item in reports.items}), 10)
            self.assertEqual(
                {item["cell_direction"] for item in reports.items},
                {"a-to-b", "b-to-a"},
            )
            for report in reports.items:
                expected = "request" if report["cell_direction"] == "a-to-b" else "event"
                self.assertEqual(set(report["observation"]), {expected})
            skew.aggregate_support(reports.items, expected_cells=cells)

    def test_frozen_lifecycle_persists_first_finishes_incomplete_and_controls_once(self):
        client = "channel"
        contract = rd.RuntimeContractEdge(
            a=client, b="server", journey=skew.CHANNEL_JOURNEY,
            artifacts={"a": skew.CLIENT_ARTIFACTS[client], "b": "pypi:aweb"},
            direction="both", supported={"policy": "additive-only"},
        )
        staged = {
            client: self.staged(client, "1.2.3"),
            "server": self.staged("server", "1.26.35"),
        }
        document = rd.freeze_skew_matrix(
            contract, moving={client, "server"}, staged=staged,
            support={"supported_versions": {
                client: ["1.2.2"], "server": ["1.26.34"],
            }},
            published_versions={client: "1.2.2", "server": "1.26.34"},
            staged_manifest_digest="f" * 64,
        )
        cells = rd.validate_skew_matrix_document(document)
        journeys = []

        def factory():
            journey = FakeJourney()
            journeys.append(journey)
            return journey

        with tempfile.TemporaryDirectory() as tmp:
            evidence = skew.FileEvidenceWriter(Path(tmp))
            harness = skew.ChannelPiHarness(
                resolver=FakeResolver(), journey_factory=factory, evidence=evidence,
            )
            with self.assertRaisesRegex(rd.ReceiptError, "before.*matrix"):
                harness.run(cells[0])
            matrix_path = harness.freeze_matrix(document)
            self.assertTrue(matrix_path.is_file())
            self.assertEqual(journeys, [], "freeze must precede every child effect")
            for value in cells:
                harness.run(value)
            self.assertFalse(any(
                event[0] == "control" for journey in journeys for event in journey.events
            ))
            report_paths = sorted((Path(tmp) / "cells").iterdir())
            originals = {path: path.read_bytes() for path in report_paths}
            for path in report_paths:
                rewritten = json.loads(originals[path])
                for artifact_name, kind_name in (
                    ("client_artifact", "client_kind"),
                    ("server_artifact", "server_kind"),
                ):
                    if rewritten[kind_name] == "candidate":
                        continue
                    artifact = rewritten[artifact_name]
                    digest_set = {
                        name: "0" * 64
                        for name in artifact["source"]["digest_set"]
                    }
                    artifact["source"]["digest_set"] = digest_set
                    artifact["source"]["canonical_set_digest"] = (
                        rd.canonical_digest_of_set(digest_set)
                    )
                    artifact["sha256"] = digest_set[artifact["filename"]]
                rewritten["report_id"] = rd.canonical_json_digest({
                    key: value for key, value in rewritten.items()
                    if key != "report_id"
                })
                path.write_text(json.dumps(
                    rewritten, sort_keys=True, separators=(",", ":")
                ))
            with self.assertRaisesRegex(
                rd.ReceiptError, "effect-time.*digest"
            ):
                harness.finish_matrix(document)
            self.assertFalse(any(
                event[0] == "control" for journey in journeys for event in journey.events
            ), "tampered reports must refuse before the one-time control")
            for path, original in originals.items():
                path.write_bytes(original)
            aggregate_path = harness.finish_matrix(document)
            aggregate = json.loads(aggregate_path.read_text())
            self.assertEqual(aggregate["status"], "incomplete-unanchored")
            self.assertFalse(aggregate["support_complete"])
            self.assertIsNone(aggregate["anchor"])
            self.assertEqual(aggregate["matrix_id"], document["matrix_id"])
            controls = [
                event for journey in journeys for event in journey.events
                if event[0] == "control"
            ]
            self.assertEqual(len(controls), 1)
            cell_path = next((Path(tmp) / "cells").iterdir())
            original = cell_path.read_bytes()
            tampered = json.loads(original)
            tampered["server_artifact"]["sha256"] = "0" * 64
            tampered["report_id"] = rd.canonical_json_digest({
                key: value for key, value in tampered.items() if key != "report_id"
            })
            cell_path.write_text(json.dumps(
                tampered, sort_keys=True, separators=(",", ":")
            ))
            with self.assertRaisesRegex(rd.ReceiptError, "artifact|runtime"):
                skew.aggregate_frozen_matrix(
                    matrix_path, Path(tmp), control_path=harness._control_path
                )
            cell_path.write_bytes(original)
            extra = Path(tmp) / "cells" / "stale.json"
            extra.write_text("{}")
            with self.assertRaisesRegex(rd.ReceiptError, "file set"):
                skew.aggregate_frozen_matrix(
                    matrix_path, Path(tmp), control_path=harness._control_path
                )
            extra.unlink()
            with self.assertRaisesRegex(rd.ReceiptError, "more than once"):
                harness.finish_matrix(document)

    def test_one_moving_side_evidences_every_measured_published_version(self):
        cells = self.matrix("channel", {"channel"})
        self.assertEqual(len(cells), 4)
        self.assertEqual(
            {value.b["version"] for value in cells}, {"1.26.33", "1.26.34"}
        )
        reports = Reports()
        for value in cells:
            harness = skew.ChannelPiHarness(
                resolver=FakeResolver(), journey=FakeJourney(), evidence=reports,
            )
            prime_harness(harness, value)
            harness.run(value)
        self.assertEqual(len(reports.items), 4)


class MeasurementCompletenessTests(unittest.TestCase):
    @staticmethod
    def resign(report):
        report["report_id"] = rd.canonical_json_digest({
            key: value for key, value in report.items() if key != "report_id"
        })
        return report

    def report(self, value):
        _, report = ChildHarnessTests().run_cell(value)
        return report

    def test_aggregate_requires_every_exact_cell_not_a_global_direction_union(self):
        cells = [
            cell(direction="a-to-b", a_kind="candidate", b_kind="published-latest"),
            cell(direction="b-to-a", a_kind="candidate", b_kind="published-latest"),
            cell(direction="a-to-b", a_kind="published-floor", b_kind="candidate"),
            cell(direction="b-to-a", a_kind="published-floor", b_kind="candidate"),
        ]
        reports = [self.report(value) for value in cells]
        document = skew.aggregate_support(reports, expected_cells=cells)
        self.assertEqual(document["completeness"], "unanchored-local-measurement")
        self.assertEqual(document["supported_versions"]["channel"], ["1.2.3"])
        self.assertEqual(document["supported_versions"]["server"], ["1.26.34"])
        self.assertEqual(len(document["evidence"]), len(cells))
        self.assertTrue(all(row["report_sha256"] for row in document["evidence"]))
        self.assertEqual(set(document["candidates"]), {"channel", "server"})
        with self.assertRaisesRegex(rd.ReceiptError, "missing exact cells"):
            skew.aggregate_support(reports[:-1], expected_cells=cells)

    def test_aggregate_refuses_duplicate_or_direction_label_without_matching_assertion(self):
        value = cell(direction="a-to-b")
        report = self.report(value)
        with self.assertRaisesRegex(rd.ReceiptError, "duplicate exact cells"):
            skew.aggregate_support([report, report], expected_cells=[value])
        report["cell_direction"] = "b-to-a"
        self.resign(report)
        with self.assertRaisesRegex(rd.ReceiptError, "cell preimage"):
            skew.aggregate_support([report], expected_cells=[value])

    def test_aggregate_refuses_runtime_drift_for_one_exact_server_artifact(self):
        cells = [cell(direction="a-to-b"), cell(direction="b-to-a")]
        reports = [self.report(value) for value in cells]
        runtime = reports[1]["server_runtime"]
        runtime["python_version"] = "3.12.13"
        preimage = {
            key: runtime[key]
            for key in ("constraints_sha256", "python_version", "distributions")
        }
        runtime["sha256"] = sha(json.dumps(
            preimage, sort_keys=True, separators=(",", ":")
        ).encode())
        self.resign(reports[1])
        with self.assertRaisesRegex(rd.ReceiptError, "runtime inventory differs"):
            skew.aggregate_support(reports, expected_cells=cells)

    def test_aggregate_refuses_mixed_edges(self):
        channel_cell = cell()
        pi_cell = cell(client="pi")
        channel_report = self.report(channel_cell)
        pi_report = self.report(pi_cell)
        with self.assertRaisesRegex(rd.ReceiptError, "one runtime edge"):
            skew.aggregate_support(
                [channel_report, pi_report], expected_cells=[channel_cell, pi_cell]
            )

    def test_aggregate_recomputes_cell_and_artifact_evidence(self):
        value = cell(direction="a-to-b")
        report = self.report(value)
        report["client_artifact"]["sha256"] = "0" * 64
        self.resign(report)
        with self.assertRaisesRegex(rd.ReceiptError, "artifact.*preimage"):
            skew.aggregate_support([report], expected_cells=[value])

        report = self.report(value)
        report["cell"]["a"]["version"] = "9.9.9"
        self.resign(report)
        with self.assertRaisesRegex(rd.ReceiptError, "cell preimage"):
            skew.aggregate_support([report], expected_cells=[value])

        report = self.report(value)
        report["server_runtime"]["sha256"] = "0" * 64
        self.resign(report)
        with self.assertRaisesRegex(rd.ReceiptError, "runtime inventory"):
            skew.aggregate_support([report], expected_cells=[value])


class ClosedRuntimeTests(unittest.TestCase):
    def test_lock_derived_constraints_pin_mcp_and_are_canonical(self):
        body, digest, constraints = skew.server_runtime_constraints()
        self.assertEqual(digest, sha(body))
        self.assertEqual(constraints["mcp"], "1.26.0")
        self.assertIn(b"mcp==1.26.0\n", body)
        self.assertNotIn(b"aweb==", body)
        names = [line.split("==", 1)[0] for line in body.decode().splitlines()]
        self.assertEqual(names, sorted(names))

    def test_pi_child_forces_cleanup_and_clears_ambient_ports_and_origins(self):
        journey = skew.SubprocessChannelPiJourney("pi")
        capture = journey.root / "captured-environment.json"
        residue = journey.root / "ambient-retained-residue"
        observation = FakeJourney.observation("pi", "a-to-b")
        script = """
import json, os, pathlib, sys
capture, residue, observation = sys.argv[1:]
keys = [
    "KEEP_OAS_PROOF", "KEEP_UP", "OAS_PROOF_AWID_PORT",
    "OAS_PROOF_AWEB_PORT", "OAS_PROOF_POSTGRES_PORT",
    "LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL",
    "LIBRARY_E2E_AWEB_PUBLIC_ORIGIN", "LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN",
    "AWEB_PUBLIC_ORIGIN", "AWID_PUBLIC_REGISTRY_URL",
    "AWEB_TEST_URL", "AWID_TEST_URL", "OAS_PROOF_REPORT",
]
pathlib.Path(capture).write_text(json.dumps({key: os.environ.get(key) for key in keys}))
if os.environ.get("KEEP_OAS_PROOF") == "1":
    pathlib.Path(residue).mkdir()
print("AWEB_SKEW_OBSERVATION " + observation)
"""
        ambient = {
            "KEEP_OAS_PROOF": "1",
            "KEEP_UP": "1",
            "OAS_PROOF_AWID_PORT": "18101",
            "OAS_PROOF_AWEB_PORT": "18100",
            "OAS_PROOF_POSTGRES_PORT": "18102",
            "LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL": "https://ambient.invalid",
            "LIBRARY_E2E_AWEB_PUBLIC_ORIGIN": "https://ambient.invalid",
            "LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN": "https://ambient.invalid",
            "AWEB_PUBLIC_ORIGIN": "https://ambient.invalid",
            "AWID_PUBLIC_REGISTRY_URL": "https://ambient.invalid",
            "AWEB_TEST_URL": "https://ambient.invalid",
            "AWID_TEST_URL": "https://ambient.invalid",
        }
        saved = {key: os.environ.get(key) for key in ambient}
        os.environ.update(ambient)
        try:
            result = journey._run(
                [sys.executable, "-c", script, str(capture), str(residue),
                 json.dumps(observation, sort_keys=True)],
                {}, "a-to-b",
            )
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        captured = json.loads(capture.read_text())
        self.assertEqual(captured["KEEP_OAS_PROOF"], "0")
        self.assertFalse(residue.exists())
        for key in ambient:
            if key != "KEEP_OAS_PROOF":
                self.assertIsNone(captured[key], key)
        self.assertEqual(
            captured["OAS_PROOF_REPORT"],
            str(journey.root / "oas-proof-report.json"),
        )
        self.assertEqual(result["operation"], "resident-mail-reply")
        journey.close()


class RegistrationAndJourneyParameterTests(unittest.TestCase):
    def test_real_journey_output_requires_one_structured_matching_observation(self):
        observation = FakeJourney.observation("channel", "a-to-b")
        body = (
            b"runner noise\nAWEB_SKEW_OBSERVATION "
            + json.dumps(observation, sort_keys=True).encode() + b"\n"
        )
        self.assertEqual(
            skew.parse_observation(body, "channel", "a-to-b"), observation
        )
        for output, needle in (
            (b"runner noise", "exactly one"),
            (body + body, "exactly one"),
            (body.replace(b"removed-from-pending", b"anything"), "structured"),
            (body.replace(b"a-to-b", b"b-to-a"), "structured"),
        ):
            with self.assertRaisesRegex(rd.ReceiptError, needle):
                skew.parse_observation(output, "channel", "a-to-b")

    def test_missing_observation_reports_what_the_journey_actually_printed(self):
        """A journey that exits 0 and prints no observation is the hard case to
        diagnose: the count alone says nothing about why. Carry the tail of the
        journey's own output into the refusal, or the only evidence of the cause
        is discarded by the instrument that detected it."""
        output = b"vitest: No test files found, exiting\n"
        with self.assertRaises(rd.ReceiptError) as raised:
            skew.parse_observation(output, "channel", "a-to-b")
        self.assertIn("exactly one", str(raised.exception))
        self.assertIn("No test files found", str(raised.exception))

    def test_missing_observation_report_bounds_the_journey_output_it_quotes(self):
        """Journey output is unbounded and lands in a receipt, so quote a bounded
        tail rather than the whole stream."""
        output = b"x" * (skew.JOURNEY_OUTPUT_REPORT_BYTES * 4)
        with self.assertRaises(rd.ReceiptError) as raised:
            skew.parse_observation(output, "channel", "a-to-b")
        message = str(raised.exception)
        self.assertLess(len(message), skew.JOURNEY_OUTPUT_REPORT_BYTES * 2)
        self.assertIn("x" * 64, message)

    def test_channel_and_pi_factories_isolate_matrix_evidence_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            prior = os.environ.get("AWEB_CHANNEL_PI_SKEW_EVIDENCE_DIR")
            os.environ["AWEB_CHANNEL_PI_SKEW_EVIDENCE_DIR"] = tmp
            try:
                channel = skew.channel_factory()
                pi = skew.pi_factory()
            finally:
                if prior is None:
                    os.environ.pop("AWEB_CHANNEL_PI_SKEW_EVIDENCE_DIR", None)
                else:
                    os.environ["AWEB_CHANNEL_PI_SKEW_EVIDENCE_DIR"] = prior
            self.assertEqual(channel._evidence.root, Path(tmp).resolve() / "channel")
            self.assertEqual(pi._evidence.root, Path(tmp).resolve() / "pi")

    def test_both_exact_journeys_are_registered_once(self):
        import release_skew_harnesses as registry

        self.assertIs(registry.REGISTRY[skew.CHANNEL_JOURNEY], skew.channel_factory)
        self.assertIs(registry.REGISTRY[skew.PI_JOURNEY], skew.pi_factory)

    def test_focused_target_is_in_release_driver_gate(self):
        makefile = (SCRIPTS.parent / "Makefile").read_text()
        target = makefile.split("test-release-channel-pi-skew:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("test_release_channel_pi_skew.py", target)
        release = makefile.split("test-release-driver:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("test-release-channel-pi-skew", release)

    def test_existing_real_journeys_accept_exact_client_and_server_artifacts(self):
        channel = (SCRIPTS.parent / "channel/test/integration.test.ts").read_text()
        resident = (SCRIPTS.parent / "scripts/e2e-oas-attached-principal-retire.sh").read_text()
        self.assertIn("AWEB_CHANNEL_PACKAGE_ROOT", channel)
        self.assertIn("OAS_PROOF_PI_PACKAGE_ROOT", resident)
        self.assertIn("exact installed Pi package", resident)
        self.assertIn("reserveLoopbackPorts(4)", channel)
        self.assertIn("AWEB_SKEW_SERVER_CONSTRAINTS", channel)
        self.assertIn("AWEB_SKEW_SERVER_CONSTRAINTS", resident)
        self.assertIn("server_runtime_inventory.py", channel)
        self.assertIn("server_runtime_inventory.py", resident)
        self.assertIn("--constraint", channel)
        self.assertIn("--constraint", resident)
        self.assertIn("Compose project ${server.projectName} still owns resources", channel)
        self.assertIn('for (const resource of ["container", "volume", "network"])', channel)
        self.assertIn("for resource in container volume network", resident)
        self.assertIn("label=com.docker.compose.project", channel)
        self.assertIn("label=com.docker.compose.project", resident)
        self.assertIn("Compose cleanup failed for exact project", resident)
        for subject in (channel, resident):
            self.assertIn("AWEB_SKEW_SERVER_WHEEL", subject)
            self.assertIn("AWEB_SKEW_SERVER_SHA256", subject)
            self.assertIn("exact server wheel", subject)
            self.assertIn("AWEB_SKEW_DIRECTION", subject)
            self.assertIn("AWEB_SKEW_OBSERVATION", subject)

    def test_disposable_mark_read_control_uses_the_exact_legacy_request(self):
        result = subprocess.run(
            [
                "uv", "run", "--project", str(SCRIPTS.parent / "server"),
                "--frozen", "--quiet", "python",
                str(SCRIPTS / "e2e/mark_read_skew_control.py"),
                "--message-id", skew.LEGACY_MESSAGE_ID,
            ],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        report = json.loads(result.stdout)
        self.assertEqual(report["request"], {
            "up_to_message_id": skew.LEGACY_MESSAGE_ID,
        })
        self.assertEqual(report["unmutated_status"], 200)
        self.assertEqual(report["mutated_status"], 422)
        self.assertEqual(
            report["mutation_subject"], "disposable required-field server"
        )

    def test_graph_support_records_remain_explicitly_incomplete(self):
        graph = rd.Graph.load(rd.GRAPH_PATH)
        for journey in (skew.CHANNEL_JOURNEY, skew.PI_JOURNEY):
            edge = next(edge for edge in graph.runtime_contracts if edge.journey == journey)
            self.assertTrue(edge.declared_incomplete)
            self.assertEqual(edge.supported, {"policy": "additive-only"})




def measurement_input(component="channel", *, server_version="1.26.34",
                      source="a" * 40, **overrides):
    """A canonical aweb.measurement-input-manifest.v1 for one edge."""
    files = {f"{component}.artifact": sha(component.encode())}
    server_files = server_lane_files(server_version)
    entries = {
        component: {
            "kind": "candidate",
            "version": "1.2.3",
            "digest": rd.canonical_digest_of_set(files),
            "digest_set": files,
            "lane_ref": {
                "artifact": "gh-artifact:awebai/aweb:17:23",
                "aw_source_sha": "a" * 40,
                "zip_digest": "sha256:" + "1" * 64,
            },
            "stage_run_id": "17",
            "stage_artifact_id": "23",
            "stage_zip_digest": "sha256:" + "1" * 64,
        },
        "server": {
            "kind": "published",
            "version": server_version,
            "digest_set": server_files,
            "authority": {
                "provider": "pypi-registry",
                "project": "aweb",
                "filename": f"aweb-{server_version}-py3-none-any.whl",
                "registry_sha256": server_files[
                    f"aweb-{server_version}-py3-none-any.whl"
                ],
                "download_url": (
                    "https://files.pythonhosted.org/"
                    f"aweb-{server_version}-py3-none-any.whl"
                ),
            },
        },
    }
    body = {
        "schema": skew.MEASUREMENT_INPUT_SCHEMA,
        "edge": {"a": component, "b": "server"},
        "source_sha": source,
        "entries": entries,
        "grants": skew.MEASUREMENT_GRANTS,
    }
    for key, value in overrides.items():
        if value is _DROP:
            body.pop(key, None)
        else:
            body[key] = value
    body["manifest_id"] = rd.canonical_json_digest(body)
    return body


class _Drop:
    pass


_DROP = _Drop()
_KEEP = _Drop()


def server_lane_zip(version="1.26.34", source_sha="c" * 40,
                    canonical_set_digest=_KEEP, mode="verify-only"):
    """A real-shaped PyPI verify-only lane artifact for package aweb."""
    names = {
        f"aweb-{version}-py3-none-any.whl": b"wheel " + version.encode(),
        f"aweb-{version}.tar.gz": b"sdist " + version.encode(),
    }
    files = {n: sha(d) for n, d in names.items()}
    manifest = {
        "mode": mode, "package": "server",
        "tag": f"server-v{version}", "candidate_version": version,
        "source_sha": source_sha, "files": files,
        "canonical_set_digest": sha(
            json.dumps(files, sort_keys=True).encode()),
    }
    if canonical_set_digest is not _KEEP:
        if canonical_set_digest is _DROP:
            manifest.pop("canonical_set_digest")
        else:
            manifest["canonical_set_digest"] = canonical_set_digest
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", json.dumps(manifest))
        for n, d in names.items():
            z.writestr(f"dist/{n}", d)
    return buf.getvalue(), files


def server_lane_files(version="1.26.34"):
    return server_lane_zip(version)[1]


def server_zip_digest(version="1.26.34", source_sha="c" * 40):
    return sha(server_lane_zip(version, source_sha)[0])


def published_registry_fixture(version="1.26.34"):
    wheel_name = f"aweb-{version}-py3-none-any.whl"
    sdist_name = f"aweb-{version}.tar.gz"
    bodies = {
        wheel_name: b"wheel " + version.encode(),
        sdist_name: b"sdist " + version.encode(),
    }
    metadata = {
        "info": {"version": version},
        "urls": [
            {
                "filename": name,
                "packagetype": (
                    "bdist_wheel" if name == wheel_name else "sdist"
                ),
                "yanked": False,
                "url": f"https://files.pythonhosted.org/{name}",
                "digests": {"sha256": sha(body)},
            }
            for name, body in bodies.items()
        ],
    }
    return bodies, metadata


_REAL_PUBLISHED_AUTHORITY = skew.PublishedServerAuthority
_REAL_ARTIFACT_RESOLVER = skew.ArtifactResolver


def published_authority(*, version="1.26.34", metadata=None, downloads=None,
                        observed_set=None):
    bodies, honest_metadata = published_registry_fixture(version)
    metadata = honest_metadata if metadata is None else metadata
    downloads = bodies if downloads is None else downloads
    observed_set = observed_set if observed_set is not None else {
        name: sha(body) for name, body in bodies.items()
    }
    metadata_url = f"https://pypi.org/pypi/aweb/{version}/json"

    def http_get(url):
        if url == metadata_url:
            return 200, json.dumps(metadata).encode()
        filename = url.rsplit("/", 1)[-1]
        return (200, downloads[filename]) if filename in downloads else (404, b"")

    resolver = _REAL_ARTIFACT_RESOLVER(
        http_get=http_get,
        pypi_observe=lambda project, requested: (200, observed_set),
    )
    return _REAL_PUBLISHED_AUTHORITY(resolver=resolver)


def input_pair(component="channel", **kw):
    """Both halves of the measurement input, always consistent."""
    document = measurement_input(component, **kw)
    return {
        "measurement_input": document,
        "measurement_input_bytes": canonical_bytes(document),
    }


def canonical_bytes(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


class MeasureSupportTests(unittest.TestCase):
    """aweb-abbe.14: the Channel and Pi measurement entrypoints.

    Orchestration is freeze -> exact cells -> finish. The mark-read mutation
    control is the single authoritative control (alice, .14 round 1): it runs
    once, at finish, outside the support cells. Channel/Pi has no reviewed
    negative-only version or first-supported floor, and this entrypoint must not
    invent one.
    """

    @staticmethod
    def staged(component, version):
        files = {f"{component}.artifact": sha(component.encode())}
        return rd.ReceiptEntry(
            version=version,
            digest=rd.canonical_digest_of_set(files),
            digest_set=files,
            lane_ref={
                "artifact": "gh-artifact:awebai/aweb:17:23",
                "aw_source_sha": "a" * 40,
                "zip_digest": "sha256:" + "1" * 64,
            },
        )

    def measure(self, component, tmp, *, journeys=None, supported=None,
                document=None, harness=None):
        def factory():
            journey = FakeJourney()
            if journeys is not None:
                journeys.append(journey)
            return journey

        if harness is None:
            harness = skew.ChannelPiHarness(
                resolver=FakeResolver(), journey_factory=factory,
                evidence=skew.evidence_writer_for(component, Path(tmp)),
            )
        document = document if document is not None else measurement_input(
            component)
        return skew.measure_support(
            component=component,
            measurement_input=document,
            measurement_input_bytes=canonical_bytes(document),
            supported_versions=supported or {"server": ["1.26.34"]},
            published_authority=published_authority(),
            harness=harness,
        )

    def test_measures_both_components_and_reports_incomplete_unanchored(self):
        for component in ("channel", "pi"):
            with tempfile.TemporaryDirectory() as tmp:
                document = self.measure(component, tmp)
            child = document["measurement"]
            self.assertEqual(document["schema"], skew.ENVELOPE_SCHEMA)
            self.assertEqual(child["status"], "incomplete-unanchored")
            self.assertEqual(
                child["completeness"], "unanchored-local-measurement")
            # Server-only: the client is the candidate, so there is no
            # client support set to measure against.
            self.assertEqual(
                document["supported_versions"], {"server": ["1.26.34"]})
            self.assertEqual(document["measurement_id"],
                             child["measurement_id"],
                             "the envelope binds the CHILD's identity")
            self.assertTrue(document["envelope_id"])

    def test_control_runs_exactly_once_and_only_after_every_cell(self):
        journeys = []
        with tempfile.TemporaryDirectory() as tmp:
            self.measure("channel", tmp, journeys=journeys)
        events = [event for journey in journeys for event in journey.events]
        kinds = [event[0] for event in events]
        self.assertEqual(kinds.count("control"), 1,
                         "the mark-read control is the single authoritative "
                         "control and runs once")
        control_at = kinds.index("control")
        self.assertNotIn("request", kinds[control_at:],
                         "no cell may run after the control")
        self.assertNotIn("event", kinds[control_at:])
        self.assertGreater(control_at, 0, "the control runs at finish, not first")

    def test_no_second_pre_cell_control_is_introduced(self):
        """.14 must not duplicate or move .12's finish-time control."""
        journeys = []
        with tempfile.TemporaryDirectory() as tmp:
            self.measure("pi", tmp, journeys=journeys)
        first = [journey.events[0][0] for journey in journeys if journey.events]
        self.assertNotIn("control", first[:-1],
                         "no control may precede the cells")

    def test_control_evidence_stays_outside_support_cells(self):
        with tempfile.TemporaryDirectory() as tmp:
            document = self.measure("channel", tmp)
            root = Path(tmp) / "channel"
            cell_reports = sorted((root / "cells").glob("*.json"))
            self.assertTrue(cell_reports)
            for path in cell_reports:
                report = json.loads(path.read_bytes())
                self.assertNotIn("negative_control", report)
                self.assertNotIn("control_id", report)
            self.assertEqual(
                len(list(root.glob("control-*.json"))), 1,
                "exactly one control document, beside the cells not inside them")
        self.assertNotIn("negative_control", document.get("cell_evidence", [{}])[0]
                         if document.get("cell_evidence") else {})

    def test_mislabelled_evidence_root_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rd.ReceiptError, "final segment"):
                skew.FileEvidenceWriter(Path(tmp) / "channel", component="pi")

    def test_real_factories_carry_their_component(self):
        for component in ("channel", "pi"):
            harness = (skew.channel_factory() if component == "channel"
                       else skew.pi_factory())
            self.assertEqual(harness.evidence_component, component)
            self.assertEqual(Path(harness._evidence.root).name, component)

    def test_channel_and_pi_evidence_roots_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.measure("channel", tmp)
            self.measure("pi", tmp)
            channel_root = Path(tmp) / "channel"
            pi_root = Path(tmp) / "pi"
            self.assertTrue(channel_root.is_dir())
            self.assertTrue(pi_root.is_dir())
            self.assertNotEqual(
                {p.name for p in (channel_root / "cells").glob("*.json")},
                {p.name for p in (pi_root / "cells").glob("*.json")},
                "each component keeps its own evidence; a shared root lets one "
                "component's reports satisfy the other's completeness check")

    def test_unknown_component_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rd.ReceiptError, "channel.*pi|component"):
                skew.measure_support(
                    component="skills",
                    **input_pair("channel"),
                    supported_versions={"server": ["1.26.34"]},
                published_authority=published_authority(),
                    harness=skew.ChannelPiHarness(
                        resolver=FakeResolver(), journey=FakeJourney(),
                        evidence=skew.evidence_writer_for("channel", Path(tmp)),
                    ),
                )

    def test_harness_without_the_frozen_lifecycle_refuses(self):
        class NoLifecycle:
            pass

        with self.assertRaisesRegex(rd.ReceiptError, "frozen matrix lifecycle"):
            skew.measure_support(
                component="channel",
                **input_pair("channel"),
                supported_versions={"server": ["1.26.34"]},
                published_authority=published_authority(),
                harness=NoLifecycle(),
            )

    def test_tampered_cell_report_refuses_at_finish(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = skew.evidence_writer_for("channel", Path(tmp))
            harness = skew.ChannelPiHarness(
                resolver=FakeResolver(), journey_factory=FakeJourney,
                evidence=evidence,
            )
            original = harness.run

            def run_then_tamper(cell):
                original(cell)
                victim = sorted((evidence.root / "cells").glob("*.json"))[0]
                victim.write_bytes(b'{"schema":"tampered"}')
                harness.run = original

            harness.run = run_then_tamper
            with self.assertRaises(rd.ReceiptError):
                skew.measure_support(
                    component="channel",
                    **input_pair("channel"),
                    supported_versions={"server": ["1.26.34"]},
                published_authority=published_authority(),
                    harness=harness,
                )

    def test_extra_report_in_the_evidence_root_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = skew.evidence_writer_for("channel", Path(tmp))
            harness = skew.ChannelPiHarness(
                resolver=FakeResolver(), journey_factory=FakeJourney,
                evidence=evidence,
            )
            original = harness.run
            state = {"done": False}

            def run_then_add(cell):
                original(cell)
                if not state["done"]:
                    state["done"] = True
                    stray = (evidence.root / "cells" /
                             "matrixzz-cellzz.json")
                    stray.write_bytes(b'{"schema":"stray"}')

            harness.run = run_then_add
            with self.assertRaises(rd.ReceiptError):
                skew.measure_support(
                    component="channel",
                    **input_pair("channel"),
                    supported_versions={"server": ["1.26.34"]},
                published_authority=published_authority(),
                    harness=harness,
                )

    def test_candidate_drift_between_staged_and_matrix_refuses(self):
        """A staged entry that changes after the matrix froze must not measure."""
        with tempfile.TemporaryDirectory() as tmp:
            evidence = skew.evidence_writer_for("channel", Path(tmp))
            harness = skew.ChannelPiHarness(
                resolver=FakeResolver(), journey_factory=FakeJourney,
                evidence=evidence,
            )
            frozen = harness.freeze_matrix
            drifted = rd.freeze_skew_matrix(
                rd.RuntimeContractEdge(
                    a="channel", b="server", journey=skew.CHANNEL_JOURNEY,
                    artifacts={"a": skew.CLIENT_ARTIFACTS["channel"],
                               "b": "pypi:aweb"},
                    direction="both", supported={"policy": "additive-only"},
                ),
                moving={"channel", "server"},
                staged={"channel": self.staged("channel", "9.9.9"),
                        "server": self.staged("server", "1.26.35")},
                support={"supported_versions": {"channel": ["1.2.2"],
                                                "server": ["1.26.34"]}},
                published_versions={"channel": "1.2.2", "server": "1.26.34"},
                staged_manifest_digest="f" * 64,
            )

            def freeze_other(document):
                return frozen(drifted)

            harness.freeze_matrix = freeze_other
            with self.assertRaises(rd.ReceiptError):
                skew.measure_support(
                    component="channel",
                    **input_pair("channel"),
                    supported_versions={"server": ["1.26.34"]},
                published_authority=published_authority(),
                    harness=harness,
                )




class MeasureSupportBoundaryTests(unittest.TestCase):
    """The reviewer's three killing substitutions against `.14`.

    Each one keeps every positive orchestration semantic intact and swaps a
    boundary the entrypoint never pinned: an unrelated component's identity, an
    unrelated component's evidence root, and an output class that claims to be
    anchored.
    """

    staged = staticmethod(MeasureSupportTests.staged)

    def harness(self, tmp, component="channel", writer_component=None):
        return skew.ChannelPiHarness(
            resolver=FakeResolver(), journey_factory=FakeJourney,
            evidence=skew.evidence_writer_for(
                writer_component or component, Path(tmp)),
        )

    def measure(self, tmp, *, component="channel", supported=None,
                document=None, harness=None):
        document = document if document is not None else measurement_input(
            component)
        return skew.measure_support(
            component=component,
            measurement_input=document,
            measurement_input_bytes=canonical_bytes(document),
            supported_versions=supported or {"server": ["1.26.34"]},
            published_authority=published_authority(),
            harness=harness if harness is not None else self.harness(
                tmp, component),
        )

    def test_shared_entrypoint_refuses_aw_before_any_effect(self):
        document = measurement_input("aw")
        authority = unittest.mock.Mock()
        harness = unittest.mock.Mock()
        with self.assertRaisesRegex(rd.ReceiptError, "supports only.*channel.*pi"):
            skew.measure_support(
                component="aw",
                measurement_input=document,
                measurement_input_bytes=canonical_bytes(document),
                supported_versions={"server": ["1.26.34"]},
                published_authority=authority,
                harness=harness,
            )
        authority.resolve.assert_not_called()
        harness.freeze_matrix.assert_not_called()
        harness.run.assert_not_called()
        harness.finish_matrix.assert_not_called()

    # 1. the measurement input is not a release staged manifest
    def test_release_staged_manifest_is_refused(self):
        """The whole point of the seam: a document that asserts a frozen plan,
        staging and publish authority is not a measurement authorization."""
        graph = rd.Graph.from_dict({"component": {"channel": {
            "source_paths": ["channel/"],
            "version_source": {"type": "manifest", "path": "channel/v"},
            "tag_format": "channel-v{version}",
            "verify": {"command": "true"},
        }}, "edge": []})
        state = rd.FixtureState(
            changed_components={"channel": True},
            versions={"channel": "1.2.3"},
            published_versions={"channel": "1.2.2"})
        plan = rd.compute_plan(graph, state)
        files = {"channel.artifact": sha(b"channel")}
        staged_bytes, _ = rd.seal_staged_manifest(
            plan, frozen_plan_id="f" * 64, source_sha="a" * 40,
            entries={"channel": rd.ReceiptEntry(
                version="1.2.3", digest=rd.canonical_digest_of_set(files),
                digest_set=files,
                lane_ref={"artifact": "gh-artifact:awebai/aweb:17:23",
                          "aw_source_sha": "a" * 40,
                          "zip_digest": "sha256:" + "1" * 64})},
            graph=graph)
        with self.assertRaisesRegex(rd.ReceiptError, "exactly|schema"):
            skew.validate_measurement_input(
                json.loads(staged_bytes), component="channel")

    def test_candidate_server_is_refused(self):
        doc = measurement_input("channel")
        doc["entries"]["server"]["kind"] = "candidate"
        doc.pop("manifest_id")
        doc["manifest_id"] = rd.canonical_json_digest(doc)
        with self.assertRaisesRegex(rd.ReceiptError, "not 'published'"):
            skew.validate_measurement_input(doc, component="channel")

    def test_invented_server_lane_ref_is_refused(self):
        doc = measurement_input("channel")
        doc["entries"]["server"]["lane_ref"] = {
            "artifact": "gh-artifact:awebai/aweb:17:23",
            "aw_source_sha": "a" * 40, "zip_digest": "sha256:" + "1" * 64}
        doc.pop("manifest_id")
        doc["manifest_id"] = rd.canonical_json_digest(doc)
        with self.assertRaisesRegex(rd.ReceiptError, "lane_ref|exactly"):
            skew.validate_measurement_input(doc, component="channel")

    def test_extra_or_missing_entry_is_refused(self):
        doc = measurement_input("channel")
        doc["entries"]["pi"] = dict(doc["entries"]["channel"])
        doc.pop("manifest_id")
        doc["manifest_id"] = rd.canonical_json_digest(doc)
        with self.assertRaisesRegex(rd.ReceiptError, "exactly"):
            skew.validate_measurement_input(doc, component="channel")

        short = measurement_input("channel")
        del short["entries"]["server"]
        short.pop("manifest_id")
        short["manifest_id"] = rd.canonical_json_digest(short)
        with self.assertRaisesRegex(rd.ReceiptError, "exactly"):
            skew.validate_measurement_input(short, component="channel")

    def test_wrong_edge_grants_source_or_authority_refused(self):
        cases = {
            "edge": {"a": "pi", "b": "server"},
            "grants": "publish",
            "source_sha": "not-a-sha",
            "schema": "aweb.staged-manifest.v1",
        }
        for key, value in cases.items():
            with self.subTest(field=key):
                doc = measurement_input("channel", **{key: value})
                with self.assertRaises(rd.ReceiptError):
                    skew.validate_measurement_input(doc, component="channel")

        doc = measurement_input("channel")
        doc["entries"]["server"]["authority"]["provider"] = "self-asserted"
        doc.pop("manifest_id")
        doc["manifest_id"] = rd.canonical_json_digest(doc)
        with self.assertRaisesRegex(rd.ReceiptError, "pypi-registry"):
            skew.validate_measurement_input(doc, component="channel")

    def test_candidate_digest_not_matching_its_set_refused(self):
        doc = measurement_input("channel")
        doc["entries"]["channel"]["digest"] = "0" * 64
        doc.pop("manifest_id")
        doc["manifest_id"] = rd.canonical_json_digest(doc)
        with self.assertRaisesRegex(rd.ReceiptError, "canonical digest"):
            skew.validate_measurement_input(doc, component="channel")

    def test_forged_manifest_id_refused(self):
        doc = measurement_input("channel")
        doc["manifest_id"] = "0" * 64
        with self.assertRaisesRegex(rd.ReceiptError, "manifest_id"):
            skew.validate_measurement_input(doc, component="channel")

    def test_honest_matrix_has_no_staged_server(self):
        """The positive: a candidate client measured against the published
        server, with the server appearing nowhere as staged."""
        with tempfile.TemporaryDirectory() as tmp:
            envelope = self.measure(tmp)
        matrix_files = list(
            (Path(tmp) / "channel").glob("matrix-*.json")) if False else []
        child = envelope["measurement"]
        self.assertEqual(child["status"], "incomplete-unanchored")
        blob = json.dumps(child)
        self.assertNotIn('"component": "server", "digest"', blob)
        self.assertIn("channel", blob)

    # 2. the evidence root must belong to the component being measured
    def test_pi_measurement_into_a_channel_evidence_root_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = self.harness(tmp, "pi", writer_component="channel")
            with self.assertRaisesRegex(rd.ReceiptError, "component|evidence"):
                self.measure(tmp, component="pi", harness=harness)
            self.assertFalse(
                (Path(tmp) / "channel" / "cells").exists(),
                "the binding must be checked BEFORE any cell effect")

    def test_writer_carries_its_component_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                skew.evidence_writer_for("pi", Path(tmp)).component, "pi")

    # 3. only the exact unanchored output class may be re-identified
    def mutating_harness(self, tmp, mutation):
        return self.mutating_harness_fn(tmp, lambda d: {**d, **mutation})

    def mutating_harness_fn(self, tmp, transform):
        base = self.harness(tmp, "channel")
        finish = base.finish_matrix

        def finish_mutated(document):
            path = finish(document)
            body = transform(json.loads(Path(path).read_bytes()))
            Path(path).write_text(json.dumps(body, sort_keys=True))
            return path

        base.finish_matrix = finish_mutated
        return base

    def test_coherent_post_finish_tamper_refuses(self):
        """The reviewer's kill: mutate the finished document AND recompute its
        identity so it is self-consistent. Only re-deriving from the evidence
        catches it."""
        def coherent(document):
            body = dict(document)
            body["supported_versions"] = {"server": ["9.9.9"]}
            body.pop("measurement_id", None)
            body["measurement_id"] = rd.canonical_json_digest(body)
            return body

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rd.ReceiptError, "derived independently"):
                self.measure(tmp, harness=self.mutating_harness_fn(tmp, coherent))

    def test_output_claiming_completion_refuses(self):
        for mutation in (
            {"status": "complete"},
            {"completeness": "anchored"},
            {"support_complete": True},
            {"anchor": {"artifact": "gh-artifact:awebai/aweb:1:1",
                        "digest": "d" * 64}},
            {"schema": "aweb.runtime-support-measurement.v2"},
        ):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as tmp:
                    with self.assertRaises(rd.ReceiptError):
                        self.measure(
                            tmp, harness=self.mutating_harness(tmp, mutation))

    def test_pretty_json_rewrite_refuses(self):
        """Semantically identical, canonical measurement_id preserved, only the
        BYTES differ. A dict comparison accepts this; the envelope would then
        bless the rewritten bytes with a fresh sha256."""
        def pretty(document):
            return document  # re-serialized non-canonically by the harness

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rd.ReceiptError, "bytes do not equal"):
                self.measure(tmp, harness=self.mutating_harness_fn(tmp, pretty))

    def test_unmutated_output_still_measures(self):
        """The control for the class check: identical machinery, honest output
        left byte-for-byte as the lifecycle wrote it."""
        with tempfile.TemporaryDirectory() as tmp:
            document = self.measure(tmp)
        child = document["measurement"]
        self.assertEqual(child["status"], "incomplete-unanchored")
        self.assertIs(child["support_complete"], False)
        self.assertIsNone(child["anchor"])




class CliMeasurementInputTests(unittest.TestCase):
    """The CLI must validate the whole measurement input before any effect and
    must never accept a release staged manifest."""

    def run_cli(self, tmp, *, component="channel", document=None, fake=True,
                out_name="out.json"):
        path = Path(tmp) / "input.json"
        document = document if document is not None else measurement_input(
            component)
        path.write_bytes(canonical_bytes(document))
        if fake:
            for name, replacement in (
                ("ArtifactResolver", lambda *a, **k: FakeResolver()),
                ("SubprocessChannelPiJourney", lambda *a, **k: FakeJourney()),
                ("PublishedServerAuthority",
                 lambda *a, **k: published_authority()),
            ):
                self.addCleanup(setattr, skew, name, getattr(skew, name))
                setattr(skew, name, replacement)
        return skew.main([
            f"measure-{component}", "--measurement-input", str(path),
            "--supported-server", "1.26.34",
            "--evidence-root", str(Path(tmp) / "evidence"),
            "--output", str(Path(tmp) / out_name),
        ])

    def capture(self, tmp, **kw):
        import contextlib
        import io as _io

        captured = _io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = self.run_cli(tmp, **kw)
        return code, captured.getvalue()

    def test_each_cli_binds_the_exact_registry_authority_report(self):
        for component in ("channel", "pi"):
            with self.subTest(component=component), tempfile.TemporaryDirectory() as tmp:
                document = measurement_input(component)
                code, output = self.capture(
                    tmp, component=component, document=document
                )
                self.assertEqual(code, 0, output)
                self.assertIn("status: incomplete-unanchored", output)
                envelope = json.loads((Path(tmp) / "out.json").read_bytes())
                self.assertEqual(envelope["schema"], skew.ENVELOPE_SCHEMA)
                self.assertEqual(envelope["component"], component)
                self.assertEqual(envelope["supported_versions"],
                                 {"server": ["1.26.34"]})
                self.assertEqual(envelope["measurement"]["status"],
                                 "incomplete-unanchored")
                self.assertEqual(
                    envelope["published_server_authority"],
                    skew.expected_published_server_authority_report(
                        document["entries"]["server"]
                    ),
                )
                self.assertTrue(envelope["measurement_input_id"])

    def test_cli_refuses_a_release_staged_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_bytes(json.dumps({
                "frozen_plan_id": "f" * 64, "source_sha": "a" * 40,
                "entries": {"channel": {"version": "1.2.3"}},
            }, sort_keys=True, separators=(",", ":")).encode())
            import contextlib
            import io as _io

            captured = _io.StringIO()
            with contextlib.redirect_stdout(captured):
                code = skew.main([
                    "measure-channel", "--measurement-input", str(path),
                    "--supported-server", "1.26.34",
                    "--evidence-root", str(Path(tmp) / "evidence"),
                    "--output", str(Path(tmp) / "out.json"),
                ])
            self.assertEqual(code, 1)
            self.assertFalse((Path(tmp) / "out.json").exists())

    def test_cli_refuses_before_any_effect(self):
        """Every refusal leaves no output and no evidence."""
        bad = [
            measurement_input("channel", grants="publish"),
            measurement_input("channel", edge={"a": "pi", "b": "server"}),
            measurement_input("channel", source_sha="nope"),
        ]
        for document in bad:
            with self.subTest(doc=document["grants"]):
                with tempfile.TemporaryDirectory() as tmp:
                    code, _ = self.capture(tmp, document=document)
                    self.assertEqual(code, 1)
                    self.assertFalse((Path(tmp) / "out.json").exists())
                    self.assertFalse((Path(tmp) / "evidence").exists())

    def test_cli_refuses_a_pre_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            out.write_text("prior contents")
            code, output = self.capture(tmp)
            self.assertEqual(code, 1)
            self.assertIn("existing output", output)
            self.assertEqual(out.read_text(), "prior contents")

    def test_cli_refuses_a_support_set_not_ending_at_the_published_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            document = measurement_input("channel", server_version="1.26.35")
            path.write_bytes(canonical_bytes(document))
            for name, replacement in (
                ("ArtifactResolver", lambda *a, **k: FakeResolver()),
                ("SubprocessChannelPiJourney", lambda *a, **k: FakeJourney()),
                ("PublishedServerAuthority",
                 lambda *a, **k: published_authority(version="1.26.35")),
            ):
                self.addCleanup(setattr, skew, name, getattr(skew, name))
                setattr(skew, name, replacement)
            import contextlib
            import io as _io

            captured = _io.StringIO()
            with contextlib.redirect_stdout(captured):
                code = skew.main([
                    "measure-channel", "--measurement-input", str(path),
                    "--supported-server", "1.26.34",
                    "--evidence-root", str(Path(tmp) / "evidence"),
                    "--output", str(Path(tmp) / "out.json"),
                ])
            self.assertEqual(code, 1)
            self.assertIn("published server", captured.getvalue())
            self.assertFalse((Path(tmp) / "out.json").exists())


class AtomicOutputTests(unittest.TestCase):
    """Reviewer: the CLI committed with write_text(), which truncates an
    existing output and can leave partial final bytes when the write fails."""

    def test_pre_existing_target_refuses_and_is_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            out.write_text("prior contents")
            with self.assertRaisesRegex(rd.ReceiptError, "existing output"):
                skew._atomic_write_text(out, "new")
            self.assertEqual(out.read_text(), "prior contents")

    def test_pre_existing_temp_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            (Path(tmp) / "out.json.part").write_text("squatted")
            with self.assertRaisesRegex(rd.ReceiptError, "temporary"):
                skew._atomic_write_text(out, "new")
            self.assertFalse(out.exists())

    def test_raced_target_refuses_and_keeps_the_winner(self):
        """The target does not exist at the check and does by the commit."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            real_fdopen = os.fdopen

            def racing(fd, mode, *a, **k):
                handle = real_fdopen(fd, mode, *a, **k)
                if not out.exists():
                    out.write_text("winner")
                return handle

            with unittest.mock.patch.object(os, "fdopen", racing):
                with self.assertRaisesRegex(rd.ReceiptError, "concurrently"):
                    skew._atomic_write_text(out, "loser")
            self.assertEqual(out.read_text(), "winner")
            self.assertFalse((Path(tmp) / "out.json.part").exists())

    def test_mid_write_failure_leaves_no_output_and_no_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"

            class Exploding:
                def write(self, data):
                    raise OSError("disk full")

                def flush(self):
                    pass

                def fileno(self):
                    return 0

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

            with unittest.mock.patch.object(
                os, "fdopen", lambda fd, *a, **k: (os.close(fd), Exploding())[1]
            ):
                with self.assertRaises(OSError):
                    skew._atomic_write_text(out, "payload")
            self.assertFalse(out.exists())
            self.assertFalse((Path(tmp) / "out.json.part").exists())

    def test_directory_fsync_failure_rolls_back_and_leaves_no_output(self):
        """The reviewer's kill: the final link already exists when the durability
        step fails, so reporting an error without undoing it leaves output
        behind."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            calls = []
            real = skew._fsync_directory

            def failing(directory):
                calls.append(directory)
                if len(calls) == 1:
                    raise OSError("directory fsync failed")
                return real(directory)

            with unittest.mock.patch.object(skew, "_fsync_directory", failing):
                with self.assertRaisesRegex(rd.ReceiptError, "rolled back"):
                    skew._atomic_write_text(out, "payload")
            self.assertFalse(out.exists(),
                             "an error must never leave the final output")
            self.assertFalse((Path(tmp) / "out.json.part").exists())
            self.assertEqual(len(calls), 2,
                             "commit fsync then rollback fsync")

    def test_rollback_never_removes_a_racers_file(self):
        """If a racer replaced the path between commit and failure, that file is
        not ours to delete."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            real = skew._fsync_directory

            def failing(directory):
                if not getattr(failing, "fired", False):
                    failing.fired = True
                    out.unlink()
                    out.write_text("racer wins")
                    raise OSError("directory fsync failed")
                return real(directory)

            with unittest.mock.patch.object(skew, "_fsync_directory", failing):
                with self.assertRaises(rd.ReceiptError):
                    skew._atomic_write_text(out, "payload")
            self.assertEqual(out.read_text(), "racer wins",
                             "rollback must remove only our own link")

    def test_uncertain_rollback_durability_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"

            def always_failing(directory):
                raise OSError("directory fsync failed")

            with unittest.mock.patch.object(
                skew, "_fsync_directory", always_failing
            ):
                with self.assertRaisesRegex(rd.ReceiptError, "failing closed"):
                    skew._atomic_write_text(out, "payload")
            self.assertFalse(out.exists())

    def test_temp_is_removed_before_the_durability_sync(self):
        """Ordering control: one sync must make BOTH the final link and the temp
        removal durable, or a .part entry can survive a crash."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            part = Path(tmp) / "out.json.part"
            observed = {}
            real = skew._fsync_directory

            def observing(directory):
                observed["part_present_at_sync"] = part.exists()
                observed["final_present_at_sync"] = out.exists()
                return real(directory)

            with unittest.mock.patch.object(skew, "_fsync_directory", observing):
                skew._atomic_write_text(out, "payload")
            self.assertFalse(observed["part_present_at_sync"],
                             "temp must be unlinked BEFORE the durability sync")
            self.assertTrue(observed["final_present_at_sync"])
            self.assertEqual(out.read_text(), "payload")
            self.assertFalse(part.exists())

    def test_post_link_temp_unlink_failure_rolls_back(self):
        """The reviewer's kill: the temp unlink sat OUTSIDE the rollback
        boundary, so its failure reported an error while the final survived."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            part = Path(tmp) / "out.json.part"
            real_unlink = os.unlink
            state = {"failed": False}

            def failing_unlink(target):
                # Fail the FIRST post-link temp removal only; the rollback's
                # retry must then succeed, leaving neither final nor temp.
                if str(target) == str(part) and not state["failed"]:
                    state["failed"] = True
                    raise OSError("temp unlink failed")
                return real_unlink(target)

            with unittest.mock.patch.object(os, "unlink", failing_unlink):
                with self.assertRaisesRegex(rd.ReceiptError, "rolled back"):
                    skew._atomic_write_text(out, "payload")
            self.assertTrue(state["failed"], "the injection must have fired")
            self.assertFalse(out.exists(), "no final may survive a refusal")
            self.assertFalse(part.exists(), "no temp may survive a refusal")

    def test_post_link_unlink_failure_preserves_a_racers_file(self):
        """Ownership rule holds on the unlink path too, not just fsync."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            part = Path(tmp) / "out.json.part"
            real_unlink = os.unlink
            state = {"failed": False}

            def failing_unlink(target):
                if str(target) == str(part) and not state["failed"]:
                    state["failed"] = True
                    real_unlink(out)
                    out.write_text("racer wins")
                    raise OSError("temp unlink failed")
                return real_unlink(target)

            with unittest.mock.patch.object(os, "unlink", failing_unlink):
                with self.assertRaises(rd.ReceiptError):
                    skew._atomic_write_text(out, "payload")
            self.assertEqual(out.read_text(), "racer wins")

    def test_unremovable_temp_fails_closed(self):
        """If cleanup cannot be completed, refuse loudly rather than report a
        refusal that quietly left state behind."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            part = Path(tmp) / "out.json.part"
            real_unlink = os.unlink

            def always_failing(target):
                if str(target) == str(part):
                    raise OSError("temp is unremovable")
                return real_unlink(target)

            with unittest.mock.patch.object(os, "unlink", always_failing):
                with self.assertRaisesRegex(rd.ReceiptError, "failing"):
                    skew._atomic_write_text(out, "payload")
            self.assertFalse(out.exists(), "the final must still be rolled back")

    def test_any_post_link_error_is_translated_and_rolled_back(self):
        """Not just OSError: any post-link exception must hit the same
        ownership-scoped rollback and be reported as a ReceiptError."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"

            def exploding(directory):
                raise RuntimeError("something unexpected after the link")

            with unittest.mock.patch.object(
                skew, "_fsync_directory", exploding
            ):
                with self.assertRaises(rd.ReceiptError):
                    skew._atomic_write_text(out, "payload")
            self.assertFalse(out.exists())
            self.assertFalse((Path(tmp) / "out.json.part").exists())

    def test_unremovable_final_fails_closed(self):
        """The rollback cannot remove the final it owns. That is the worst
        case: refuse loudly rather than report a refusal with output present."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            real_unlink = os.unlink

            def failing_final(target):
                if str(target) == str(out):
                    raise OSError("final is unremovable")
                return real_unlink(target)

            def bad_sync(directory):
                raise OSError("durability failed")

            with unittest.mock.patch.object(os, "unlink", failing_final), \
                    unittest.mock.patch.object(skew, "_fsync_directory", bad_sync):
                with self.assertRaisesRegex(
                    rd.ReceiptError, "could not remove the final output"
                ):
                    skew._atomic_write_text(out, "payload")

    def test_redundant_finalizer_cannot_mask_a_successful_commit(self):
        """After the protected unlink and fsync both succeed, no last-resort
        cleanup may run and report an error over a committed final."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            real_unlink = os.unlink
            calls = {"n": 0}

            def unlink_then_explode(target):
                calls["n"] += 1
                if calls["n"] == 1:
                    return real_unlink(target)
                # Any later unlink is the redundant finalizer. Non-OSError on
                # purpose: catching only OSError would let this through.
                raise RuntimeError("redundant finalizer exploded")

            with unittest.mock.patch.object(os, "unlink", unlink_then_explode):
                skew._atomic_write_text(out, "payload")

            self.assertEqual(out.read_text(), "payload",
                             "the commit must stand")
            self.assertEqual(calls["n"], 1,
                             "no redundant unlink may run after a commit")
            self.assertFalse((Path(tmp) / "out.json.part").exists())

    def test_pre_link_cleanup_errors_stay_strict(self):
        """Before any commit the temp is ours alone, so a cleanup failure is a
        real problem and must not be swallowed."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            real_unlink = os.unlink

            class Exploding:
                def write(self, data):
                    raise OSError("disk full")

                def flush(self):
                    pass

                def fileno(self):
                    return 0

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

            def failing_unlink(target):
                raise OSError("temp cleanup failed before any commit")

            with unittest.mock.patch.object(
                os, "fdopen", lambda fd, *a, **k: (os.close(fd), Exploding())[1]
            ), unittest.mock.patch.object(os, "unlink", failing_unlink):
                with self.assertRaises(OSError):
                    skew._atomic_write_text(out, "payload")
            self.assertFalse(out.exists())

    def test_successful_write_commits_exact_bytes_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.json"
            skew._atomic_write_text(out, "exact\n")
            self.assertEqual(out.read_bytes(), b"exact\n")
            self.assertFalse((Path(tmp) / "out.json.part").exists())


class EnvelopeAuthorityTests(unittest.TestCase):
    """Reviewer: _require_envelope validated selected fields only."""

    def envelope(self, **overrides):
        child = {
            "schema": "aweb.runtime-support-measurement.v1",
            "status": "incomplete-unanchored",
            "measurement_id": "c" * 64,
            "supported_versions": {"channel": ["1.2.2"], "server": ["1.26.34"]},
        }
        canonical = json.dumps(
            child, sort_keys=True, separators=(",", ":")).encode()
        body = {
            "schema": skew.ENVELOPE_SCHEMA,
            "policy": "additive-only",
            "component": "channel",
            "measurement_input_id": "a" * 64,
            "measurement_input_sha256": "b" * 64,
            "published_server_authority": {"artifact": "gh-artifact:awebai/aweb:41:9001"},
            "supported_versions": {"channel": ["1.2.2"], "server": ["1.26.34"]},
            "measurement_id": child["measurement_id"],
            "measurement_sha256": hashlib.sha256(canonical).hexdigest(),
            "measurement": child,
        }
        body.update(overrides)
        body["envelope_id"] = rd.canonical_json_digest(body)
        return body

    def check(self, document, **kw):
        return skew._require_envelope(
            document, component="channel",
            measurement_input_id="a" * 64, measurement_input_digest="b" * 64,
            supported_versions={"channel": ["1.2.2"], "server": ["1.26.34"]},
            **kw)

    def test_honest_envelope_validates(self):
        self.assertEqual(self.check(self.envelope()), "incomplete-unanchored")

    def test_wrong_policy_refuses(self):
        with self.assertRaisesRegex(rd.ReceiptError, "policy"):
            self.check(self.envelope(policy="replace-all"))

    def test_supported_versions_disagreeing_with_the_frozen_input_refuses(self):
        """Discriminating: the envelope and the child AGREE with each other, so
        only the frozen-input comparison can catch this."""
        drifted = {"channel": ["9.9.9"], "server": ["1.26.34"]}
        doc = self.envelope(supported_versions=drifted)
        child = dict(doc["measurement"], supported_versions=drifted)
        canonical = json.dumps(
            child, sort_keys=True, separators=(",", ":")).encode()
        doc["measurement"] = child
        doc["measurement_sha256"] = hashlib.sha256(canonical).hexdigest()
        doc.pop("envelope_id")
        doc["envelope_id"] = rd.canonical_json_digest(doc)
        with self.assertRaisesRegex(rd.ReceiptError, "frozen measurement input"):
            self.check(doc)

    def test_supported_versions_disagreeing_with_the_child_refuses(self):
        doc = self.envelope()
        doc["measurement"] = dict(
            doc["measurement"],
            supported_versions={"channel": ["0.0.1"], "server": ["1.26.34"]})
        doc.pop("envelope_id")
        doc["envelope_id"] = rd.canonical_json_digest(doc)
        with self.assertRaisesRegex(rd.ReceiptError, "child"):
            self.check(doc)

    def test_forged_envelope_id_refuses(self):
        doc = self.envelope()
        doc["envelope_id"] = "0" * 64
        with self.assertRaisesRegex(rd.ReceiptError, "envelope_id"):
            self.check(doc)

    def test_coherent_mutation_with_recomputed_envelope_id_still_refuses(self):
        """The coherent case: change a field AND re-sign the envelope. It is
        caught because the envelope is checked against the frozen input and the
        child, not only against itself."""
        doc = self.envelope(component="pi")
        with self.assertRaisesRegex(rd.ReceiptError, "component"):
            self.check(doc)




class MeasurementInputBindingTests(unittest.TestCase):
    """One stage, one identity.

    The candidate duplicates facts the lane reference already carries, so a
    coherently re-signed manifest could name one source/run/artifact/ZIP in its
    provenance fields and a different one in the lane reference it claims to
    describe. Recomputing manifest_id makes such a document internally valid,
    which is exactly why the bindings have to be checked.
    """

    @staticmethod
    def reseal(document):
        document.pop("manifest_id", None)
        document["manifest_id"] = rd.canonical_json_digest(document)
        return document

    def contradiction(self, **changes):
        doc = measurement_input("channel")
        entry = doc["entries"]["channel"]
        for key, value in changes.items():
            if key == "source_sha":
                doc["source_sha"] = value
            elif key.startswith("lane_"):
                entry["lane_ref"][key[len("lane_"):]] = value
            else:
                entry[key] = value
        return self.reseal(doc)

    def test_manifest_source_must_equal_the_lane_source(self):
        doc = self.contradiction(source_sha="b" * 40)
        with self.assertRaisesRegex(rd.ReceiptError, "must name one stage"):
            skew.validate_measurement_input(doc, component="channel")

    def test_stage_run_must_equal_the_run_in_the_lane_artifact(self):
        doc = self.contradiction(stage_run_id="99")
        with self.assertRaisesRegex(rd.ReceiptError, "must name one stage"):
            skew.validate_measurement_input(doc, component="channel")

    def test_stage_artifact_must_equal_the_artifact_in_the_lane_artifact(self):
        doc = self.contradiction(stage_artifact_id="99")
        with self.assertRaisesRegex(rd.ReceiptError, "must name one stage"):
            skew.validate_measurement_input(doc, component="channel")

    def test_stage_zip_digest_must_equal_the_lane_zip_digest(self):
        doc = self.contradiction(stage_zip_digest="sha256:" + "2" * 64)
        with self.assertRaisesRegex(rd.ReceiptError, "must name one stage"):
            skew.validate_measurement_input(doc, component="channel")

    def test_moving_the_lane_side_of_the_binding_also_refuses(self):
        """Symmetry: contradicting from the lane_ref side is the same defect."""
        doc = self.contradiction(lane_aw_source_sha="c" * 40)
        with self.assertRaisesRegex(rd.ReceiptError, "must name one stage"):
            skew.validate_measurement_input(doc, component="channel")

    def test_consistent_bindings_still_validate(self):
        """Control: the same machinery accepts one coherent stage."""
        doc = measurement_input("channel")
        self.assertEqual(
            skew.validate_measurement_input(doc, component="channel"), doc)

    # --- typing and grammar -------------------------------------------------
    def test_candidate_version_must_be_a_nonempty_exact_version(self):
        for bad in (None, "", 123, "not-a-version", ["1.2.3"]):
            with self.subTest(version=bad):
                doc = measurement_input("channel")
                doc["entries"]["channel"]["version"] = bad
                with self.assertRaises(rd.ReceiptError):
                    skew.validate_measurement_input(
                        self.reseal(doc), component="channel")

    def test_server_version_must_be_a_nonempty_exact_version(self):
        for bad in (None, "", 7):
            with self.subTest(version=bad):
                doc = measurement_input("channel")
                doc["entries"]["server"]["version"] = bad
                with self.assertRaises(rd.ReceiptError):
                    skew.validate_measurement_input(
                        self.reseal(doc), component="channel")

    def test_non_string_scalars_refuse_as_receipt_errors_not_type_errors(self):
        """A malformed input must always surface as a refusal. Matching a regex
        against a non-string raises TypeError, which escapes unhandled."""
        cases = [
            ("source_sha", 12345),
            ("authority_run", None),
            ("authority_artifact", 99),
            ("stage_run_id", 17),
            ("stage_zip_digest", None),
        ]
        for label, value in cases:
            with self.subTest(field=label):
                doc = measurement_input("channel")
                if label == "source_sha":
                    doc["source_sha"] = value
                elif label == "authority_run":
                    doc["entries"]["server"]["authority"][
                        "verify_only_run_id"] = value
                elif label == "authority_artifact":
                    doc["entries"]["server"]["authority"][
                        "verify_only_artifact_id"] = value
                else:
                    doc["entries"]["channel"][label] = value
                try:
                    skew.validate_measurement_input(
                        self.reseal(doc), component="channel")
                except rd.ReceiptError:
                    pass
                except Exception as exc:  # noqa: BLE001 - that is the point
                    self.fail(
                        f"{label}={value!r} escaped as {type(exc).__name__}, "
                        "not a ReceiptError")
                else:
                    self.fail(f"{label}={value!r} was accepted")

    # --- the same substitutions through the real CLI ------------------------
    def cli(self, tmp, document):
        import contextlib
        import io as _io

        path = Path(tmp) / "input.json"
        path.write_bytes(canonical_bytes(document))
        for name, replacement in (
            ("ArtifactResolver", lambda *a, **k: FakeResolver()),
            ("SubprocessChannelPiJourney", lambda *a, **k: FakeJourney()),
            ("PublishedServerAuthority", lambda *a, **k: published_authority()),
        ):
            self.addCleanup(setattr, skew, name, getattr(skew, name))
            setattr(skew, name, replacement)
        captured = _io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = skew.main([
                "measure-channel", "--measurement-input", str(path),
                "--supported-server", "1.26.34",
                "--evidence-root", str(Path(tmp) / "evidence"),
                "--output", str(Path(tmp) / "out.json"),
            ])
        return code, captured.getvalue()

    def test_cli_refuses_every_contradiction_before_any_effect(self):
        documents = {
            "source": self.contradiction(source_sha="b" * 40),
            "run": self.contradiction(stage_run_id="99"),
            "artifact": self.contradiction(stage_artifact_id="99"),
            "zip": self.contradiction(stage_zip_digest="sha256:" + "2" * 64),
            "version": self.reseal({
                **measurement_input("channel"),
            }) if False else None,
        }
        documents.pop("version")
        null_version = measurement_input("channel")
        null_version["entries"]["channel"]["version"] = None
        documents["null-version"] = self.reseal(null_version)

        for label, document in documents.items():
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as tmp:
                    code, _ = self.cli(tmp, document)
                    self.assertEqual(code, 1)
                    self.assertFalse((Path(tmp) / "out.json").exists())
                    self.assertFalse((Path(tmp) / "evidence").exists(),
                                     "refusal must precede any evidence")




class PublishedAuthorityConsumedTests(unittest.TestCase):
    """Published server authority is the one shared immutable PyPI report."""

    @staticmethod
    def reseal(document):
        document.pop("manifest_id", None)
        document["manifest_id"] = rd.canonical_json_digest(document)
        return document

    def resolve(self, document, *, authority=None):
        resolver = authority or published_authority(
            version=document["entries"]["server"]["version"])
        return resolver.resolve(document["entries"]["server"])

    def test_honest_registry_authority_resolves(self):
        document = measurement_input("channel")
        report = self.resolve(document)
        self.assertEqual(
            report,
            skew.expected_published_server_authority_report(
                document["entries"]["server"]
            ),
        )

    def test_registry_download_digest_mismatch_refuses(self):
        version = "1.26.34"
        bodies, metadata = published_registry_fixture(version)
        wheel = f"aweb-{version}-py3-none-any.whl"
        downloads = dict(bodies, **{wheel: b"substituted"})
        with self.assertRaisesRegex(rd.ReceiptError, "does not equal PyPI"):
            self.resolve(
                measurement_input("channel"),
                authority=published_authority(
                    version=version, metadata=metadata, downloads=downloads
                ),
            )

    def test_ambiguous_registry_files_refuse(self):
        version = "1.26.34"
        _, metadata = published_registry_fixture(version)
        metadata = json.loads(json.dumps(metadata))
        metadata["urls"].append(dict(metadata["urls"][0]))
        with self.assertRaisesRegex(rd.ReceiptError, "repeats filename"):
            self.resolve(
                measurement_input("channel"),
                authority=published_authority(version=version, metadata=metadata),
            )

    def test_projection_mutation_refuses(self):
        document = measurement_input("channel")
        document["entries"]["server"]["authority"]["registry_sha256"] = "0" * 64
        self.reseal(document)
        with self.assertRaisesRegex(rd.ReceiptError, "registry projection"):
            self.resolve(document)

    def test_measurement_refuses_bad_registry_before_evidence(self):
        document = measurement_input("channel")
        document["entries"]["server"]["authority"]["registry_sha256"] = "0" * 64
        document["entries"]["server"]["digest_set"][
            "aweb-1.26.34-py3-none-any.whl"
        ] = "0" * 64
        self.reseal(document)
        journeys = []

        def factory():
            journeys.append(FakeJourney())
            return journeys[-1]

        with tempfile.TemporaryDirectory() as tmp:
            evidence = skew.evidence_writer_for("channel", Path(tmp))
            harness = skew.ChannelPiHarness(
                resolver=FakeResolver(), journey_factory=factory,
                evidence=evidence,
            )
            with self.assertRaises(rd.ReceiptError):
                skew.measure_support(
                    component="channel",
                    measurement_input=document,
                    measurement_input_bytes=canonical_bytes(document),
                    supported_versions={"server": ["1.26.34"]},
                    published_authority=published_authority(),
                    harness=harness,
                )
            self.assertEqual(journeys, [])
            self.assertFalse((evidence.root / "cells").exists())

    def test_missing_resolver_refuses(self):
        document = measurement_input("channel")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rd.ReceiptError, "must be consumed"):
                skew.measure_support(
                    component="channel",
                    measurement_input=document,
                    measurement_input_bytes=canonical_bytes(document),
                    supported_versions={"server": ["1.26.34"]},
                    harness=skew.ChannelPiHarness(
                        resolver=FakeResolver(), journey_factory=FakeJourney,
                        evidence=skew.evidence_writer_for("channel", Path(tmp)),
                    ),
                )


class PypiLaneValidatorTests(unittest.TestCase):
    """The lane validator remains explicit for candidate-stage callers."""

    def test_stage_only_artifact_refused_when_verify_only_is_requested(self):
        stage, _ = server_lane_zip(mode="stage-only")
        with self.assertRaisesRegex(rd.ReceiptError, "verify-only"):
            rd.validate_pypi_lane_artifact(
                stage, expected_source_sha="c" * 40,
                expected_version="1.26.34", package="server",
                pypi_name="aweb", required_mode="verify-only")

    def test_default_mode_is_unchanged_for_candidate_callers(self):
        body, _ = server_lane_zip()
        with self.assertRaisesRegex(rd.ReceiptError, "stage-only"):
            rd.validate_pypi_lane_artifact(
                body, expected_source_sha="c" * 40,
                expected_version="1.26.34", package="server",
                pypi_name="aweb")


if __name__ == "__main__":
    unittest.main()
