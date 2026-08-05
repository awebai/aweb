#!/usr/bin/env python3
"""Channel/Pi ↔ server skew child harness contract tests (tmux-free)."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
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
        wheel = b"published wheel"
        wheel_name = "aweb-1.26.34-py3-none-any.whl"
        wheel_url = "https://files.example/aweb.whl"
        metadata_url = "https://pypi.org/pypi/aweb/1.26.34/json"
        metadata = json.dumps({"urls": [{
            "filename": wheel_name,
            "packagetype": "bdist_wheel",
            "url": wheel_url,
            "digests": {"sha256": sha(wheel)},
        }]}).encode()
        resolver = skew.ArtifactResolver(
            pypi_observe=lambda package, version: (200, {wheel_name: sha(wheel)}),
            http_get=lambda url: (200, metadata if url == metadata_url else wheel),
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
            source["registry"] = locator
        if kind == "candidate":
            source.update(
                lane_ref=side["lane_ref"],
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
        }

    def run_client_request(self, client, server, cell):
        self.events.append(("request", client.component, server.component, cell.direction))
        return self.observation(client.component, cell.direction)

    def run_server_event(self, client, server, cell):
        self.events.append(("event", server.component, client.component, cell.direction))
        return self.observation(client.component, cell.direction)

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


class ChildHarnessTests(unittest.TestCase):
    def run_cell(self, value, *, journey=None):
        reports = Reports()
        journey = journey or FakeJourney()
        skew.ChannelPiHarness(
            resolver=FakeResolver(), journey=journey, evidence=reports,
        ).run(value)
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
        self.assertEqual(request["artifacts"], {
            "a": "npm:@awebai/claude-channel", "b": "pypi:aweb",
        })

    def test_required_field_control_is_disposable_exact_and_precontinuation(self):
        journey, report = self.run_cell(cell(
            client="pi", direction="a-to-b",
            a_kind="published-floor", b_kind="candidate",
        ))
        control_event = next(event for event in journey.events if event[0] == "control")
        self.assertEqual(control_event[1], {"up_to_message_id": skew.LEGACY_MESSAGE_ID})
        self.assertEqual(report["negative_control"], {
            "request": {"up_to_message_id": skew.LEGACY_MESSAGE_ID},
            "unmutated_status": 200,
            "mutated_status": 422,
            "mutation_subject": "disposable required-field server",
            "evidence_class": "control-only-not-candidate",
        })
        self.assertNotIn("mutation_subject", report["server_artifact"])

    def test_control_must_be_green_then_422(self):
        for statuses in ((500, 422), (200, 200), (200, 400)):
            with self.assertRaisesRegex(rd.ReceiptError, "200.*422"):
                self.run_cell(
                    cell(a_kind="published-latest", b_kind="candidate"),
                    journey=FakeJourney(control=statuses),
                )

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
            skew.ChannelPiHarness(
                resolver=FakeResolver(), journey=LabelOnlyJourney(), evidence=reports
            ).run(cell())
        self.assertEqual(reports.items, [])

    def test_cleanup_failure_blocks_and_writes_no_green_evidence(self):
        reports = Reports()
        with self.assertRaisesRegex(rd.ReceiptError, "cleanup refused"):
            skew.ChannelPiHarness(
                resolver=FakeResolver(),
                journey=FakeJourney(close_error="cleanup refused"),
                evidence=reports,
            ).run(cell())
        self.assertEqual(reports.items, [])

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
            skew.ChannelPiHarness(
                resolver=RefusingResolver(), journey=journey, evidence=Reports()
            ).run(cell())
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
                skew.ChannelPiHarness(
                    resolver=FakeResolver(), journey=FakeJourney(), evidence=reports,
                ).run(value)
            self.assertEqual(len({item["cell_id"] for item in reports.items}), 10)
            self.assertEqual(
                {item["cell_direction"] for item in reports.items},
                {"a-to-b", "b-to-a"},
            )
            for report in reports.items:
                expected = "request" if report["cell_direction"] == "a-to-b" else "event"
                self.assertEqual(set(report["observation"]), {expected})
            skew.aggregate_support(reports.items, expected_cells=cells)

    def test_one_moving_side_evidences_every_measured_published_version(self):
        cells = self.matrix("channel", {"channel"})
        self.assertEqual(len(cells), 4)
        self.assertEqual(
            {value.b["version"] for value in cells}, {"1.26.33", "1.26.34"}
        )
        reports = Reports()
        for value in cells:
            skew.ChannelPiHarness(
                resolver=FakeResolver(), journey=FakeJourney(), evidence=reports,
            ).run(value)
        self.assertEqual(len(reports.items), 4)


class MeasurementCompletenessTests(unittest.TestCase):
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
        with self.assertRaisesRegex(rd.ReceiptError, "cell preimage"):
            skew.aggregate_support([report], expected_cells=[value])

    def test_aggregate_refuses_mixed_edges_or_missing_required_control(self):
        channel_cell = cell()
        pi_cell = cell(client="pi")
        channel_report = self.report(channel_cell)
        pi_report = self.report(pi_cell)
        with self.assertRaisesRegex(rd.ReceiptError, "one runtime edge"):
            skew.aggregate_support(
                [channel_report, pi_report], expected_cells=[channel_cell, pi_cell]
            )
        controlled_cell = cell(a_kind="published-latest", b_kind="candidate")
        controlled = self.report(controlled_cell)
        controlled["negative_control"] = None
        with self.assertRaisesRegex(rd.ReceiptError, "required-field control"):
            skew.aggregate_support([controlled], expected_cells=[controlled_cell])

    def test_aggregate_recomputes_cell_and_artifact_evidence(self):
        value = cell(direction="a-to-b")
        report = self.report(value)
        report["client_artifact"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(rd.ReceiptError, "artifact.*preimage"):
            skew.aggregate_support([report], expected_cells=[value])

        report = self.report(value)
        report["cell"]["a"]["version"] = "9.9.9"
        with self.assertRaisesRegex(rd.ReceiptError, "cell preimage"):
            skew.aggregate_support([report], expected_cells=[value])


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


if __name__ == "__main__":
    unittest.main()
