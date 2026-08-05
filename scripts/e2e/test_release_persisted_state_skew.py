#!/usr/bin/env python3
"""Persisted-state version-skew child harness contract tests."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import release_driver as rd  # noqa: E402
import release_persisted_state_skew as skew  # noqa: E402


JOURNEY = (
    "persisted-state fixture (aweb-abbe.7.4): migrate a database created by "
    "the published release; published server against upgraded schema where "
    "rollout is non-atomic"
)


def pypi_release(version="1.2.2", wheel=b"published wheel", sdist=b"published sdist"):
    wheel_name = f"aweb-{version}-py3-none-any.whl"
    sdist_name = f"aweb-{version}.tar.gz"
    records = [
        {
            "filename": wheel_name,
            "packagetype": "bdist_wheel",
            "url": f"https://files.pythonhosted.org/packages/{wheel_name}",
            "digests": {"sha256": hashlib.sha256(wheel).hexdigest()},
            "yanked": False,
        },
        {
            "filename": sdist_name,
            "packagetype": "sdist",
            "url": f"https://files.pythonhosted.org/packages/{sdist_name}",
            "digests": {"sha256": hashlib.sha256(sdist).hexdigest()},
            "yanked": False,
        },
    ]
    return {"info": {"version": version}, "urls": records}, wheel, sdist


def staged_zip(version: str = "1.2.3", source: str = "a" * 40):
    wheel_name = f"aweb-{version}-py3-none-any.whl"
    wheel = b"exact staged wheel"
    sdist_name = f"aweb-{version}.tar.gz"
    sdist = b"exact staged sdist"
    files = {
        wheel_name: hashlib.sha256(wheel).hexdigest(),
        sdist_name: hashlib.sha256(sdist).hexdigest(),
    }
    manifest = {
        "mode": "stage-only",
        "package": "server",
        "source_sha": source,
        "candidate_version": version,
        "files": files,
        "canonical_set_digest": hashlib.sha256(
            json.dumps(files, sort_keys=True).encode()
        ).hexdigest(),
    }
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr(f"dist/{wheel_name}", wheel)
        archive.writestr(f"dist/{sdist_name}", sdist)
    return out.getvalue(), wheel_name, wheel, files, manifest


class BytesStore:
    def __init__(self, body: bytes):
        self.body = body
        self.requests = []

    def get(self, artifact_id: str) -> bytes:
        self.requests.append(artifact_id)
        return self.body


class DigestAuthority:
    def __init__(self, digest: str):
        self.digest = digest
        self.requests = []

    def expected_digest(self, artifact_id: str) -> str:
        self.requests.append(artifact_id)
        return self.digest


class PersistedArtifactTests(unittest.TestCase):
    def test_candidate_preserves_and_verifies_every_staged_identity(self):
        body, wheel_name, wheel, files, manifest = staged_zip()
        store = BytesStore(body)
        side = {
            "component": "server",
            "version": "1.2.3",
            "digest": rd.canonical_digest_of_set(files),
            "digest_set": files,
            "lane_ref": {
                "artifact": "gh-artifact:awebai/aweb:17:23",
                "aw_source_sha": "a" * 40,
                "zip_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
            },
        }
        authority = DigestAuthority(hashlib.sha256(body).hexdigest())
        wheel_identity = skew.WheelResolver(
            staged_store=store, staged_authority=authority
        ).resolve("candidate", side, "pypi:aweb")
        self.assertEqual(authority.requests, [side["lane_ref"]["artifact"]])
        self.assertEqual(store.requests, [side["lane_ref"]["artifact"]])
        self.assertEqual(wheel_identity.bytes, wheel)
        self.assertEqual(wheel_identity.filename, wheel_name)
        self.assertEqual(wheel_identity.sha256, files[wheel_name])
        self.assertEqual(wheel_identity.version, "1.2.3")
        self.assertEqual(wheel_identity.source["source_sha"], "a" * 40)
        self.assertEqual(wheel_identity.source["outer_zip_sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(wheel_identity.source["canonical_set_digest"], manifest["canonical_set_digest"])

    def test_candidate_digest_only_or_changed_zip_refuses(self):
        body, _, _, files, _ = staged_zip()
        base = {
            "component": "server",
            "version": "1.2.3",
            "digest": rd.canonical_digest_of_set(files),
            "digest_set": files,
        }
        with self.assertRaisesRegex(rd.ReceiptError, "lane reference"):
            skew.WheelResolver(
                staged_store=BytesStore(body),
                staged_authority=DigestAuthority(hashlib.sha256(body).hexdigest()),
            ).resolve("candidate", base, "pypi:aweb")
        side = {
            **base,
            "lane_ref": {
                "artifact": "gh-artifact:awebai/aweb:17:23",
                "aw_source_sha": "a" * 40,
                "zip_digest": "sha256:" + "0" * 64,
            },
        }
        with self.assertRaisesRegex(rd.ReceiptError, "authority"):
            skew.WheelResolver(
                staged_store=BytesStore(body),
                staged_authority=DigestAuthority(hashlib.sha256(body).hexdigest()),
            ).resolve("candidate", side, "pypi:aweb")

    def test_candidate_authority_mismatch_refuses_before_store_read(self):
        body, _, _, files, _ = staged_zip()
        store = BytesStore(body)
        side = {
            "component": "server", "version": "1.2.3",
            "digest": rd.canonical_digest_of_set(files), "digest_set": files,
            "lane_ref": {
                "artifact": "gh-artifact:awebai/aweb:17:23",
                "aw_source_sha": "a" * 40,
                "zip_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
            },
        }
        with self.assertRaisesRegex(rd.ReceiptError, "authority"):
            skew.WheelResolver(
                staged_store=store, staged_authority=DigestAuthority("0" * 64)
            ).resolve("candidate", side, "pypi:aweb")
        self.assertEqual(store.requests, [])

    def test_published_wheel_binds_complete_exact_pypi_release(self):
        metadata, wheel, _ = pypi_release()
        wheel_sha = hashlib.sha256(wheel).hexdigest()
        requests = []

        def fetch(url):
            requests.append(url)
            return json.dumps(metadata).encode() if url.endswith("/json") else wheel

        identity = skew.WheelResolver(pypi_fetch=fetch).resolve(
            "published-latest",
            {"component": "server", "version": "1.2.2"},
            "pypi:aweb",
        )
        self.assertEqual(requests, [
            "https://pypi.org/pypi/aweb/1.2.2/json",
            "https://files.pythonhosted.org/packages/aweb-1.2.2-py3-none-any.whl",
        ])
        expected_set = {
            item["filename"]: item["digests"]["sha256"]
            for item in metadata["urls"]
        }
        self.assertEqual(identity.sha256, wheel_sha)
        self.assertEqual(identity.source["registry_digest_set"], expected_set)
        self.assertEqual(
            identity.source["registry_set_digest"],
            rd.canonical_digest_of_set(expected_set),
        )

    def test_published_release_metadata_mutations_refuse(self):
        metadata, wheel, _ = pypi_release()
        mutations = []
        wrong_version = json.loads(json.dumps(metadata))
        wrong_version["info"]["version"] = "9.9.9"
        mutations.append((wrong_version, "info.version"))
        missing_sdist = json.loads(json.dumps(metadata))
        missing_sdist["urls"] = missing_sdist["urls"][:1]
        mutations.append((missing_sdist, "release file set"))
        extra = json.loads(json.dumps(metadata))
        extra["urls"].append({
            "filename": "aweb-1.2.2.zip", "packagetype": "sdist",
            "url": "https://files.pythonhosted.org/packages/aweb-1.2.2.zip",
            "digests": {"sha256": "f" * 64}, "yanked": False,
        })
        mutations.append((extra, "release file set"))
        unsafe = json.loads(json.dumps(metadata))
        unsafe["urls"][0]["url"] = "https://example.invalid/aweb-1.2.2-py3-none-any.whl"
        mutations.append((unsafe, "unsafe"))
        for changed, message in mutations:
            with self.subTest(message=message):
                with self.assertRaisesRegex(rd.ReceiptError, message):
                    skew.WheelResolver(
                        pypi_fetch=lambda url, m=changed: (
                            json.dumps(m).encode() if url.endswith("/json") else wheel
                        )
                    ).resolve(
                        "published-latest",
                        {"component": "server", "version": "1.2.2"},
                        "pypi:aweb",
                    )

    def test_published_wheel_digest_mismatch_refuses(self):
        metadata, _, _ = pypi_release(wheel=b"expected")

        def fetch(url):
            return json.dumps(metadata).encode() if url.endswith("/json") else b"changed"

        with self.assertRaisesRegex(rd.ReceiptError, "does not equal PyPI"):
            skew.WheelResolver(pypi_fetch=fetch).resolve(
                "published-latest",
                {"component": "server", "version": "1.2.2"},
                "pypi:aweb",
            )


class FakeResolver:
    def __init__(self):
        self.calls = []

    def resolve(self, kind, side, locator):
        self.calls.append((kind, side["version"], locator))
        if kind == "candidate":
            filename, digest = next(iter(side["digest_set"].items()))
            lane_ref = side["lane_ref"]
            source = {
                "kind": "candidate",
                "artifact": lane_ref["artifact"],
                "source_sha": lane_ref["aw_source_sha"],
                "outer_zip_sha256": lane_ref["zip_digest"].removeprefix("sha256:"),
                "canonical_set_digest": side["digest"],
                "digest_set": side["digest_set"],
            }
        else:
            version = side["version"]
            filename = f"aweb-{version}-py3-none-any.whl"
            digest = hashlib.sha256(version.encode()).hexdigest()
            digest_set = {
                filename: digest,
                f"aweb-{version}.tar.gz": hashlib.sha256(
                    f"sdist:{version}".encode()
                ).hexdigest(),
            }
            source = {
                "kind": "published",
                "registry": "pypi:aweb",
                "metadata_url": f"https://pypi.org/pypi/aweb/{version}/json",
                "download_url": (
                    f"https://files.pythonhosted.org/packages/{filename}"
                ),
                "registry_digest_set": digest_set,
                "registry_set_digest": rd.canonical_digest_of_set(digest_set),
                "payload_sha256": digest,
            }
        return skew.WheelIdentity(
            filename=filename, version=side["version"], sha256=digest,
            bytes=side["version"].encode(), source=source,
        )


class FakeJourney:
    def __init__(
        self, *, cleanup_fails=False, causal_signal=True,
        dependency_version="4.5.6",
    ):
        self.events = []
        self.cleanup_fails = cleanup_fails
        self.causal_signal = causal_signal
        self.dependency_version = dependency_version
        self._runtime_proofs = []

    def new_database(self, cell):
        self.events.append(("database", cell.edge_id))
        return "primary"

    def clone_database(self, database):
        self.events.append(("clone", database))
        return "control"

    @contextmanager
    def serve(self, wheel, database):
        self.events.append(("start", wheel.version, database))
        inventory = {
            "aweb": wheel.version,
            "fixture-dependency": self.dependency_version,
            "mcp": "1.26.0",
        }
        self._runtime_proofs.append({
            "sequence": len(self._runtime_proofs) + 1,
            "wheel_sha256": wheel.sha256,
            "wheel_version": wheel.version,
            "installed_distributions": inventory,
            "installed_distributions_sha256": rd.canonical_json_digest(inventory),
        })
        try:
            yield f"server:{wheel.version}:{database}"
        finally:
            self.events.append(("stop", wheel.version, database))

    def runtime_proofs(self):
        return list(self._runtime_proofs)

    def seed(self, server, cell):
        self.events.append(("seed", server))

    def published_seed_probe(self, server, cell):
        self.events.append(("published-seed", server))

    def candidate_upgrade_assertion(self, server, cell):
        self.events.append(("candidate-upgrade-focal", server))

    def published_after_upgrade(self, server, cell):
        self.events.append(("published-after-upgrade", server))

    def candidate_prepare_rollback(self, server, cell):
        self.events.append(("candidate-prepares-rollback", server))

    def published_rollback_assertion(self, server, cell):
        self.events.append(("published-rollback-focal", server))

    def mail_control_baseline(self, server, cell):
        self.events.append(("mail-control-green", server))
        return {"conversation_id": "conversation-1"}

    def break_schema(self, database):
        self.events.append(("break", database, "aweb.messages.subject"))

    def mail_control_failure(self, server, cell):
        self.events.append(("mail-control-red", server))
        if self.causal_signal:
            raise RuntimeError(
                'PostgreSQL 42703 UndefinedColumn: column "messages.subject" does not exist'
            )
        raise RuntimeError("unrelated connection failure")

    def assert_causal_mail_failure(self, error):
        text = str(error)
        self.events.append(("causal-check", text))
        if "42703" not in text or "messages.subject" not in text:
            raise rd.ReceiptError("mail failure lacks the causal missing-column signal")
        return {"sqlstate": "42703", "column": "messages.subject"}

    def database_identity(self, database):
        identity = {"database": database, "migration_rows_sha256": database * 4}
        self.events.append(("identity", database))
        return identity

    def close(self):
        self.events.append(("cleanup",))
        if self.cleanup_fails:
            raise rd.ReceiptError("targeted cleanup failed")
        return {
            "targeted_containers_absent": True,
            "processes_exited": True,
            "temp_root_absent": True,
        }


def matrix_document(versions=("1.2.2",)):
    edge = rd.RuntimeContractEdge(
        a="server", b="server", journey=JOURNEY,
        artifacts={"a": "pypi:aweb", "b": "pypi:aweb"},
        direction="persisted-state-both",
        supported={"policy": "additive-only"},
    )
    files = {"aweb-1.2.3.whl": "1" * 64}
    staged = {"server": rd.ReceiptEntry(
        version="1.2.3", digest=rd.canonical_digest_of_set(files),
        digest_set=files,
        lane_ref={
            "artifact": "gh-artifact:awebai/aweb:17:23",
            "aw_source_sha": "a" * 40,
            "zip_digest": "sha256:" + "2" * 64,
        },
    )}
    document = rd.freeze_skew_matrix(
        edge, moving={"server"}, staged=staged,
        support={"supported_versions": {"server": list(versions)}},
        published_versions={"server": versions[-1]},
        staged_manifest_digest="3" * 64,
    )
    return document, rd.validate_skew_matrix_document(document)


class PersistedJourneyTests(unittest.TestCase):
    def test_installed_wheel_is_started_through_its_serve_subcommand(self):
        self.assertEqual(
            skew.server_command(Path("/runtime"), 8123),
            ["/runtime/bin/aweb", "serve", "--host", "127.0.0.1", "--port", "8123"],
        )
        self.assertEqual(
            skew.runtime_install_command(
                Path("/runtime/bin/python"), Path("/wheels/aweb.whl")
            ),
            [
                "uv", "pip", "install", "--python", "/runtime/bin/python",
                "/wheels/aweb.whl", "mcp==1.26.0",
            ],
        )

    def run_direction(self, direction, *, cleanup_fails=False):
        document, cells = matrix_document()
        cell = next(item for item in cells if item.direction == direction)
        journeys = []

        def make_journey():
            journey = FakeJourney(cleanup_fails=cleanup_fails)
            journeys.append(journey)
            return journey

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        harness = skew.PersistedStateHarness(
            resolver=FakeResolver(), journey_factory=make_journey,
            evidence_dir=Path(temporary.name),
        )
        harness.freeze_matrix(document)
        harness.run(cell)
        return document, cell, journeys[0], Path(temporary.name)

    def test_upgrade_direction_has_fixed_temporal_actors_and_candidate_focal(self):
        document, cell, journey, root = self.run_direction("b-to-a")
        starts = [event for event in journey.events if event[0] == "start"]
        self.assertEqual(starts, [
            ("start", "1.2.2", "primary"),
            ("start", "1.2.3", "primary"),
            ("start", "1.2.2", "primary"),
        ])
        self.assertIn(("candidate-upgrade-focal", "server:1.2.3:primary"), journey.events)
        self.assertIn(("published-after-upgrade", "server:1.2.2:primary"), journey.events)
        self.assertNotIn(("published-rollback-focal", "server:1.2.2:primary"), journey.events)
        cleanup = journey.events.index(("cleanup",))
        report_path = root / f"cell-{document['matrix_id']}-{rd.skew_cell_identity(cell)}.json"
        self.assertTrue(report_path.exists())
        report = json.loads(report_path.read_text())
        self.assertEqual(report["focal_actor"], "candidate")
        self.assertEqual(report["matrix_id"], document["matrix_id"])
        self.assertEqual(len(report["runtime_proofs"]), 3)
        self.assertEqual(
            [proof["installed_distributions"]["aweb"]
             for proof in report["runtime_proofs"]],
            ["1.2.2", "1.2.3", "1.2.2"],
        )
        self.assertTrue(all(
            proof["installed_distributions"]["mcp"] == "1.26.0"
            for proof in report["runtime_proofs"]
        ))
        self.assertTrue(report["cleanup"]["targeted_containers_absent"])
        self.assertEqual(journey.events[cleanup], ("cleanup",))

    def test_rollback_direction_has_fixed_temporal_actors_and_published_focal(self):
        _, _, journey, _ = self.run_direction("a-to-b")
        starts = [event for event in journey.events if event[0] == "start"]
        self.assertEqual(starts, [
            ("start", "1.2.2", "primary"),
            ("start", "1.2.3", "primary"),
            ("start", "1.2.2", "primary"),
        ])
        self.assertIn(("candidate-prepares-rollback", "server:1.2.3:primary"), journey.events)
        self.assertIn(("published-rollback-focal", "server:1.2.2:primary"), journey.events)
        self.assertNotIn(("candidate-upgrade-focal", "server:1.2.3:primary"), journey.events)

    def test_refuses_noncanonical_or_candidate_only_cell(self):
        document, cells = matrix_document()
        canonical = cells[0]
        for changes in (
            {"a_kind": "published-latest", "b_kind": "candidate",
             "a": canonical.b, "b": canonical.a},
            {"b_kind": "candidate", "b": canonical.a},
        ):
            wrong = rd.SkewCell(**{**canonical.__dict__, **changes})
            with tempfile.TemporaryDirectory() as tmp:
                harness = skew.PersistedStateHarness(
                    resolver=FakeResolver(), journey_factory=FakeJourney,
                    evidence_dir=Path(tmp),
                )
                harness.freeze_matrix(document)
                with self.assertRaisesRegex(
                    rd.ReceiptError, "frozen persisted matrix|canonical candidate/published"
                ):
                    harness.run(wrong)

    def test_cleanup_failure_writes_no_green_cell(self):
        document, cells = matrix_document()
        with tempfile.TemporaryDirectory() as tmp:
            harness = skew.PersistedStateHarness(
                resolver=FakeResolver(),
                journey_factory=lambda: FakeJourney(cleanup_fails=True),
                evidence_dir=Path(tmp),
            )
            harness.freeze_matrix(document)
            with self.assertRaisesRegex(rd.ReceiptError, "cleanup failed"):
                harness.run(cells[0])
            self.assertEqual(list(Path(tmp).glob("cell-*.json")), [])

    def test_dependency_inventory_must_match_across_cells_and_control(self):
        document, cells = matrix_document()
        versions = iter(("4.5.6", "9.9.9", "8.8.8"))

        def make_journey():
            return FakeJourney(dependency_version=next(versions))

        with tempfile.TemporaryDirectory() as tmp:
            harness = skew.PersistedStateHarness(
                resolver=FakeResolver(), journey_factory=make_journey,
                evidence_dir=Path(tmp),
            )
            harness.freeze_matrix(document)
            harness.run(cells[0])
            with self.assertRaisesRegex(rd.ReceiptError, "dependency resolution"):
                harness.run(cells[1])
            with self.assertRaisesRegex(rd.ReceiptError, "dependency resolution"):
                harness.run_negative_control()
            self.assertEqual(len(list(Path(tmp).glob("cell-*.json"))), 1)
            self.assertEqual(list(Path(tmp).glob("control-*.json")), [])

    def test_negative_control_is_explicit_once_narrow_and_not_support_evidence(self):
        document, _ = matrix_document()
        journeys = []

        def make_journey():
            journey = FakeJourney()
            journeys.append(journey)
            return journey

        with tempfile.TemporaryDirectory() as tmp:
            harness = skew.PersistedStateHarness(
                resolver=FakeResolver(), journey_factory=make_journey,
                evidence_dir=Path(tmp),
            )
            harness.freeze_matrix(document)
            harness.run_negative_control()
            events = journeys[0].events
            self.assertLess(events.index(("mail-control-green", "server:1.2.3:control")),
                            events.index(("break", "control", "aweb.messages.subject")))
            self.assertLess(events.index(("cleanup",)),
                            len(events))
            controls = list(Path(tmp).glob("control-*.json"))
            self.assertEqual(len(controls), 1)
            control = json.loads(controls[0].read_text())
            self.assertEqual(control["causal_signal"]["sqlstate"], "42703")
            self.assertEqual(len(control["runtime_proofs"]), 4)
            self.assertEqual(list(Path(tmp).glob("cell-*.json")), [])

    def test_unrelated_negative_failure_and_cleanup_failure_write_no_control(self):
        document, _ = matrix_document()
        for journey in (
            FakeJourney(causal_signal=False),
            FakeJourney(cleanup_fails=True),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                harness = skew.PersistedStateHarness(
                    resolver=FakeResolver(), journey_factory=lambda j=journey: j,
                    evidence_dir=Path(tmp),
                )
                harness.freeze_matrix(document)
                with self.assertRaises(rd.ReceiptError):
                    harness.run_negative_control()
                self.assertEqual(list(Path(tmp).glob("control-*.json")), [])


class CausalDiagnosticTests(unittest.TestCase):
    def journey_with_log(self, line):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        log = Path(temporary.name) / "server.log"
        log.write_text(line + "\n")
        journey = object.__new__(skew.SubprocessPersistedStateJourney)
        journey._current_server_log = log
        journey._log_handles = []
        return journey

    def test_real_matcher_extracts_exact_undefined_column_entry(self):
        block = "\n".join((
            "2026-08-05 19:48:46 UTC [140] ERROR:  42703: "
            "column m.subject does not exist at character 214",
            "2026-08-05 19:48:46 UTC [140] LOCATION:  errorMissingColumn",
            "2026-08-05 19:48:46 UTC [140] STATEMENT:",
            ' SELECT m.subject FROM "aweb".messages m',
        ))
        signal = self.journey_with_log(block).assert_causal_mail_failure(
            RuntimeError("mail command failed: HTTP 500")
        )
        self.assertEqual(signal["sqlstate"], "42703")
        self.assertEqual(signal["column"], "messages.subject")
        self.assertEqual(signal["diagnostic_column"], "m.subject")
        self.assertEqual(signal["relation"], "aweb.messages")
        self.assertEqual(
            signal["diagnostic_sha256"], hashlib.sha256(block.encode()).hexdigest()
        )

    def test_real_matcher_refuses_wrong_cause_despite_json_subject_key(self):
        line = json.dumps({
            "subject": "ordinary message subject",
            "diagnostic": (
                "relation aweb.conversations does not exist; SQLSTATE 42P01"
            ),
        }, separators=(",", ":"))
        with self.assertRaisesRegex(rd.ReceiptError, "messages.subject/42703"):
            self.journey_with_log(line).assert_causal_mail_failure(
                RuntimeError("mail command failed: HTTP 500")
            )


class SupportMeasurementTests(unittest.TestCase):
    def measured_matrix(self):
        document, cells = matrix_document(("1.2.1", "1.2.2"))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        harness = skew.PersistedStateHarness(
            resolver=FakeResolver(), journey_factory=FakeJourney,
            evidence_dir=Path(temporary.name),
        )
        matrix_path = harness.freeze_matrix(document)
        for cell in cells:
            harness.run(cell)
        return document, cells, matrix_path

    def test_aggregate_consumes_exact_matrix_and_all_report_digests(self):
        document, cells, matrix_path = self.measured_matrix()
        measurement = skew.aggregate_support(matrix_path)
        self.assertEqual(measurement["matrix_id"], document["matrix_id"])
        self.assertEqual(
            measurement["supported_versions"]["server"], ["1.2.1", "1.2.2"]
        )
        self.assertEqual(measurement["candidate"]["version"], "1.2.3")
        self.assertEqual(len(measurement["reports"]), len(cells))
        self.assertTrue(all(item.get("file_sha256") for item in measurement["reports"]))
        preimage = {k: v for k, v in measurement.items() if k != "measurement_id"}
        self.assertEqual(measurement["measurement_id"], rd.canonical_json_digest(preimage))

    def test_aggregate_revalidates_release_set_and_dependency_posture(self):
        document, cells, matrix_path = self.measured_matrix()
        root = matrix_path.parent
        paths = [
            root / (
                f"cell-{document['matrix_id']}-{rd.skew_cell_identity(cell)}.json"
            )
            for cell in cells
        ]
        report = json.loads(paths[0].read_text())
        source = report["published"]["source"]
        source["registry_digest_set"].pop(
            f"aweb-{report['published']['version']}.tar.gz"
        )
        source["registry_set_digest"] = rd.canonical_digest_of_set(
            source["registry_digest_set"]
        )
        report["report_id"] = rd.canonical_json_digest(
            {key: value for key, value in report.items() if key != "report_id"}
        )
        paths[0].write_text(json.dumps(report, sort_keys=True, separators=(",", ":")))
        with self.assertRaisesRegex(rd.ReceiptError, "complete bound PyPI"):
            skew.aggregate_support(matrix_path)

        document, cells, matrix_path = self.measured_matrix()
        root = matrix_path.parent
        path = root / (
            f"cell-{document['matrix_id']}-{rd.skew_cell_identity(cells[0])}.json"
        )
        report = json.loads(path.read_text())
        for proof in report["runtime_proofs"]:
            proof["installed_distributions"]["fixture-dependency"] = "9.9.9"
            proof["installed_distributions_sha256"] = rd.canonical_json_digest(
                proof["installed_distributions"]
            )
        report["report_id"] = rd.canonical_json_digest(
            {key: value for key, value in report.items() if key != "report_id"}
        )
        path.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")))
        with self.assertRaisesRegex(rd.ReceiptError, "dependency resolution"):
            skew.aggregate_support(matrix_path)

    def test_aggregate_refuses_missing_extra_or_wrong_matrix_report(self):
        document, cells, matrix_path = self.measured_matrix()
        root = matrix_path.parent
        first_id = rd.skew_cell_identity(cells[0])
        first_path = root / f"cell-{document['matrix_id']}-{first_id}.json"
        original = first_path.read_bytes()
        first_path.unlink()
        with self.assertRaisesRegex(rd.ReceiptError, "report-file set"):
            skew.aggregate_support(matrix_path)
        first_path.write_bytes(original)
        extra = root / f"cell-{document['matrix_id']}-{'f' * 64}.json"
        extra.write_text("{}")
        with self.assertRaisesRegex(rd.ReceiptError, "report-file set"):
            skew.aggregate_support(matrix_path)
        extra.unlink()
        report = json.loads(first_path.read_text())
        report["matrix_id"] = "0" * 64
        first_path.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")))
        with self.assertRaisesRegex(rd.ReceiptError, "matrix"):
            skew.aggregate_support(matrix_path)
        report["matrix_id"] = document["matrix_id"]
        report["database_seeded"]["database"] = "tampered"
        first_path.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")))
        with self.assertRaisesRegex(rd.ReceiptError, "digest"):
            skew.aggregate_support(matrix_path)


class RegistrationTests(unittest.TestCase):
    def test_exact_journey_is_registered_once(self):
        import release_skew_harnesses as registry

        self.assertEqual(skew.JOURNEY, JOURNEY)
        self.assertIs(registry.REGISTRY[JOURNEY], skew.factory)

    def test_focused_target_is_part_of_the_release_driver_gate(self):
        makefile = (SCRIPTS.parent / "Makefile").read_text()
        self.assertIn("test-release-persisted-state-skew", makefile)
        target = makefile.split("test-release-persisted-state-skew:", 1)[1]
        self.assertIn("test_release_persisted_state_skew.py", target.split("\n\n", 1)[0])
        release_target = makefile.split("test-release-driver:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("test-release-persisted-state-skew", release_target)


if __name__ == "__main__":
    unittest.main()
