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
        wheel_identity = skew.WheelResolver(staged_store=store).resolve(
            "candidate", side, "pypi:aweb"
        )
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
            skew.WheelResolver(staged_store=BytesStore(body)).resolve(
                "candidate", base, "pypi:aweb"
            )
        side = {
            **base,
            "lane_ref": {
                "artifact": "gh-artifact:awebai/aweb:17:23",
                "aw_source_sha": "a" * 40,
                "zip_digest": "sha256:" + "0" * 64,
            },
        }
        with self.assertRaisesRegex(rd.ReceiptError, "outer ZIP"):
            skew.WheelResolver(staged_store=BytesStore(body)).resolve(
                "candidate", side, "pypi:aweb"
            )

    def test_published_wheel_comes_from_pypi_metadata_and_digest(self):
        wheel = b"published wheel"
        wheel_sha = hashlib.sha256(wheel).hexdigest()
        metadata = json.dumps({
            "urls": [{
                "filename": "aweb-1.2.2-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "url": "https://files.example/aweb.whl",
                "digests": {"sha256": wheel_sha},
            }]
        }).encode()
        requests = []

        def fetch(url):
            requests.append(url)
            return metadata if url.endswith("/json") else wheel

        identity = skew.WheelResolver(pypi_fetch=fetch).resolve(
            "published-latest",
            {"component": "server", "version": "1.2.2"},
            "pypi:aweb",
        )
        self.assertEqual(requests, [
            "https://pypi.org/pypi/aweb/1.2.2/json",
            "https://files.example/aweb.whl",
        ])
        self.assertEqual(identity.sha256, wheel_sha)
        self.assertEqual(identity.source["registry"], "pypi:aweb")

    def test_published_wheel_digest_mismatch_refuses(self):
        expected = hashlib.sha256(b"expected").hexdigest()
        metadata = json.dumps({
            "urls": [{
                "filename": "aweb-1.2.2-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "url": "https://files.example/aweb.whl",
                "digests": {"sha256": expected},
            }]
        }).encode()

        def fetch(url):
            return metadata if url.endswith("/json") else b"changed"

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
        return skew.WheelIdentity(
            filename=f"aweb-{side['version']}.whl",
            version=side["version"],
            sha256=side["version"].replace(".", "") * 16,
            bytes=side["version"].encode(),
            source={"kind": kind},
        )


class FakeJourney:
    def __init__(self, *, control_fails=True):
        self.events = []
        self.control_fails = control_fails
        self.broken = set()

    def new_database(self, cell):
        self.events.append(("database", cell.edge_id))
        return "primary"

    def clone_database(self, database):
        self.events.append(("clone", database))
        return "control"

    def break_schema(self, database):
        self.events.append(("break", database, "aweb.messages.subject"))
        self.broken.add(database)

    @contextmanager
    def serve(self, wheel, database):
        self.events.append(("start", wheel.version, database))
        try:
            yield f"server:{wheel.version}:{database}"
        finally:
            self.events.append(("stop", wheel.version, database))

    def seed(self, server, cell):
        self.events.append(("seed", server))

    def exercise(self, server, phase, cell):
        self.events.append(("exercise", phase, server))
        database = server.rsplit(":", 1)[-1]
        if database in self.broken and self.control_fails:
            raise RuntimeError("mail journey broke on missing subject")

    def database_identity(self, database):
        identity = {"database": database, "migration_rows_sha256": database * 4}
        self.events.append(("identity", database))
        return identity

    def write_report(self, report):
        self.events.append(("report", report))

    def close(self):
        self.events.append(("close",))


def cell(direction="b-to-a"):
    return rd.SkewCell(
        edge_id="edge-7.4", edge_a="server", edge_b="server",
        journey=JOURNEY,
        artifacts={"a": "pypi:aweb", "b": "pypi:aweb"},
        declared_direction="persisted-state-both", direction=direction,
        a_kind="candidate", b_kind="published-latest",
        a={"component": "server", "version": "1.2.3"},
        b={"component": "server", "version": "1.2.2"},
    )


class PersistedJourneyTests(unittest.TestCase):
    def test_installed_wheel_is_started_through_its_serve_subcommand(self):
        self.assertEqual(
            skew.server_command(Path("/runtime"), 8123),
            ["/runtime/bin/aweb", "serve", "--host", "127.0.0.1", "--port", "8123"],
        )

    def test_published_seed_candidate_migration_and_published_additive_read(self):
        resolver = FakeResolver()
        journey = FakeJourney()
        skew.PersistedStateHarness(resolver=resolver, journey=journey).run(cell())
        starts = [event for event in journey.events if event[0] == "start"]
        self.assertEqual(starts[:3], [
            ("start", "1.2.2", "primary"),
            ("start", "1.2.3", "primary"),
            ("start", "1.2.2", "primary"),
        ])
        exercises = [event[1] for event in journey.events if event[0] == "exercise"]
        self.assertEqual(exercises[:3], [
            "published-seed", "candidate-on-populated", "published-on-upgraded",
        ])
        report = next(event[1] for event in journey.events if event[0] == "report")
        self.assertEqual(report["edge_id"], "edge-7.4")
        self.assertEqual(report["database_seeded"]["database"], "primary")
        self.assertEqual(report["negative_control"]["baseline"], "green")
        self.assertEqual(report["negative_control"]["result"], "red")
        control_baseline = journey.events.index((
            "exercise", "negative-control-baseline", "server:1.2.3:control"
        ))
        mutation = journey.events.index(("break", "control", "aweb.messages.subject"))
        self.assertLess(control_baseline, mutation)
        self.assertEqual(journey.events[-1], ("close",))

    def test_cell_direction_selects_the_exact_first_and_second_wheels(self):
        journey = FakeJourney()
        skew.PersistedStateHarness(
            resolver=FakeResolver(), journey=journey
        ).run(cell(direction="a-to-b"))
        starts = [event for event in journey.events if event[0] == "start"]
        self.assertEqual(starts[:3], [
            ("start", "1.2.3", "primary"),
            ("start", "1.2.2", "primary"),
            ("start", "1.2.3", "primary"),
        ])

    def test_known_breaking_schema_must_make_the_real_journey_red(self):
        journey = FakeJourney(control_fails=False)
        with self.assertRaisesRegex(rd.ReceiptError, "negative control stayed green"):
            skew.PersistedStateHarness(
                resolver=FakeResolver(), journey=journey
            ).run(cell())
        self.assertEqual(journey.events[-1], ("close",))

    def test_refuses_any_other_edge_contract(self):
        wrong = cell()
        wrong = rd.SkewCell(**{
            **wrong.__dict__, "artifacts": {"a": "oci:aweb", "b": "pypi:aweb"}
        })
        with self.assertRaisesRegex(rd.ReceiptError, "exact persisted-state edge"):
            skew.PersistedStateHarness(
                resolver=FakeResolver(), journey=FakeJourney()
            ).run(wrong)


class SupportMeasurementTests(unittest.TestCase):
    @staticmethod
    def report(direction, first_kind, first_version, second_kind, second_version):
        side = lambda kind, version: {
            "kind": kind, "version": version,
            "filename": f"aweb-{version}.whl", "sha256": version * 8,
            "source": {"kind": kind},
        }
        return {
            "schema": "aweb.persisted-state-skew-measurement.v1",
            "edge_id": "edge-7.4",
            "edge": {"a": "server", "b": "server"},
            "journey": JOURNEY,
            "artifacts": {"a": "pypi:aweb", "b": "pypi:aweb"},
            "declared_direction": "persisted-state-both",
            "cell_direction": direction,
            "first": side(first_kind, first_version),
            "second": side(second_kind, second_version),
            "database_seeded": {"database": "aweb"},
            "database_after_transition": {"database": "aweb"},
            "negative_control": {"baseline": "green", "result": "red"},
            "result": "green",
        }

    def test_aggregate_is_the_exact_anchor_body_for_measured_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = [
                self.report("b-to-a", "published-latest", "1.26.34", "candidate", "1.26.35"),
                self.report("a-to-b", "candidate", "1.26.35", "published-latest", "1.26.34"),
                self.report("b-to-a", "published-floor", "1.25.9", "candidate", "1.26.35"),
                self.report("a-to-b", "candidate", "1.26.35", "published-floor", "1.25.9"),
            ]
            for index, report in enumerate(reports):
                (root / f"cell-{index}.json").write_text(
                    json.dumps(report, sort_keys=True, separators=(",", ":"))
                )
            document = skew.aggregate_support(root)
        self.assertEqual(document["edge"], {"a": "server", "b": "server"})
        self.assertEqual(document["direction"], "persisted-state-both")
        self.assertEqual(
            document["supported_versions"]["server"], ["1.25.9", "1.26.34"]
        )
        self.assertEqual(document["candidate"]["version"], "1.26.35")
        self.assertEqual(len(document["evidence"]), 4)

    def test_aggregate_refuses_one_direction_or_a_green_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self.report(
                "b-to-a", "published-latest", "1.26.34", "candidate", "1.26.35"
            )
            (root / "cell-one.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(rd.ReceiptError, "both directions"):
                skew.aggregate_support(root)
            report["cell_direction"] = "a-to-b"
            report["negative_control"]["result"] = "green"
            (root / "cell-two.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(rd.ReceiptError, "red control"):
                skew.aggregate_support(root)

    def test_aggregate_refuses_partial_version_direction_or_mixed_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = [
                self.report("b-to-a", "published-latest", "1.26.34", "candidate", "1.26.35"),
                self.report("a-to-b", "candidate", "1.26.36", "published-latest", "1.26.34"),
            ]
            for index, report in enumerate(reports):
                (root / f"cell-{index}.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(rd.ReceiptError, "one exact candidate"):
                skew.aggregate_support(root)

            reports[1] = self.report(
                "a-to-b", "published-latest", "1.26.34", "candidate", "1.26.35"
            )
            (root / "cell-1.json").write_text(json.dumps(reports[1]))
            with self.assertRaisesRegex(rd.ReceiptError, "both transition orders"):
                skew.aggregate_support(root)


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
