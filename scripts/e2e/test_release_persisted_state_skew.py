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

import release_channel_pi_skew as channel_pi  # noqa: E402
import release_driver as rd  # noqa: E402
import release_persisted_state_skew as skew  # noqa: E402

def fixture_server_lock_bytes(provenance: str, version: str):
    return (
        (SCRIPTS.parent / "server" / "uv.lock").read_bytes(),
        f"fixture-lock:{provenance}",
    )


class FixtureServerLock:
    """Serve the working tree's lock for every version. OPT-IN, per class.

    This harness installs a published wheel and a candidate wheel in one run, so
    their constraints legitimately differ. Fixture versions here are invented
    (1.2.1, 1.2.3), so no tag exists for the published side and the real reader
    correctly refuses it; classes about persisted-state behaviour mix this in
    and stop depending on tag history.

    Opt-in rather than module-wide, because the fake makes both provenances
    resolve the SAME constraints digest - the value the evidence anchors - and
    so hides the divergence per-wheel keying exists to carry. A plain TestCase
    gets the real reader, and ConstraintsPerWheelTests is one.
    """

    def setUp(self):
        super().setUp()
        self._real_server_lock_bytes = channel_pi._server_lock_bytes
        channel_pi._server_lock_bytes = fixture_server_lock_bytes

    def tearDown(self):
        channel_pi._server_lock_bytes = self._real_server_lock_bytes
        super().tearDown()


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

    @staticmethod
    def published_metadata(version="1.2.2", *, wheel=b"published wheel",
                           sdist=b"published sdist", info_version=None,
                           host="https://files.pythonhosted.org",
                           include_sdist=True):
        urls = [{
            "filename": f"aweb-{version}-py3-none-any.whl",
            "packagetype": "bdist_wheel",
            "url": f"{host}/packages/aweb-{version}-py3-none-any.whl",
            "digests": {"sha256": hashlib.sha256(wheel).hexdigest()},
            "yanked": False,
        }]
        if include_sdist:
            urls.append({
                "filename": f"aweb-{version}.tar.gz",
                "packagetype": "sdist",
                "url": f"{host}/packages/aweb-{version}.tar.gz",
                "digests": {"sha256": hashlib.sha256(sdist).hexdigest()},
                "yanked": False,
            })
        return json.dumps({
            "info": {"version": info_version or version},
            "urls": urls,
        }).encode()

    def resolve_published(self, metadata, *, wheel=b"published wheel"):
        requests = []

        def fetch(url):
            requests.append(url)
            return metadata if url.endswith("/json") else wheel

        identity = skew.WheelResolver(pypi_fetch=fetch).resolve(
            "published-latest",
            {"component": "server", "version": "1.2.2"},
            "pypi:aweb",
        )
        return identity, requests

    def test_published_binds_complete_release_set_and_exact_wheel(self):
        wheel = b"published wheel"
        metadata = self.published_metadata(wheel=wheel)
        identity, requests = self.resolve_published(metadata, wheel=wheel)
        self.assertEqual(requests[0], "https://pypi.org/pypi/aweb/1.2.2/json")
        self.assertEqual(identity.sha256, hashlib.sha256(wheel).hexdigest())
        digest_set = identity.source["digest_set"]
        self.assertEqual(len(digest_set), 2, "wheel AND sdist bound")
        self.assertEqual(
            identity.source["canonical_set_digest"],
            rd.canonical_digest_of_set(digest_set),
        )

    def test_published_wrong_info_version_refuses(self):
        metadata = self.published_metadata(info_version="9.9.9")
        with self.assertRaisesRegex(rd.ReceiptError, "info.version"):
            self.resolve_published(metadata)

    def test_published_missing_sdist_refuses(self):
        metadata = self.published_metadata(include_sdist=False)
        with self.assertRaises(rd.ReceiptError):
            self.resolve_published(metadata)

    def test_published_untrusted_url_refuses(self):
        metadata = self.published_metadata(host="https://evil.example")
        with self.assertRaises(rd.ReceiptError):
            self.resolve_published(metadata)

    def test_published_wheel_digest_mismatch_refuses(self):
        metadata = self.published_metadata(wheel=b"published wheel")
        with self.assertRaisesRegex(rd.ReceiptError, "does not equal"):
            self.resolve_published(metadata, wheel=b"different bytes")



def valid_runtime_inventory(aweb_version, extra_locked=()):
    import release_channel_pi_skew as channel_pi

    resolved = channel_pi.server_runtime_constraints(
        channel_pi.CANDIDATE_PROVENANCE, aweb_version)
    digest, constraints = resolved.digest, resolved.constraints
    rows = [{"name": "aweb", "version": aweb_version},
            {"name": "mcp", "version": constraints["mcp"]}]
    for name in extra_locked:
        rows.append({"name": name, "version": constraints[name]})
    distributions = sorted(rows, key=lambda row: row["name"])
    preimage = {
        "constraints_sha256": digest,
        "python_version": "3.12.9",
        "distributions": distributions,
    }
    body = json.dumps(preimage, sort_keys=True, separators=(",", ":")).encode()
    return {"schema": "aweb.server-runtime-inventory.v1", **preimage,
            "sha256": hashlib.sha256(body).hexdigest()}


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
            digest = hashlib.sha256(f"wheel-{version}".encode()).hexdigest()
            digest_set = {
                filename: digest,
                f"aweb-{version}.tar.gz": hashlib.sha256(
                    f"sdist-{version}".encode()).hexdigest(),
            }
            source = {
                "kind": "published",
                "registry": "pypi:aweb",
                "metadata_url": skew.PYPI_METADATA_URL.format(version=version),
                "download_url": (
                    "https://files.pythonhosted.org/packages/" + filename),
                "digest_set": digest_set,
                "canonical_set_digest": rd.canonical_digest_of_set(digest_set),
            }
        return skew.WheelIdentity(
            filename=filename, version=side["version"], sha256=digest,
            bytes=side["version"].encode(), source=source,
        )


class FakeJourney:
    def __init__(self, *, cleanup_fails=False, causal_signal=True):
        self.events = []
        self.cleanup_fails = cleanup_fails
        self.causal_signal = causal_signal

    def new_database(self, cell):
        self.events.append(("database", cell.edge_id))
        return "primary"

    def clone_database(self, database):
        self.events.append(("clone", database))
        return "control"

    @contextmanager
    def serve(self, wheel, database):
        self.events.append(("start", wheel.version, database))
        try:
            yield f"server:{wheel.version}:{database}"
        finally:
            self.events.append(("stop", wheel.version, database))

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

    def runtime_inventory(self, wheel):
        return valid_runtime_inventory(wheel.version)

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


class PublishedAuthorityContractTests(unittest.TestCase):
    """The exact PyPI authority contract landed in .7.3, enforced for EVERY
    release record - reviewer counterexamples included."""

    def metadata(self, *, version="1.2.2", wheel=b"w", sdist=b"s",
                 wheel_url=None, sdist_url=None, wheel_yanked=False,
                 sdist_yanked=False, wheel_name=None, sdist_name=None,
                 wheel_digest=None, drop_yanked=False, extra=None):
        wname = wheel_name or f"aweb-{version}-py3-none-any.whl"
        sname = sdist_name or f"aweb-{version}.tar.gz"
        wrec = {
            "filename": wname, "packagetype": "bdist_wheel",
            "url": wheel_url or f"https://files.pythonhosted.org/packages/{wname}",
            "digests": {"sha256": wheel_digest or hashlib.sha256(wheel).hexdigest()},
            "yanked": wheel_yanked,
        }
        srec = {
            "filename": sname, "packagetype": "sdist",
            "url": sdist_url or f"https://files.pythonhosted.org/packages/{sname}",
            "digests": {"sha256": hashlib.sha256(sdist).hexdigest()},
            "yanked": sdist_yanked,
        }
        if drop_yanked:
            wrec.pop("yanked")
        urls = [wrec, srec] + list(extra or [])
        return json.dumps({"info": {"version": version}, "urls": urls}).encode()

    def resolve(self, metadata, wheel=b"w"):
        def fetch(url):
            return metadata if url.endswith("/json") else wheel
        return skew.WheelResolver(pypi_fetch=fetch).resolve(
            "published-latest",
            {"component": "server", "version": "1.2.2"}, "pypi:aweb")

    def test_complete_exact_release_set_validates(self):
        identity = self.resolve(self.metadata())
        self.assertEqual(len(identity.source["digest_set"]), 2)
        self.assertEqual(
            identity.source["canonical_set_digest"],
            rd.canonical_digest_of_set(identity.source["digest_set"]))

    def test_missing_yanked_field_refuses(self):
        with self.assertRaises(rd.ReceiptError):
            self.resolve(self.metadata(drop_yanked=True))

    def test_yanked_true_refuses(self):
        with self.assertRaises(rd.ReceiptError):
            self.resolve(self.metadata(wheel_yanked=True))

    def test_url_with_query_or_fragment_refuses(self):
        url = ("https://files.pythonhosted.org/packages/"
               "aweb-1.2.2-py3-none-any.whl?variant=other#fragment")
        with self.assertRaises(rd.ReceiptError):
            self.resolve(self.metadata(wheel_url=url))

    def test_url_basename_differing_from_filename_refuses(self):
        url = "https://files.pythonhosted.org/packages/unrelated.tar.gz"
        with self.assertRaises(rd.ReceiptError):
            self.resolve(self.metadata(sdist_url=url))

    def test_non_https_or_wrong_host_refuses(self):
        for url in ("http://files.pythonhosted.org/packages/aweb-1.2.2-py3-none-any.whl",
                    "https://evil.example/packages/aweb-1.2.2-py3-none-any.whl"):
            with self.assertRaises(rd.ReceiptError):
                self.resolve(self.metadata(wheel_url=url))

    def test_uppercase_or_short_digest_refuses(self):
        for digest in ("A" * 64, "ab" * 31):
            with self.assertRaises(rd.ReceiptError):
                self.resolve(self.metadata(wheel_digest=digest))

    def test_unexpected_filenames_refuse(self):
        with self.assertRaises(rd.ReceiptError):
            self.resolve(self.metadata(wheel_name="aweb-9.9.9-py3-none-any.whl"))

    def test_extra_release_record_refuses(self):
        extra = [{
            "filename": "aweb-1.2.2-py2-none-any.whl",
            "packagetype": "bdist_wheel",
            "url": "https://files.pythonhosted.org/packages/aweb-1.2.2-py2-none-any.whl",
            "digests": {"sha256": "c" * 64}, "yanked": False,
        }]
        with self.assertRaises(rd.ReceiptError):
            self.resolve(self.metadata(extra=extra))


class PublishedTypeBindingTests(unittest.TestCase):
    """Reviewer counterexample: swapping ONLY the two packagetype values must
    not let the sdist be selected and fetched as the wheel."""

    def metadata(self, *, swap_types=False, version="1.2.2",
                 wheel=b"w", sdist=b"s"):
        wname = f"aweb-{version}-py3-none-any.whl"
        sname = f"aweb-{version}.tar.gz"
        wtype, stype = ("sdist", "bdist_wheel") if swap_types else (
            "bdist_wheel", "sdist")
        urls = [
            {"filename": wname, "packagetype": wtype,
             "url": f"https://files.pythonhosted.org/packages/{wname}",
             "digests": {"sha256": hashlib.sha256(wheel).hexdigest()},
             "yanked": False},
            {"filename": sname, "packagetype": stype,
             "url": f"https://files.pythonhosted.org/packages/{sname}",
             "digests": {"sha256": hashlib.sha256(sdist).hexdigest()},
             "yanked": False},
        ]
        return json.dumps({"info": {"version": version}, "urls": urls}).encode()

    def resolve(self, metadata):
        fetched = []

        def fetch(url):
            # Serve the CORRECT bytes for each URL, so a digest mismatch can
            # never be what catches the swap: only binding filename to package
            # type can.
            fetched.append(url)
            if url.endswith("/json"):
                return metadata
            return b"s" if url.endswith(".tar.gz") else b"w"
        identity = skew.WheelResolver(pypi_fetch=fetch).resolve(
            "published-latest",
            {"component": "server", "version": "1.2.2"}, "pypi:aweb")
        return identity, fetched

    def test_correct_types_select_the_wheel(self):
        identity, fetched = self.resolve(self.metadata())
        self.assertTrue(identity.filename.endswith(".whl"))
        self.assertTrue(fetched[-1].endswith(".whl"))

    def test_swapped_packagetypes_refuse(self):
        with self.assertRaises(rd.ReceiptError):
            self.resolve(self.metadata(swap_types=True))


class AggregatePublishedIdentityTests(FixtureServerLock, unittest.TestCase):
    """aggregate_support must exact-revalidate the complete published actor
    identity - reviewer tampering counterexamples, each with a recomputed
    self-presented report_id so the digest check cannot mask them."""

    def measured(self, tamper=None):
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
        if tamper is not None:
            target = sorted(matrix_path.parent.glob("cell-*.json"))[0]
            report = json.loads(target.read_text())
            tamper(report)
            report.pop("report_id", None)
            report["report_id"] = rd.canonical_json_digest(report)
            target.write_text(json.dumps(
                report, sort_keys=True, separators=(",", ":")))
        return matrix_path

    def test_untampered_aggregate_succeeds(self):
        skew.aggregate_support(self.measured())

    def test_zeroed_published_sha_refuses(self):
        path = self.measured(
            lambda r: r["published"].__setitem__("sha256", "0" * 64))
        with self.assertRaises(rd.ReceiptError):
            skew.aggregate_support(path)

    def test_unrelated_published_filename_refuses(self):
        path = self.measured(
            lambda r: r["published"].__setitem__("filename", "unrelated.whl"))
        with self.assertRaises(rd.ReceiptError):
            skew.aggregate_support(path)

    def test_unrelated_published_registry_refuses(self):
        def tamper(report):
            report["published"]["source"]["registry"] = "pypi:unrelated"
        with self.assertRaises(rd.ReceiptError):
            skew.aggregate_support(self.measured(tamper))

    def test_unrelated_published_digest_set_refuses(self):
        def tamper(report):
            report["published"]["source"]["digest_set"] = {"x": "0" * 64}
        with self.assertRaises(rd.ReceiptError):
            skew.aggregate_support(self.measured(tamper))

    def test_coherent_multifield_tamper_still_refuses(self):
        """Reviewer's coherent tamper: change the published wheel sha AND its
        digest-set entry, recompute the canonical scalar (and the report id),
        so nothing is internally inconsistent - it must still refuse because
        the frozen published VERSION already has a different exact identity."""
        def tamper(report):
            published = report["published"]
            zeros = "0" * 64
            published["sha256"] = zeros
            published["source"]["digest_set"][published["filename"]] = zeros
            published["source"]["canonical_set_digest"] = (
                rd.canonical_digest_of_set(published["source"]["digest_set"]))
        with self.assertRaises(rd.ReceiptError):
            skew.aggregate_support(self.measured(tamper))

    def test_measurement_binds_published_identities(self):
        measurement = skew.aggregate_support(self.measured())
        self.assertIn("published_identities", measurement)
        identities = measurement["published_identities"]
        self.assertEqual(
            [entry["version"] for entry in identities],
            sorted(entry["version"] for entry in identities),
            "published identities are canonically ordered")
        preimage = {k: v for k, v in measurement.items()
                    if k != "measurement_id"}
        self.assertEqual(measurement["measurement_id"],
                         rd.canonical_json_digest(preimage),
                         "measurement_id binds the published identity bytes")

    def test_canonical_scalar_disagreeing_with_set_refuses(self):
        def tamper(report):
            report["published"]["source"]["canonical_set_digest"] = "0" * 64
        with self.assertRaises(rd.ReceiptError):
            skew.aggregate_support(self.measured(tamper))


class PersistedJourneyTests(FixtureServerLock, unittest.TestCase):
    def test_installed_wheel_is_started_through_its_serve_subcommand(self):
        self.assertEqual(
            skew.server_command(Path("/runtime"), 8123),
            ["/runtime/bin/aweb", "serve", "--host", "127.0.0.1", "--port", "8123"],
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


class RealCausalMatcherTests(unittest.TestCase):
    """The PRODUCTION matcher, never the FakeJourney flag: one exact
    diagnostic entry must bind the HTTP-500 failure to SQLSTATE 42703
    AND messages.subject; JSON logging must not make a conjunct vacuous;
    recorded values are extracted from the entry, never constants."""

    def journey_with_log(self, log_text: str):
        journey = skew.SubprocessPersistedStateJourney()
        self.addCleanup(journey.close)
        log_path = journey._root / "server.log"
        log_path.write_text(log_text)
        journey._current_server_log = log_path
        return journey

    ERROR = RuntimeError("aw: mail send failed: http 500 from server")

    def test_genuine_same_entry_diagnostic_accepts_and_extracts(self):
        log = "\n".join([
            json.dumps({"level": "info", "msg": "mail send",
                        "subject": "skew-marker-1"}),
            json.dumps({"level": "error", "msg": "insert failed",
                        "exc": 'asyncpg.exceptions.UndefinedColumnError: '
                               'column "subject" of relation "messages" '
                               'does not exist', "pgcode": "42703"}),
        ])
        journey = self.journey_with_log(log)
        causal = journey.assert_causal_mail_failure(self.ERROR)
        self.assertEqual(causal["sqlstate"], "42703")
        self.assertEqual(causal["column"], "messages.subject")
        self.assertTrue(causal["entry_sha256"])
        self.assertIn("does not exist", causal["matched_entry"])

    def test_wrong_cause_with_json_subject_keys_refuses(self):
        log = "\n".join([
            json.dumps({"level": "info", "msg": "mail send",
                        "subject": "skew-marker-1"}),
            json.dumps({"level": "error", "msg": "read failed",
                        "exc": 'relation "aweb.conversations" does not '
                               'exist'}),
        ])
        journey = self.journey_with_log(log)
        with self.assertRaisesRegex(rd.ReceiptError, "42703"):
            journey.assert_causal_mail_failure(self.ERROR)

    def test_split_entries_do_not_bind_causally(self):
        log = "\n".join([
            json.dumps({"level": "error", "msg": "other failure",
                        "pgcode": "42703",
                        "exc": 'column "widget" of relation "gadgets" '
                               'does not exist'}),
            json.dumps({"level": "info", "msg": "mail subject noted",
                        "subject": "messages subject text"}),
        ])
        journey = self.journey_with_log(log)
        with self.assertRaisesRegex(rd.ReceiptError, "42703"):
            journey.assert_causal_mail_failure(self.ERROR)

    def test_non_500_client_error_refuses(self):
        log = json.dumps({"level": "error", "pgcode": "42703",
                          "exc": 'column "subject" of relation "messages"'})
        journey = self.journey_with_log(log)
        with self.assertRaisesRegex(rd.ReceiptError, "500"):
            journey.assert_causal_mail_failure(RuntimeError("timeout"))


class RuntimePostureTests(FixtureServerLock, unittest.TestCase):
    """Cells and control bind canonical in-venv distribution inventories;
    only the aweb wheel may differ across compared runtimes."""

    def measured(self, tamper=None):
        document, cells = matrix_document(("1.2.1", "1.2.2"))
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        class InventoryJourney(FakeJourney):
            def runtime_inventory(self, wheel):
                inventory = valid_runtime_inventory(wheel.version)
                if tamper is not None:
                    inventory = tamper(wheel, inventory)
                return inventory

        harness = skew.PersistedStateHarness(
            resolver=FakeResolver(), journey_factory=InventoryJourney,
            evidence_dir=Path(temporary.name),
        )
        matrix_path = harness.freeze_matrix(document)
        for cell in cells:
            harness.run(cell)
        return matrix_path

    def test_cell_reports_bind_validated_runtimes(self):
        matrix_path = self.measured()
        reports = sorted(matrix_path.parent.glob("cell-*.json"))
        report = json.loads(reports[0].read_text())
        self.assertIn("server_runtimes", report)
        self.assertEqual(
            report["server_runtimes"]["candidate"]["distributions"][0]["name"],
            "aweb")

    def test_journey_without_inventory_refuses(self):
        class NoInventoryJourney(FakeJourney):
            runtime_inventory = None

        document, cells = matrix_document()
        with tempfile.TemporaryDirectory() as tmp:
            harness = skew.PersistedStateHarness(
                resolver=FakeResolver(), journey_factory=NoInventoryJourney,
                evidence_dir=Path(tmp),
            )
            harness.freeze_matrix(document)
            with self.assertRaisesRegex(rd.ReceiptError, "inventory"):
                harness.run(cells[0])

    def test_unlocked_distribution_refuses_at_cell_time(self):
        def tamper(wheel, inventory):
            rows = [dict(r) for r in inventory["distributions"]]
            for row in rows:
                if row["name"] == "mcp":
                    row["version"] = "0.0.1"
            preimage = {
                "constraints_sha256": inventory["constraints_sha256"],
                "python_version": inventory["python_version"],
                "distributions": rows,
            }
            body = json.dumps(preimage, sort_keys=True,
                              separators=(",", ":")).encode()
            return {"schema": inventory["schema"], **preimage,
                    "sha256": hashlib.sha256(body).hexdigest()}

        with self.assertRaisesRegex(rd.ReceiptError, "unlocked"):
            self.measured(tamper=tamper)

    def test_aggregate_refuses_dependency_drift(self):
        import release_channel_pi_skew as channel_pi

        constraints = channel_pi.server_runtime_constraints(
            channel_pi.CANDIDATE_PROVENANCE, "1.2.1").constraints
        extra = sorted(n for n in constraints if n != "mcp")[0]

        def tamper(wheel, inventory):
            if wheel.version == "1.2.1":
                return valid_runtime_inventory(
                    wheel.version, extra_locked=(extra,))
            return inventory

        matrix_path = self.measured(tamper=tamper)
        with self.assertRaisesRegex(rd.ReceiptError, "drift"):
            skew.aggregate_support(matrix_path)


class SupportMeasurementTests(FixtureServerLock, unittest.TestCase):
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



class ConstraintsPerWheelTests(unittest.TestCase):
    """This harness installs TWO server wheels in one run, so constraints have
    to be keyed per wheel.

    A plain TestCase, so it runs against the real lock reader. A fixture that
    makes both sides resolve the same constraints cannot see the keying at all,
    which is exactly what FixtureServerLock does for the classes that mix it
    in - so the property has to be covered by a class that does not."""

    def setUp(self):
        self.journey = skew.SubprocessPersistedStateJourney()

    def _wheel(self, version, sha_seed, kind):
        return skew.WheelIdentity(
            filename=f"aweb-{version}-py3-none-any.whl",
            version=version, sha256=sha_seed * 64, bytes=b"",
            source={"kind": kind},
        )

    def test_two_wheels_get_separate_constraints_files_and_digests(self):
        published = self._wheel("1.27.0", "a", "published")
        candidate = self._wheel("1.27.1", "b", "candidate")

        published_path, published_digest = self.journey._constraints_path(published)
        candidate_path, candidate_digest = self.journey._constraints_path(candidate)

        self.assertNotEqual(published_path, candidate_path)
        self.assertNotEqual(
            published_digest, candidate_digest,
            "published 1.27.0 is built under its tag's lock and the candidate "
            "under the working tree's; identical digests would mean one of them "
            "is measured under the other's dependencies",
        )
        self.assertEqual(
            hashlib.sha256(published_path.read_bytes()).hexdigest(),
            published_digest,
        )
        self.assertEqual(
            hashlib.sha256(candidate_path.read_bytes()).hexdigest(),
            candidate_digest,
        )

    def test_the_drift_check_still_fires_within_one_wheel(self):
        """Keying per wheel must not cost the guard it replaces. A constraints
        file that changes under the SAME wheel is still drift."""
        wheel = self._wheel("1.27.0", "c", "published")
        path, _ = self.journey._constraints_path(wheel)
        path.write_bytes(b"tampered==0.0.0\n")

        with self.assertRaisesRegex(rd.ReceiptError, "constraints changed"):
            self.journey._constraints_path(wheel)

    def test_a_published_wheel_with_no_tag_refuses_rather_than_borrowing(self):
        with self.assertRaisesRegex(rd.ReceiptError, "no server-v9.9.9 tag"):
            self.journey._constraints_path(
                self._wheel("9.9.9", "d", "published"))


if __name__ == "__main__":
    unittest.main()
