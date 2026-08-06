"""Child-harness tests for the federation server/server G5 skew edge."""

from __future__ import annotations

import hashlib
import io
import json
import socket
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import release_driver as rd

try:
    import release_federation_skew as federation
except ModuleNotFoundError:
    federation = None


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def wheel_artifact(version: str, body: bytes, name: str | None = None):
    name = name or f"aweb-{version}-py3-none-any.whl"
    digest_set = {
        name: sha256(body),
        f"aweb-{version}.tar.gz": sha256(f"sdist-{version}".encode()),
    }
    return federation.WheelArtifact(
        name,
        version,
        body,
        sha256(body),
        digest_set,
        rd.canonical_digest_of_set(digest_set),
        version,
    )


def candidate_zip(version="1.26.36", source_sha="c" * 40):
    wheel_name = f"aweb-{version}-py3-none-any.whl"
    wheel = b"candidate-wheel"
    sdist_name = f"aweb-{version}.tar.gz"
    sdist = b"candidate-sdist"
    files = {wheel_name: sha256(wheel), sdist_name: sha256(sdist)}
    manifest = {
        "mode": "stage-only",
        "package": "server",
        "tag": f"server-v{version}",
        "candidate_version": version,
        "source_sha": source_sha,
        "files": files,
        "canonical_set_digest": sha256(json.dumps(files, sort_keys=True).encode()),
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr(f"dist/{wheel_name}", wheel)
        archive.writestr(f"dist/{sdist_name}", sdist)
    return buffer.getvalue(), wheel_name, wheel, files


class Response:
    def __init__(self, data: bytes):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return self.data


@unittest.skipIf(federation is None, "release_federation_skew is not implemented")
class CandidateWheelTests(unittest.TestCase):
    def side(self, zip_bytes, files, *, version="1.26.36"):
        return {
            "component": "server",
            "version": version,
            "digest": rd.canonical_digest_of_set(files),
            "digest_set": files,
            "lane_ref": {
                "artifact": "gh-artifact:awebai/aweb:41:42",
                "aw_source_sha": "c" * 40,
                "zip_digest": "sha256:" + sha256(zip_bytes),
            },
        }

    def test_candidate_uses_separate_store_and_digest_authority(self):
        zip_bytes, wheel_name, wheel, files = candidate_zip()

        class Store:
            calls = []

            def get(self, artifact):
                self.calls.append(artifact)
                return zip_bytes

        class Authority:
            calls = []

            def expected_digest(self, artifact):
                self.calls.append(artifact)
                return sha256(zip_bytes)

        store, authority = Store(), Authority()
        resolver = federation.WheelResolver(store=store, authority=authority)
        resolved = resolver.candidate(self.side(zip_bytes, files))
        self.assertEqual(resolved.name, wheel_name)
        self.assertEqual(resolved.bytes, wheel)
        self.assertEqual(resolved.sha256, sha256(wheel))
        self.assertEqual(store.calls, ["gh-artifact:awebai/aweb:41:42"])
        self.assertEqual(authority.calls, ["gh-artifact:awebai/aweb:41:42"])

    def test_candidate_refuses_authority_or_cell_identity_mismatch(self):
        zip_bytes, _, _, files = candidate_zip()

        class Store:
            def get(self, artifact):
                return zip_bytes

        class BadAuthority:
            def expected_digest(self, artifact):
                return "0" * 64

        with self.assertRaises(rd.ReceiptError):
            federation.WheelResolver(store=Store(), authority=BadAuthority()).candidate(
                self.side(zip_bytes, files)
            )

        class Authority:
            def expected_digest(self, artifact):
                return sha256(zip_bytes)

        side = self.side(zip_bytes, files)
        side["digest_set"] = {**files, "extra.whl": "0" * 64}
        with self.assertRaises(rd.ReceiptError):
            federation.WheelResolver(store=Store(), authority=Authority()).candidate(side)


@unittest.skipIf(federation is None, "release_federation_skew is not implemented")
class PublishedWheelTests(unittest.TestCase):
    def test_published_wheel_is_metadata_bound_and_digest_checked(self):
        wheel = b"published-wheel"
        wheel_url = "https://files.pythonhosted.org/packages/aweb-1.26.35-py3-none-any.whl"
        sdist = b"published-sdist"
        metadata = {
            "info": {"version": "1.26.35"},
            "urls": [{
                "filename": "aweb-1.26.35-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "url": wheel_url,
                "digests": {"sha256": sha256(wheel)},
                "yanked": False,
            }, {
                "filename": "aweb-1.26.35.tar.gz",
                "packagetype": "sdist",
                "url": "https://files.pythonhosted.org/packages/aweb-1.26.35.tar.gz",
                "digests": {"sha256": sha256(sdist)},
                "yanked": False,
            }],
        }
        calls = []

        def opener(request, timeout=0):
            url = request.full_url if hasattr(request, "full_url") else request
            calls.append(url)
            if url == "https://pypi.org/pypi/aweb/1.26.35/json":
                return Response(json.dumps(metadata).encode())
            if url == wheel_url:
                return Response(wheel)
            raise AssertionError(url)

        resolved = federation.WheelResolver(urlopen=opener).published("1.26.35")
        self.assertEqual(resolved.bytes, wheel)
        self.assertEqual(resolved.sha256, sha256(wheel))
        self.assertEqual(resolved.release_digest_set, {
            "aweb-1.26.35-py3-none-any.whl": sha256(wheel),
            "aweb-1.26.35.tar.gz": sha256(sdist),
        })
        self.assertEqual(
            resolved.release_set_digest,
            rd.canonical_digest_of_set(resolved.release_digest_set),
        )
        self.assertEqual(resolved.info_version, "1.26.35")
        self.assertEqual(calls, [
            "https://pypi.org/pypi/aweb/1.26.35/json", wheel_url
        ])

    def test_published_release_set_must_be_complete_nonempty_and_exact(self):
        wheel = b"wheel"
        valid_records = [{
            "filename": "aweb-1.26.35-py3-none-any.whl",
            "packagetype": "bdist_wheel",
            "url": "https://files.pythonhosted.org/aweb-1.26.35-py3-none-any.whl",
            "digests": {"sha256": sha256(wheel)},
            "yanked": False,
        }, {
            "filename": "aweb-1.26.35.tar.gz",
            "packagetype": "sdist",
            "url": "https://files.pythonhosted.org/aweb-1.26.35.tar.gz",
            "digests": {"sha256": "d" * 64},
            "yanked": False,
        }]
        mutations = (
            [],
            valid_records[:1],
            valid_records + [{**valid_records[1], "filename": "extra.tar.gz"}],
            [valid_records[0], valid_records[0]],
        )
        for records in mutations:
            metadata = {"info": {"version": "1.26.35"}, "urls": records}
            with self.subTest(records=records), self.assertRaises(rd.ReceiptError):
                federation.WheelResolver(
                    urlopen=lambda request, timeout=0, value=metadata:
                    Response(json.dumps(value).encode())
                ).published("1.26.35")

    def test_published_urls_and_yanked_flags_are_exact(self):
        wheel_name = "aweb-1.26.35-py3-none-any.whl"
        sdist_name = "aweb-1.26.35.tar.gz"
        valid = [{
            "filename": wheel_name,
            "packagetype": "bdist_wheel",
            "url": f"https://files.pythonhosted.org/packages/{wheel_name}",
            "digests": {"sha256": "a" * 64},
            "yanked": False,
        }, {
            "filename": sdist_name,
            "packagetype": "sdist",
            "url": f"https://files.pythonhosted.org/packages/{sdist_name}",
            "digests": {"sha256": "b" * 64},
            "yanked": False,
        }]
        unsafe_urls = (
            f"https://user:secret@files.pythonhosted.org/packages/{wheel_name}",
            f"https://files.pythonhosted.org:444/packages/{wheel_name}",
            f"https://files.pythonhosted.org/packages/{wheel_name};variant",
            f"https://files.pythonhosted.org/packages/{wheel_name}?variant=other",
            f"https://files.pythonhosted.org/packages/{wheel_name}#fragment",
        )
        mutations = []
        for url in unsafe_urls:
            mutations.append([{**valid[0], "url": url}, valid[1]])
        for yanked in (None, "missing"):
            record = dict(valid[0])
            if yanked == "missing":
                record.pop("yanked")
            else:
                record["yanked"] = None
            mutations.append([record, valid[1]])
        for records in mutations:
            metadata = {"info": {"version": "1.26.35"}, "urls": records}

            calls = []

            def metadata_only(request, timeout=0, value=metadata):
                calls.append(request.full_url)
                if request.full_url == "https://pypi.org/pypi/aweb/1.26.35/json":
                    return Response(json.dumps(value).encode())
                raise AssertionError(f"unsafe metadata reached fetch: {request.full_url}")

            with self.subTest(records=records):
                with self.assertRaises(rd.ReceiptError):
                    federation.WheelResolver(urlopen=metadata_only).published("1.26.35")
                self.assertEqual(calls, ["https://pypi.org/pypi/aweb/1.26.35/json"])

    def test_only_metadata_404_is_classified_as_absence(self):
        def metadata_404(request, timeout=0):
            raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)

        with self.assertRaisesRegex(rd.ReceiptError, "absent"):
            federation.WheelResolver(urlopen=metadata_404).published("1.22.1")

        def metadata_503(request, timeout=0):
            raise urllib.error.HTTPError(request.full_url, 503, "down", {}, None)

        with self.assertRaisesRegex(rd.ReceiptError, "unavailable"):
            federation.WheelResolver(urlopen=metadata_503).published("1.22.1")

    def test_malformed_metadata_and_wheel_failure_block(self):
        for metadata in ({}, {"info": {"version": "other"}, "urls": []}):
            with self.subTest(metadata=metadata):
                with self.assertRaises(rd.ReceiptError):
                    federation.WheelResolver(
                        urlopen=lambda request, timeout=0, m=metadata:
                        Response(json.dumps(m).encode())
                    ).published("1.26.35")

        metadata = {
            "info": {"version": "1.26.35"},
            "urls": [{
                "filename": "aweb-1.26.35-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "url": "https://files.pythonhosted.org/aweb-1.26.35-py3-none-any.whl",
                "digests": {"sha256": "0" * 64},
                "yanked": False,
            }, {
                "filename": "aweb-1.26.35.tar.gz",
                "packagetype": "sdist",
                "url": "https://files.pythonhosted.org/aweb-1.26.35.tar.gz",
                "digests": {"sha256": "1" * 64},
                "yanked": False,
            }],
        }

        def missing_wheel(request, timeout=0):
            if "pypi.org/pypi" in request.full_url:
                return Response(json.dumps(metadata).encode())
            raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)

        with self.assertRaisesRegex(rd.ReceiptError, "wheel download"):
            federation.WheelResolver(urlopen=missing_wheel).published("1.26.35")


@unittest.skipIf(federation is None, "release_federation_skew is not implemented")
class FederationHarnessTests(unittest.TestCase):
    def cell(self, direction="a-to-b"):
        candidate_set = {
            "aweb-1.26.36-py3-none-any.whl": sha256(b"candidate"),
            "aweb-1.26.36.tar.gz": sha256(b"sdist-1.26.36"),
        }
        candidate = {
            "component": "server",
            "version": "1.26.36",
            "digest": rd.canonical_digest_of_set(candidate_set),
            "digest_set": candidate_set,
            "lane_ref": {
                "artifact": "gh-artifact:awebai/aweb:41:42",
                "aw_source_sha": "d" * 40,
                "zip_digest": "sha256:" + "e" * 64,
            },
        }
        return SimpleNamespace(
            edge_id="e" * 64,
            edge_a="server",
            edge_b="server",
            journey=federation.JOURNEY,
            artifacts={"a": "pypi:aweb", "b": "pypi:aweb"},
            declared_direction="both",
            direction=direction,
            a_kind="candidate",
            b_kind="published",
            a=candidate,
            b={"component": "server", "version": "1.26.35", "kind": "published"},
        )

    def wheels(self):
        return {
            "1.26.36": wheel_artifact("1.26.36", b"candidate"),
            "1.26.35": wheel_artifact("1.26.35", b"published"),
        }

    def inventory(self, version, mcp, *, dependency="0.37.2"):
        return {"aweb": version, "mcp": mcp, "starlette": dependency}

    def runtime(self, env, prefix, *, dependency="0.37.2"):
        inventory = self.inventory(
            env[f"AWEB_{prefix}_VERSION"],
            env["AWEB_FED_E2E_MCP_VERSION"],
            dependency=dependency,
        )
        return {
            "version": env[f"AWEB_{prefix}_VERSION"],
            "wheel_sha256": env[f"AWEB_{prefix}_WHEEL_SHA256"],
            "mcp_version": env["AWEB_FED_E2E_MCP_VERSION"],
            "installed_distributions": inventory,
            "installed_distributions_sha256": sha256(
                json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
            ),
        }

    def observation(self, env, **changes):
        value = {
            "schema": federation.OBSERVATION_SCHEMA,
            "cell_id": env["AWEB_FED_E2E_CELL_ID"],
            "initiated_side": "a" if env["AWEB_FED_E2E_DIRECTION"] == "a-to-b" else "b",
            "project": env["AWEB_FED_E2E_PROJECT"],
            "ports": {
                "awid": int(env["AWID_FED_E2E_PORT"]),
                "alpha": int(env["AWEB_ALPHA_E2E_PORT"]),
                "beta": int(env["AWEB_BETA_E2E_PORT"]),
            },
            "alpha": self.runtime(env, "ALPHA"),
            "beta": self.runtime(env, "BETA"),
            "outcomes": dict(federation.REQUIRED_OUTCOMES),
        }
        value.update(changes)
        return federation.OBSERVATION_PREFIX + json.dumps(
            value, sort_keys=True, separators=(",", ":")
        )

    def control_runtime(self, env, *, beta_dependency="0.37.2"):
        value = {
            "alpha": self.runtime(env, "ALPHA"),
            "beta": self.runtime(env, "BETA", dependency=beta_dependency),
            "cell_id": env["AWEB_FED_E2E_CELL_ID"],
            "ports": {
                "awid": int(env["AWID_FED_E2E_PORT"]),
                "alpha": int(env["AWEB_ALPHA_E2E_PORT"]),
                "beta": int(env["AWEB_BETA_E2E_PORT"]),
            },
            "project": env["AWEB_FED_E2E_PROJECT"],
            "schema": federation.CONTROL_RUNTIME_SCHEMA,
        }
        return federation.CONTROL_RUNTIME_PREFIX + json.dumps(
            value, sort_keys=True, separators=(",", ":")
        )

    def prime(self, harness, cells):
        harness._matrix = {"matrix_id": None}
        harness._cells = {rd.skew_cell_identity(cell): cell for cell in cells}
        return harness

    def harness(self, root, journey):
        wheels = self.wheels()

        class Resolver:
            def side(self, value, kind):
                return wheels[value["version"]]

        return federation.FederationSkewHarness(
            resolver=Resolver(), journey=journey, report_dir=Path(root)
        )

    def test_each_cell_binds_full_identity_observation_and_reverses_direction(self):
        calls = []

        def journey(env):
            calls.append(dict(env))
            expected = (
                (b"candidate", b"published")
                if env["AWEB_FED_E2E_DIRECTION"] == "a-to-b"
                else (b"published", b"candidate")
            )
            self.assertEqual(Path(env["AWEB_ALPHA_WHEEL"]).read_bytes(), expected[0])
            self.assertEqual(Path(env["AWEB_BETA_WHEEL"]).read_bytes(), expected[1])
            return SimpleNamespace(
                returncode=0, stdout=self.observation(env) + "\n", stderr=""
            )

        with tempfile.TemporaryDirectory() as tmp:
            cells = [self.cell("a-to-b"), self.cell("b-to-a")]
            harness = self.prime(self.harness(tmp, journey), cells)
            for cell in cells:
                harness.run(cell)
            reports = [
                json.loads((Path(tmp) / "cells" / f"{federation.cell_identity(c)}.json").read_text())
                for c in cells
            ]

        self.assertNotEqual(reports[0]["cell_id"], reports[1]["cell_id"])
        self.assertEqual(reports[0]["cell"], federation.cell_preimage(cells[0]))
        self.assertEqual(reports[1]["cell"], federation.cell_preimage(cells[1]))
        self.assertEqual(
            [(call["AWEB_ALPHA_VERSION"], call["AWEB_BETA_VERSION"]) for call in calls],
            [("1.26.36", "1.26.35"), ("1.26.35", "1.26.36")],
        )
        self.assertNotEqual(calls[0]["AWEB_FED_E2E_PROJECT"], calls[1]["AWEB_FED_E2E_PROJECT"])
        self.assertTrue(all(call["AWEB_FED_E2E_MCP_VERSION"] == "1.26.0" for call in calls))

    def test_success_without_exact_or_untampered_observation_is_red_and_writes_nothing(self):
        mutations = (
            lambda env: "green without evidence",
            lambda env: self.observation(env, cell_id="0" * 64),
            lambda env: self.observation(env, initiated_side="b"),
            lambda env: self.observation(env) + "\n" + self.observation(env),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as tmp:
                harness = self.harness(
                    tmp,
                    lambda env, mutate=mutate: SimpleNamespace(
                        returncode=0, stdout=mutate(env), stderr=""
                    ),
                )
                value = self.cell()
                self.prime(harness, [value])
                with self.assertRaises(rd.ReceiptError):
                    harness.run(value)
                self.assertFalse((Path(tmp) / "cells").exists())

    def test_dependency_only_inventory_mismatch_is_red(self):
        with tempfile.TemporaryDirectory() as tmp:
            def journey(env):
                return SimpleNamespace(
                    returncode=0,
                    stdout=self.observation(
                        env,
                        beta=self.runtime(env, "BETA", dependency="9.9.9"),
                    ),
                    stderr="",
                )

            value = self.cell()
            harness = self.prime(self.harness(tmp, journey), [value])
            with self.assertRaisesRegex(rd.ReceiptError, "dependency"):
                harness.run(value)
            self.assertFalse((Path(tmp) / "cells").exists())

    def test_child_forces_keep_off_despite_ambient_debug_setting(self):
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.dict("os.environ", {"AWEB_FED_E2E_KEEP": "1"}):
            with mock.patch.object(federation.subprocess, "run", return_value=completed) as run:
                federation.run_federation_journey({"EXACT": "value"})
        self.assertEqual(run.call_args.kwargs["env"]["AWEB_FED_E2E_KEEP"], "0")

    def test_nonzero_cell_journey_is_red_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            harness = self.harness(
                tmp,
                lambda env: SimpleNamespace(returncode=3, stdout="bad", stderr="worse"),
            )
            value = self.cell()
            self.prime(harness, [value])
            with self.assertRaisesRegex(rd.ReceiptError, "federation skew journey"):
                harness.run(value)
            self.assertFalse((Path(tmp) / "cells").exists())

    def test_frozen_lifecycle_persists_before_effect_and_finishes_incomplete(self):
        def journey(env):
            return SimpleNamespace(returncode=0, stdout=self.observation(env), stderr="")

        candidate = self.cell().a
        staged = {"server": rd.ReceiptEntry(
            version=candidate["version"], digest=candidate["digest"],
            digest_set=candidate["digest_set"], lane_ref=candidate["lane_ref"],
        )}
        contract = rd.RuntimeContractEdge(
            a="server", b="server", journey=federation.JOURNEY,
            artifacts={"a": "pypi:aweb", "b": "pypi:aweb"},
            direction="both", supported={"policy": "additive-only"},
        )
        document = rd.freeze_skew_matrix(
            contract, moving={"server"}, staged=staged,
            support={"supported_versions": {"server": ["1.26.35"]}},
            published_versions={"server": "1.26.35"},
            staged_manifest_digest="f" * 64,
        )
        cells = rd.validate_skew_matrix_document(document)
        with tempfile.TemporaryDirectory() as tmp:
            harness = self.harness(tmp, journey)
            with self.assertRaisesRegex(rd.ReceiptError, "before.*matrix"):
                harness.run(cells[0])
            matrix_path = harness.freeze_matrix(document)
            self.assertTrue(matrix_path.is_file())
            for value in cells:
                harness.run(value)
            report_paths = sorted((Path(tmp) / "cells").iterdir())
            originals = {path: path.read_bytes() for path in report_paths}
            for index, path in enumerate(report_paths):
                rewritten = json.loads(originals[path])
                token = f"{index + 10:032x}"
                rewritten["observation"]["project"] = f"aweb-fed-e2e-{token}"
                rewritten["observation"]["ports"] = {
                    "awid": federation._token_port(token, 0),
                    "alpha": federation._token_port(token, 1),
                    "beta": federation._token_port(token, 2),
                }
                rewritten["observation_sha256"] = sha256(json.dumps(
                    rewritten["observation"], sort_keys=True, separators=(",", ":")
                ).encode())
                path.write_text(json.dumps(
                    rewritten, sort_keys=True, separators=(",", ":")
                ) + "\n")
            with self.assertRaisesRegex(
                rd.ReceiptError, "effect-time.*digest"
            ):
                harness.finish_matrix(document)
            for path, original in originals.items():
                path.write_bytes(original)
            aggregate_path = harness.finish_matrix(document)
            aggregate = json.loads(aggregate_path.read_text())
            self.assertEqual(aggregate["matrix_id"], document["matrix_id"])
            self.assertEqual(aggregate["status"], "incomplete-unanchored")
            self.assertFalse(aggregate["support_complete"])
            self.assertIsNone(aggregate["anchor"])

    def test_complete_matrix_aggregate_binds_reports_and_one_candidate(self):
        def journey(env):
            return SimpleNamespace(returncode=0, stdout=self.observation(env), stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            cells = [self.cell("a-to-b"), self.cell("b-to-a")]
            harness = self.prime(self.harness(tmp, journey), cells)
            for cell in cells:
                harness.run(cell)
            aggregate = federation.aggregate_cell_reports(cells, Path(tmp))
            self.assertEqual(aggregate["status"], "incomplete-unanchored")
            self.assertEqual(len(aggregate["reports"]), 2)
            self.assertEqual(aggregate["candidate"]["component"], "server")
            self.assertEqual(aggregate["candidate"]["lane_ref"], cells[0].a["lane_ref"])
            self.assertIsNone(aggregate["anchor"])
            self.assertEqual(
                federation.load_aggregate(cells, Path(tmp)), aggregate
            )

            extra = Path(tmp) / "cells" / "extra.json"
            extra.write_text("{}\n")
            with self.assertRaisesRegex(rd.ReceiptError, "file set"):
                federation.load_aggregate(cells, Path(tmp))
            extra.unlink()

            aggregate_path = Path(tmp) / "aggregates" / f"{aggregate['aggregate_id']}.json"
            rewritten = dict(aggregate)
            rewritten["aggregate_id"] = "0" * 64
            aggregate_path.write_text(json.dumps(
                rewritten, sort_keys=True, separators=(",", ":")
            ) + "\n")
            with self.assertRaisesRegex(rd.ReceiptError, "aggregate"):
                federation.load_aggregate(cells, Path(tmp))

    def test_reload_revalidates_cell_report_instead_of_trusting_write_time(self):
        def journey(env):
            return SimpleNamespace(returncode=0, stdout=self.observation(env), stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            cells = [self.cell("a-to-b"), self.cell("b-to-a")]
            harness = self.prime(self.harness(tmp, journey), cells)
            for cell in cells:
                harness.run(cell)
            federation.aggregate_cell_reports(cells, Path(tmp))
            report_path = Path(tmp) / "cells" / f"{federation.cell_identity(cells[0])}.json"
            report = json.loads(report_path.read_text())
            report["observation"]["alpha"]["installed_distributions"]["mcp"] = "0.0.0"
            report["observation_sha256"] = sha256(json.dumps(
                report["observation"], sort_keys=True, separators=(",", ":")
            ).encode())
            report_path.write_text(json.dumps(
                report, sort_keys=True, separators=(",", ":")
            ) + "\n")
            with self.assertRaisesRegex(rd.ReceiptError, "runtime|report"):
                federation.load_aggregate(cells, Path(tmp))

    def test_invocations_reserve_distinct_token_derived_loopback_ports(self):
        first = federation.reserve_invocation(token="0" * 32)
        second = federation.reserve_invocation(token="1" * 32)
        try:
            self.assertNotEqual(first.project, second.project)
            self.assertTrue(set(first.ports).isdisjoint(second.ports))
            for port in first.ports + second.ports:
                probe = socket.socket()
                with self.assertRaises(OSError):
                    probe.bind(("127.0.0.1", port))
                probe.close()
        finally:
            first.release()
            second.release()

    def test_controls_are_one_explicit_measurement_and_never_hidden_in_cells(self):
        versions = []

        class Resolver:
            def published(self, version):
                versions.append(version)
                return wheel_artifact(version, version.encode())

        calls = []

        def control_journey(env):
            calls.append(dict(env))
            if env["AWEB_BETA_VERSION"] == "1.22.1":
                return SimpleNamespace(
                    returncode=1,
                    stdout=(
                        self.control_runtime(env)
                        + "\nbeta federation route probe returned 404"
                    ),
                    stderr="",
                )
            return SimpleNamespace(
                returncode=0,
                stdout=self.control_runtime(env) + "\nroute probe green",
                stderr="",
            )

        with tempfile.TemporaryDirectory() as tmp:
            report = federation.prove_route_controls(
                Resolver(), control_journey, report_dir=Path(tmp)
            )
            self.assertEqual(report["schema"], federation.CONTROL_SCHEMA)
            self.assertIn("installed_distributions", report["controls"]["negative"]["runtime"]["alpha"])
            self.assertTrue((Path(tmp) / "control.json").is_file())
        self.assertEqual(versions, ["1.23.0", "1.22.1"])
        self.assertEqual(len(calls), 2)

        cell_calls = []
        with tempfile.TemporaryDirectory() as tmp:
            harness = self.harness(
                tmp,
                lambda env: cell_calls.append(dict(env)) or SimpleNamespace(
                    returncode=0, stdout=self.observation(env), stderr=""
                ),
            )
            cells = [self.cell("a-to-b"), self.cell("b-to-a")]
            self.prime(harness, cells)
            for value in cells:
                harness.run(value)
        self.assertEqual(len(cell_calls), 2, "ordinary cells must run no historical controls")

    def test_control_dependency_inventories_must_match_across_runtimes_and_runs(self):
        class Resolver:
            def published(self, version):
                return wheel_artifact(version, version.encode())

        def journey(env):
            mismatched = env["AWEB_BETA_VERSION"] == "1.23.0"
            output = self.control_runtime(
                env, beta_dependency="9.9.9" if mismatched else "0.37.2"
            )
            if env["AWEB_BETA_VERSION"] == "1.22.1":
                return SimpleNamespace(
                    returncode=1,
                    stdout=output + "\nbeta federation route probe returned 404",
                    stderr="",
                )
            return SimpleNamespace(returncode=0, stdout=output, stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(rd.ReceiptError, "dependency"):
                federation.prove_route_controls(
                    Resolver(), journey, report_dir=Path(tmp)
                )
            self.assertFalse((Path(tmp) / "control.json").exists())

    def test_negative_control_must_fail_for_the_exact_missing_route(self):
        class Resolver:
            def published(self, version):
                return wheel_artifact(version, b"x")

        with self.assertRaises(rd.ReceiptError):
            federation.prove_route_controls(
                Resolver(),
                lambda env: SimpleNamespace(returncode=0, stdout="false green", stderr=""),
            )


class ParameterizedJourneyContractTests(unittest.TestCase):
    def test_wheel_mode_requires_and_proves_both_exact_runtimes(self):
        script = (REPO_ROOT / "scripts/e2e-oss-federation.sh").read_text()
        dockerfile = (REPO_ROOT / "scripts/federation-wheel-server.Dockerfile").read_text()
        for marker in (
            "AWEB_FED_E2E_SERVER_MODE",
            "AWEB_ALPHA_WHEEL_SHA256",
            "AWEB_BETA_WHEEL_SHA256",
            "alpha installs selected aweb version",
            "beta installs selected aweb version",
            "alpha retains selected wheel sha256",
            "beta retains selected wheel sha256",
        ):
            self.assertIn(marker, script)
        self.assertIn("sha256sum -c", dockerfile)
        self.assertIn("pip install --no-cache-dir", dockerfile)
        self.assertIn("mcp==$MCP_VERSION", dockerfile)
        self.assertNotIn("mcp<2", dockerfile)
        self.assertIn("alpha installs exact locked mcp", script)
        self.assertIn("beta installs exact locked mcp", script)
        self.assertIn("installed_distributions", script)
        self.assertIn("installed_distributions_sha256", script)
        self.assertIn("AWEB_FED_E2E_KEEP", script)
        self.assertNotIn("COPY server/src", dockerfile)

    def test_route_probe_precedes_setup_and_direction_is_evidenced(self):
        script = (REPO_ROOT / "scripts/e2e-oss-federation.sh").read_text()
        self.assertLess(
            script.index("federation route probe returned"),
            script.index("=== Phase 2: Create alpha and beta identities/teams ==="),
        )
        self.assertIn("AWEB_FED_E2E_ROUTE_PROBE_ONLY", script)
        self.assertIn("AWEB_FED_E2E_DIRECTION", script)
        self.assertIn("AWEB_FED_E2E_CELL_ID", script)
        self.assertIn("AWEB_FED_E2E_PROJECT", script)
        self.assertIn("AWEB_FEDERATION_SKEW_OBSERVATION=", script)
        self.assertIn("skew cell direction", script)


class RegistrationAndTargetTests(unittest.TestCase):
    def test_exact_federation_journey_is_registered(self):
        import release_skew_harnesses

        self.assertIn(
            "make test-federation-e2e (both request directions)",
            release_skew_harnesses.REGISTRY,
        )

    def test_focused_make_target_runs_the_child_tests(self):
        makefile = (REPO_ROOT / "Makefile").read_text()
        self.assertIn("test-release-federation-skew:", makefile)
        self.assertIn("test_release_federation_skew.py", makefile)


if __name__ == "__main__":
    unittest.main()
