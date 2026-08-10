"""Persisted-database version-skew journey for the aweb server wheel.

This module is a child of the release driver's frozen matrix.  It does not
compute cells: it consumes one exact :class:`release_driver.SkewCell`, obtains
the wheel bytes named by that cell, and proves a real populated PostgreSQL
database survives published -> candidate -> published operation. The frozen
cell direction chooses the focal upgrade or non-atomic rollback assertion; it
never reorders those temporal actors.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import release_driver as rd
from release_channel_pi_skew import (
    CANDIDATE_PROVENANCE,
    PUBLISHED_PROVENANCE,
    artifact_provenance,
    server_runtime_constraints,
    validate_server_runtime,
)

JOURNEY = (
    "persisted-state fixture (aweb-abbe.7.4): migrate a database created by "
    "the published release; published server against upgraded schema where "
    "rollout is non-atomic"
)
ARTIFACTS = {"a": "pypi:aweb", "b": "pypi:aweb"}
PUBLISHED_REGISTRY = "pypi:aweb"
PYPI_METADATA_URL = "https://pypi.org/pypi/aweb/{version}/json"
PUBLISHED_REPORT_KEYS = {"kind", "filename", "version", "sha256", "source"}
PUBLISHED_SOURCE_KEYS = {
    "kind", "registry", "metadata_url", "download_url", "digest_set",
    "canonical_set_digest",
}


def expected_wheel_name(version: str) -> str:
    return f"aweb-{version}-py3-none-any.whl"


def expected_sdist_name(version: str) -> str:
    return f"aweb-{version}.tar.gz"


def validate_published_identity(published, *, version: str, label: str) -> dict:
    """One shared validation of a published actor's COMPLETE identity, used by
    the aggregate for every report. Nothing here trusts a self-presented
    report: each field is re-derived from the frozen published version."""
    if not isinstance(published, dict) or set(published) != PUBLISHED_REPORT_KEYS:
        present = set(published) if isinstance(published, dict) else set()
        raise rd.ReceiptError(
            f"{label}: published report keys are not exactly "
            f"{sorted(PUBLISHED_REPORT_KEYS)} (missing "
            f"{sorted(PUBLISHED_REPORT_KEYS - present)}, unexpected "
            f"{sorted(present - PUBLISHED_REPORT_KEYS)})"
        )
    source = published["source"]
    if not isinstance(source, dict) or set(source) != PUBLISHED_SOURCE_KEYS:
        present = set(source) if isinstance(source, dict) else set()
        raise rd.ReceiptError(
            f"{label}: published source keys are not exactly "
            f"{sorted(PUBLISHED_SOURCE_KEYS)} (missing "
            f"{sorted(PUBLISHED_SOURCE_KEYS - present)}, unexpected "
            f"{sorted(present - PUBLISHED_SOURCE_KEYS)})"
        )
    if published["version"] != version:
        raise rd.ReceiptError(
            f"{label}: published version {published['version']!r} is not the "
            f"frozen {version!r}"
        )
    wheel_name = expected_wheel_name(version)
    sdist_name = expected_sdist_name(version)
    if published["filename"] != wheel_name:
        raise rd.ReceiptError(
            f"{label}: published filename {published['filename']!r} is not the "
            f"exact wheel {wheel_name!r}"
        )
    digest_set = source["digest_set"]
    if not isinstance(digest_set, dict) or set(digest_set) != {
        wheel_name, sdist_name
    }:
        raise rd.ReceiptError(
            f"{label}: published digest set is not the exact release set "
            f"{sorted([wheel_name, sdist_name])}"
        )
    for name, digest in digest_set.items():
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise rd.ReceiptError(
                f"{label}: published digest for {name} is not lowercase 64-hex"
            )
    if published["sha256"] != digest_set[wheel_name]:
        raise rd.ReceiptError(
            f"{label}: published sha256 does not equal the digest-set entry "
            "for its own wheel"
        )
    if source["canonical_set_digest"] != rd.canonical_digest_of_set(digest_set):
        raise rd.ReceiptError(
            f"{label}: published canonical scalar does not recompute from its "
            "digest set"
        )
    if source["kind"] != "published" or source["registry"] != PUBLISHED_REGISTRY:
        raise rd.ReceiptError(
            f"{label}: published source kind/registry is not the exact "
            f"published {PUBLISHED_REGISTRY}"
        )
    if source["metadata_url"] != PYPI_METADATA_URL.format(version=version):
        raise rd.ReceiptError(
            f"{label}: published metadata URL is not the exact PyPI metadata "
            f"URL for {version}"
        )
    parsed = urllib.parse.urlparse(source["download_url"] or "")
    if (
        parsed.scheme != "https"
        or parsed.netloc != WheelResolver.PYPI_HOST
        or bool(parsed.params) or bool(parsed.query) or bool(parsed.fragment)
        or Path(urllib.parse.unquote(parsed.path)).name != wheel_name
    ):
        raise rd.ReceiptError(
            f"{label}: published download URL is not an exact extras-free "
            f"{WheelResolver.PYPI_HOST} URL whose basename is {wheel_name!r}"
        )
    return published


@dataclass(frozen=True)
class WheelIdentity:
    filename: str
    version: str
    sha256: str
    bytes: bytes
    source: dict


def _url_bytes(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


class WheelResolver:
    """Resolve exact staged and published server wheels from cell identity."""

    def __init__(
        self, *, staged_store=None, staged_authority=None, pypi_fetch=None
    ):
        self._staged_store = staged_store
        self._staged_authority = staged_authority
        self._pypi_fetch = pypi_fetch or _url_bytes

    def resolve(self, kind: str, side: dict, locator: str) -> WheelIdentity:
        if locator != "pypi:aweb" or side.get("component") != "server":
            raise rd.ReceiptError(
                "persisted-state skew accepts only the declared pypi:aweb "
                f"server artifact, got {locator!r} / {side.get('component')!r}"
            )
        if kind == "candidate":
            return self._candidate(side)
        if kind not in {"published", "published-latest", "published-floor"}:
            raise rd.ReceiptError(
                f"persisted-state skew does not understand side kind {kind!r}"
            )
        return self._published(side)

    def _candidate(self, side: dict) -> WheelIdentity:
        if self._staged_store is None:
            self._staged_store = rd.GithubArtifactStore(
                repo="awebai/aweb",
                workflow_path=".github/workflows/pypi-release.yml",
            )
        if self._staged_authority is None:
            self._staged_authority = rd.GithubArtifactDigestAuthority(
                repo="awebai/aweb",
                workflow_path=".github/workflows/pypi-release.yml",
            )
        lane_data = side.get("lane_ref")
        if lane_data is None:
            raise rd.ReceiptError(
                "candidate wheel requires the unchanged structured lane reference"
            )
        ref = rd.LaneRef.from_dict(lane_data)
        authority_digest = self._staged_authority.expected_digest(ref.artifact)
        if ref.zip_digest != f"sha256:{authority_digest}":
            raise rd.ReceiptError(
                f"candidate digest authority records sha256:{authority_digest}, "
                f"not the frozen LaneRef {ref.zip_digest}"
            )
        outer = self._staged_store.get(ref.artifact)
        outer_sha = hashlib.sha256(outer).hexdigest()
        if ref.zip_digest != f"sha256:{outer_sha}":
            raise rd.ReceiptError(
                f"candidate outer ZIP hash sha256:{outer_sha} does not equal "
                f"the bound {ref.zip_digest}"
            )
        manifest = rd.validate_pypi_lane_artifact(
            outer,
            expected_source_sha=ref.aw_source_sha,
            expected_version=side.get("version"),
            package="server",
            pypi_name="aweb",
        )
        files = manifest["files"]
        if side.get("digest_set") != files:
            raise rd.ReceiptError(
                "candidate wheel manifest file set does not equal the frozen "
                "cell digest_set"
            )
        canonical = rd.canonical_digest_of_set(files)
        if side.get("digest") != canonical:
            raise rd.ReceiptError(
                f"candidate canonical digest {canonical} does not equal the "
                f"frozen cell digest {side.get('digest')!r}"
            )
        wheels = [name for name in files if name.endswith(".whl")]
        if len(wheels) != 1:
            raise rd.ReceiptError(
                f"candidate lane binds {len(wheels)} wheels, expected exactly one"
            )
        filename = wheels[0]
        with zipfile.ZipFile(io.BytesIO(outer)) as archive:
            wheel = archive.read(f"dist/{filename}")
        wheel_sha = hashlib.sha256(wheel).hexdigest()
        if wheel_sha != files[filename]:
            raise rd.ReceiptError(
                f"candidate wheel hash {wheel_sha} does not equal the staged "
                f"manifest digest {files[filename]}"
            )
        return WheelIdentity(
            filename=filename,
            version=side["version"],
            sha256=wheel_sha,
            bytes=wheel,
            source={
                "kind": "candidate",
                "artifact": ref.artifact,
                "source_sha": ref.aw_source_sha,
                "outer_zip_sha256": outer_sha,
                "canonical_set_digest": manifest["canonical_set_digest"],
                "digest_set": dict(files),
            },
        )

    # NOTE (aweb-abbe.8 consolidation): this is the same exact PyPI authority
    # contract landed with .7.3 in release_federation_skew. It is inlined here
    # because that copy lives inside a method rather than a shared helper;
    # .8 should hoist ONE definition and have both children call it.
    PYPI_HOST = "files.pythonhosted.org"

    @classmethod
    def _validate_release_record(cls, record, version: str) -> tuple[str, str]:
        if not isinstance(record, dict):
            raise rd.ReceiptError(
                f"PyPI aweb {version} has malformed release file metadata"
            )
        name = record.get("filename")
        package_type = record.get("packagetype")
        digest = (record.get("digests") or {}).get("sha256")
        url = record.get("url")
        parsed = urllib.parse.urlparse(url or "")
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or package_type not in {"bdist_wheel", "sdist"}
            or record.get("yanked") is not False
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or parsed.scheme != "https"
            or parsed.netloc != cls.PYPI_HOST
            or bool(parsed.params)
            or bool(parsed.query)
            or bool(parsed.fragment)
            or Path(urllib.parse.unquote(parsed.path)).name != name
        ):
            raise rd.ReceiptError(
                f"PyPI aweb {version} has invalid release record {record!r}"
            )
        return name, digest

    def _published(self, side: dict) -> WheelIdentity:
        version = side.get("version")
        if not isinstance(version, str) or not version:
            raise rd.ReceiptError("published server side has no version")
        metadata_url = f"https://pypi.org/pypi/aweb/{version}/json"
        try:
            metadata = json.loads(self._pypi_fetch(metadata_url))
        except (json.JSONDecodeError, TypeError) as exc:
            raise rd.ReceiptError(
                f"PyPI metadata for aweb {version} is not valid JSON"
            ) from exc
        info_version = (metadata.get("info") or {}).get("version")
        if info_version != version:
            raise rd.ReceiptError(
                f"PyPI metadata info.version {info_version!r} does not equal "
                f"the requested version {version}"
            )
        records = metadata.get("urls")
        if not isinstance(records, list) or not records:
            raise rd.ReceiptError(
                f"PyPI aweb {version} release file set is empty"
            )
        digest_set: dict[str, str] = {}
        by_type: dict[str, list] = {}
        for record in records:
            name, digest = self._validate_release_record(record, version)
            if name in digest_set:
                raise rd.ReceiptError(
                    f"PyPI aweb {version} repeats release filename {name}"
                )
            digest_set[name] = digest
            by_type.setdefault(record["packagetype"], []).append(record)
        expected_names = {
            f"aweb-{version}-py3-none-any.whl",
            f"aweb-{version}.tar.gz",
        }
        if set(digest_set) != expected_names or set(by_type) != {
            "bdist_wheel", "sdist"
        }:
            raise rd.ReceiptError(
                f"PyPI aweb {version} release file set is not exact: got "
                f"{sorted(digest_set)}, expected {sorted(expected_names)}"
            )
        if len(by_type["bdist_wheel"]) != 1 or len(by_type["sdist"]) != 1:
            raise rd.ReceiptError(
                f"PyPI aweb {version} must bind exactly one wheel and one sdist"
            )
        # Filename is bound to package TYPE, not just present in the set:
        # swapping only the two packagetype values would otherwise select and
        # fetch the sdist as the wheel.
        wheel_name = expected_wheel_name(version)
        sdist_name = expected_sdist_name(version)
        if (
            by_type["bdist_wheel"][0]["filename"] != wheel_name
            or by_type["sdist"][0]["filename"] != sdist_name
        ):
            raise rd.ReceiptError(
                f"PyPI aweb {version} package types do not bind their exact "
                f"filenames: bdist_wheel is "
                f"{by_type['bdist_wheel'][0]['filename']!r}, sdist is "
                f"{by_type['sdist'][0]['filename']!r}"
            )
        item = by_type["bdist_wheel"][0]
        filename = item["filename"]
        expected = digest_set[filename]
        body = self._pypi_fetch(item["url"])
        actual = hashlib.sha256(body).hexdigest()
        if actual != expected:
            raise rd.ReceiptError(
                f"published wheel hash {actual} does not equal PyPI's {expected}"
            )
        return WheelIdentity(
            filename=filename,
            version=version,
            sha256=actual,
            bytes=body,
            source={
                "kind": "published",
                "registry": "pypi:aweb",
                "metadata_url": metadata_url,
                "download_url": item["url"],
                "digest_set": dict(digest_set),
                "canonical_set_digest": rd.canonical_digest_of_set(digest_set),
            },
        )



class PersistedStateHarness:
    """Consume one coordinator-frozen persisted matrix without inference."""

    def __init__(
        self, *, resolver: WheelResolver, journey=None, journey_factory=None,
        evidence_dir: Path | None = None,
    ):
        if (journey is None) == (journey_factory is None):
            raise TypeError("provide exactly one of journey or journey_factory")
        self._resolver = resolver
        self._fixed_journey = journey
        self._journey_factory = journey_factory
        configured = os.getenv("AWEB_PERSISTED_SKEW_EVIDENCE_DIR")
        self._evidence_dir = Path(evidence_dir or configured or (
            Path(tempfile.gettempdir()) / "aweb-persisted-skew-evidence"
        )).resolve()
        self._evidence_dir.mkdir(parents=True, exist_ok=True)
        self._matrix: dict | None = None
        self._cells: dict[str, rd.SkewCell] = {}
        self._control_path: Path | None = None

    def _new_journey(self):
        if self._fixed_journey is not None:
            journey, self._fixed_journey = self._fixed_journey, None
            return journey
        return self._journey_factory()

    @staticmethod
    def _atomic_json(path: Path, document: dict) -> Path:
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(body)
        os.replace(temporary, path)
        return path

    def freeze_matrix(self, document) -> Path:
        cells = rd.validate_skew_matrix_document(document)
        edge = document["preimage"]["edge"]
        if (
            edge != {
                "a": "server", "b": "server", "journey": JOURNEY,
                "artifacts": ARTIFACTS, "direction": "persisted-state-both",
            }
            or any(
                cell.a_kind != "candidate"
                or not cell.b_kind.startswith("published")
                for cell in cells
            )
        ):
            raise rd.ReceiptError(
                "persisted-state child accepts only its exact canonical "
                "candidate/published frozen matrix"
            )
        if self._matrix is not None and self._matrix != document:
            raise rd.ReceiptError("persisted-state child was given two matrices")
        self._matrix = json.loads(json.dumps(document))
        self._cells = {rd.skew_cell_identity(cell): cell for cell in cells}
        path = self._evidence_dir / f"matrix-{document['matrix_id']}.json"
        if path.exists() and json.loads(path.read_bytes()) != document:
            raise rd.ReceiptError("matrix evidence path contains different bytes")
        return self._atomic_json(path, document)

    def _validate_cell(self, cell) -> str:
        if self._matrix is None:
            raise rd.ReceiptError("persisted-state cell arrived before its matrix")
        cell_id = rd.skew_cell_identity(cell)
        expected = self._cells.get(cell_id)
        if expected != cell:
            raise rd.ReceiptError(
                "cell is not an exact member of the frozen persisted matrix"
            )
        if (
            cell.journey != JOURNEY
            or cell.edge_a != "server"
            or cell.edge_b != "server"
            or cell.artifacts != ARTIFACTS
            or cell.declared_direction != "persisted-state-both"
            or cell.direction not in {"a-to-b", "b-to-a"}
            or cell.a_kind != "candidate"
            or not cell.b_kind.startswith("published")
        ):
            raise rd.ReceiptError(
                "persisted-state cell is not the canonical candidate/published "
                f"layout: {cell!r}"
            )
        return cell_id

    def _cleanup(self, journey, operation_error=None) -> dict:
        try:
            cleanup = journey.close()
        except Exception as cleanup_error:
            if operation_error is not None:
                raise rd.ReceiptError(
                    f"targeted cleanup failed after journey error: {cleanup_error}"
                ) from operation_error
            raise
        if not isinstance(cleanup, dict) or not all((
            cleanup.get("targeted_containers_absent"),
            cleanup.get("processes_exited"), cleanup.get("temp_root_absent"),
        )):
            raise rd.ReceiptError(
                f"targeted cleanup returned incomplete proof: {cleanup!r}"
            )
        return cleanup

    def run(self, cell) -> None:
        cell_id = self._validate_cell(cell)
        candidate = self._resolver.resolve(
            cell.a_kind, cell.a, cell.artifacts["a"]
        )
        published = self._resolver.resolve(
            cell.b_kind, cell.b, cell.artifacts["b"]
        )
        journey = self._new_journey()
        report = None
        operation_error = None
        try:
            database = journey.new_database(cell)
            with journey.serve(published, database) as server:
                journey.seed(server, cell)
                journey.published_seed_probe(server, cell)
            seeded = journey.database_identity(database)

            with journey.serve(candidate, database) as server:
                if cell.direction == "b-to-a":
                    journey.candidate_upgrade_assertion(server, cell)
                else:
                    journey.candidate_prepare_rollback(server, cell)
            after_candidate = journey.database_identity(database)

            with journey.serve(published, database) as server:
                if cell.direction == "a-to-b":
                    journey.published_rollback_assertion(server, cell)
                else:
                    journey.published_after_upgrade(server, cell)
            after_published = journey.database_identity(database)

            report = {
                "schema": "aweb.persisted-state-skew-cell.v2",
                "matrix_id": self._matrix["matrix_id"],
                "cell_id": cell_id,
                "cell": rd.skew_cell_preimage(cell),
                "candidate": self._wheel_report(candidate, cell.a_kind),
                "published": self._wheel_report(published, cell.b_kind),
                "server_runtimes": self._validated_runtimes(
                    journey, candidate, published
                ),
                "chronology": ["published", "candidate", "published"],
                "focal_actor": (
                    "candidate" if cell.direction == "b-to-a" else "published"
                ),
                "database_seeded": seeded,
                "database_after_candidate": after_candidate,
                "database_after_published": after_published,
                "result": "green",
            }
        except Exception as exc:
            operation_error = exc
        cleanup = self._cleanup(journey, operation_error)
        if operation_error is not None:
            raise operation_error
        report["cleanup"] = cleanup
        report["report_id"] = rd.canonical_json_digest(report)
        path = self._evidence_dir / (
            f"cell-{self._matrix['matrix_id']}-{cell_id}.json"
        )
        self._atomic_json(path, report)

    def finish_matrix(self, document) -> Path:
        if document != self._matrix:
            raise rd.ReceiptError("finish request does not equal the frozen matrix")
        if self._control_path is not None:
            raise rd.ReceiptError("persisted-state negative control ran more than once")
        self._control_path = self.run_negative_control()
        return self._control_path

    def run_negative_control(self) -> Path:
        if self._matrix is None:
            raise rd.ReceiptError("negative control requires a frozen matrix")
        latest = [
            cell for cell in self._cells.values()
            if cell.b_kind == "published-latest" and cell.direction == "b-to-a"
        ]
        if len(latest) != 1:
            raise rd.ReceiptError(
                "negative control requires one exact latest published/candidate cell"
            )
        cell = latest[0]
        candidate = self._resolver.resolve(
            cell.a_kind, cell.a, cell.artifacts["a"]
        )
        published = self._resolver.resolve(
            cell.b_kind, cell.b, cell.artifacts["b"]
        )
        journey = self._new_journey()
        operation_error = None
        report = None
        try:
            database = journey.new_database(cell)
            with journey.serve(published, database) as server:
                journey.seed(server, cell)
                journey.published_seed_probe(server, cell)
            with journey.serve(candidate, database) as server:
                journey.candidate_prepare_rollback(server, cell)
            control = journey.clone_database(database)
            with journey.serve(candidate, control) as server:
                baseline = journey.mail_control_baseline(server, cell)
            journey.break_schema(control)
            failure = None
            with journey.serve(candidate, control) as server:
                try:
                    journey.mail_control_failure(server, cell)
                except Exception as exc:
                    failure = exc
            if failure is None:
                raise rd.ReceiptError(
                    "known-breaking messages.subject control stayed green"
                )
            causal = journey.assert_causal_mail_failure(failure)
            report = {
                "schema": "aweb.persisted-state-skew-control.v1",
                "matrix_id": self._matrix["matrix_id"],
                "candidate": self._wheel_report(candidate, cell.a_kind),
                "published": self._wheel_report(published, cell.b_kind),
                "server_runtimes": self._validated_runtimes(
                    journey, candidate, published
                ),
                "baseline": baseline,
                "mutation": "ALTER TABLE aweb.messages DROP COLUMN subject",
                "causal_signal": causal,
                "result": "red-as-required",
            }
        except Exception as exc:
            operation_error = exc
        cleanup = self._cleanup(journey, operation_error)
        if operation_error is not None:
            raise operation_error
        report["cleanup"] = cleanup
        report["report_id"] = rd.canonical_json_digest(report)
        path = self._evidence_dir / f"control-{self._matrix['matrix_id']}.json"
        return self._atomic_json(path, report)

    @staticmethod
    def _validated_runtimes(journey, candidate: WheelIdentity,
                            published: WheelIdentity) -> dict:
        runtime_of = getattr(journey, "runtime_inventory", None)
        if runtime_of is None:
            raise rd.ReceiptError(
                "journey provides no in-service runtime inventory; wheel "
                "bytes alone do not define a reproducible runtime posture"
            )
        runtimes = {}
        for label, wheel in (("candidate", candidate),
                             ("published", published)):
            inventory = runtime_of(wheel)
            validate_server_runtime(
                inventory, artifact_provenance(wheel), wheel.version)
            runtimes[label] = inventory
        return runtimes

    @staticmethod
    def _wheel_report(wheel: WheelIdentity, kind: str) -> dict:
        return {
            "kind": kind,
            "filename": wheel.filename,
            "version": wheel.version,
            "sha256": wheel.sha256,
            "source": dict(wheel.source),
        }


def factory():
    return PersistedStateHarness(
        resolver=WheelResolver(), journey_factory=SubprocessPersistedStateJourney
    )


def server_command(venv: Path, port: int) -> list[str]:
    return [
        str(venv / "bin" / "aweb"), "serve", "--host", "127.0.0.1",
        "--port", str(port),
    ]


class SubprocessPersistedStateJourney:
    """Run exact wheel processes over one isolated real OSS stack.

    PostgreSQL and Redis are disposable named Docker containers.  AWID and the
    Go CLI are the checked-in journey dependencies; only the aweb server is
    varied, and it always runs from the wheel bytes resolved from the cell.
    """

    def __init__(self):
        self._repo = Path(__file__).resolve().parents[1]
        self._root = Path(tempfile.mkdtemp(prefix="aweb-persisted-skew-"))
        suffix = uuid.uuid4().hex[:10]
        self._postgres = f"aweb-skew-pg-{suffix}"
        self._redis = f"aweb-skew-redis-{suffix}"
        self._postgres_port = self._free_port()
        self._redis_port = self._free_port()
        self._awid_port = self._free_port()
        self._aweb_port = self._free_port()
        self._processes: list[subprocess.Popen] = []
        self._server_exit_codes: list[int] = []
        self._containers: list[str] = []
        self._log_handles = []
        self._installed: dict[str, Path] = {}
        self._runtime_inventories: dict[str, dict] = {}
        self._markers: list[str] = []
        self._mail_conversation: str | None = None
        self._counter = 0
        self._started = False
        self._current_database: str | None = None
        self._current_server_log: Path | None = None
        self._closed_proof: dict | None = None

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    @property
    def _database_url(self) -> str:
        database = self._current_database or "aweb"
        return (
            f"postgresql://aweb:aweb-skew@127.0.0.1:"
            f"{self._postgres_port}/{database}"
        )

    @property
    def _awid_database_url(self) -> str:
        return (
            f"postgresql://aweb:aweb-skew@127.0.0.1:"
            f"{self._postgres_port}/awid"
        )

    @property
    def _redis_url(self) -> str:
        return f"redis://127.0.0.1:{self._redis_port}/0"

    @property
    def _awid_url(self) -> str:
        return f"http://127.0.0.1:{self._awid_port}"

    @property
    def _aweb_url(self) -> str:
        return f"http://127.0.0.1:{self._aweb_port}"

    def _run(self, argv, *, cwd=None, env=None, input_bytes=None):
        result = subprocess.run(
            [str(item) for item in argv], cwd=cwd, env=env,
            input=input_bytes, capture_output=True,
        )
        if result.returncode != 0:
            raise rd.ReceiptError(
                f"persisted-state command failed ({' '.join(map(str, argv))}): "
                + result.stderr.decode(errors="replace")[-2000:]
            )
        return result.stdout

    def _docker(self, *args):
        return self._run(["docker", *args])

    def _wait_postgres(self) -> None:
        for _ in range(60):
            result = subprocess.run(
                ["docker", "exec", self._postgres, "pg_isready", "-U", "aweb"],
                capture_output=True,
            )
            if result.returncode == 0:
                return
            time.sleep(1)
        raise rd.ReceiptError("throwaway PostgreSQL did not become ready")

    @staticmethod
    def _wait_http(url: str, process=None) -> None:
        last = None
        for _ in range(90):
            if process is not None and process.poll() is not None:
                raise rd.ReceiptError(
                    f"server process exited {process.returncode} before {url}"
                )
            try:
                with urllib.request.urlopen(url, timeout=2) as response:
                    if response.status == 200:
                        return
            except Exception as exc:  # readiness records the last concrete error
                last = exc
            time.sleep(1)
        raise rd.ReceiptError(f"service at {url} did not become healthy: {last}")

    def _start_infrastructure(self) -> None:
        if self._started:
            return
        self._docker(
            "run", "--rm", "-d", "--name", self._postgres,
            "-e", "POSTGRES_USER=aweb",
            "-e", "POSTGRES_PASSWORD=aweb-skew",
            "-e", "POSTGRES_DB=postgres",
            "-p", f"127.0.0.1:{self._postgres_port}:5432",
            "postgres:17-alpine",
        )
        self._containers.append(self._postgres)
        self._docker(
            "run", "--rm", "-d", "--name", self._redis,
            "-p", f"127.0.0.1:{self._redis_port}:6379",
            "redis:7-alpine",
        )
        self._containers.append(self._redis)
        self._wait_postgres()
        self._docker("exec", self._postgres, "createdb", "-U", "aweb", "aweb")
        self._docker("exec", self._postgres, "createdb", "-U", "aweb", "awid")
        awid_log = open(self._root / "awid.log", "wb")
        self._log_handles.append(awid_log)
        awid_env = {
            **os.environ,
            "AWID_DATABASE_URL": self._awid_database_url,
            "AWID_REDIS_URL": self._redis_url,
            "AWID_HOST": "127.0.0.1",
            "AWID_PORT": str(self._awid_port),
            "AWID_SKIP_DNS_VERIFY": "1",
            "AWID_ALLOW_INSECURE_DELIVERY_ORIGIN": "1",
            "AWID_RATE_LIMIT_DISABLED": "1",
            "APP_ENV": "development",
        }
        process = subprocess.Popen(
            ["uv", "run", "--frozen", "awid", "--host", "127.0.0.1",
             "--port", str(self._awid_port)],
            cwd=self._repo / "awid", env=awid_env,
            stdout=awid_log, stderr=subprocess.STDOUT,
        )
        self._processes.append(process)
        self._wait_http(f"{self._awid_url}/health", process)
        self._run(["make", "build"], cwd=self._repo / "cli" / "go")
        (self._root / "home" / ".config" / "aw").mkdir(parents=True)
        (self._root / "alice").mkdir()
        (self._root / "bob").mkdir()
        self._started = True

    def new_database(self, cell):
        self._start_infrastructure()
        return "aweb"

    def _constraints_path(self, wheel: WheelIdentity) -> tuple[Path, str]:
        """Keyed per wheel, like _installed, because this harness measures TWO
        server artifacts in one run and their constraints legitimately differ -
        the published wheel's come from its tag, the candidate's from the tree.
        One file per run would make that disagreement fire the drift check
        below, whose message says the opposite of what happened. Within a wheel
        the check still means what it always did."""
        resolved = server_runtime_constraints(
            artifact_provenance(wheel), wheel.version)
        path = self._root / wheel.sha256 / "server-runtime-constraints.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(resolved.body)
        if hashlib.sha256(path.read_bytes()).hexdigest() != resolved.digest:
            raise rd.ReceiptError(
                "server runtime constraints changed while materializing"
            )
        return path, resolved.digest

    def _install(self, wheel: WheelIdentity) -> Path:
        existing = self._installed.get(wheel.sha256)
        if existing is not None:
            return existing
        wheel_path = self._root / wheel.sha256 / wheel.filename
        wheel_path.parent.mkdir(parents=True)
        wheel_path.write_bytes(wheel.bytes)
        if hashlib.sha256(wheel_path.read_bytes()).hexdigest() != wheel.sha256:
            raise rd.ReceiptError("wheel bytes changed while materializing runtime")
        constraints, constraints_digest = self._constraints_path(wheel)
        venv = self._root / "venvs" / wheel.sha256
        self._run(["uv", "venv", "--python", "3.12", str(venv)])
        python = venv / "bin" / "python"
        self._run([
            "uv", "pip", "install", "--python", str(python),
            "--constraint", str(constraints), str(wheel_path),
        ])
        inventory_script = (
            self._repo / "scripts" / "e2e" / "server_runtime_inventory.py"
        )
        inventory = json.loads(self._run(
            [str(python), str(inventory_script)],
            env={
                **os.environ,
                "AWEB_SKEW_SERVER_CONSTRAINTS_SHA256": constraints_digest,
            },
        ))
        validate_server_runtime(
            inventory, artifact_provenance(wheel), wheel.version)
        self._runtime_inventories[wheel.sha256] = inventory
        self._installed[wheel.sha256] = venv
        return venv

    def runtime_inventory(self, wheel: WheelIdentity) -> dict:
        inventory = self._runtime_inventories.get(wheel.sha256)
        if inventory is None:
            raise rd.ReceiptError(
                f"no captured runtime inventory for wheel {wheel.sha256}; "
                "the exact runtime was never materialized"
            )
        return dict(inventory)

    @contextmanager
    def serve(self, wheel, database):
        self._current_database = database
        venv = self._install(wheel)
        log_path = (
            self._root
            / f"aweb-{wheel.version}-{database}-{uuid.uuid4().hex[:6]}.log"
        )
        self._current_server_log = log_path
        log = open(log_path, "wb")
        self._log_handles.append(log)
        env = {
            **os.environ,
            "AWEB_DATABASE_URL": self._database_url,
            "AWEB_REDIS_URL": self._redis_url,
            "AWID_REGISTRY_URL": self._awid_url,
            "AWEB_HOST": "127.0.0.1",
            "AWEB_PORT": str(self._aweb_port),
            "AWEB_PUBLIC_ORIGIN": self._aweb_url,
            "AWEB_LOG_JSON": "true",
            "APP_ENV": "development",
        }
        process = subprocess.Popen(
            server_command(venv, self._aweb_port),
            cwd=self._root, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            try:
                self._wait_http(f"{self._aweb_url}/health", process)
            except Exception as exc:
                log.flush()
                tail = log.name and Path(log.name).read_text(errors="replace")[-4000:]
                raise rd.ReceiptError(f"{exc}; exact-wheel server log:\n{tail}") from exc
            yield self._aweb_url
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            log.flush()
            self._server_exit_codes.append(process.returncode)

    def _aw_env(self):
        home = self._root / "home"
        return {
            **os.environ,
            "HOME": str(home),
            "AW_CONFIG_PATH": str(home / ".config" / "aw" / "config.yaml"),
            "AWID_REGISTRY_URL": self._awid_url,
            "AWID_SKIP_DNS_VERIFY": "1",
            "AWEB_URL": self._aweb_url,
        }

    def _aw(self, workspace: str, *args) -> str:
        binary = self._repo / "cli" / "go" / "aw"
        return self._run(
            [binary, *args], cwd=self._root / workspace, env=self._aw_env()
        ).decode(errors="replace")

    @staticmethod
    def _json_output(output: str) -> dict:
        start = output.find("{")
        if start < 0:
            raise rd.ReceiptError(f"aw returned no JSON object: {output[-500:]}")
        try:
            value, _ = json.JSONDecoder().raw_decode(output[start:])
        except json.JSONDecodeError as exc:
            raise rd.ReceiptError(f"aw returned invalid JSON: {output[-500:]}") from exc
        return value

    def seed(self, server, cell):
        self._json_output(self._aw(
            "alice", "id", "create", "--name", "alice", "--domain", "skew.local",
            "--registry", self._awid_url, "--skip-dns-verify", "--json",
        ))
        self._json_output(self._aw(
            "alice", "id", "namespace", "set-delivery-origin",
            "--namespace", "skew.local", "--origin", self._aweb_url, "--json",
        ))
        self._json_output(self._aw(
            "alice", "id", "team", "create", "--name", "devteam",
            "--namespace", "skew.local", "--registry", self._awid_url, "--json",
        ))
        invite = self._json_output(self._aw(
            "alice", "id", "team", "invite", "--team", "devteam",
            "--namespace", "skew.local", "--global", "--json",
        ))["token"]
        self._json_output(self._aw(
            "alice", "id", "team", "accept-invite", invite, "--global",
            "--alias", "alice", "--json",
        ))
        self._aw("alice", "init", "--url", self._aweb_url)

        self._json_output(self._aw(
            "bob", "id", "create", "--name", "bob", "--domain", "skew.local",
            "--registry", self._awid_url, "--skip-dns-verify", "--json",
        ))
        invite = self._json_output(self._aw(
            "alice", "id", "team", "invite", "--team", "devteam",
            "--namespace", "skew.local", "--global", "--json",
        ))["token"]
        self._json_output(self._aw(
            "bob", "id", "team", "accept-invite", invite, "--global",
            "--alias", "bob", "--json",
        ))
        self._aw("bob", "init", "--url", self._aweb_url)

    def _next_marker(self, cell, phase):
        self._counter += 1
        return f"skew-{cell.edge_id[:12]}-{self._counter}-{phase}"

    def _assert_mail_markers(self, phase):
        inbox = self._aw("bob", "mail", "inbox", "--show-all", "--json")
        for expected in self._markers:
            if expected not in inbox:
                raise rd.ReceiptError(
                    f"mail journey did not preserve marker {expected!r} during {phase}"
                )

    def _mail_probe(self, cell, phase):
        marker = self._next_marker(cell, phase)
        mail_args = [
            "mail", "send", "--plaintext", "--subject", marker,
            "--body", marker, "--json",
        ]
        if self._mail_conversation is None:
            mail_args.extend(["--to", "bob"])
        else:
            mail_args.extend(["--conversation-id", self._mail_conversation])
        sent = self._json_output(self._aw("alice", *mail_args))
        observed = sent.get("conversation_id")
        if not observed:
            raise rd.ReceiptError("mail journey returned no conversation identity")
        if self._mail_conversation not in (None, observed):
            raise rd.ReceiptError(
                "mail continuation changed conversation identity across restart"
            )
        self._mail_conversation = observed
        self._markers.append(marker)
        self._assert_mail_markers(phase)
        return {"conversation_id": observed, "marker": marker}

    def _chat_probe(self, cell, phase):
        marker = self._next_marker(cell, phase)
        self._aw(
            "alice", "chat", "send-and-leave", "--plaintext", "bob", marker,
        )
        history = self._aw("alice", "chat", "history", "bob", "--json")
        if marker not in history:
            raise rd.ReceiptError(f"chat journey lost {marker!r} during {phase}")

    def _task_lock_probe(self, cell, phase):
        marker = self._next_marker(cell, phase)
        self._aw(
            "alice", "task", "create", "--title", marker,
            "--description", "persisted-state skew fixture", "--type", "task",
            "--json",
        )
        tasks = self._aw("alice", "task", "list", "--json")
        if marker not in tasks:
            raise rd.ReceiptError(f"task journey lost {marker!r} during {phase}")
        resource = f"persisted-skew-{self._counter}"
        self._aw(
            "alice", "lock", "acquire", "--resource-key", resource,
            "--ttl-seconds", "3600", "--json",
        )
        locks = self._aw("alice", "lock", "list", "--json")
        if resource not in locks:
            raise rd.ReceiptError(f"lock journey did not observe {resource!r}")
        self._aw("alice", "lock", "release", "--resource-key", resource, "--json")

    def published_seed_probe(self, server, cell):
        self._mail_probe(cell, "published-seed")
        self._chat_probe(cell, "published-seed")
        self._task_lock_probe(cell, "published-seed")

    def candidate_upgrade_assertion(self, server, cell):
        self._mail_probe(cell, "candidate-upgrade-focal")
        self._chat_probe(cell, "candidate-upgrade-focal")
        self._task_lock_probe(cell, "candidate-upgrade-focal")

    def published_after_upgrade(self, server, cell):
        self._assert_mail_markers("published-after-upgrade")
        self._task_lock_probe(cell, "published-after-upgrade")

    def candidate_prepare_rollback(self, server, cell):
        self._chat_probe(cell, "candidate-prepares-rollback")
        self._task_lock_probe(cell, "candidate-prepares-rollback")

    def published_rollback_assertion(self, server, cell):
        self._mail_probe(cell, "published-rollback-focal")
        self._task_lock_probe(cell, "published-rollback-focal")

    def mail_control_baseline(self, server, cell):
        return self._mail_probe(cell, "negative-control-baseline")

    def mail_control_failure(self, server, cell):
        return self._mail_probe(cell, "known-breaking-schema")

    # One exact diagnostic entry must bind the undefined-column class AND the
    # messages.subject reference; JSON logging writes "subject" as a field name
    # on every mail line, so bare substring conjuncts over the whole log are
    # vacuous and must never be used here.
    _CAUSAL_CLASS = re.compile(r"42703|UndefinedColumn")
    _CAUSAL_COLUMN = re.compile(
        r'column \\?"subject\\?" of relation \\?"messages\\?"'
        r"|messages\.subject"
    )

    def assert_causal_mail_failure(self, error):
        if self._current_server_log is None:
            raise rd.ReceiptError("mail control has no exact server diagnostic")
        for handle in self._log_handles:
            handle.flush()
        if "http 500" not in str(error).lower():
            raise rd.ReceiptError(
                "mail control failure is not an HTTP 500 server failure: "
                f"{error}"
            )
        log = self._current_server_log.read_text(errors="replace")
        for line in log.splitlines():
            class_match = self._CAUSAL_CLASS.search(line)
            column_match = self._CAUSAL_COLUMN.search(line)
            if class_match and column_match:
                # Extracted, never constant: the literal SQLSTATE when the
                # entry carries it; otherwise the deterministic class mapping
                # UndefinedColumn <-> 42703, recorded with what matched.
                sqlstate = (
                    "42703" if "42703" in line
                    else {"UndefinedColumn": "42703"}[class_match.group(0)]
                )
                return {
                    "sqlstate": sqlstate,
                    "column": "messages.subject",
                    "matched_entry": line,
                    "entry_sha256": hashlib.sha256(line.encode()).hexdigest(),
                }
        raise rd.ReceiptError(
            "no single diagnostic entry binds SQLSTATE 42703/UndefinedColumn "
            "to messages.subject; refusing a wrong-cause failure"
        )

    def _psql(self, database: str, sql: str) -> bytes:
        return self._docker(
            "exec", "-i", self._postgres, "psql", "-X", "-v", "ON_ERROR_STOP=1",
            "-U", "aweb", "-d", database, "-At", "-F", "\t", "-c", sql,
        )

    def database_identity(self, database):
        migrations = self._psql(
            database,
            "SELECT filename, checksum FROM aweb.schema_migrations ORDER BY filename",
        )
        schema_dump = self._docker(
            "exec", self._postgres, "pg_dump", "-U", "aweb", "-d", database,
            "--schema=aweb", "--schema-only", "--no-owner", "--no-privileges",
        )
        data_dump = self._docker(
            "exec", self._postgres, "pg_dump", "-U", "aweb", "-d", database,
            "--schema=aweb", "--data-only", "--inserts", "--no-owner",
            "--no-privileges",
        )
        return {
            "database": database,
            "migration_rows_sha256": hashlib.sha256(migrations).hexdigest(),
            "schema_dump_sha256": hashlib.sha256(schema_dump).hexdigest(),
            "data_dump_sha256": hashlib.sha256(data_dump).hexdigest(),
            "migration_rows": migrations.decode().splitlines(),
        }

    def clone_database(self, database):
        control = f"control_{uuid.uuid4().hex[:10]}"
        self._docker(
            "exec", self._postgres, "createdb", "-U", "aweb",
            "--template", database, control,
        )
        return control

    def break_schema(self, database):
        self._psql(database, "ALTER TABLE aweb.messages DROP COLUMN subject")

    def close(self):
        if self._closed_proof is not None:
            return dict(self._closed_proof)
        errors = []
        process_results = []
        for process in reversed(self._processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process_results.append(process.returncode)
        for handle in self._log_handles:
            try:
                handle.close()
            except Exception as exc:
                errors.append(f"log close: {exc}")
        for name in reversed(self._containers):
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            observed = subprocess.run(
                ["docker", "ps", "-a", "--filter", f"name=^/{name}$",
                 "--format", "{{.Names}}"],
                capture_output=True,
            )
            if observed.returncode != 0:
                errors.append(
                    f"cannot verify targeted container {name}: "
                    + observed.stderr.decode(errors="replace")[-500:]
                )
            elif observed.stdout.strip():
                errors.append(f"targeted container remains: {name}")
        shutil.rmtree(self._root, ignore_errors=True)
        if self._root.exists():
            errors.append(f"temporary root remains: {self._root}")
        if errors:
            raise rd.ReceiptError("; ".join(errors))
        all_exit_codes = process_results + list(self._server_exit_codes)
        self._closed_proof = {
            "targeted_containers": list(self._containers),
            "targeted_containers_absent": True,
            "process_exit_codes": all_exit_codes,
            "processes_exited": all(code is not None for code in all_exit_codes),
            "temp_root_absent": True,
        }
        return dict(self._closed_proof)


def _report_without_id(report: dict) -> dict:
    return {key: value for key, value in report.items() if key != "report_id"}


def _candidate_matches_frozen(report: dict, cell: rd.SkewCell) -> bool:
    candidate = report.get("candidate", {})
    source = candidate.get("source", {})
    wheel_digest = (cell.a.get("digest_set") or {}).get(candidate.get("filename"))
    lane_ref = cell.a.get("lane_ref") or {}
    return (
        candidate.get("kind") == "candidate"
        and candidate.get("version") == cell.a.get("version")
        and candidate.get("sha256") == wheel_digest
        and source.get("artifact") == lane_ref.get("artifact")
        and source.get("source_sha") == lane_ref.get("aw_source_sha")
        and source.get("outer_zip_sha256")
            == str(lane_ref.get("zip_digest", "")).removeprefix("sha256:")
        and source.get("digest_set") == cell.a.get("digest_set")
        and source.get("canonical_set_digest") == cell.a.get("digest")
    )


def aggregate_support(matrix_path: Path) -> dict:
    """Build incomplete/unanchored support from one exact frozen matrix.

    Expected report names derive from the matrix's complete cell-ID set. The
    directory is used only to prove there are neither missing nor extra reports;
    it never defines what the matrix was.
    """
    matrix_path = Path(matrix_path)
    document = json.loads(matrix_path.read_bytes())
    cells = rd.validate_skew_matrix_document(document)
    matrix_id = document["matrix_id"]
    if matrix_path.name != f"matrix-{matrix_id}.json":
        raise rd.ReceiptError("matrix filename does not equal its matrix identity")
    expected = {
        f"cell-{matrix_id}-{rd.skew_cell_identity(cell)}.json": cell
        for cell in cells
    }
    actual = {
        path.name: path
        for path in matrix_path.parent.glob(f"cell-{matrix_id}-*.json")
    }
    if set(actual) != set(expected):
        raise rd.ReceiptError(
            "persisted-state report-file set does not equal the exact frozen "
            f"cell set; missing={sorted(set(expected) - set(actual))}, "
            f"extra={sorted(set(actual) - set(expected))}"
        )
    report_digests = []
    candidate_identities = {}
    dependency_postures: set[str] = set()
    published_identities: dict[str, dict] = {}
    for name, cell in expected.items():
        report_bytes = actual[name].read_bytes()
        report = json.loads(report_bytes)
        cell_id = rd.skew_cell_identity(cell)
        if report.get("matrix_id") != matrix_id:
            raise rd.ReceiptError(f"{name}: report binds the wrong matrix")
        if report.get("cell_id") != cell_id:
            raise rd.ReceiptError(f"{name}: report binds the wrong cell")
        if report.get("cell") != rd.skew_cell_preimage(cell):
            raise rd.ReceiptError(f"{name}: report cell preimage drifted")
        if report.get("schema") != "aweb.persisted-state-skew-cell.v2":
            raise rd.ReceiptError(f"{name}: report schema is unsupported")
        if report.get("result") != "green":
            raise rd.ReceiptError(f"{name}: report is not green")
        cleanup = report.get("cleanup", {})
        if not all((
            cleanup.get("targeted_containers_absent"),
            cleanup.get("processes_exited"), cleanup.get("temp_root_absent"),
        )):
            raise rd.ReceiptError(f"{name}: report lacks completed cleanup")
        expected_report_id = rd.canonical_json_digest(_report_without_id(report))
        if report.get("report_id") != expected_report_id:
            raise rd.ReceiptError(f"{name}: report digest does not recompute")
        runtimes = report.get("server_runtimes")
        if not isinstance(runtimes, dict) or set(runtimes) != {
            "candidate", "published"
        }:
            raise rd.ReceiptError(f"{name}: report lacks runtime inventories")
        validate_server_runtime(
            runtimes["candidate"], CANDIDATE_PROVENANCE,
            report["candidate"].get("version"))
        validate_server_runtime(
            runtimes["published"], PUBLISHED_PROVENANCE,
            report["published"].get("version"))
        for label, runtime in runtimes.items():
            dependency_rows = json.dumps(
                [row for row in runtime["distributions"]
                 if row["name"] not in ("aweb", "pip", "setuptools", "wheel")],
                sort_keys=True, separators=(",", ":"))
            dependency_postures.add(dependency_rows)
        if not _candidate_matches_frozen(report, cell):
            raise rd.ReceiptError(f"{name}: candidate is not the frozen identity")
        published = report.get("published", {})
        if (
            published.get("kind") != cell.b_kind
            or published.get("version") != cell.b.get("version")
        ):
            raise rd.ReceiptError(f"{name}: published actor is not the frozen side")
        # One shared validation of the COMPLETE published identity, re-derived
        # from the FROZEN published version rather than from anything the
        # report presents about itself.
        frozen_version = cell.b.get("version")
        validate_published_identity(
            published, version=frozen_version, label=name)
        # Keyed by the frozen version ALONE: keying by (version, sha) would let
        # a tampered sha open a second key and escape the consistency check.
        prior_published = published_identities.setdefault(
            frozen_version, published)
        if prior_published != published:
            raise rd.ReceiptError(
                f"{name}: published identity for frozen version "
                f"{frozen_version} differs across directional cells"
            )
        expected_focal = "candidate" if cell.direction == "b-to-a" else "published"
        if (
            report.get("chronology") != ["published", "candidate", "published"]
            or report.get("focal_actor") != expected_focal
        ):
            raise rd.ReceiptError(f"{name}: temporal actor semantics drifted")
        candidate = report["candidate"]
        candidate_identities[
            json.dumps(candidate, sort_keys=True, separators=(",", ":"))
        ] = candidate
        report_digests.append({
            "cell_id": cell_id,
            "report_id": expected_report_id,
            "file_sha256": hashlib.sha256(report_bytes).hexdigest(),
        })
    if len(candidate_identities) != 1:
        raise rd.ReceiptError(
            "persisted-state reports do not bind one exact candidate"
        )
    if len(dependency_postures) > 1:
        raise rd.ReceiptError(
            "runtime dependency drift across compared runs: only the aweb "
            "wheel may differ between runtimes"
        )
    preimage = document["preimage"]
    edge = preimage["edge"]
    measurement = {
        "schema": "aweb.runtime-support-measurement.v1",
        "status": "incomplete-unanchored",
        "matrix_id": matrix_id,
        "edge": {"a": edge["a"], "b": edge["b"]},
        "journey": edge["journey"],
        "artifacts": edge["artifacts"],
        "direction": edge["direction"],
        "staged_manifest_digest": preimage["staged_manifest_digest"],
        "supported_versions": preimage["support"]["supported_versions"],
        "published_versions": preimage["published_versions"],
        "candidate": next(iter(candidate_identities.values())),
        # Canonically ordered so measurement_id binds these exact bytes: the
        # published actors are part of what the measurement asserts, not
        # incidental context.
        "published_identities": [
            published_identities[version]
            for version in sorted(published_identities)
        ],
        "reports": report_digests,
    }
    measurement["measurement_id"] = rd.canonical_json_digest(measurement)
    return measurement


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="verb", required=True)
    aggregate = subparsers.add_parser("aggregate")
    aggregate.add_argument("--matrix", type=Path, required=True)
    aggregate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.verb == "aggregate":
        document = aggregate_support(args.matrix)
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(body)
        print(f"{args.output} sha256:{hashlib.sha256(body).hexdigest()}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
