"""Exact-artifact channel/Pi ↔ server version-skew child harness.

The release driver owns matrix semantics.  This child accepts one frozen cell,
resolves only the artifacts named by that cell, executes one direction-specific
journey assertion, and writes one cell-bound evidence record.  It never stages,
publishes, anchors, or invents a supported floor.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

import release_driver as rd

CHANNEL_JOURNEY = "channel integration journey (aweb-abbe.7.2)"
PI_JOURNEY = "pi integration journey (aweb-abbe.7.2)"
CLIENT_ARTIFACTS = {
    "channel": "npm:@awebai/claude-channel",
    "pi": "npm:@awebai/pi",
}
SERVER_ARTIFACT = "pypi:aweb"
LEGACY_MESSAGE_ID = "00000000-0000-4000-8000-000000000726"
LEGACY_MARK_READ_REQUEST = {"up_to_message_id": LEGACY_MESSAGE_ID}
PUBLISHED_KINDS = {"published", "published-latest", "published-floor"}
OBSERVATION_PREFIX = "AWEB_SKEW_OBSERVATION "
OBSERVATION_SCHEMA = "aweb.channel-pi-skew-observation.v1"
OBSERVATION_CONTRACTS = {
    ("channel", "a-to-b"): ("chat-mark-read", "removed-from-pending"),
    ("channel", "b-to-a"): ("sse-chat-presentation", "presented"),
    ("pi", "a-to-b"): ("resident-mail-reply", "observer-verified"),
    ("pi", "b-to-a"): ("resident-mail-wake", "session-observed"),
}
RUNTIME_INVENTORY_SCHEMA = "aweb.server-runtime-inventory.v1"
CLOSED_AMBIENT_ENV = {
    "KEEP_UP",
    "OAS_PROOF_AWID_PORT",
    "OAS_PROOF_AWEB_PORT",
    "OAS_PROOF_POSTGRES_PORT",
    "LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL",
    "LIBRARY_E2E_AWEB_PUBLIC_ORIGIN",
    "LIBRARY_E2E_LIBRARY_PUBLIC_ORIGIN",
    "AWEB_PUBLIC_ORIGIN",
    "AWID_PUBLIC_REGISTRY_URL",
    "AWEB_TEST_URL",
    "AWID_TEST_URL",
    "OAS_PROOF_REPORT",
}


def _canonical_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def server_runtime_constraints() -> tuple[bytes, str, dict[str, str]]:
    """Derive canonical exact constraints from the reviewed server lock."""
    lock = Path(__file__).resolve().parents[1] / "server" / "uv.lock"
    document = tomllib.loads(lock.read_text())
    constraints: dict[str, str] = {}
    for package in document.get("package", []):
        name = _canonical_package_name(package.get("name", ""))
        version = package.get("version")
        if not name or not isinstance(version, str) or not version:
            raise rd.ReceiptError("server lock contains an unversioned package")
        if name == "aweb":
            continue
        prior = constraints.setdefault(name, version)
        if prior != version:
            raise rd.ReceiptError(
                f"server lock resolves multiple versions for {name}: {prior}, {version}"
            )
    if "mcp" not in constraints:
        raise rd.ReceiptError("server lock does not pin the moving mcp dependency")
    body = "".join(
        f"{name}=={version}\n" for name, version in sorted(constraints.items())
    ).encode()
    return body, hashlib.sha256(body).hexdigest(), constraints


def validate_server_runtime(runtime: dict, server_version: str | None = None) -> None:
    body, constraints_digest, constraints = server_runtime_constraints()
    del body
    if not isinstance(runtime, dict) or runtime.get("schema") != RUNTIME_INVENTORY_SCHEMA:
        raise rd.ReceiptError("server runtime inventory has the wrong schema")
    distributions = runtime.get("distributions")
    preimage = {
        "constraints_sha256": runtime.get("constraints_sha256"),
        "python_version": runtime.get("python_version"),
        "distributions": distributions,
    }
    if (
        runtime.get("constraints_sha256") != constraints_digest
        or not isinstance(runtime.get("python_version"), str)
        or not runtime["python_version"]
        or not isinstance(distributions, list)
        or runtime.get("sha256") != hashlib.sha256(
            json.dumps(preimage, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    ):
        raise rd.ReceiptError(
            "server runtime inventory does not bind its canonical lock-derived preimage"
        )
    observed: dict[str, str] = {}
    for row in distributions:
        if not isinstance(row, dict) or set(row) != {"name", "version"}:
            raise rd.ReceiptError("server runtime inventory has a malformed distribution")
        name = row.get("name")
        version = row.get("version")
        if (
            not isinstance(name, str) or name != _canonical_package_name(name)
            or not isinstance(version, str) or not version
            or name in observed
        ):
            raise rd.ReceiptError("server runtime inventory is not canonical and unique")
        observed[name] = version
    expected_rows = [
        {"name": name, "version": version}
        for name, version in sorted(observed.items())
    ]
    if distributions != expected_rows:
        raise rd.ReceiptError("server runtime inventory is not canonically ordered")
    for name, version in observed.items():
        if name == "aweb":
            if server_version is not None and version != server_version:
                raise rd.ReceiptError(
                    f"server runtime inventory has aweb {version}, expected {server_version}"
                )
        elif name in {"pip", "setuptools", "wheel"}:
            continue
        elif constraints.get(name) != version:
            raise rd.ReceiptError(
                f"server runtime inventory contains unlocked distribution {name}=={version}"
            )
    if "aweb" not in observed or observed.get("mcp") != constraints["mcp"]:
        raise rd.ReceiptError(
            "server runtime inventory lacks the exact aweb or locked mcp distribution"
        )


def validate_observation(
    observation: dict, component: str, direction: str,
    server_version: str | None = None,
) -> None:
    operation, result = OBSERVATION_CONTRACTS[(component, direction)]
    expected = {
        "schema": OBSERVATION_SCHEMA,
        "component": component,
        "direction": direction,
        "operation": operation,
        "result": result,
    }
    if not isinstance(observation, dict) or any(
        observation.get(key) != value for key, value in expected.items()
    ):
        raise rd.ReceiptError(
            f"{component} {direction} observation does not match its structured "
            f"operation/result contract {expected!r}"
        )
    for key in ("message_id", "conversation_id"):
        if not isinstance(observation.get(key), str) or not observation[key]:
            raise rd.ReceiptError(
                f"{component} {direction} observation lacks concrete {key}"
            )
    validate_server_runtime(observation.get("server_runtime"), server_version)


def parse_observation(
    output: bytes, component: str, direction: str,
    server_version: str | None = None,
) -> dict:
    observations = []
    for line in output.decode(errors="replace").splitlines():
        if line.startswith(OBSERVATION_PREFIX):
            try:
                observations.append(json.loads(line.removeprefix(OBSERVATION_PREFIX)))
            except json.JSONDecodeError as exc:
                raise rd.ReceiptError("skew journey emitted malformed observation JSON") from exc
    if len(observations) != 1:
        raise rd.ReceiptError(
            f"skew journey must emit exactly one direction observation, got "
            f"{len(observations)}"
        )
    observation = observations[0]
    validate_observation(observation, component, direction, server_version)
    return observation


@dataclass(frozen=True)
class PackageArtifact:
    component: str
    filename: str
    version: str
    sha256: str
    bytes: bytes
    source: dict


def _http_get(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception as exc:
        raise rd.ReceiptError(f"registry observation failed for {url}: {exc}") from exc


def _npm_profile_check(body: bytes, component: str, version: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / f"{component}-{version}.tgz"
        path.write_bytes(body)
        result = subprocess.run(
            [
                "bash", str(Path(__file__).with_name("npm-exact-publish.sh")),
                "inspect-tgz", "--tgz", str(path), "--version", version,
                "--profile", component, "--source-root",
                str(Path(__file__).resolve().parents[1]),
            ],
            capture_output=True,
        )
    if result.returncode != 0:
        raise rd.ReceiptError(
            f"published {component} tgz fails the reviewed package profile: "
            + result.stderr.decode(errors="replace").strip()
        )


class ArtifactResolver:
    """Resolve exact candidate or published bytes without a source fallback."""

    def __init__(
        self,
        *,
        staged_store_factory=None,
        staged_authority_factory=None,
        http_get=None,
        pypi_observe=None,
        npm_lane_validator=None,
        npm_profile_check=None,
    ):
        self._staged_store_factory = staged_store_factory or self._github_store
        self._staged_authority_factory = (
            staged_authority_factory or self._github_authority
        )
        self._http_get = http_get or _http_get
        self._pypi_observe = pypi_observe or rd._observe_pypi
        self._npm_lane_validator = npm_lane_validator or rd.validate_npm_lane_artifact
        self._npm_profile_check = npm_profile_check or _npm_profile_check

    @staticmethod
    def _lane(component: str) -> tuple[str, str]:
        if component in {"channel", "pi"}:
            return "awebai/aweb", ".github/workflows/npm-release.yml"
        if component == "server":
            return "awebai/aweb", ".github/workflows/pypi-release.yml"
        raise rd.ReceiptError(f"unsupported skew artifact component {component!r}")

    @classmethod
    def _github_store(cls, component: str):
        repo, workflow = cls._lane(component)
        return rd.GithubArtifactStore(repo=repo, workflow_path=workflow)

    @classmethod
    def _github_authority(cls, component: str):
        repo, workflow = cls._lane(component)
        return rd.GithubArtifactDigestAuthority(repo=repo, workflow_path=workflow)

    def resolve(self, kind: str, side: dict, locator: str) -> PackageArtifact:
        component = side.get("component")
        expected = (
            CLIENT_ARTIFACTS.get(component)
            if component in CLIENT_ARTIFACTS else SERVER_ARTIFACT
            if component == "server" else None
        )
        if expected is None or locator != expected:
            raise rd.ReceiptError(
                f"channel/Pi skew artifact locator {locator!r} does not match "
                f"component {component!r} ({expected!r})"
            )
        if kind == "candidate":
            return self._candidate(side)
        if kind not in PUBLISHED_KINDS:
            raise rd.ReceiptError(f"unknown channel/Pi skew side kind {kind!r}")
        if component in CLIENT_ARTIFACTS:
            return self._published_npm(side, locator.removeprefix("npm:"))
        return self._published_server(side)

    def _candidate(self, side: dict) -> PackageArtifact:
        component = side["component"]
        lane_data = side.get("lane_ref")
        if lane_data is None:
            raise rd.ReceiptError(
                f"candidate {component} requires the unchanged structured lane reference"
            )
        ref = rd.LaneRef.from_dict(lane_data)
        authority = self._staged_authority_factory(component)
        independently_recorded = authority.expected_digest(ref.artifact)
        if f"sha256:{independently_recorded}" != ref.zip_digest:
            raise rd.ReceiptError(
                f"{component}: independent authority records "
                f"sha256:{independently_recorded}, not {ref.zip_digest}"
            )
        store = self._staged_store_factory(component)
        outer = store.get(ref.artifact)
        outer_digest = hashlib.sha256(outer).hexdigest()
        if f"sha256:{outer_digest}" != ref.zip_digest:
            raise rd.ReceiptError(
                f"{component}: staged outer ZIP sha256:{outer_digest} does not "
                f"equal {ref.zip_digest}"
            )
        if component in CLIENT_ARTIFACTS:
            manifest, filename, body = self._npm_lane_validator(
                outer,
                expected_source_sha=ref.aw_source_sha,
                expected_version=side.get("version"),
                package=component,
                profile=component,
            )
        else:
            manifest = rd.validate_pypi_lane_artifact(
                outer,
                expected_source_sha=ref.aw_source_sha,
                expected_version=side.get("version"),
                package="server",
                pypi_name="aweb",
            )
            wheels = [name for name in manifest["files"] if name.endswith(".whl")]
            if len(wheels) != 1:
                raise rd.ReceiptError(
                    f"candidate server lane binds {len(wheels)} wheels, expected one"
                )
            filename = wheels[0]
            with zipfile.ZipFile(io.BytesIO(outer)) as archive:
                body = archive.read(f"dist/{filename}")
        files = manifest["files"]
        if side.get("digest_set") != files:
            raise rd.ReceiptError(
                f"candidate {component} complete set does not equal the frozen cell"
            )
        canonical = rd.canonical_digest_of_set(files)
        if side.get("digest") != canonical:
            raise rd.ReceiptError(
                f"candidate {component} canonical complete-set digest {canonical} "
                f"does not equal frozen {side.get('digest')!r}"
            )
        payload_digest = hashlib.sha256(body).hexdigest()
        if files.get(filename) != payload_digest:
            raise rd.ReceiptError(
                f"candidate {component} payload hash {payload_digest} does not "
                f"equal manifest {files.get(filename)!r}"
            )
        return PackageArtifact(
            component=component,
            filename=filename,
            version=side["version"],
            sha256=payload_digest,
            bytes=body,
            source={
                "kind": "candidate",
                "lane_ref": ref.to_dict(),
                "outer_zip_sha256": outer_digest,
                "canonical_set_digest": manifest["canonical_set_digest"],
                "digest_set": dict(files),
            },
        )

    def _published_npm(self, side: dict, package: str) -> PackageArtifact:
        component = side["component"]
        version = side.get("version")
        if not isinstance(version, str) or not version:
            raise rd.ReceiptError(f"published {component} side has no version")
        observed: dict[str, tuple[int, bytes]] = {}

        def recording_http(url: str):
            result = self._http_get(url)
            observed[url] = result
            return result

        digest = rd._observe_npm_registry(package, version, http=recording_http)
        if digest is None:
            raise rd.ReceiptError(
                f"published npm {package}@{version} returned 404 and is absent"
            )
        encoded = package.replace("/", "%2F")
        metadata_url = f"https://registry.npmjs.org/{encoded}/{version}"
        try:
            metadata = json.loads(observed[metadata_url][1])
            tarball_url = metadata["dist"]["tarball"]
            body = observed[tarball_url][1]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise rd.ReceiptError(
                f"published npm {package}@{version} observation lost exact bytes"
            ) from exc
        if hashlib.sha256(body).hexdigest() != digest:
            raise rd.ReceiptError(
                f"published npm {package}@{version} bytes changed after observation"
            )
        self._npm_profile_check(body, component, version)
        self._assert_npm_manifest(body, package, version)
        filename = tarball_url.rsplit("/", 1)[-1] or f"{component}-{version}.tgz"
        return PackageArtifact(
            component=component, filename=filename, version=version,
            sha256=digest, bytes=body,
            source={
                "kind": "published", "registry": f"npm:{package}",
                "metadata_url": metadata_url, "tarball_url": tarball_url,
                "digest_set": {filename: digest},
                "canonical_set_digest": rd.canonical_digest_of_set(
                    {filename: digest}
                ),
            },
        )

    @staticmethod
    def _assert_npm_manifest(body: bytes, package: str, version: str) -> None:
        try:
            with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
                manifest_file = archive.extractfile("package/package.json")
                manifest = json.load(manifest_file) if manifest_file else None
        except (tarfile.TarError, KeyError, json.JSONDecodeError) as exc:
            raise rd.ReceiptError(
                f"published npm {package}@{version} is not a valid package tgz"
            ) from exc
        if not isinstance(manifest, dict) or (
            manifest.get("name"), manifest.get("version")
        ) != (package, version):
            raise rd.ReceiptError(
                f"published npm manifest does not declare {package}@{version}"
            )

    def _published_server(self, side: dict) -> PackageArtifact:
        version = side.get("version")
        if not isinstance(version, str) or not version:
            raise rd.ReceiptError("published server side has no version")
        status, observed_set = self._pypi_observe("aweb", version)
        if status == 404:
            raise rd.ReceiptError(
                f"published PyPI aweb {version} returned 404 and is absent"
            )
        if status != 200:
            raise rd.ReceiptError(
                f"published PyPI aweb {version} returned {status}; "
                "unavailability is never an observation"
            )
        metadata_url = f"https://pypi.org/pypi/aweb/{version}/json"
        metadata_status, metadata_body = self._http_get(metadata_url)
        if metadata_status != 200:
            raise rd.ReceiptError(
                f"published PyPI aweb {version} metadata returned "
                f"{metadata_status}; unavailability is never an observation"
            )
        try:
            metadata = json.loads(metadata_body)
        except json.JSONDecodeError as exc:
            raise rd.ReceiptError(
                f"published PyPI aweb {version} metadata is malformed"
            ) from exc
        metadata_set = {
            item.get("filename"): (item.get("digests") or {}).get("sha256")
            for item in metadata.get("urls", [])
            if item.get("filename")
        }
        if metadata_set != observed_set:
            raise rd.ReceiptError(
                f"published PyPI aweb {version} metadata set does not equal "
                "the classified complete registry set"
            )
        wheels = [
            item for item in metadata.get("urls", [])
            if item.get("packagetype") == "bdist_wheel"
        ]
        if len(wheels) != 1:
            raise rd.ReceiptError(
                f"published PyPI aweb {version} exposes {len(wheels)} wheels, expected one"
            )
        item = wheels[0]
        filename = item.get("filename")
        expected = (item.get("digests") or {}).get("sha256")
        if observed_set.get(filename) != expected:
            raise rd.ReceiptError(
                f"published PyPI aweb {version} wheel metadata does not equal "
                "the classified complete registry set"
            )
        body_status, body = self._http_get(item["url"])
        if body_status != 200:
            raise rd.ReceiptError(
                f"published PyPI aweb {version} wheel download returned {body_status}"
            )
        actual = hashlib.sha256(body).hexdigest()
        if actual != expected:
            raise rd.ReceiptError(
                f"published wheel hash {actual} does not equal PyPI's {expected}"
            )
        return PackageArtifact(
            component="server", filename=filename, version=version,
            sha256=actual, bytes=body,
            source={
                "kind": "published", "registry": SERVER_ARTIFACT,
                "metadata_url": metadata_url, "download_url": item["url"],
                "digest_set": dict(observed_set),
                "canonical_set_digest": rd.canonical_digest_of_set(observed_set),
            },
        )


def _side_identity(kind: str, side: dict) -> dict:
    value = {"kind": kind, "component": side.get("component"),
             "version": side.get("version")}
    if kind == "candidate":
        value.update(
            digest=side.get("digest"), digest_set=side.get("digest_set"),
            lane_ref=side.get("lane_ref"),
        )
    return value


def cell_preimage(cell) -> dict:
    return rd.skew_cell_preimage(cell)


def cell_identity_from_preimage(preimage: dict) -> str:
    return rd.canonical_json_digest(preimage)


def cell_identity(cell) -> str:
    return rd.skew_cell_identity(cell)


class FileEvidenceWriter:
    def __init__(self, root: Path | None = None):
        configured = os.getenv("AWEB_CHANNEL_PI_SKEW_EVIDENCE_DIR")
        self.root = Path(root or configured or (
            Path(tempfile.gettempdir()) / "aweb-channel-pi-skew-evidence"
        )).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def write_path(self, path: Path, document: dict) -> Path:
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(body)
        os.replace(temporary, path)
        return path

    def write(self, report: dict) -> None:
        path = self.root / "cells" / (
            f"{report['matrix_id']}-{report['cell_id']}.json"
        )
        self.write_path(path, report)
        print(
            f"channel/Pi skew evidence: {path} "
            f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
        )


class ChannelPiHarness:
    def __init__(
        self, *, resolver: ArtifactResolver, evidence,
        journey=None, journey_factory=None,
    ):
        if (journey is None) == (journey_factory is None):
            raise TypeError("provide exactly one of journey or journey_factory")
        self._resolver = resolver
        self._journey = journey
        self._journey_factory = journey_factory
        self._evidence = evidence
        self._matrix: dict | None = None
        self._cells: dict[str, object] = {}
        self._control_path: Path | None = None

    def _new_journey(self):
        return self._journey if self._journey is not None else self._journey_factory()

    def freeze_matrix(self, document: dict) -> Path:
        cells = rd.validate_skew_matrix_document(document)
        edge = document["preimage"]["edge"]
        if not cells:
            raise rd.ReceiptError("channel/Pi matrix is empty")
        client = cells[0].edge_a
        expected_journey = CHANNEL_JOURNEY if client == "channel" else PI_JOURNEY
        if edge != {
            "a": client, "b": "server", "journey": expected_journey,
            "artifacts": {"a": CLIENT_ARTIFACTS.get(client), "b": SERVER_ARTIFACT},
            "direction": "both",
        } or any(self._cell_invalid(cell) for cell in cells):
            raise rd.ReceiptError(
                "channel/Pi child accepts only its exact frozen edge matrix"
            )
        if self._matrix is not None and self._matrix != document:
            raise rd.ReceiptError("channel/Pi child was given two matrices")
        path = self._evidence.root / f"matrix-{document['matrix_id']}.json"
        if path.exists():
            try:
                body = path.read_bytes()
                stored = json.loads(body)
            except (OSError, json.JSONDecodeError) as exc:
                raise rd.ReceiptError("channel/Pi matrix evidence is unreadable") from exc
            if stored != document or body != json.dumps(
                stored, sort_keys=True, separators=(",", ":")
            ).encode():
                raise rd.ReceiptError("channel/Pi matrix evidence is stale or tampered")
        else:
            self._evidence.write_path(path, document)
        self._matrix = json.loads(json.dumps(document))
        self._cells = {rd.skew_cell_identity(cell): cell for cell in cells}
        return path

    @staticmethod
    def _cell_invalid(cell) -> bool:
        try:
            ChannelPiHarness._validate_cell(cell)
        except rd.ReceiptError:
            return True
        return False

    def _frozen_cell_id(self, cell) -> str:
        if self._matrix is None:
            raise rd.ReceiptError("channel/Pi cell arrived before its frozen matrix")
        identity = rd.skew_cell_identity(cell)
        if self._cells.get(identity) != cell:
            raise rd.ReceiptError(
                "channel/Pi cell is not an exact member of its frozen matrix"
            )
        return identity

    @staticmethod
    def _validate_cell(cell) -> str:
        client = cell.edge_a
        expected_journey = (
            CHANNEL_JOURNEY if client == "channel" else PI_JOURNEY
            if client == "pi" else None
        )
        if (
            expected_journey is None
            or cell.edge_b != "server"
            or cell.journey != expected_journey
            or cell.artifacts != {
                "a": CLIENT_ARTIFACTS[client], "b": SERVER_ARTIFACT,
            }
            or cell.declared_direction != "both"
            or cell.direction not in {"a-to-b", "b-to-a"}
        ):
            raise rd.ReceiptError(
                f"harness accepts only an exact channel/Pi-server edge, got {cell!r}"
            )
        return client

    def run(self, cell) -> None:
        frozen_cell_id = self._frozen_cell_id(cell)
        evidence_root = getattr(self._evidence, "root", None)
        target = (
            Path(evidence_root) / "cells" /
            f"{self._matrix['matrix_id']}-{frozen_cell_id}.json"
            if evidence_root is not None else None
        )
        if target is not None and target.exists():
            raise rd.ReceiptError("channel/Pi frozen cell already has evidence")
        journey = self._new_journey()
        report = None
        try:
            client_component = self._validate_cell(cell)
            client = self._resolver.resolve(
                cell.a_kind, cell.a, cell.artifacts["a"]
            )
            server = self._resolver.resolve(
                cell.b_kind, cell.b, cell.artifacts["b"]
            )
            if cell.direction == "a-to-b":
                observation = {"request": journey.run_client_request(
                    client, server, cell
                )}
            else:
                observation = {"event": journey.run_server_event(
                    client, server, cell
                )}
            observed = next(iter(observation.values()))
            validate_observation(
                observed, client_component, cell.direction, server.version
            )
            report = {
                "schema": "aweb.channel-pi-server-skew-cell.v1",
                "result": "green",
                "matrix_id": self._matrix["matrix_id"],
                "cell_id": frozen_cell_id,
                "cell": cell_preimage(cell),
                "edge_id": cell.edge_id,
                "edge": {"a": cell.edge_a, "b": cell.edge_b},
                "journey": cell.journey,
                "artifacts": dict(cell.artifacts),
                "declared_direction": cell.declared_direction,
                "cell_direction": cell.direction,
                "client_kind": cell.a_kind,
                "server_kind": cell.b_kind,
                "client_artifact": self._artifact_report(client),
                "server_artifact": self._artifact_report(server),
                "server_runtime": observed["server_runtime"],
                "observation": observation,
            }
        finally:
            journey.close()
        report["report_id"] = rd.canonical_json_digest(report)
        self._evidence.write(report)

    def finish_matrix(self, document: dict) -> Path:
        if document != self._matrix:
            raise rd.ReceiptError(
                "channel/Pi finish request does not equal its frozen matrix"
            )
        if self._control_path is not None:
            raise rd.ReceiptError("channel/Pi control ran more than once")
        _require_channel_report_files(document, self._evidence.root)
        journey = self._new_journey()
        try:
            measured = journey.run_mark_read_control(
                dict(LEGACY_MARK_READ_REQUEST)
            )
        finally:
            journey.close()
        if (
            measured.get("unmutated_status") != 200
            or measured.get("mutated_status") != 422
        ):
            raise rd.ReceiptError(
                "required-field control must observe 200 on the unmutated "
                "server and 422 on the disposable mutation"
            )
        control = {
            "schema": "aweb.channel-pi-skew-control.v1",
            "matrix_id": document["matrix_id"],
            "request": dict(LEGACY_MARK_READ_REQUEST),
            "unmutated_status": 200,
            "mutated_status": 422,
            "mutation_subject": measured.get("mutation_subject"),
            "evidence_class": "control-only-not-candidate",
        }
        control["control_id"] = rd.canonical_json_digest(control)
        self._control_path = self._evidence.write_path(
            self._evidence.root / f"control-{document['matrix_id']}.json", control
        )
        measurement = aggregate_frozen_matrix(
            self._evidence.root / f"matrix-{document['matrix_id']}.json",
            self._evidence.root,
            control_path=self._control_path,
        )
        return self._evidence.write_path(
            self._evidence.root / (
                f"aggregate-{document['matrix_id']}-"
                f"{measurement['measurement_id']}.json"
            ),
            measurement,
        )

    @staticmethod
    def _artifact_report(artifact: PackageArtifact) -> dict:
        return {
            "component": artifact.component,
            "filename": artifact.filename,
            "version": artifact.version,
            "sha256": artifact.sha256,
            "source": dict(artifact.source),
        }


def compose_project_name(root: Path, cell) -> str:
    raw = f"aweb-skew-{root.name}-{cell_identity(cell)[:16]}".lower()
    project = "".join(
        character if character.isalnum() or character in "_.-" else "-"
        for character in raw
    )[:63]
    if not project or not project[0].isalnum():
        raise rd.ReceiptError(f"could not derive bounded Compose project from {raw!r}")
    return project


class SubprocessChannelPiJourney:
    """Committed real-journey adapter; execution is separately cleared.

    The channel integration and resident-Pi scripts accept an exact installed
    package root.  This adapter materializes the already-validated bytes and
    delegates to those existing journeys.  It intentionally contains no tmux
    cleanup; the resident script owns its isolated socket and guard contract.
    """

    def __init__(self, component: str):
        self.component = component
        self.repo = Path(__file__).resolve().parents[1]
        self.root = Path(tempfile.mkdtemp(prefix=f"aweb-{component}-skew-"))

    def _materialize(self, artifact: PackageArtifact) -> Path:
        path = self.root / artifact.sha256 / artifact.filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(artifact.bytes)
        if hashlib.sha256(path.read_bytes()).hexdigest() != artifact.sha256:
            raise rd.ReceiptError("artifact bytes changed while materializing journey")
        return path

    def _client_root(self, artifact: PackageArtifact) -> Path:
        tgz = self._materialize(artifact)
        prefix = tgz.parent / "installed"
        result = subprocess.run(
            ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund",
             "--prefix", str(prefix), str(tgz)],
            capture_output=True,
        )
        if result.returncode != 0:
            raise rd.ReceiptError(
                "exact client tgz install failed: "
                + result.stderr.decode(errors="replace")[-2000:]
            )
        package = CLIENT_ARTIFACTS[artifact.component].removeprefix("npm:")
        package_root = prefix / "node_modules" / package
        manifest = json.loads((package_root / "package.json").read_bytes())
        if manifest.get("version") != artifact.version:
            raise rd.ReceiptError(
                f"installed {artifact.component} reports {manifest.get('version')}, "
                f"expected {artifact.version}"
            )
        return package_root

    def _run(self, command: list[str], env: dict, direction: str) -> dict:
        child_env = dict(os.environ)
        for key in CLOSED_AMBIENT_ENV:
            child_env.pop(key, None)
        child_env.update(env)
        child_env["KEEP_OAS_PROOF"] = "0"
        child_env["OAS_PROOF_REPORT"] = str(self.root / "oas-proof-report.json")
        result = subprocess.run(
            command, cwd=self.repo, env=child_env, capture_output=True
        )
        if result.returncode != 0:
            raise rd.ReceiptError(
                f"skew journey command failed ({' '.join(command)}): "
                + result.stderr.decode(errors="replace")[-4000:]
            )
        observation = parse_observation(
            result.stdout, self.component, direction,
            env.get("AWEB_SKEW_SERVER_VERSION"),
        )
        return {
            **observation,
            "command": command,
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        }

    def _journey(self, client, server, cell) -> dict:
        client_root = self._client_root(client)
        server_wheel = self._materialize(server)
        constraints_body, constraints_digest, _ = server_runtime_constraints()
        constraints_path = self.root / "server-runtime-constraints.txt"
        constraints_path.write_bytes(constraints_body)
        if hashlib.sha256(constraints_path.read_bytes()).hexdigest() != constraints_digest:
            raise rd.ReceiptError("server runtime constraints changed while materializing")
        project = compose_project_name(self.root, cell)
        common = {
            "AWEB_SKEW_SERVER_WHEEL": str(server_wheel),
            "AWEB_SKEW_PROJECT_TOKEN": project,
            "OAS_PROOF_PROJECT": project,
            "AWEB_SKEW_SERVER_SHA256": server.sha256,
            "AWEB_SKEW_SERVER_VERSION": server.version,
            "AWEB_SKEW_SERVER_CONSTRAINTS": str(constraints_path),
            "AWEB_SKEW_SERVER_CONSTRAINTS_SHA256": constraints_digest,
            "AWEB_SKEW_CELL_ID": cell_identity(cell),
            "AWEB_SKEW_DIRECTION": cell.direction,
        }
        if client.component == "channel":
            return self._run(
                ["npm", "--prefix", "channel", "run", "test:integration"],
                {**common, "AWEB_CHANNEL_PACKAGE_ROOT": str(client_root)},
                cell.direction,
            )
        return self._run(
            ["make", "test-oas-pi-resident-e2e"],
            {**common, "OAS_PROOF_PI_PACKAGE_ROOT": str(client_root)},
            cell.direction,
        )

    def run_client_request(self, client, server, cell):
        return self._journey(client, server, cell)

    def run_server_event(self, client, server, cell):
        return self._journey(client, server, cell)

    def run_mark_read_control(self, payload):
        command = [
            "uv", "run", "--project", str(self.repo / "server"),
            "--frozen", "--quiet", "python",
            str(self.repo / "scripts/e2e/mark_read_skew_control.py"),
            "--message-id", payload["up_to_message_id"],
        ]
        result = subprocess.run(command, cwd=self.repo, capture_output=True)
        if result.returncode != 0:
            raise rd.ReceiptError(
                "mark-read mutation control failed: "
                + result.stderr.decode(errors="replace")[-2000:]
            )
        return json.loads(result.stdout)

    def close(self):
        import shutil
        try:
            shutil.rmtree(self.root)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise rd.ReceiptError(
                f"skew journey cleanup failed for {self.root}: {exc}"
            ) from exc
        if self.root.exists():
            raise rd.ReceiptError(
                f"skew journey cleanup left its root behind: {self.root}"
            )


def _factory(component: str):
    configured = os.getenv("AWEB_CHANNEL_PI_SKEW_EVIDENCE_DIR")
    base = Path(configured or (
        Path(tempfile.gettempdir()) / "aweb-channel-pi-skew-evidence"
    ))
    return ChannelPiHarness(
        resolver=ArtifactResolver(),
        journey_factory=lambda: SubprocessChannelPiJourney(component),
        evidence=FileEvidenceWriter(base / component),
    )


def channel_factory():
    return _factory("channel")


def pi_factory():
    return _factory("pi")


def _version_key(value: str):
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError as exc:
        raise rd.ReceiptError(f"measured version {value!r} is not dotted numeric") from exc


def _canonical_json_digest(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _validate_artifact_against_side(
    artifact: dict, side: dict, locator: str
) -> None:
    component = side.get("component")
    if (
        not isinstance(artifact, dict)
        or set(artifact) != {"component", "filename", "version", "sha256", "source"}
        or artifact.get("component") != component
        or artifact.get("version") != side.get("version")
        or not isinstance(artifact.get("filename"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", artifact.get("sha256", ""))
    ):
        raise rd.ReceiptError(
            f"{component} artifact does not bind its frozen cell preimage"
        )
    source = artifact.get("source") or {}
    if side.get("kind") == "candidate":
        digest_set = side.get("digest_set")
        filename = artifact["filename"]
        if (
            set(source) != {
                "kind", "lane_ref", "outer_zip_sha256",
                "canonical_set_digest", "digest_set",
            }
            or source.get("kind") != "candidate"
            or source.get("lane_ref") != side.get("lane_ref")
            or source.get("digest_set") != digest_set
            or not isinstance(digest_set, dict)
            or source.get("canonical_set_digest") != rd.canonical_digest_of_set(digest_set)
            or digest_set.get(filename) != artifact["sha256"]
            or side.get("digest") != rd.canonical_digest_of_set(digest_set)
        ):
            raise rd.ReceiptError(
                f"candidate {component} artifact does not bind its LaneRef/"
                "payload complete-set preimage"
            )
    else:
        digest_set = source.get("digest_set")
        expected_source_fields = (
            {"kind", "registry", "metadata_url", "tarball_url",
             "digest_set", "canonical_set_digest"}
            if component in CLIENT_ARTIFACTS else
            {"kind", "registry", "metadata_url", "download_url",
             "digest_set", "canonical_set_digest"}
        )
        metadata_url = urllib.parse.urlparse(source.get("metadata_url", ""))
        payload_url = urllib.parse.urlparse(
            source.get(
                "tarball_url" if component in CLIENT_ARTIFACTS else "download_url",
                "",
            )
        )
        expected_metadata = (
            f"https://registry.npmjs.org/"
            f"{CLIENT_ARTIFACTS[component].removeprefix('npm:').replace('/', '%2F')}/"
            f"{artifact['version']}"
            if component in CLIENT_ARTIFACTS else
            f"https://pypi.org/pypi/aweb/{artifact['version']}/json"
        )
        safe_payload = (
            payload_url.scheme == "https"
            and payload_url.username is None
            and payload_url.password is None
            and payload_url.port is None
            and not payload_url.params
            and not payload_url.query
            and not payload_url.fragment
            and urllib.parse.unquote(Path(payload_url.path).name)
                == artifact["filename"]
            and payload_url.netloc == (
                "registry.npmjs.org"
                if component in CLIENT_ARTIFACTS else "files.pythonhosted.org"
            )
        )
        if (
            set(source) != expected_source_fields
            or source.get("kind") != "published"
            or source.get("registry") != locator
            or source.get("metadata_url") != expected_metadata
            or not safe_payload
            or not isinstance(digest_set, dict) or not digest_set
            or any(not re.fullmatch(r"[0-9a-f]{64}", value or "")
                   for value in digest_set.values())
            or digest_set.get(artifact["filename"]) != artifact["sha256"]
            or source.get("canonical_set_digest")
                != rd.canonical_digest_of_set(digest_set)
        ):
            raise rd.ReceiptError(
                f"published {component} artifact does not bind its complete "
                f"registry identity {locator}"
            )


def aggregate_support(
    reports: list[dict], *, expected_cells: list, matrix_id: str | None = None,
) -> dict:
    """Build an explicitly unanchored body from every exact frozen cell."""
    if not expected_cells:
        raise rd.ReceiptError("no expected frozen skew cells were supplied")
    expected_preimages = [cell_preimage(cell) for cell in expected_cells]
    edge_bindings = {
        json.dumps({
            key: preimage[key]
            for key in (
                "edge_id", "edge_a", "edge_b", "journey", "artifacts",
                "declared_direction",
            )
        }, sort_keys=True, separators=(",", ":"))
        for preimage in expected_preimages
    }
    if len(edge_bindings) != 1:
        raise rd.ReceiptError("support aggregation accepts exactly one runtime edge")
    expected = {
        cell_identity_from_preimage(preimage): preimage
        for preimage in expected_preimages
    }
    if len(expected) != len(expected_cells):
        raise rd.ReceiptError("expected frozen matrix contains duplicate exact cells")
    ids = [report.get("cell_id") for report in reports]
    duplicates = sorted({identity for identity in ids if ids.count(identity) > 1})
    if duplicates:
        raise rd.ReceiptError(f"duplicate exact cells in evidence: {duplicates}")
    missing = sorted(set(expected) - set(ids))
    extra = sorted(set(ids) - set(expected))
    if missing or extra:
        raise rd.ReceiptError(
            f"missing exact cells {missing}; unexpected exact cells {extra}"
        )

    clients: set[str] = set()
    servers: set[str] = set()
    candidate_identities: dict[str, dict] = {}
    published_identities: dict[tuple[str, str], dict] = {}
    server_runtime_identities: dict[tuple[str, str], dict] = {}
    evidence = []
    for report in reports:
        identity = report["cell_id"]
        preimage = expected[identity]
        if report.get("cell") != preimage:
            raise rd.ReceiptError(f"cell {identity} does not carry its exact cell preimage")
        if cell_identity_from_preimage(report["cell"]) != identity:
            raise rd.ReceiptError(f"cell {identity} identity does not recompute")
        without_id = {key: value for key, value in report.items() if key != "report_id"}
        if (
            set(report) != {
                "schema", "result", "matrix_id", "cell_id", "cell",
                "edge_id", "edge", "journey", "artifacts",
                "declared_direction", "cell_direction", "client_kind",
                "server_kind", "client_artifact", "server_artifact",
                "server_runtime", "observation", "report_id",
            }
            or report.get("schema") != "aweb.channel-pi-server-skew-cell.v1"
            or report.get("matrix_id") != matrix_id
            or report.get("report_id") != rd.canonical_json_digest(without_id)
        ):
            raise rd.ReceiptError(f"cell {identity} has the wrong evidence schema/digest")
        expected_top = {
            "edge_id": preimage["edge_id"],
            "edge": {"a": preimage["edge_a"], "b": preimage["edge_b"]},
            "journey": preimage["journey"],
            "artifacts": preimage["artifacts"],
            "declared_direction": preimage["declared_direction"],
            "cell_direction": preimage["direction"],
        }
        for key, value in expected_top.items():
            if report.get(key) != value:
                raise rd.ReceiptError(
                    f"cell {identity} top-level {key} differs from its cell preimage"
                )
        if (
            report.get("client_kind") != preimage["a_kind"]
            or report.get("server_kind") != preimage["b_kind"]
        ):
            raise rd.ReceiptError(f"cell {identity} kind differs from its cell preimage")
        direction = preimage["direction"]
        observation = report.get("observation") or {}
        expected_key = "request" if direction == "a-to-b" else "event"
        if set(observation) != {expected_key}:
            raise rd.ReceiptError(
                f"cell {identity} lacks its {expected_key} assertion"
            )
        validate_observation(
            observation[expected_key], preimage["edge_a"], direction,
            preimage["b"]["version"],
        )
        runtime = report.get("server_runtime")
        if runtime != observation[expected_key].get("server_runtime"):
            raise rd.ReceiptError(
                f"cell {identity} runtime inventory differs from its observation"
            )
        if report.get("result") != "green":
            raise rd.ReceiptError(f"cell {identity} is not green")
        client = report.get("client_artifact")
        server = report.get("server_artifact")
        a_side = {"kind": preimage["a_kind"], **preimage["a"]}
        b_side = {"kind": preimage["b_kind"], **preimage["b"]}
        _validate_artifact_against_side(
            client, a_side, preimage["artifacts"]["a"]
        )
        _validate_artifact_against_side(
            server, b_side, preimage["artifacts"]["b"]
        )
        runtime_key = (server["version"], server["sha256"])
        prior_runtime = server_runtime_identities.setdefault(runtime_key, runtime)
        if prior_runtime != runtime:
            raise rd.ReceiptError(
                f"server runtime inventory differs for exact artifact {runtime_key}"
            )
        for side, artifact in ((a_side, client), (b_side, server)):
            component = side["component"]
            if side["kind"] == "candidate":
                prior = candidate_identities.setdefault(component, artifact)
                if prior != artifact:
                    raise rd.ReceiptError(
                        f"candidate {component} identity differs across exact cells"
                    )
            else:
                key = (component, side["version"])
                prior = published_identities.setdefault(key, artifact)
                if prior != artifact:
                    raise rd.ReceiptError(
                        f"published {component} {side['version']} identity "
                        "differs across exact cells"
                    )
        if str(preimage["a_kind"]).startswith("published"):
            clients.add(client["version"])
        if str(preimage["b_kind"]).startswith("published"):
            servers.add(server["version"])
        evidence.append({
            "cell_id": identity,
            "cell": preimage,
            "report_sha256": _canonical_json_digest(report),
            "client_artifact": client,
            "server_artifact": server,
            "server_runtime": runtime,
        })

    first = expected_preimages[0]
    measurement = {
        "schema": "aweb.runtime-support-measurement.v1",
        "completeness": "unanchored-local-measurement",
        "status": "incomplete-unanchored",
        "support_complete": False,
        "anchor": None,
        "matrix_id": matrix_id,
        "edge_id": first["edge_id"],
        "edge": {"a": first["edge_a"], "b": first["edge_b"]},
        "journey": first["journey"],
        "artifacts": first["artifacts"],
        "direction": first["declared_direction"],
        "supported_versions": {
            first["edge_a"]: sorted(clients, key=_version_key),
            "server": sorted(servers, key=_version_key),
        },
        "candidates": candidate_identities,
        "published_identities": [
            published_identities[key] for key in sorted(published_identities)
        ],
        "evidence": evidence,
    }
    measurement["measurement_id"] = rd.canonical_json_digest(measurement)
    return measurement


def _require_channel_report_files(document: dict, evidence_root: Path) -> dict[str, Path]:
    cells = rd.validate_skew_matrix_document(document)
    matrix_id = document["matrix_id"]
    expected = {
        f"{matrix_id}-{rd.skew_cell_identity(cell)}.json" for cell in cells
    }
    cell_dir = Path(evidence_root) / "cells"
    try:
        entries = list(cell_dir.iterdir())
    except OSError as exc:
        raise rd.ReceiptError(f"channel/Pi reports are unreadable: {exc}") from exc
    actual = {
        item.name: item for item in entries
        if item.is_file() and not item.is_symlink()
    }
    if set(actual) != expected or len(entries) != len(expected):
        raise rd.ReceiptError(
            "channel/Pi report-file set does not equal the frozen matrix; "
            f"missing={sorted(expected - set(actual))}, "
            f"extra={sorted(set(actual) - expected)}"
        )
    return actual


def aggregate_frozen_matrix(
    matrix_path: Path, evidence_root: Path, *, control_path: Path,
) -> dict:
    matrix_path = Path(matrix_path)
    matrix_body = matrix_path.read_bytes()
    document = json.loads(matrix_body)
    if matrix_body != json.dumps(
        document, sort_keys=True, separators=(",", ":")
    ).encode():
        raise rd.ReceiptError("channel/Pi matrix is not canonical JSON")
    cells = rd.validate_skew_matrix_document(document)
    matrix_id = document["matrix_id"]
    if matrix_path.name != f"matrix-{matrix_id}.json":
        raise rd.ReceiptError("channel/Pi matrix filename does not equal its identity")
    expected = {
        f"{matrix_id}-{rd.skew_cell_identity(cell)}.json": cell
        for cell in cells
    }
    actual = _require_channel_report_files(document, evidence_root)
    reports = []
    for filename in expected:
        body = actual[filename].read_bytes()
        report = json.loads(body)
        if body != json.dumps(
            report, sort_keys=True, separators=(",", ":")
        ).encode():
            raise rd.ReceiptError(f"{filename}: report is not canonical JSON")
        reports.append(report)
    measurement = aggregate_support(
        reports, expected_cells=cells, matrix_id=matrix_id
    )
    measurement["supported_versions"] = document["preimage"]["support"][
        "supported_versions"
    ]
    expected_candidates = set(document["preimage"]["staged"])
    if set(measurement["candidates"]) != expected_candidates:
        raise rd.ReceiptError(
            "channel/Pi candidate identities do not equal the frozen matrix"
        )
    control_body = Path(control_path).read_bytes()
    control = json.loads(control_body)
    without_id = {key: value for key, value in control.items() if key != "control_id"}
    if (
        set(control) != {
            "schema", "matrix_id", "request", "unmutated_status",
            "mutated_status", "mutation_subject", "evidence_class", "control_id",
        }
        or control.get("schema") != "aweb.channel-pi-skew-control.v1"
        or control.get("matrix_id") != matrix_id
        or control.get("request") != LEGACY_MARK_READ_REQUEST
        or control.get("unmutated_status") != 200
        or control.get("mutated_status") != 422
        or control.get("evidence_class") != "control-only-not-candidate"
        or control.get("control_id") != rd.canonical_json_digest(without_id)
        or control_body != json.dumps(
            control, sort_keys=True, separators=(",", ":")
        ).encode()
    ):
        raise rd.ReceiptError("channel/Pi control evidence is invalid")
    measurement.update({
        "staged_manifest_digest": document["preimage"]["staged_manifest_digest"],
        "published_versions": document["preimage"]["published_versions"],
        "control": {
            "control_id": control["control_id"],
            "file_sha256": hashlib.sha256(control_body).hexdigest(),
            "evidence_class": "control-only-not-candidate",
        },
    })
    measurement.pop("measurement_id", None)
    measurement["measurement_id"] = rd.canonical_json_digest(measurement)
    return measurement
