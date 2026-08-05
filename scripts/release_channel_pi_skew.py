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
import subprocess
import tarfile
import tempfile
import urllib.error
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


def parse_observation(output: bytes, direction: str) -> dict:
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
    if observation.get("direction") != direction:
        raise rd.ReceiptError(
            f"skew journey observation {observation.get('direction')!r} does not "
            f"match cell direction {direction!r}"
        )
    if not isinstance(observation.get("assertion"), str) or not observation["assertion"]:
        raise rd.ReceiptError("skew journey observation has no assertion")
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


def cell_identity(cell) -> str:
    preimage = {
        "edge_id": cell.edge_id,
        "journey": cell.journey,
        "artifacts": cell.artifacts,
        "declared_direction": cell.declared_direction,
        "cell_direction": cell.direction,
        "a": _side_identity(cell.a_kind, cell.a),
        "b": _side_identity(cell.b_kind, cell.b),
    }
    return hashlib.sha256(
        json.dumps(preimage, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class FileEvidenceWriter:
    def __init__(self, root: Path | None = None):
        configured = os.getenv("AWEB_CHANNEL_PI_SKEW_EVIDENCE_DIR")
        self.root = Path(root or configured or (
            Path(tempfile.gettempdir()) / "aweb-channel-pi-skew-evidence"
        )).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def write(self, report: dict) -> None:
        body = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        identity = hashlib.sha256(body).hexdigest()
        path = self.root / f"cell-{report['cell_id']}-{identity}.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(body)
        os.replace(temporary, path)
        print(f"channel/Pi skew evidence: {path} sha256:{identity}")


class ChannelPiHarness:
    def __init__(self, *, resolver: ArtifactResolver, journey, evidence):
        self._resolver = resolver
        self._journey = journey
        self._evidence = evidence

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
        client_component = self._validate_cell(cell)
        client = self._resolver.resolve(
            cell.a_kind, cell.a, cell.artifacts["a"]
        )
        server = self._resolver.resolve(
            cell.b_kind, cell.b, cell.artifacts["b"]
        )
        negative = None
        try:
            if cell.direction == "a-to-b":
                observation = {"request": self._journey.run_client_request(
                    client, server, cell
                )}
            else:
                observation = {"event": self._journey.run_server_event(
                    client, server, cell
                )}
            if cell.a_kind in PUBLISHED_KINDS and cell.b_kind == "candidate":
                measured = self._journey.run_mark_read_control(
                    dict(LEGACY_MARK_READ_REQUEST)
                )
                if (
                    measured.get("unmutated_status") != 200
                    or measured.get("mutated_status") != 422
                ):
                    raise rd.ReceiptError(
                        "required-field control must observe 200 on the "
                        "unmutated server and 422 on the disposable mutation"
                    )
                negative = {
                    "request": dict(LEGACY_MARK_READ_REQUEST),
                    "unmutated_status": 200,
                    "mutated_status": 422,
                    "mutation_subject": measured.get("mutation_subject"),
                    "evidence_class": "control-only-not-candidate",
                }
            report = {
                "schema": "aweb.channel-pi-server-skew-cell.v1",
                "result": "green",
                "cell_id": cell_identity(cell),
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
                "observation": observation,
                "negative_control": negative,
            }
            self._evidence.write(report)
        finally:
            self._journey.close()

    @staticmethod
    def _artifact_report(artifact: PackageArtifact) -> dict:
        return {
            "component": artifact.component,
            "filename": artifact.filename,
            "version": artifact.version,
            "sha256": artifact.sha256,
            "source": dict(artifact.source),
        }


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
        result = subprocess.run(command, cwd=self.repo, env={**os.environ, **env},
                                capture_output=True)
        if result.returncode != 0:
            raise rd.ReceiptError(
                f"skew journey command failed ({' '.join(command)}): "
                + result.stderr.decode(errors="replace")[-4000:]
            )
        observation = parse_observation(result.stdout, direction)
        return {
            **observation,
            "command": command,
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        }

    def _journey(self, client, server, cell) -> dict:
        client_root = self._client_root(client)
        server_wheel = self._materialize(server)
        common = {
            "AWEB_SKEW_SERVER_WHEEL": str(server_wheel),
            "AWEB_SKEW_SERVER_SHA256": server.sha256,
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
        shutil.rmtree(self.root, ignore_errors=True)


def _factory(component: str):
    return ChannelPiHarness(
        resolver=ArtifactResolver(),
        journey=SubprocessChannelPiJourney(component),
        evidence=FileEvidenceWriter(),
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


def aggregate_support(reports: list[dict], *, expected_cell_ids: list[str]) -> dict:
    """Create an explicitly unanchored document only from complete exact cells."""
    ids = [report.get("cell_id") for report in reports]
    duplicates = sorted({identity for identity in ids if ids.count(identity) > 1})
    if duplicates:
        raise rd.ReceiptError(f"duplicate exact cells in evidence: {duplicates}")
    missing = sorted(set(expected_cell_ids) - set(ids))
    extra = sorted(set(ids) - set(expected_cell_ids))
    if missing or extra:
        raise rd.ReceiptError(
            f"missing exact cells {missing}; unexpected exact cells {extra}"
        )
    clients = set()
    servers = set()
    for report in reports:
        direction = report.get("cell_direction")
        observation = report.get("observation") or {}
        if direction == "a-to-b" and set(observation) != {"request"}:
            raise rd.ReceiptError(
                f"cell {report.get('cell_id')} lacks its request assertion"
            )
        if direction == "b-to-a" and set(observation) != {"event"}:
            raise rd.ReceiptError(
                f"cell {report.get('cell_id')} lacks its event assertion"
            )
        if report.get("result") != "green":
            raise rd.ReceiptError(f"cell {report.get('cell_id')} is not green")
        client = report["client_artifact"]
        server = report["server_artifact"]
        if str(report["client_kind"]).startswith("published"):
            clients.add(client["version"])
        if str(report["server_kind"]).startswith("published"):
            servers.add(server["version"])
    first = reports[0]
    return {
        "schema": "aweb.runtime-support-measurement.v1",
        "completeness": "unanchored-local-measurement",
        "edge": first["edge"],
        "journey": first["journey"],
        "artifacts": first["artifacts"],
        "direction": first["declared_direction"],
        "supported_versions": {
            first["edge"]["a"]: sorted(clients, key=_version_key),
            "server": sorted(servers, key=_version_key),
        },
        "evidence": [
            {"cell_id": report["cell_id"], "direction": report["cell_direction"]}
            for report in reports
        ],
    }
