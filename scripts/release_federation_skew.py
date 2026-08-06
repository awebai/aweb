"""Exact-wheel child harness for the federation server/server skew edge."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

import release_driver

JOURNEY = "make test-federation-e2e (both request directions)"
PYPI_METADATA = "https://pypi.org/pypi/aweb/{version}/json"
FIRST_FEDERATION_VERSION = "1.23.0"
MISSING_FEDERATION_VERSION = "1.22.1"
REPO_ROOT = Path(__file__).resolve().parents[1]
FEDERATION_SCRIPT = REPO_ROOT / "scripts/e2e-oss-federation.sh"
PYPI_WORKFLOW = ".github/workflows/pypi-release.yml"
OBSERVATION_PREFIX = "AWEB_FEDERATION_SKEW_OBSERVATION="
OBSERVATION_SCHEMA = "aweb.release.federation-skew-observation.v1"
CONTROL_RUNTIME_PREFIX = "AWEB_FEDERATION_SKEW_CONTROL_RUNTIME="
CONTROL_RUNTIME_SCHEMA = "aweb.release.federation-skew-control-runtime.v1"
CELL_REPORT_SCHEMA = "aweb.release.federation-skew-cell-report.v1"
AGGREGATE_SCHEMA = "aweb.release.federation-skew-aggregate.v1"
CONTROL_SCHEMA = "aweb.release.federation-skew-control.v1"
SUPPORT_SCHEMA = "aweb.runtime-support-measurement.v1"
DEFAULT_REPORT_DIR = REPO_ROOT / ".release-runs/federation-skew"
REQUIRED_OUTCOMES = {
    "encrypted_chat": True,
    "encrypted_mail": True,
    "fail_closed": True,
    "plaintext_mail": True,
    "replay_idempotent": True,
    "route_validation": True,
}


@dataclass(frozen=True)
class WheelArtifact:
    name: str
    version: str
    bytes: bytes
    sha256: str
    release_digest_set: dict[str, str]
    release_set_digest: str
    info_version: str

    def __post_init__(self) -> None:
        if Path(self.name).name != self.name or not self.name.endswith(".whl"):
            raise release_driver.ReceiptError(
                f"unsafe or non-wheel artifact name {self.name!r}"
            )
        if not re.fullmatch(r"\d+(?:\.\d+)+", self.version or ""):
            raise release_driver.ReceiptError(
                f"wheel version must be dotted numeric, got {self.version!r}"
            )
        actual = hashlib.sha256(self.bytes).hexdigest()
        if actual != self.sha256:
            raise release_driver.ReceiptError(
                f"{self.name}: wheel bytes hash {actual}, declared {self.sha256}"
            )
        valid_set = (
            isinstance(self.release_digest_set, dict)
            and bool(self.release_digest_set)
            and all(
                isinstance(name, str)
                and Path(name).name == name
                and isinstance(digest, str)
                and bool(re.fullmatch(r"[0-9a-f]{64}", digest))
                for name, digest in self.release_digest_set.items()
            )
        )
        if (
            not valid_set
            or self.release_digest_set.get(self.name) != self.sha256
            or self.release_set_digest
            != release_driver.canonical_digest_of_set(self.release_digest_set)
            or self.info_version != self.version
        ):
            raise release_driver.ReceiptError(
                f"{self.name}: release identity is incomplete or inconsistent"
            )


class WheelResolver:
    """Resolve candidate bytes through two authorities and published bytes
    through exact version metadata. Neither path builds or repacks a wheel."""

    def __init__(self, *, store=None, authority=None, urlopen=None):
        self._store = store or release_driver.GithubArtifactStore(
            repo="awebai/aweb", workflow_path=PYPI_WORKFLOW
        )
        self._authority = authority or release_driver.GithubArtifactDigestAuthority(
            repo="awebai/aweb", workflow_path=PYPI_WORKFLOW
        )
        self._urlopen = urlopen or urllib.request.urlopen

    def candidate(self, side: dict) -> WheelArtifact:
        if side.get("component") != "server":
            raise release_driver.ReceiptError(
                f"federation skew candidate must be server, got {side!r}"
            )
        version = side.get("version")
        ref = release_driver.LaneRef.from_dict(side.get("lane_ref"))
        independently_recorded = self._authority.expected_digest(ref.artifact)
        if f"sha256:{independently_recorded}" != ref.zip_digest:
            raise release_driver.ReceiptError(
                "server candidate lane reference disagrees with the independent "
                "GitHub artifact digest authority"
            )
        archive_bytes = self._store.get(ref.artifact)
        actual_zip = f"sha256:{hashlib.sha256(archive_bytes).hexdigest()}"
        if actual_zip != ref.zip_digest:
            raise release_driver.ReceiptError(
                f"server candidate artifact hashes to {actual_zip}, not {ref.zip_digest}"
            )
        manifest = release_driver.validate_pypi_lane_artifact(
            archive_bytes,
            expected_source_sha=ref.aw_source_sha,
            expected_version=version,
            package="server",
            pypi_name="aweb",
        )
        files = manifest["files"]
        if side.get("digest_set") != files:
            raise release_driver.ReceiptError(
                "server candidate cell digest_set does not equal the validated "
                "staged PyPI manifest"
            )
        canonical = release_driver.canonical_digest_of_set(files)
        if side.get("digest") != canonical:
            raise release_driver.ReceiptError(
                f"server candidate cell digest {side.get('digest')!r} does not "
                f"equal staged set {canonical}"
            )
        wheel_names = [name for name in files if name.endswith(".whl")]
        if len(wheel_names) != 1:
            raise release_driver.ReceiptError(
                f"server candidate binds {len(wheel_names)} wheels, expected one"
            )
        name = wheel_names[0]
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            wheel_bytes = archive.read(f"dist/{name}")
        digest = hashlib.sha256(wheel_bytes).hexdigest()
        if digest != files[name]:
            raise release_driver.ReceiptError(
                f"{name}: extracted wheel hash {digest}, manifest {files[name]}"
            )
        return WheelArtifact(
            name,
            version,
            wheel_bytes,
            digest,
            dict(files),
            canonical,
            version,
        )

    def published(self, version: str) -> WheelArtifact:
        metadata_url = PYPI_METADATA.format(version=version)
        metadata = self._read_metadata(metadata_url, version)
        if metadata.get("info", {}).get("version") != version:
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} metadata binds version "
                f"{metadata.get('info', {}).get('version')!r}"
            )
        records = metadata.get("urls")
        if not isinstance(records, list) or not records:
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} release file set is empty"
            )
        release_set = {}
        by_type = {}
        for record in records:
            if not isinstance(record, dict):
                raise release_driver.ReceiptError(
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
                or parsed.netloc != "files.pythonhosted.org"
                or bool(parsed.params)
                or bool(parsed.query)
                or bool(parsed.fragment)
                or Path(urllib.parse.unquote(parsed.path)).name != name
            ):
                raise release_driver.ReceiptError(
                    f"PyPI aweb {version} has invalid release record {record!r}"
                )
            if name in release_set:
                raise release_driver.ReceiptError(
                    f"PyPI aweb {version} repeats release filename {name}"
                )
            release_set[name] = digest
            by_type.setdefault(package_type, []).append(record)
        expected_names = {
            f"aweb-{version}-py3-none-any.whl",
            f"aweb-{version}.tar.gz",
        }
        if set(release_set) != expected_names or set(by_type) != {"bdist_wheel", "sdist"}:
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} release file set is not exact: "
                f"got {sorted(release_set)}, expected {sorted(expected_names)}"
            )
        wheels = by_type["bdist_wheel"]
        if len(wheels) != 1 or len(by_type["sdist"]) != 1:
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} metadata must bind one wheel and one sdist"
            )
        wheel = wheels[0]
        name = wheel["filename"]
        digest = release_set[name]
        url = wheel["url"]
        request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
        try:
            with self._urlopen(request, timeout=30) as response:
                wheel_bytes = response.read()
        except urllib.error.HTTPError as exc:
            exc.close()
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} wheel download failed: HTTP {exc.code}"
            ) from exc
        except Exception as exc:
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} wheel download failed: {exc}"
            ) from exc
        actual = hashlib.sha256(wheel_bytes).hexdigest()
        if actual != digest:
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} wheel hashes to {actual}, metadata {digest}"
            )
        return WheelArtifact(
            name,
            version,
            wheel_bytes,
            digest,
            release_set,
            release_driver.canonical_digest_of_set(release_set),
            metadata["info"]["version"],
        )

    def _read_metadata(self, url: str, version: str) -> dict:
        request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
        try:
            with self._urlopen(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            if code == 404:
                raise release_driver.ReceiptError(
                    f"PyPI aweb {version} is absent (metadata HTTP 404)"
                ) from exc
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} metadata unavailable: HTTP {code}"
            ) from exc
        except Exception as exc:
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} metadata unavailable: {exc}"
            ) from exc
        try:
            metadata = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} metadata is malformed: {exc}"
            ) from exc
        if not isinstance(metadata, dict):
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} metadata is not an object"
            )
        return metadata

    def side(self, side: dict, kind: str) -> WheelArtifact:
        if kind == "candidate":
            return self.candidate(side)
        if kind in {"published", "published-floor", "published-latest"}:
            if side.get("component") != "server":
                raise release_driver.ReceiptError(
                    f"federation skew published side must be server, got {side!r}"
                )
            return self.published(side.get("version"))
        raise release_driver.ReceiptError(
            f"unsupported federation skew side kind {kind!r}"
        )


def _canonical_bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _identity(value) -> str:
    return hashlib.sha256(_canonical_bytes(value).rstrip(b"\n")).hexdigest()


def cell_preimage(cell) -> dict:
    """The full immutable cell preimage; edge identity alone aliases every
    direction and candidate/published pairing on the federation edge."""

    return {
        "a": dict(cell.a),
        "a_kind": cell.a_kind,
        "artifacts": dict(cell.artifacts),
        "b": dict(cell.b),
        "b_kind": cell.b_kind,
        "declared_direction": cell.declared_direction,
        "direction": cell.direction,
        "edge_a": cell.edge_a,
        "edge_b": cell.edge_b,
        "edge_id": cell.edge_id,
        "journey": cell.journey,
    }


def cell_identity(cell) -> str:
    return _identity(cell_preimage(cell))


def _atomic_report(path: Path, value: dict) -> str:
    body = _canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return hashlib.sha256(body).hexdigest()


def locked_mcp_version() -> str:
    with (REPO_ROOT / "server/uv.lock").open("rb") as stream:
        packages = tomllib.load(stream).get("package", [])
    versions = [item.get("version") for item in packages if item.get("name") == "mcp"]
    if len(versions) != 1 or not isinstance(versions[0], str) or not versions[0]:
        raise release_driver.ReceiptError(
            f"server/uv.lock must bind exactly one mcp version, found {versions!r}"
        )
    return versions[0]


@dataclass
class InvocationReservation:
    token: str
    project: str
    ports: tuple[int, int, int]
    _sockets: list[socket.socket]

    def release(self) -> None:
        while self._sockets:
            self._sockets.pop().close()


def _token_port(token: str, counter: int) -> int:
    digest = hashlib.sha256(f"{token}:{counter}".encode()).digest()
    return 20000 + int.from_bytes(digest[:4], "big") % 40000


def reserve_invocation(*, token: str | None = None) -> InvocationReservation:
    """Reserve three token-derived loopback ports until immediately before
    Compose starts. A colliding derived port is skipped, never reused."""

    token = token or secrets.token_hex(16)
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        raise release_driver.ReceiptError(
            f"federation invocation token must be 32 lowercase hex, got {token!r}"
        )
    sockets: list[socket.socket] = []
    ports: list[int] = []
    counter = 0
    try:
        while len(ports) < 3 and counter < 1000:
            port = _token_port(token, counter)
            counter += 1
            if port in ports:
                continue
            reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                reservation.bind(("127.0.0.1", port))
            except OSError:
                reservation.close()
                continue
            sockets.append(reservation)
            ports.append(port)
        if len(ports) != 3:
            raise release_driver.ReceiptError(
                f"could not reserve three loopback ports for invocation {token}"
            )
        return InvocationReservation(
            token=token,
            project=f"aweb-fed-e2e-{token}",
            ports=tuple(ports),
            _sockets=sockets,
        )
    except BaseException:
        for reservation in sockets:
            reservation.close()
        raise


def _write_wheel(root: Path, side: str, wheel: WheelArtifact) -> Path:
    directory = root / side
    directory.mkdir()
    path = directory / wheel.name
    path.write_bytes(wheel.bytes)
    return path


def _journey_environment(
    root: Path,
    alpha: WheelArtifact,
    beta: WheelArtifact,
    *,
    direction: str,
    cell_id: str,
    invocation: InvocationReservation,
    route_probe_only: bool = False,
) -> dict[str, str]:
    alpha_path = _write_wheel(root, "alpha", alpha)
    beta_path = _write_wheel(root, "beta", beta)
    awid_port, alpha_port, beta_port = invocation.ports
    return {
        "AWEB_FED_E2E_SERVER_MODE": "wheel",
        "AWEB_ALPHA_WHEEL": str(alpha_path),
        "AWEB_ALPHA_WHEEL_SHA256": alpha.sha256,
        "AWEB_ALPHA_VERSION": alpha.version,
        "AWEB_BETA_WHEEL": str(beta_path),
        "AWEB_BETA_WHEEL_SHA256": beta.sha256,
        "AWEB_BETA_VERSION": beta.version,
        "AWEB_FED_E2E_DIRECTION": direction,
        "AWEB_FED_E2E_CELL_ID": cell_id,
        "AWEB_FED_E2E_ROUTE_PROBE_ONLY": "1" if route_probe_only else "0",
        "AWEB_FED_E2E_KEEP": "0",
        "AWEB_FED_E2E_MCP_VERSION": locked_mcp_version(),
        "AWEB_FED_E2E_PROJECT": invocation.project,
        "AWID_FED_E2E_PORT": str(awid_port),
        "AWEB_ALPHA_E2E_PORT": str(alpha_port),
        "AWEB_BETA_E2E_PORT": str(beta_port),
    }


def run_federation_journey(environment: dict[str, str]):
    env = dict(os.environ)
    env.update(environment)
    # A release cell can never inherit the source harness's debugging escape
    # hatch: subprocess success must mean targeted cleanup actually ran.
    env["AWEB_FED_E2E_KEEP"] = "0"
    return subprocess.run(
        [str(FEDERATION_SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=3600,
    )


def _run_reserved_journey(
    root: Path,
    alpha: WheelArtifact,
    beta: WheelArtifact,
    *,
    direction: str,
    cell_id: str,
    journey,
    route_probe_only: bool = False,
):
    invocation = reserve_invocation()
    try:
        environment = _journey_environment(
            root,
            alpha,
            beta,
            direction=direction,
            cell_id=cell_id,
            invocation=invocation,
            route_probe_only=route_probe_only,
        )
        # The bind proves availability and prevents another child selecting the
        # endpoints during preparation. Compose receives them immediately after
        # release and owns the exact project through targeted teardown.
        invocation.release()
        return environment, journey(environment)
    finally:
        invocation.release()


def _wheel_identity(wheel: WheelArtifact) -> dict:
    return {
        "filename": wheel.name,
        "info_version": wheel.info_version,
        "registry_digest_set": dict(wheel.release_digest_set),
        "registry_set_digest": wheel.release_set_digest,
        "sha256": wheel.sha256,
        "version": wheel.version,
    }


def _resolved_identity(wheel: WheelArtifact, side: dict, kind: str) -> dict:
    selected = {"filename": wheel.name, "sha256": wheel.sha256}
    if kind == "candidate":
        expected_fields = {
            "component", "digest", "digest_set", "lane_ref", "version"
        }
        if (
            set(side) != expected_fields
            or side.get("component") != "server"
            or side.get("version") != wheel.version
            or side.get("digest_set") != wheel.release_digest_set
            or side.get("digest") != wheel.release_set_digest
        ):
            raise release_driver.ReceiptError(
                "federation candidate resolved identity does not equal its frozen side"
            )
        release_driver.LaneRef.from_dict(side.get("lane_ref"))
        return {
            "component": "server",
            "digest": side["digest"],
            "digest_set": dict(side["digest_set"]),
            "kind": "candidate",
            "lane_ref": dict(side["lane_ref"]),
            "selected_wheel": selected,
            "version": wheel.version,
        }
    expected_side = {"component", "kind", "version"}
    if (
        kind not in {"published", "published-floor", "published-latest"}
        or set(side) != expected_side
        or side.get("component") != "server"
        or side.get("kind") != kind
        or side.get("version") != wheel.version
    ):
        raise release_driver.ReceiptError(
            "federation published resolved identity does not equal its frozen side"
        )
    return {
        "component": "server",
        "info_version": wheel.info_version,
        "kind": kind,
        "registry": "pypi:aweb",
        "registry_digest_set": dict(wheel.release_digest_set),
        "registry_set_digest": wheel.release_set_digest,
        "selected_wheel": selected,
        "version": wheel.version,
    }


def prove_route_controls(
    resolver,
    journey=run_federation_journey,
    *,
    report_dir: Path = DEFAULT_REPORT_DIR,
) -> dict:
    """Run the historical mutation once as an explicit measurement control.
    Ordinary matrix cells never call this function."""

    first = resolver.published(FIRST_FEDERATION_VERSION)
    missing = resolver.published(MISSING_FEDERATION_VERSION)
    with tempfile.TemporaryDirectory(prefix="aweb-fed-skew-negative-") as tmp:
        negative_env, negative = _run_reserved_journey(
            Path(tmp),
            first,
            missing,
            direction="a-to-b",
            cell_id=f"negative:{MISSING_FEDERATION_VERSION}",
            journey=journey,
            route_probe_only=True,
        )
    negative_output = (negative.stdout or "") + (negative.stderr or "")
    marker = "beta federation route probe returned 404"
    if negative.returncode == 0 or marker not in negative_output:
        raise release_driver.ReceiptError(
            f"federation negative control did not red on exact missing-route "
            f"marker {marker!r}: exit={negative.returncode}, "
            f"output={negative_output[-1000:]}"
        )
    negative_runtime = _parse_control_runtime(negative_output, negative_env)

    with tempfile.TemporaryDirectory(prefix="aweb-fed-skew-positive-") as tmp:
        positive_env, positive = _run_reserved_journey(
            Path(tmp),
            first,
            first,
            direction="a-to-b",
            cell_id=f"positive:{FIRST_FEDERATION_VERSION}",
            journey=journey,
            route_probe_only=True,
        )
    positive_output = (positive.stdout or "") + (positive.stderr or "")
    if positive.returncode != 0:
        raise release_driver.ReceiptError(
            f"federation first-containing release route probe red: "
            f"exit={positive.returncode}, output={positive_output[-1000:]}"
        )
    positive_runtime = _parse_control_runtime(positive_output, positive_env)
    dependency_inventories = {
        _identity(_dependency_inventory(runtime))
        for record in (negative_runtime, positive_runtime)
        for runtime in (record["alpha"], record["beta"])
    }
    if len(dependency_inventories) != 1:
        raise release_driver.ReceiptError(
            "federation control dependency-only inventories differ across runs"
        )

    def invocation(environment: dict[str, str]) -> dict:
        return {
            "ports": {
                "alpha": int(environment["AWEB_ALPHA_E2E_PORT"]),
                "awid": int(environment["AWID_FED_E2E_PORT"]),
                "beta": int(environment["AWEB_BETA_E2E_PORT"]),
            },
            "project": environment["AWEB_FED_E2E_PROJECT"],
        }

    report = {
        "controls": {
            "negative": {
                "expected_marker": marker,
                "invocation": invocation(negative_env),
                "missing_route_wheel": _wheel_identity(missing),
                "observed_exit": negative.returncode,
                "route_present_wheel": _wheel_identity(first),
                "runtime": negative_runtime,
                "runtime_sha256": _identity(negative_runtime),
            },
            "positive": {
                "expected_exit": 0,
                "invocation": invocation(positive_env),
                "observed_exit": positive.returncode,
                "route_present_wheel": _wheel_identity(first),
                "runtime": positive_runtime,
                "runtime_sha256": _identity(positive_runtime),
            },
        },
        "mcp_version": locked_mcp_version(),
        "schema": CONTROL_SCHEMA,
    }
    _atomic_report(Path(report_dir) / "control.json", report)
    return report


def measure_current_published_support(
    version: str,
    *,
    output: Path,
    store_root: Path,
    artifact_id: str,
    resolver=None,
    journey=run_federation_journey,
) -> dict:
    """Measure both federation directions from exact published registry bytes.

    This is the runnerless support-declaration path: it reuses the existing
    wheel journey, records canonical evidence in the existing local immutable
    store/digest authority, and creates no workflow artifact or anchor.
    """

    if not re.fullmatch(r"\d+(?:\.\d+)+", version or ""):
        raise release_driver.ReceiptError(
            f"federation support version must be dotted numeric, got {version!r}"
        )
    if not artifact_id or artifact_id.strip() != artifact_id:
        raise release_driver.ReceiptError(
            "federation support artifact id must be nonempty and canonical"
        )
    resolver = resolver or WheelResolver()
    wheel = resolver.published(version)
    side = {"component": "server", "kind": "published", "version": version}
    resolved = _resolved_identity(wheel, side, "published")
    cells = []
    dependency_digests = set()
    for direction in ("a-to-b", "b-to-a"):
        cell_id = _identity({
            "artifact": _wheel_identity(wheel),
            "direction": direction,
            "journey": JOURNEY,
        })
        with tempfile.TemporaryDirectory(prefix="aweb-fed-current-support-") as tmp:
            environment, result = _run_reserved_journey(
                Path(tmp),
                wheel,
                wheel,
                direction=direction,
                cell_id=cell_id,
                journey=journey,
            )
        combined = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0:
            raise release_driver.ReceiptError(
                f"current federation support {direction} red: "
                f"exit={result.returncode}, output={combined[-2000:]}"
            )
        observation = _parse_observation(combined, environment)
        for runtime in (observation["alpha"], observation["beta"]):
            dependency_digests.add(_identity(_dependency_inventory(runtime)))
        cells.append({
            "cell_id": cell_id,
            "direction": direction,
            "observation": observation,
            "observation_sha256": _identity(observation),
            "resolved": {"alpha": resolved, "beta": resolved},
        })
    if len(dependency_digests) != 1:
        raise release_driver.ReceiptError(
            "current federation support dependency inventories differ across directions"
        )

    document = {
        "artifacts": {"a": "pypi:aweb", "b": "pypi:aweb"},
        "cells": cells,
        "completeness": "recorded-local-authority",
        "direction": "both",
        "edge": {"a": "server", "b": "server"},
        "journey": JOURNEY,
        "published_identity": resolved,
        "schema": SUPPORT_SCHEMA,
        "supported_versions": {"server": [version]},
    }
    document["measurement_id"] = _identity(document)
    digest = _atomic_report(Path(output), document)
    body = Path(output).read_bytes()
    store = release_driver.FileArtifactStore(Path(store_root))
    authority = release_driver.FileDigestAuthority(Path(store_root))
    store.put(artifact_id, body)
    authority.record(artifact_id, digest)
    return {
        "artifact_id": artifact_id,
        "digest": digest,
        "measurement": document,
        "record": {
            "authority": "local-development",
            "artifact_id": artifact_id,
            "digest": digest,
        },
        "set": f"measured:{document['measurement_id']}",
    }


def _expected_observation(environment: dict[str, str]) -> dict:
    initiated = "a" if environment["AWEB_FED_E2E_DIRECTION"] == "a-to-b" else "b"
    runtime = lambda prefix: {
        "mcp_version": environment["AWEB_FED_E2E_MCP_VERSION"],
        "version": environment[f"AWEB_{prefix}_VERSION"],
        "wheel_sha256": environment[f"AWEB_{prefix}_WHEEL_SHA256"],
    }
    return {
        "cell_id": environment["AWEB_FED_E2E_CELL_ID"],
        "initiated_side": initiated,
        "project": environment["AWEB_FED_E2E_PROJECT"],
        "ports": {
            "alpha": int(environment["AWEB_ALPHA_E2E_PORT"]),
            "awid": int(environment["AWID_FED_E2E_PORT"]),
            "beta": int(environment["AWEB_BETA_E2E_PORT"]),
        },
        "runtime": {"alpha": runtime("ALPHA"), "beta": runtime("BETA")},
    }


def _decode_structured_line(output: str, prefix: str, label: str) -> dict:
    lines = [line for line in output.splitlines() if line.startswith(prefix)]
    if len(lines) != 1:
        raise release_driver.ReceiptError(
            f"federation {label} emitted {len(lines)} structured records, expected one"
        )
    encoded = lines[0][len(prefix):]
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError as exc:
        raise release_driver.ReceiptError(
            f"federation {label} is malformed: {exc}"
        ) from exc
    if encoded != _canonical_bytes(value).decode().rstrip("\n"):
        raise release_driver.ReceiptError(
            f"federation {label} is not canonical JSON"
        )
    return value


def _validate_runtime(runtime: dict, expected: dict, label: str) -> dict:
    fields = {
        "installed_distributions",
        "installed_distributions_sha256",
        "mcp_version",
        "version",
        "wheel_sha256",
    }
    if not isinstance(runtime, dict) or set(runtime) != fields:
        raise release_driver.ReceiptError(
            f"federation {label} runtime fields are not exact"
        )
    inventory = runtime["installed_distributions"]
    valid_inventory = (
        isinstance(inventory, dict)
        and bool(inventory)
        and all(
            isinstance(name, str)
            and bool(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name))
            and isinstance(version, str)
            and bool(version)
            for name, version in inventory.items()
        )
    )
    inventory_digest = _identity(inventory) if valid_inventory else ""
    if (
        runtime["mcp_version"] != expected["mcp_version"]
        or runtime["version"] != expected["version"]
        or runtime["wheel_sha256"] != expected["wheel_sha256"]
        or not valid_inventory
        or inventory.get("aweb") != runtime["version"]
        or inventory.get("mcp") != runtime["mcp_version"]
        or runtime["installed_distributions_sha256"] != inventory_digest
    ):
        raise release_driver.ReceiptError(
            f"federation {label} runtime does not bind exact wheel/dependencies"
        )
    return runtime


def _dependency_inventory(runtime: dict) -> dict:
    return {
        name: version
        for name, version in runtime["installed_distributions"].items()
        if name != "aweb"
    }


def _validate_invocation(value: dict, expected: dict, label: str) -> None:
    for field in ("cell_id", "ports", "project"):
        if value.get(field) != expected[field]:
            raise release_driver.ReceiptError(
                f"federation {label} {field} {value.get(field)!r} does not "
                f"equal invocation {expected[field]!r}"
            )


def _parse_observation(output: str, environment: dict[str, str]) -> dict:
    observation = _decode_structured_line(
        output, OBSERVATION_PREFIX, "journey observation"
    )
    expected_keys = {
        "alpha", "beta", "cell_id", "initiated_side", "outcomes",
        "ports", "project", "schema",
    }
    if not isinstance(observation, dict) or set(observation) != expected_keys:
        raise release_driver.ReceiptError(
            f"federation journey observation fields are not exact: {observation!r}"
        )
    expected = _expected_observation(environment)
    _validate_invocation(observation, expected, "observation")
    if observation["initiated_side"] != expected["initiated_side"]:
        raise release_driver.ReceiptError(
            "federation observation initiated side does not equal cell direction"
        )
    if observation["schema"] != OBSERVATION_SCHEMA:
        raise release_driver.ReceiptError(
            f"federation observation schema {observation['schema']!r} is not supported"
        )
    if observation["outcomes"] != REQUIRED_OUTCOMES:
        raise release_driver.ReceiptError(
            f"federation observation outcomes are incomplete: {observation['outcomes']!r}"
        )
    alpha = _validate_runtime(
        observation["alpha"], expected["runtime"]["alpha"], "alpha"
    )
    beta = _validate_runtime(
        observation["beta"], expected["runtime"]["beta"], "beta"
    )
    if _dependency_inventory(alpha) != _dependency_inventory(beta):
        raise release_driver.ReceiptError(
            "federation cell dependency-only inventories differ between runtimes"
        )
    return observation


def _parse_control_runtime(output: str, environment: dict[str, str]) -> dict:
    runtime = _decode_structured_line(
        output, CONTROL_RUNTIME_PREFIX, "control runtime"
    )
    if not isinstance(runtime, dict) or set(runtime) != {
        "alpha", "beta", "cell_id", "ports", "project", "schema"
    }:
        raise release_driver.ReceiptError(
            f"federation control runtime fields are not exact: {runtime!r}"
        )
    expected = _expected_observation(environment)
    _validate_invocation(runtime, expected, "control runtime")
    if runtime["schema"] != CONTROL_RUNTIME_SCHEMA:
        raise release_driver.ReceiptError(
            f"federation control runtime schema {runtime['schema']!r} is unsupported"
        )
    alpha = _validate_runtime(
        runtime["alpha"], expected["runtime"]["alpha"], "control alpha"
    )
    beta = _validate_runtime(
        runtime["beta"], expected["runtime"]["beta"], "control beta"
    )
    if _dependency_inventory(alpha) != _dependency_inventory(beta):
        raise release_driver.ReceiptError(
            "federation control dependency-only inventories differ between runtimes"
        )
    return runtime


def _read_canonical_report(path: Path) -> tuple[dict, bytes]:
    try:
        body = path.read_bytes()
        value = json.loads(body)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise release_driver.ReceiptError(
            f"federation cell report {path} is unreadable: {exc}"
        ) from exc
    if body != _canonical_bytes(value):
        raise release_driver.ReceiptError(
            f"federation cell report {path} is not canonical JSON"
        )
    return value, body


def _validate_resolved_identity(
    value: dict, side: dict, kind: str, runtime: dict, label: str
) -> dict:
    selected = value.get("selected_wheel") if isinstance(value, dict) else None
    digest_set = side.get("digest_set") if kind == "candidate" else value.get(
        "registry_digest_set", {}
    ) if isinstance(value, dict) else {}
    wheels = [name for name in digest_set if name.endswith(".whl")]
    valid_selected = (
        isinstance(selected, dict)
        and set(selected) == {"filename", "sha256"}
        and len(wheels) == 1
        and selected.get("filename") == wheels[0]
        and selected.get("sha256") == digest_set.get(wheels[0])
        and selected.get("sha256") == runtime.get("wheel_sha256")
    )
    if kind == "candidate":
        expected = {
            "component": side.get("component"),
            "digest": side.get("digest"),
            "digest_set": side.get("digest_set"),
            "kind": "candidate",
            "lane_ref": side.get("lane_ref"),
            "selected_wheel": selected,
            "version": side.get("version"),
        }
        valid = (
            isinstance(value, dict)
            and value == expected
            and set(side) == {
                "component", "digest", "digest_set", "lane_ref", "version"
            }
            and side.get("component") == "server"
            and side.get("digest")
            == release_driver.canonical_digest_of_set(side.get("digest_set", {}))
        )
        if valid:
            release_driver.LaneRef.from_dict(side.get("lane_ref"))
    else:
        version = side.get("version")
        expected_names = {
            f"aweb-{version}-py3-none-any.whl",
            f"aweb-{version}.tar.gz",
        }
        valid = (
            isinstance(value, dict)
            and set(value) == {
                "component", "info_version", "kind", "registry",
                "registry_digest_set", "registry_set_digest",
                "selected_wheel", "version",
            }
            and set(side) == {"component", "kind", "version"}
            and side.get("component") == "server"
            and side.get("kind") == kind
            and value.get("component") == "server"
            and value.get("kind") == kind
            and value.get("registry") == "pypi:aweb"
            and value.get("version") == version
            and value.get("info_version") == version
            and set(digest_set) == expected_names
            and value.get("registry_set_digest")
            == release_driver.canonical_digest_of_set(digest_set)
        )
    if (
        not valid
        or not valid_selected
        or runtime.get("version") != value.get("version")
    ):
        raise release_driver.ReceiptError(
            f"federation cell report {label} resolved artifact identity is invalid"
        )
    return value


def _ports_match_project(project: str, ports: dict) -> bool:
    match = re.fullmatch(r"aweb-fed-e2e-([0-9a-f]{32})", project or "")
    if not match:
        return False
    token = match.group(1)
    counters = []
    for port in (ports.get("awid"), ports.get("alpha"), ports.get("beta")):
        found = next(
            (counter for counter in range((counters[-1] + 1) if counters else 0, 1000)
             if _token_port(token, counter) == port),
            None,
        )
        if found is None:
            return False
        counters.append(found)
    return True


def _reload_cell_report(
    cell, path: Path, *, matrix_id: str | None = None,
) -> tuple[dict, bytes, list[dict]]:
    identity = cell_identity(cell)
    report, body = _read_canonical_report(path)
    if not isinstance(report, dict) or set(report) != {
        "cell", "cell_id", "matrix_id", "observation", "observation_sha256",
        "resolved", "schema", "status",
    }:
        raise release_driver.ReceiptError(
            f"federation cell report {identity} fields are not exact"
        )
    observation = report["observation"]
    resolved = report["resolved"]
    initiated = "a" if cell.direction == "a-to-b" else "b"
    valid_ports = (
        isinstance(observation, dict)
        and isinstance(observation.get("ports"), dict)
        and set(observation["ports"]) == {"alpha", "awid", "beta"}
        and all(
            isinstance(port, int) and not isinstance(port, bool) and 1024 <= port <= 65535
            for port in observation["ports"].values()
        )
        and len(set(observation["ports"].values())) == 3
    )
    if (
        report["schema"] != CELL_REPORT_SCHEMA
        or report["matrix_id"] != matrix_id
        or report["cell_id"] != identity
        or report["cell"] != cell_preimage(cell)
        or report["status"] != "green"
        or not isinstance(observation, dict)
        or set(observation) != {
            "alpha", "beta", "cell_id", "initiated_side", "outcomes",
            "ports", "project", "schema",
        }
        or report["observation_sha256"] != _identity(observation)
        or observation.get("schema") != OBSERVATION_SCHEMA
        or observation.get("cell_id") != identity
        or observation.get("initiated_side") != initiated
        or observation.get("outcomes") != REQUIRED_OUTCOMES
        or not valid_ports
        or not _ports_match_project(
            observation.get("project", ""), observation.get("ports", {})
        )
        or not isinstance(resolved, dict)
        or set(resolved) != {"alpha", "beta"}
        or not all(isinstance(value, dict) for value in resolved.values())
    ):
        raise release_driver.ReceiptError(
            f"federation cell report {identity} does not bind its expected frozen cell"
        )
    alpha_expected_side, alpha_kind, beta_expected_side, beta_kind = (
        (cell.a, cell.a_kind, cell.b, cell.b_kind)
        if cell.direction == "a-to-b"
        else (cell.b, cell.b_kind, cell.a, cell.a_kind)
    )
    alpha_expected = {
        "mcp_version": locked_mcp_version(),
        "version": resolved["alpha"].get("version"),
        "wheel_sha256": (resolved["alpha"].get("selected_wheel") or {}).get("sha256"),
    }
    beta_expected = {
        "mcp_version": locked_mcp_version(),
        "version": resolved["beta"].get("version"),
        "wheel_sha256": (resolved["beta"].get("selected_wheel") or {}).get("sha256"),
    }
    alpha = _validate_runtime(observation["alpha"], alpha_expected, "reloaded alpha")
    beta = _validate_runtime(observation["beta"], beta_expected, "reloaded beta")
    alpha_identity = _validate_resolved_identity(
        resolved["alpha"], alpha_expected_side, alpha_kind, alpha, "alpha"
    )
    beta_identity = _validate_resolved_identity(
        resolved["beta"], beta_expected_side, beta_kind, beta, "beta"
    )
    if _dependency_inventory(alpha) != _dependency_inventory(beta):
        raise release_driver.ReceiptError(
            f"federation cell report {identity} dependency inventories differ"
        )
    identities = (alpha_identity, beta_identity)
    candidates = [value for value in identities if value["kind"] == "candidate"]
    published = [value for value in identities if value["kind"] != "candidate"]
    return report, body, candidates, published


def _matrix_aggregate(
    expected_cells, report_dir: Path, *, matrix_id: str | None = None,
) -> dict:
    cells = list(expected_cells)
    if not cells:
        raise release_driver.ReceiptError("federation aggregate requires expected cells")
    identities = [cell_identity(cell) for cell in cells]
    if len(set(identities)) != len(identities):
        raise release_driver.ReceiptError(
            "federation aggregate expected matrix contains duplicate full-cell identities"
        )
    cell_dir = Path(report_dir) / "cells"
    expected_files = {f"{identity}.json" for identity in identities}
    try:
        actual_entries = list(cell_dir.iterdir())
    except OSError as exc:
        raise release_driver.ReceiptError(
            f"federation aggregate cell report directory is unreadable: {exc}"
        ) from exc
    actual_files = {
        entry.name for entry in actual_entries
        if entry.is_file() and not entry.is_symlink()
    }
    if actual_files != expected_files or len(actual_entries) != len(expected_files):
        raise release_driver.ReceiptError(
            f"federation aggregate cell file set {sorted(actual_files)} does not "
            f"equal expected {sorted(expected_files)}"
        )

    reports = []
    candidates = []
    published_by_version: dict[tuple[str, str], dict] = {}
    dependency_digests = set()
    for identity, cell in zip(identities, cells):
        path = cell_dir / f"{identity}.json"
        report, body, cell_candidates, cell_published = _reload_cell_report(
            cell, path, matrix_id=matrix_id
        )
        reports.append({
            "cell_id": identity,
            "sha256": hashlib.sha256(body).hexdigest(),
        })
        candidates.extend(cell_candidates)
        for published in cell_published:
            key = (published["kind"], published["version"])
            prior = published_by_version.setdefault(key, published)
            if prior != published:
                raise release_driver.ReceiptError(
                    f"federation published {published['version']} identity "
                    "differs across cells"
                )
        for runtime in report["observation"]["alpha"], report["observation"]["beta"]:
            dependency_digests.add(_identity(_dependency_inventory(runtime)))
    candidate_by_identity = {_identity(value): value for value in candidates}
    if len(candidate_by_identity) != 1:
        raise release_driver.ReceiptError(
            f"federation aggregate must bind one exact candidate identity, "
            f"found {sorted(candidate_by_identity)}"
        )
    if len(dependency_digests) != 1:
        raise release_driver.ReceiptError(
            "federation aggregate dependency-only inventories differ across cells"
        )
    candidate_id, candidate = next(iter(candidate_by_identity.items()))
    aggregate_preimage = {
        "matrix_id": matrix_id,
        "candidate": candidate,
        "candidate_id": candidate_id,
        "expected_cell_ids": identities,
        "published_identities": [
            published_by_version[key] for key in sorted(published_by_version)
        ],
        "reports": reports,
    }
    aggregate_id = _identity(aggregate_preimage)
    return {
        "aggregate_id": aggregate_id,
        "matrix_id": matrix_id,
        "anchor": None,
        "candidate": candidate,
        "candidate_id": candidate_id,
        "expected_cell_ids": identities,
        "published_identities": [
            published_by_version[key] for key in sorted(published_by_version)
        ],
        "reports": reports,
        "schema": AGGREGATE_SCHEMA,
        "status": "incomplete-unanchored",
        "support_complete": False,
    }


def aggregate_cell_reports(expected_cells, report_dir: Path = DEFAULT_REPORT_DIR) -> dict:
    """Write an unanchored aggregate from the ordered frozen matrix authority."""

    aggregate = _matrix_aggregate(expected_cells, Path(report_dir))
    path = Path(report_dir) / "aggregates" / f"{aggregate['aggregate_id']}.json"
    _atomic_report(path, aggregate)
    return load_aggregate(expected_cells, report_dir)


def load_aggregate(expected_cells, report_dir: Path = DEFAULT_REPORT_DIR) -> dict:
    """Reload every report and recompute the aggregate identity from scratch."""

    expected = _matrix_aggregate(expected_cells, Path(report_dir))
    path = Path(report_dir) / "aggregates" / f"{expected['aggregate_id']}.json"
    aggregate, _ = _read_canonical_report(path)
    if aggregate != expected:
        raise release_driver.ReceiptError(
            "federation aggregate identity or canonical content does not match reports"
        )
    return aggregate


class FederationSkewHarness:
    def __init__(self, *, resolver=None, journey=None, report_dir=None):
        self._resolver = resolver or WheelResolver()
        self._journey = journey or run_federation_journey
        self._report_dir = Path(report_dir or DEFAULT_REPORT_DIR)
        self._matrix: dict | None = None
        self._cells: dict[str, object] = {}
        self._cell_evidence: dict[str, dict] = {}
        self._finished = False

    def freeze_matrix(self, document: dict) -> Path:
        cells = release_driver.validate_skew_matrix_document(document)
        edge = document["preimage"]["edge"]
        if edge != {
            "a": "server", "b": "server", "journey": JOURNEY,
            "artifacts": {"a": "pypi:aweb", "b": "pypi:aweb"},
            "direction": "both",
        } or any(self._cell_invalid(cell) for cell in cells):
            raise release_driver.ReceiptError(
                "federation child accepts only its exact frozen edge matrix"
            )
        if self._matrix is not None and self._matrix != document:
            raise release_driver.ReceiptError("federation child was given two matrices")
        path = self._report_dir / f"matrix-{document['matrix_id']}.json"
        if path.exists():
            stored, _ = _read_canonical_report(path)
            if stored != document:
                raise release_driver.ReceiptError(
                    "federation matrix evidence is stale or tampered"
                )
        else:
            _atomic_report(path, document)
        self._matrix = json.loads(json.dumps(document))
        self._cells = {
            release_driver.skew_cell_identity(cell): cell for cell in cells
        }
        return path

    def _cell_invalid(self, cell) -> bool:
        try:
            self._validate_cell(cell)
        except release_driver.ReceiptError:
            return True
        return False

    def _frozen_cell_id(self, cell) -> str:
        if self._matrix is None:
            raise release_driver.ReceiptError(
                "federation cell arrived before its frozen matrix"
            )
        identity = release_driver.skew_cell_identity(cell)
        if self._cells.get(identity) != cell:
            raise release_driver.ReceiptError(
                "federation cell is not an exact member of its frozen matrix"
            )
        return identity

    def _validate_cell(self, cell) -> None:
        expected = {
            "edge_a": "server",
            "edge_b": "server",
            "journey": JOURNEY,
            "artifacts": {"a": "pypi:aweb", "b": "pypi:aweb"},
            "declared_direction": "both",
        }
        for field, value in expected.items():
            if getattr(cell, field) != value:
                raise release_driver.ReceiptError(
                    f"federation child received {field}={getattr(cell, field)!r}, "
                    f"expected {value!r}"
                )
        if cell.direction not in {"a-to-b", "b-to-a"}:
            raise release_driver.ReceiptError(
                f"federation child received direction {cell.direction!r}"
            )

    def run(self, cell) -> None:
        identity = self._frozen_cell_id(cell)
        target = self._report_dir / "cells" / f"{identity}.json"
        if target.exists():
            raise release_driver.ReceiptError(
                "federation frozen cell already has evidence"
            )
        self._validate_cell(cell)
        side_a = self._resolver.side(cell.a, cell.a_kind)
        side_b = self._resolver.side(cell.b, cell.b_kind)
        # The reused journey's alpha identity initiates its first-contact
        # checks. Swap runtime placement for b-to-a so every request in this
        # exact runner cell starts on the declared side, not a global union.
        if cell.direction == "a-to-b":
            alpha, beta = side_a, side_b
            alpha_identity = _resolved_identity(side_a, cell.a, cell.a_kind)
            beta_identity = _resolved_identity(side_b, cell.b, cell.b_kind)
        else:
            alpha, beta = side_b, side_a
            alpha_identity = _resolved_identity(side_b, cell.b, cell.b_kind)
            beta_identity = _resolved_identity(side_a, cell.a, cell.a_kind)
        with tempfile.TemporaryDirectory(prefix="aweb-fed-skew-cell-") as tmp:
            environment, result = _run_reserved_journey(
                Path(tmp),
                alpha,
                beta,
                direction=cell.direction,
                cell_id=identity,
                journey=self._journey,
            )
        output = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0:
            raise release_driver.ReceiptError(
                f"federation skew journey {identity} {cell.direction} red: "
                f"exit={result.returncode}, output={output[-2000:]}"
            )
        observation = _parse_observation(output, environment)
        report = {
            "cell": cell_preimage(cell),
            "cell_id": identity,
            "matrix_id": self._matrix["matrix_id"],
            "observation": observation,
            "observation_sha256": _identity(observation),
            "resolved": {
                "alpha": alpha_identity,
                "beta": beta_identity,
            },
            "schema": CELL_REPORT_SCHEMA,
            "status": "green",
        }
        # subprocess completion includes the shell EXIT trap and exact-project
        # teardown. Only then may a green report become visible atomically.
        path = self._report_dir / "cells" / f"{identity}.json"
        digest = _atomic_report(path, report)
        self._cell_evidence[identity] = {"path": path, "sha256": digest}

    def _validate_effect_time_evidence(self) -> None:
        if set(self._cell_evidence) != set(self._cells):
            raise release_driver.ReceiptError(
                "federation effect-time evidence inventory is not exact"
            )
        for cell_id in self._cells:
            expected_path = self._report_dir / "cells" / f"{cell_id}.json"
            evidence = self._cell_evidence[cell_id]
            if (
                not isinstance(evidence, dict)
                or set(evidence) != {"path", "sha256"}
                or evidence["path"] != expected_path
                or expected_path.is_symlink()
            ):
                raise release_driver.ReceiptError(
                    f"federation effect-time evidence inventory drifted for {cell_id}"
                )
            try:
                observed = hashlib.sha256(expected_path.read_bytes()).hexdigest()
            except OSError as exc:
                raise release_driver.ReceiptError(
                    f"federation effect-time evidence is unreadable for {cell_id}: {exc}"
                ) from exc
            if observed != evidence["sha256"]:
                raise release_driver.ReceiptError(
                    f"federation effect-time report digest changed for {cell_id}"
                )

    def finish_matrix(self, document: dict) -> Path:
        if document != self._matrix:
            raise release_driver.ReceiptError(
                "federation finish request does not equal its frozen matrix"
            )
        if self._finished:
            raise release_driver.ReceiptError(
                "federation frozen matrix already finished"
            )
        self._validate_effect_time_evidence()
        matrix_path = self._report_dir / f"matrix-{document['matrix_id']}.json"
        stored, _ = _read_canonical_report(matrix_path)
        if stored != document:
            raise release_driver.ReceiptError(
                "federation persisted matrix differs from finish request"
            )
        cells = release_driver.validate_skew_matrix_document(document)
        aggregate = _matrix_aggregate(
            cells, self._report_dir, matrix_id=document["matrix_id"]
        )
        aggregate.update({
            "edge": {"a": "server", "b": "server"},
            "journey": JOURNEY,
            "artifacts": {"a": "pypi:aweb", "b": "pypi:aweb"},
            "direction": "both",
            "staged_manifest_digest": document["preimage"]["staged_manifest_digest"],
            "supported_versions": document["preimage"]["support"]["supported_versions"],
            "published_versions": document["preimage"]["published_versions"],
        })
        aggregate.pop("aggregate_id", None)
        aggregate["aggregate_id"] = _identity(aggregate)
        path = self._report_dir / "aggregates" / f"{aggregate['aggregate_id']}.json"
        _atomic_report(path, aggregate)
        stored_aggregate, _ = _read_canonical_report(path)
        if stored_aggregate != aggregate:
            raise release_driver.ReceiptError("federation aggregate reload drifted")
        self._finished = True
        return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="verb", required=True)
    measure = subparsers.add_parser(
        "measure-current",
        help="run both federation directions from one exact published server wheel",
    )
    measure.add_argument("--version", required=True)
    measure.add_argument("--output", required=True)
    measure.add_argument("--store-root", required=True)
    measure.add_argument("--artifact-id", required=True)
    args = parser.parse_args(argv)
    if args.verb == "measure-current":
        result = measure_current_published_support(
            args.version,
            output=Path(args.output),
            store_root=Path(args.store_root),
            artifact_id=args.artifact_id,
        )
        print(json.dumps({
            "artifact_id": result["artifact_id"],
            "digest": result["digest"],
            "measurement_id": result["measurement"]["measurement_id"],
            "set": result["set"],
        }, sort_keys=True))
        return 0
    raise AssertionError(args.verb)


if __name__ == "__main__":
    raise SystemExit(main())
