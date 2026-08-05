"""Exact-wheel child harness for the federation server/server skew edge."""

from __future__ import annotations

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
CELL_REPORT_SCHEMA = "aweb.release.federation-skew-cell-report.v1"
AGGREGATE_SCHEMA = "aweb.release.federation-skew-aggregate.v1"
CONTROL_SCHEMA = "aweb.release.federation-skew-control.v1"
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
        return WheelArtifact(name, version, wheel_bytes, digest)

    def published(self, version: str) -> WheelArtifact:
        metadata_url = PYPI_METADATA.format(version=version)
        metadata = self._read_metadata(metadata_url, version)
        if metadata.get("info", {}).get("version") != version:
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} metadata binds version "
                f"{metadata.get('info', {}).get('version')!r}"
            )
        wheels = [
            item for item in metadata.get("urls", [])
            if isinstance(item, dict) and item.get("packagetype") == "bdist_wheel"
        ]
        if len(wheels) != 1:
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} metadata must bind exactly one wheel, "
                f"found {len(wheels)}"
            )
        wheel = wheels[0]
        name = wheel.get("filename")
        expected_name_prefix = f"aweb-{version}-"
        if (
            not isinstance(name, str)
            or not name.startswith(expected_name_prefix)
            or not name.endswith(".whl")
            or Path(name).name != name
        ):
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} metadata names invalid wheel {name!r}"
            )
        digest = (wheel.get("digests") or {}).get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} wheel has invalid sha256 {digest!r}"
            )
        url = wheel.get("url")
        parsed = urllib.parse.urlparse(url or "")
        if parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org":
            raise release_driver.ReceiptError(
                f"PyPI aweb {version} metadata names unexpected wheel URL {url!r}"
            )
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
        return WheelArtifact(name, version, wheel_bytes, digest)

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
        "AWEB_FED_E2E_MCP_VERSION": locked_mcp_version(),
        "AWEB_FED_E2E_PROJECT": invocation.project,
        "AWID_FED_E2E_PORT": str(awid_port),
        "AWEB_ALPHA_E2E_PORT": str(alpha_port),
        "AWEB_BETA_E2E_PORT": str(beta_port),
    }


def run_federation_journey(environment: dict[str, str]):
    env = dict(os.environ)
    env.update(environment)
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
        "sha256": wheel.sha256,
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
    if positive.returncode != 0:
        output = (positive.stdout or "") + (positive.stderr or "")
        raise release_driver.ReceiptError(
            f"federation first-containing release route probe red: "
            f"exit={positive.returncode}, output={output[-1000:]}"
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
            },
            "positive": {
                "expected_exit": 0,
                "invocation": invocation(positive_env),
                "observed_exit": positive.returncode,
                "route_present_wheel": _wheel_identity(first),
            },
        },
        "mcp_version": locked_mcp_version(),
        "schema": CONTROL_SCHEMA,
    }
    _atomic_report(Path(report_dir) / "control.json", report)
    return report


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


def _parse_observation(output: str, environment: dict[str, str]) -> dict:
    lines = [line for line in output.splitlines() if line.startswith(OBSERVATION_PREFIX)]
    if len(lines) != 1:
        raise release_driver.ReceiptError(
            f"federation journey emitted {len(lines)} structured observations, expected one"
        )
    encoded = lines[0][len(OBSERVATION_PREFIX):]
    try:
        observation = json.loads(encoded)
    except json.JSONDecodeError as exc:
        raise release_driver.ReceiptError(
            f"federation journey observation is malformed: {exc}"
        ) from exc
    if encoded != _canonical_bytes(observation).decode().rstrip("\n"):
        raise release_driver.ReceiptError(
            "federation journey observation is not canonical JSON"
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
    for field in ("cell_id", "initiated_side", "ports", "project"):
        if observation[field] != expected[field]:
            raise release_driver.ReceiptError(
                f"federation observation {field} {observation[field]!r} does not "
                f"equal invocation {expected[field]!r}"
            )
    if observation["schema"] != OBSERVATION_SCHEMA:
        raise release_driver.ReceiptError(
            f"federation observation schema {observation['schema']!r} is not supported"
        )
    if observation["outcomes"] != REQUIRED_OUTCOMES:
        raise release_driver.ReceiptError(
            f"federation observation outcomes are incomplete: {observation['outcomes']!r}"
        )
    for name in ("alpha", "beta"):
        runtime = observation[name]
        if not isinstance(runtime, dict) or set(runtime) != {
            "inventory_sha256", "mcp_version", "version", "wheel_sha256"
        }:
            raise release_driver.ReceiptError(
                f"federation observation {name} runtime fields are not exact"
            )
        for field in ("mcp_version", "version", "wheel_sha256"):
            if runtime[field] != expected["runtime"][name][field]:
                raise release_driver.ReceiptError(
                    f"federation observation {name} {field} {runtime[field]!r} "
                    f"does not equal selected {expected['runtime'][name][field]!r}"
                )
        if not re.fullmatch(r"[0-9a-f]{64}", runtime["inventory_sha256"] or ""):
            raise release_driver.ReceiptError(
                f"federation observation {name} inventory digest is invalid"
            )
    return observation


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


def aggregate_cell_reports(expected_cells, report_dir: Path = DEFAULT_REPORT_DIR) -> dict:
    """Bind a complete expected frozen matrix to exact cell-report digests.
    The aggregate remains deliberately unanchored and cannot complete support."""

    cells = list(expected_cells)
    if not cells:
        raise release_driver.ReceiptError("federation aggregate requires expected cells")
    identities = [cell_identity(cell) for cell in cells]
    if len(set(identities)) != len(identities):
        raise release_driver.ReceiptError(
            "federation aggregate expected matrix contains duplicate full-cell identities"
        )
    candidates = []
    for cell in cells:
        if cell.a_kind == "candidate":
            candidates.append(dict(cell.a))
        if cell.b_kind == "candidate":
            candidates.append(dict(cell.b))
    candidate_by_identity = {_identity(value): value for value in candidates}
    if len(candidate_by_identity) != 1:
        raise release_driver.ReceiptError(
            f"federation aggregate must bind one exact candidate identity, "
            f"found {sorted(candidate_by_identity)}"
        )
    candidate_id, candidate = next(iter(candidate_by_identity.items()))

    reports = []
    for identity, cell in sorted(zip(identities, cells), key=lambda item: item[0]):
        path = Path(report_dir) / "cells" / f"{identity}.json"
        report, body = _read_canonical_report(path)
        observation = report.get("observation")
        initiated = "a" if cell.direction == "a-to-b" else "b"
        if (
            report.get("schema") != CELL_REPORT_SCHEMA
            or report.get("cell_id") != identity
            or report.get("cell") != cell_preimage(cell)
            or report.get("status") != "green"
            or not isinstance(observation, dict)
            or report.get("observation_sha256") != _identity(observation)
            or observation.get("cell_id") != identity
            or observation.get("initiated_side") != initiated
            or observation.get("outcomes") != REQUIRED_OUTCOMES
        ):
            raise release_driver.ReceiptError(
                f"federation cell report {identity} does not bind its expected frozen cell"
            )
        reports.append({
            "cell_id": identity,
            "sha256": hashlib.sha256(body).hexdigest(),
        })

    matrix_preimage = {
        "candidate_id": candidate_id,
        "cell_ids": sorted(identities),
    }
    matrix_id = _identity(matrix_preimage)
    aggregate = {
        "anchor": None,
        "candidate": {
            "id": candidate_id,
            "side": candidate,
        },
        "expected_cell_ids": sorted(identities),
        "matrix_id": matrix_id,
        "reports": reports,
        "schema": AGGREGATE_SCHEMA,
        "status": "incomplete-unanchored",
        "support_complete": False,
    }
    _atomic_report(Path(report_dir) / "aggregates" / f"{matrix_id}.json", aggregate)
    return aggregate


class FederationSkewHarness:
    def __init__(self, *, resolver=None, journey=None, report_dir=None):
        self._resolver = resolver or WheelResolver()
        self._journey = journey or run_federation_journey
        self._report_dir = Path(report_dir or DEFAULT_REPORT_DIR)

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
        self._validate_cell(cell)
        side_a = self._resolver.side(cell.a, cell.a_kind)
        side_b = self._resolver.side(cell.b, cell.b_kind)
        # The reused journey's alpha identity initiates its first-contact
        # checks. Swap runtime placement for b-to-a so every request in this
        # exact runner cell starts on the declared side, not a global union.
        alpha, beta = (
            (side_a, side_b)
            if cell.direction == "a-to-b"
            else (side_b, side_a)
        )
        identity = cell_identity(cell)
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
            "observation": observation,
            "observation_sha256": _identity(observation),
            "schema": CELL_REPORT_SCHEMA,
            "status": "green",
        }
        # subprocess completion includes the shell EXIT trap and exact-project
        # teardown. Only then may a green report become visible atomically.
        _atomic_report(self._report_dir / "cells" / f"{identity}.json", report)
