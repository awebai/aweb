"""Exact-wheel child harness for the federation server/server skew edge."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
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
    route_probe_only: bool = False,
) -> dict[str, str]:
    alpha_path = _write_wheel(root, "alpha", alpha)
    beta_path = _write_wheel(root, "beta", beta)
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


def prove_route_controls(resolver, journey=run_federation_journey) -> None:
    """The same pre-setup route probe must kill the last pre-route release
    and admit the first route-containing release before any cell is trusted."""

    first = resolver.published(FIRST_FEDERATION_VERSION)
    missing = resolver.published(MISSING_FEDERATION_VERSION)
    with tempfile.TemporaryDirectory(prefix="aweb-fed-skew-negative-") as tmp:
        environment = _journey_environment(
            Path(tmp), first, missing,
            direction="a-to-b",
            cell_id=f"negative:{MISSING_FEDERATION_VERSION}",
            route_probe_only=True,
        )
        result = journey(environment)
    output = (result.stdout or "") + (result.stderr or "")
    marker = "beta federation route probe returned 404"
    if result.returncode == 0 or marker not in output:
        raise release_driver.ReceiptError(
            f"federation negative control did not red on exact missing-route "
            f"marker {marker!r}: exit={result.returncode}, output={output[-1000:]}"
        )

    with tempfile.TemporaryDirectory(prefix="aweb-fed-skew-positive-") as tmp:
        environment = _journey_environment(
            Path(tmp), first, first,
            direction="a-to-b",
            cell_id=f"positive:{FIRST_FEDERATION_VERSION}",
            route_probe_only=True,
        )
        result = journey(environment)
    if result.returncode != 0:
        output = (result.stdout or "") + (result.stderr or "")
        raise release_driver.ReceiptError(
            f"federation first-containing release route probe red: "
            f"exit={result.returncode}, output={output[-1000:]}"
        )


class FederationSkewHarness:
    def __init__(self, *, resolver=None, journey=None, controls=None):
        self._resolver = resolver or WheelResolver()
        self._journey = journey or run_federation_journey
        self._controls = controls or (
            lambda: prove_route_controls(self._resolver, self._journey)
        )
        self._controls_proved = False

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
        if not self._controls_proved:
            self._controls()
            self._controls_proved = True
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
        with tempfile.TemporaryDirectory(prefix="aweb-fed-skew-cell-") as tmp:
            environment = _journey_environment(
                Path(tmp), alpha, beta,
                direction=cell.direction,
                cell_id=cell.edge_id,
            )
            result = self._journey(environment)
        if result.returncode != 0:
            output = (result.stdout or "") + (result.stderr or "")
            raise release_driver.ReceiptError(
                f"federation skew journey {cell.edge_id} {cell.direction} red: "
                f"exit={result.returncode}, output={output[-2000:]}"
            )
