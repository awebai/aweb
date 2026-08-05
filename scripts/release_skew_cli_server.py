#!/usr/bin/env python3
"""Exact-artifact CLI/server version-skew journey.

This is the child harness for the ``make cli-e2e`` runtime-contract edge.  It
only resolves the bytes named by a :class:`release_driver.SkewCell`, runs the
existing real-stack journey, and records digest-bearing evidence.  Matrix
selection and release ordering remain in ``release_driver.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

import release_driver as rd

REPO_ROOT = Path(__file__).resolve().parents[1]
JOURNEY = "make cli-e2e"
ARTIFACTS = {"a": "github-release:awebai/aw", "b": "pypi:aweb"}
DIRECTION = "both"
EDGE = rd.RuntimeContractEdge(
    a="aw",
    b="server",
    journey=JOURNEY,
    artifacts=ARTIFACTS,
    direction=DIRECTION,
    supported={"policy": "additive-only"},
)
EDGE_ID = rd.edge_identity(EDGE)
NEGATIVE_SERVER_VERSION = "1.26.31"
FIRST_SUPPORTED_SERVER_VERSION = "1.26.35"
DIRTY_FLEET_AW_VERSION = "1.34.2"
NEGATIVE_FEATURE_MARKERS = (
    "workspace and agent identifiers were not distinct",
    "workspace status locks",
    "server status locks",
    "want holder agent",
)


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _default_platform_name() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    systems = {"darwin": "darwin", "linux": "linux"}
    machines = {
        "arm64": "arm64",
        "aarch64": "arm64",
        "x86_64": "amd64",
        "amd64": "amd64",
    }
    try:
        return f"{systems[system]}_{machines[machine]}"
    except KeyError:
        raise rd.ReceiptError(
            f"the CLI/server skew harness has no aw archive for {system}/{machine}"
        ) from None


def _default_staged_capabilities(component: str):
    repo, workflow = rd.LANE_ARTIFACT_SOURCES[component]
    return (
        rd.GithubArtifactStore(repo=repo, workflow_path=workflow),
        rd.GithubArtifactDigestAuthority(repo=repo, workflow_path=workflow),
    )


def _github_release_fetch(version: str, name: str) -> bytes | None:
    return rd._fetch_aw_release_asset(name, version)


def _pypi_metadata_fetch(version: str) -> dict | None:
    try:
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/aweb/{version}/json"
        ) as response:
            return json.load(response)
    except Exception as exc:
        raise rd.ReceiptError(
            f"PyPI metadata read failed for aweb {version}: {exc}"
        ) from exc


def _url_fetch(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url) as response:
            return response.read()
    except Exception as exc:
        raise rd.ReceiptError(f"artifact download failed for {url}: {exc}") from exc


@dataclass(frozen=True)
class ResolvedArtifact:
    component: str
    version: str
    path: Path
    evidence: dict


class CliServerArtifactResolver:
    """Resolve candidate or published aw/server bytes without rebuilding."""

    def __init__(
        self,
        *,
        staged_capabilities=_default_staged_capabilities,
        github_release_fetch=_github_release_fetch,
        pypi_metadata_fetch=_pypi_metadata_fetch,
        url_fetch=_url_fetch,
        platform_name=_default_platform_name,
    ):
        self._staged_capabilities = staged_capabilities
        self._release_fetch = github_release_fetch
        self._pypi = pypi_metadata_fetch
        self._url = url_fetch
        self._platform = platform_name

    def resolve(self, side: dict, kind: str, locator: str, root: Path) -> ResolvedArtifact:
        component = side.get("component")
        if component not in ("aw", "server"):
            raise rd.ReceiptError(f"CLI/server skew side names {component!r}")
        expected_locator = ARTIFACTS["a" if component == "aw" else "b"]
        if locator != expected_locator:
            raise rd.ReceiptError(
                f"{component}: artifact locator {locator!r} is not {expected_locator!r}"
            )
        if kind == "candidate":
            return self._candidate(side, root)
        if not kind.startswith("published"):
            raise rd.ReceiptError(f"{component}: unsupported skew side kind {kind!r}")
        if component == "aw":
            return self._published_aw(side, kind, root)
        return self._published_server(side, kind, root)

    def _candidate(self, side: dict, root: Path) -> ResolvedArtifact:
        component = side["component"]
        version = side.get("version") or ""
        if component == "aw" and version == DIRTY_FLEET_AW_VERSION:
            raise rd.ReceiptError(
                f"aw {version} is a rejected dirty published artifact; it may "
                "be exercised only as installed-fleet compatibility, never "
                "as candidate provenance"
            )
        ref = rd.LaneRef.from_dict(side.get("lane_ref"))
        store, authority = self._staged_capabilities(component)
        authoritative = authority.expected_digest(ref.artifact)
        if f"sha256:{authoritative}" != ref.zip_digest:
            raise rd.ReceiptError(
                f"{component}: independent authority records sha256:{authoritative}, "
                f"not the candidate LaneRef's {ref.zip_digest}"
            )
        outer = store.get(ref.artifact)
        actual_outer = f"sha256:{_sha256(outer)}"
        if actual_outer != ref.zip_digest:
            raise rd.ReceiptError(
                f"{component}: downloaded staged ZIP hashes {actual_outer}, "
                f"not {ref.zip_digest}"
            )
        if component == "aw":
            manifest = rd.validate_lane_staged_artifact(
                outer,
                expected_source_sha=ref.aw_source_sha,
                expected_version=version,
            )
            payload_name = f"aw_{version}_{self._platform()}.tar.gz"
            payload = _zip_member(outer, f"dist/{payload_name}")
            executable = _aw_from_archive(payload, payload_name)
            output = root / "aw"
            output.write_bytes(executable)
            output.chmod(output.stat().st_mode | stat.S_IXUSR)
        else:
            manifest = rd.validate_pypi_lane_artifact(
                outer,
                expected_source_sha=ref.aw_source_sha,
                expected_version=version,
                package="server",
                pypi_name="aweb",
            )
            wheels = sorted(name for name in manifest["files"] if name.endswith(".whl"))
            payload_name = wheels[0]
            payload = _zip_member(outer, f"dist/{payload_name}")
            output = root / payload_name
            output.write_bytes(payload)
        self._bind_candidate_side(side, manifest)
        return ResolvedArtifact(
            component=component,
            version=version,
            path=output,
            evidence={
                "component": component,
                "version": version,
                "kind": "candidate",
                "lane_ref": ref.to_dict(),
                "outer_sha256": _sha256(outer),
                "digest_set": dict(manifest["files"]),
                "payload_name": payload_name,
                "payload_sha256": _sha256(payload if component == "server" else executable),
                "archive_payload_sha256": _sha256(payload),
            },
        )

    @staticmethod
    def _bind_candidate_side(side: dict, manifest: dict) -> None:
        if side.get("digest_set") != manifest["files"]:
            raise rd.ReceiptError(
                f"{side['component']}: SkewCell digest set does not equal the staged manifest"
            )
        canonical = rd.canonical_digest_of_set(manifest["files"])
        if side.get("digest") != canonical:
            raise rd.ReceiptError(
                f"{side['component']}: SkewCell digest {side.get('digest')!r} "
                f"does not equal staged canonical set digest {canonical}"
            )

    def _published_aw(self, side: dict, kind: str, root: Path) -> ResolvedArtifact:
        version = side.get("version") or ""
        archive_name = f"aw_{version}_{self._platform()}.tar.gz"
        checksums = self._release_fetch(version, "checksums.txt")
        archive = self._release_fetch(version, archive_name)
        if checksums is None or archive is None:
            raise rd.ReceiptError(
                f"GitHub release v{version} lacks checksums.txt or {archive_name}"
            )
        expected = _checksum_for(checksums, archive_name)
        actual = _sha256(archive)
        if actual != expected:
            raise rd.ReceiptError(
                f"GitHub release {archive_name} hashes {actual}, checksums.txt records {expected}"
            )
        executable = _aw_from_archive(archive, archive_name)
        output = root / "aw"
        output.write_bytes(executable)
        output.chmod(output.stat().st_mode | stat.S_IXUSR)
        evidence = {
            "component": "aw",
            "version": version,
            "kind": kind,
            "registry": "github-release:awebai/aw",
            "tag": f"v{version}",
            "checksums_sha256": _sha256(checksums),
            "payload_name": archive_name,
            "outer_sha256": actual,
            "registry_sha256": expected,
            "payload_sha256": _sha256(executable),
        }
        if version == DIRTY_FLEET_AW_VERSION:
            evidence.update({
                "provenance_status": "rejected-dirty",
                "use": "installed-fleet-compatibility-only",
            })
        return ResolvedArtifact(
            component="aw", version=version, path=output, evidence=evidence
        )

    def _published_server(self, side: dict, kind: str, root: Path) -> ResolvedArtifact:
        version = side.get("version") or ""
        metadata = self._pypi(version)
        if not isinstance(metadata, dict):
            raise rd.ReceiptError(f"PyPI has no metadata for aweb {version}")
        wheels = [
            item for item in metadata.get("urls", [])
            if item.get("packagetype") == "bdist_wheel"
            and item.get("yanked") is not True
            and str(item.get("filename", "")).endswith(".whl")
        ]
        if len(wheels) != 1:
            raise rd.ReceiptError(
                f"PyPI aweb {version} exposes {len(wheels)} usable wheels, expected exactly one"
            )
        record = wheels[0]
        expected = (record.get("digests") or {}).get("sha256") or ""
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise rd.ReceiptError(
                f"PyPI aweb {version} wheel has no sha256 digest"
            )
        body = self._url(record["url"])
        actual = _sha256(body)
        if actual != expected:
            raise rd.ReceiptError(
                f"downloaded PyPI wheel hashes {actual}, PyPI records {expected}"
            )
        output = root / record["filename"]
        output.write_bytes(body)
        return ResolvedArtifact(
            component="server",
            version=version,
            path=output,
            evidence={
                "component": "server",
                "version": version,
                "kind": kind,
                "registry": "pypi:aweb",
                "url": record["url"],
                "payload_name": record["filename"],
                "outer_sha256": actual,
                "registry_sha256": expected,
                "payload_sha256": actual,
            },
        )


def _zip_member(body: bytes, member: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        names = [name for name in archive.namelist() if name == member]
        if len(names) != 1:
            raise rd.ReceiptError(
                f"staged artifact carries {len(names)} copies of {member}, expected one"
            )
        return archive.read(member)


def _aw_from_archive(body: bytes, name: str) -> bytes:
    if name.endswith(".tar.gz"):
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
            members = [
                item for item in archive.getmembers()
                if item.isfile() and Path(item.name).name == "aw"
            ]
            if len(members) != 1:
                raise rd.ReceiptError(
                    f"{name} carries {len(members)} aw executables, expected one"
                )
            extracted = archive.extractfile(members[0])
            if extracted is None:
                raise rd.ReceiptError(f"cannot read aw executable from {name}")
            return extracted.read()
    if name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            members = [n for n in archive.namelist() if Path(n).name == "aw.exe"]
            if len(members) != 1:
                raise rd.ReceiptError(
                    f"{name} carries {len(members)} aw.exe files, expected one"
                )
            return archive.read(members[0])
    raise rd.ReceiptError(f"unsupported aw release archive {name}")


def _checksum_for(body: bytes, filename: str) -> str:
    matches = []
    for raw in body.decode("utf-8").splitlines():
        parts = raw.split()
        if len(parts) == 2 and parts[1].lstrip("*") == filename:
            matches.append(parts[0])
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{64}", matches[0]):
        raise rd.ReceiptError(
            f"checksums.txt carries {len(matches)} valid entries for {filename}, expected one"
        )
    return matches[0]


def cell_document(cell: rd.SkewCell) -> dict:
    return {
        "edge_id": cell.edge_id,
        "edge": {"a": cell.edge_a, "b": cell.edge_b},
        "journey": cell.journey,
        "artifacts": dict(cell.artifacts),
        "declared_direction": cell.declared_direction,
        "direction": cell.direction,
        "a": {"kind": cell.a_kind, **cell.a},
        "b": {"kind": cell.b_kind, **cell.b},
    }


class SkewJourneyFailure(Exception):
    def __init__(self, message: str, evidence: dict):
        super().__init__(message)
        self.evidence = evidence


_DEFAULT_EVIDENCE = object()


class CliServerSkewHarness:
    """Small child invocation contract consumed by ``SkewHarnessRouter``."""

    def __init__(
        self,
        *,
        resolver=None,
        journey=None,
        evidence_root=_DEFAULT_EVIDENCE,
    ):
        self._resolver = resolver or CliServerArtifactResolver()
        self._journey = journey or _run_real_stack_journey
        if evidence_root is _DEFAULT_EVIDENCE:
            evidence_root = os.environ.get(
                "AWEB_SKEW_EVIDENCE_DIR",
                str(REPO_ROOT / ".release-runs" / "skew-cli-server"),
            )
        self._evidence_root = Path(evidence_root) if evidence_root is not None else None

    def run(self, cell: rd.SkewCell) -> None:
        self.run_evidenced(cell)

    def run_evidenced(self, cell: rd.SkewCell) -> dict:
        _validate_cell(cell)
        with tempfile.TemporaryDirectory(prefix="aweb-skew-cli-server-") as tmp:
            root = Path(tmp)
            aw = self._resolver.resolve(cell.a, cell.a_kind, cell.artifacts["a"], root)
            server = self._resolver.resolve(cell.b, cell.b_kind, cell.artifacts["b"], root)
            evidence = {
                "schema": "aweb.release.skew-cell-evidence.v1",
                "cell": cell_document(cell),
                "artifacts": [aw.evidence, server.evidence],
            }
            try:
                self._journey(aw, server, cell.direction)
            except Exception as exc:
                evidence["outcome"] = "red"
                evidence["error"] = str(exc)
                self._write_evidence(evidence)
                raise SkewJourneyFailure(str(exc), evidence) from exc
            evidence["outcome"] = "green"
            self._write_evidence(evidence)
            return evidence

    def _write_evidence(self, evidence: dict) -> None:
        if self._evidence_root is None:
            return
        body = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
        identity = _sha256(json.dumps(evidence["cell"], sort_keys=True).encode())
        self._evidence_root.mkdir(parents=True, exist_ok=True)
        target = self._evidence_root / f"{identity}.json"
        temporary = target.with_suffix(".tmp")
        temporary.write_bytes(body)
        os.replace(temporary, target)


def _validate_cell(cell: rd.SkewCell) -> None:
    if (
        cell.edge_id != EDGE_ID
        or cell.edge_a != "aw"
        or cell.edge_b != "server"
        or cell.journey != JOURNEY
        or cell.artifacts != ARTIFACTS
        or cell.declared_direction != DIRECTION
        or cell.direction not in ("a-to-b", "b-to-a")
        or cell.a.get("component") != "aw"
        or cell.b.get("component") != "server"
    ):
        raise rd.ReceiptError(
            "skew cell does not bind the exact CLI/server edge preimage"
        )


def _run_real_stack_journey(
    aw: ResolvedArtifact, server: ResolvedArtifact, direction: str
) -> None:
    env = os.environ.copy()
    env.update({
        "AW_BIN": str(aw.path),
        "AWEB_E2E_SERVER_WHEEL": str(server.path),
        "AW_SKEW_DIRECTION": direction,
    })
    result = subprocess.run(
        ["make", "cli-server-skew-cell"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            _summarize_journey_failure(
                result.returncode, result.stdout, result.stderr
            )
        )


def _summarize_journey_failure(returncode: int, stdout: str, stderr: str) -> str:
    combined = stdout + "\n" + stderr
    for marker in NEGATIVE_FEATURE_MARKERS:
        if marker in combined:
            # The control identity is the assertion category, not the temp
            # workspace path or host metadata rendered after it.
            return f"real-stack journey exited {returncode}: {marker}"
    tails = []
    for label, value in (("stdout", stdout), ("stderr", stderr)):
        lines = value.splitlines()[-20:]
        if lines:
            tails.append(f"{label}:\n" + "\n".join(lines))
    detail = "\n".join(tails)
    return (f"real-stack journey exited {returncode}\n{detail}")[:4000]


def measure_support(
    *,
    staged: dict[str, rd.ReceiptEntry],
    supported_versions: dict[str, list[str]],
    published_versions: dict[str, str],
    negative_server: str,
    harness,
) -> dict:
    """Run the known-red control, then the runner-defined supported matrix."""
    server_support = supported_versions.get("server") or []
    if negative_server in server_support:
        raise rd.ReceiptError(
            f"server {negative_server} is negative-only and cannot enter "
            "supported_versions"
        )
    if negative_server != NEGATIVE_SERVER_VERSION:
        raise rd.ReceiptError(
            f"CLI/server measurement control must be {NEGATIVE_SERVER_VERSION}, "
            f"got {negative_server}"
        )
    if not server_support or server_support[0] != FIRST_SUPPORTED_SERVER_VERSION:
        raise rd.ReceiptError(
            f"the measured server floor must start at the first published fix "
            f"{FIRST_SUPPORTED_SERVER_VERSION}, got {server_support}"
        )
    negative_cells = rd.compute_skew_cells(
        EDGE,
        moving={"aw"},
        staged=staged,
        support={"supported_versions": {"server": [negative_server]}},
        published_versions={"server": negative_server},
    )
    negative_evidence = []
    for negative in negative_cells:
        try:
            green = harness.run_evidenced(negative)
        except SkewJourneyFailure as exc:
            failure = exc.evidence.get("error", "")
            if not any(marker in failure for marker in NEGATIVE_FEATURE_MARKERS):
                raise rd.ReceiptError(
                    f"negative control server {negative_server} did not fail "
                    f"on the required distinct-ID/lock feature: {failure}"
                ) from exc
            negative_evidence.append(exc.evidence)
        else:
            raise rd.ReceiptError(
                f"negative control server {negative_server} was green for "
                f"{negative.direction}: {green!r}"
            )

    supported_cells = rd.compute_skew_cells(
        EDGE,
        moving={"aw", "server"},
        staged=staged,
        support={"supported_versions": supported_versions},
        published_versions=published_versions,
    )
    evidence = [harness.run_evidenced(item) for item in supported_cells]
    if DIRTY_FLEET_AW_VERSION in (supported_versions.get("aw") or []):
        _require_dirty_fleet_evidence(evidence)
    return {
        "schema": "aweb.release.runtime-support-measurement.v1",
        "edge_id": EDGE_ID,
        "edge": {"a": "aw", "b": "server"},
        "journey": JOURNEY,
        "artifacts": dict(ARTIFACTS),
        "direction": DIRECTION,
        "policy": "additive-only",
        "support_basis": {
            "server": {
                "negative_only": NEGATIVE_SERVER_VERSION,
                "first_supported": FIRST_SUPPORTED_SERVER_VERSION,
                "required_feature": "distinct workspace/agent lock and presence identity",
            },
            "aw": {
                DIRTY_FLEET_AW_VERSION: {
                    "provenance_status": "rejected-dirty",
                    "use": "installed-fleet-compatibility-only",
                    "candidate_eligible": False,
                }
            },
        },
        "supported_versions": {
            name: list(versions) for name, versions in sorted(supported_versions.items())
        },
        "negative_control": negative_evidence,
        "evidence": evidence,
    }


def _require_dirty_fleet_evidence(evidence: list[dict]) -> None:
    observed = [
        artifact
        for row in evidence
        for artifact in row.get("artifacts", [])
        if artifact.get("component") == "aw"
        and artifact.get("version") == DIRTY_FLEET_AW_VERSION
    ]
    if not observed:
        raise rd.ReceiptError(
            f"aw {DIRTY_FLEET_AW_VERSION} support lacks independently bound "
            "installed-fleet artifact evidence"
        )
    for artifact in observed:
        if (
            artifact.get("kind") == "candidate"
            or artifact.get("provenance_status") != "rejected-dirty"
            or artifact.get("use") != "installed-fleet-compatibility-only"
            or artifact.get("outer_sha256") != artifact.get("registry_sha256")
            or not re.fullmatch(r"[0-9a-f]{64}", artifact.get("payload_sha256", ""))
        ):
            raise rd.ReceiptError(
                f"aw {DIRTY_FLEET_AW_VERSION} evidence is not exact public "
                f"installed-fleet compatibility evidence: {artifact!r}"
            )


def _entry_from_manifest(name: str, entry: dict) -> rd.ReceiptEntry:
    return rd.ReceiptEntry(
        version=entry["version"],
        digest=entry["digest"],
        phase="staged",
        digest_set=entry.get("digest_set"),
        lane_ref=entry.get("lane_ref"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="verb", required=True)
    measure = sub.add_parser("measure")
    measure.add_argument("--staged-manifest", required=True)
    measure.add_argument("--supported-aw", action="append", required=True)
    measure.add_argument("--supported-server", action="append", required=True)
    measure.add_argument("--published-aw-latest", required=True)
    measure.add_argument("--published-server-latest", required=True)
    measure.add_argument("--negative-server", default=NEGATIVE_SERVER_VERSION)
    measure.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    manifest_path = Path(args.staged_manifest)
    body = manifest_path.read_bytes()
    try:
        manifest = json.loads(body)
        rd.validate_staged_manifest(manifest)
        entries = {
            name: _entry_from_manifest(name, manifest["entries"][name])
            for name in ("aw", "server")
        }
        document = measure_support(
            staged=entries,
            supported_versions={
                "aw": args.supported_aw,
                "server": args.supported_server,
            },
            published_versions={
                "aw": args.published_aw_latest,
                "server": args.published_server_latest,
            },
            negative_server=args.negative_server,
            harness=CliServerSkewHarness(),
        )
        document["staged_manifest_sha256"] = _sha256(body)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        print(f"measurement {output} sha256:{_sha256(output.read_bytes())}")
        return 0
    except (KeyError, ValueError, rd.ReceiptError, SkewJourneyFailure) as exc:
        print(f"BLOCKED: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
