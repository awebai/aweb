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
import tomllib
import urllib.parse
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


def _github_release_metadata_fetch(version: str) -> dict:
    try:
        return json.loads(
            rd._run_gh_api(f"repos/awebai/aw/releases/tags/v{version}")
        )
    except (json.JSONDecodeError, rd.ReceiptError) as exc:
        raise rd.ReceiptError(
            f"GitHub release metadata read failed for aw {version}: {exc}"
        ) from exc


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


def _probe_aw_version(path: Path) -> dict:
    env = os.environ.copy()
    env["AW_NO_UPDATE_CHECK"] = "1"
    result = subprocess.run(
        [str(path), "version"], env=env, text=True, capture_output=True
    )
    if result.returncode != 0:
        raise rd.ReceiptError(
            f"selected published aw version command exited {result.returncode}: "
            f"{(result.stderr or result.stdout)[:500]}"
        )
    build = subprocess.run(
        ["go", "version", "-m", str(path)], text=True, capture_output=True
    )
    if build.returncode != 0:
        raise rd.ReceiptError(
            f"cannot read selected published aw module provenance: {build.stderr[:500]}"
        )
    modules = []
    for line in build.stdout.splitlines():
        fields = line.strip().split("\t")
        if len(fields) >= 3 and fields[0] == "mod" and fields[1] == "github.com/awebai/aw":
            modules.append(fields[2])
    if len(modules) != 1:
        raise rd.ReceiptError(
            f"selected published aw carries {len(modules)} main module versions"
        )
    return {"version_output": result.stdout, "module_version": modules[0]}


def locked_mcp_version() -> str:
    with (REPO_ROOT / "server/uv.lock").open("rb") as stream:
        packages = tomllib.load(stream).get("package", [])
    versions = [item.get("version") for item in packages if item.get("name") == "mcp"]
    if len(versions) != 1 or not isinstance(versions[0], str) or not versions[0]:
        raise rd.ReceiptError(
            f"server/uv.lock must bind exactly one mcp version, found {versions!r}"
        )
    return versions[0]


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
        github_release_metadata_fetch=_github_release_metadata_fetch,
        pypi_metadata_fetch=_pypi_metadata_fetch,
        url_fetch=_url_fetch,
        platform_name=_default_platform_name,
        aw_version_probe=_probe_aw_version,
    ):
        self._staged_capabilities = staged_capabilities
        self._release_fetch = github_release_fetch
        self._release_metadata = github_release_metadata_fetch
        self._pypi = pypi_metadata_fetch
        self._url = url_fetch
        self._platform = platform_name
        self._aw_version_probe = aw_version_probe

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
        metadata = self._release_metadata(version)
        registry_set = _github_release_digest_set(metadata, version)
        expected_names = set(rd.expected_lane_payload_names(version)[0])
        if set(registry_set) != expected_names:
            raise rd.ReceiptError(
                f"GitHub release v{version} asset set is not exact: "
                f"got {sorted(registry_set)}, expected {sorted(expected_names)}"
            )
        checksums = self._release_fetch(version, "checksums.txt")
        archive = self._release_fetch(version, archive_name)
        if checksums is None or archive is None:
            raise rd.ReceiptError(
                f"GitHub release v{version} lacks checksums.txt or {archive_name}"
            )
        actual_checksums = _sha256(checksums)
        if actual_checksums != registry_set["checksums.txt"]:
            raise rd.ReceiptError(
                f"downloaded checksums.txt hashes {actual_checksums}, GitHub API "
                f"records {registry_set['checksums.txt']}"
            )
        checksums_set = _checksum_set(checksums)
        expected_checksums = {
            name: digest for name, digest in registry_set.items()
            if name != "checksums.txt"
        }
        if checksums_set != expected_checksums:
            raise rd.ReceiptError(
                f"checksums.txt set does not equal the complete GitHub asset digest set"
            )
        actual = _sha256(archive)
        archive_registry = registry_set[archive_name]
        if actual != archive_registry:
            raise rd.ReceiptError(
                f"GitHub release {archive_name} hashes {actual}, GitHub API "
                f"records {archive_registry}"
            )
        executable = _aw_from_archive(archive, archive_name)
        output = root / "aw"
        output.write_bytes(executable)
        output.chmod(output.stat().st_mode | stat.S_IXUSR)
        version_proof = _validate_aw_version_proof(
            self._aw_version_probe(output), version
        )
        evidence = {
            "component": "aw",
            "version": version,
            "kind": kind,
            "registry": "github-release:awebai/aw",
            "tag": f"v{version}",
            "registry_digest_set": registry_set,
            "registry_set_digest": rd.canonical_digest_of_set(registry_set),
            "checksums_sha256": actual_checksums,
            "checksums_registry_sha256": registry_set["checksums.txt"],
            "payload_name": archive_name,
            "outer_sha256": actual,
            "registry_sha256": archive_registry,
            "checksums_recorded_sha256": checksums_set[archive_name],
            "payload_sha256": _sha256(executable),
            **version_proof,
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
        info_version = (metadata.get("info") or {}).get("version")
        if info_version != version:
            raise rd.ReceiptError(
                f"PyPI metadata info.version {info_version!r} is not requested {version!r}"
            )
        records = metadata.get("urls")
        if not isinstance(records, list) or not records:
            raise rd.ReceiptError(f"PyPI aweb {version} release file set is empty")
        registry_set = {}
        by_type = {}
        for record in records:
            filename, digest = _validate_pypi_record(record, version)
            if filename in registry_set:
                raise rd.ReceiptError(
                    f"PyPI aweb {version} repeats release filename {filename}"
                )
            registry_set[filename] = digest
            by_type.setdefault(record["packagetype"], []).append(record)
        expected_names = {
            f"aweb-{version}-py3-none-any.whl",
            f"aweb-{version}.tar.gz",
        }
        if set(registry_set) != expected_names or set(by_type) != {"bdist_wheel", "sdist"}:
            raise rd.ReceiptError(
                f"PyPI aweb {version} release file set is not exact: "
                f"got {sorted(registry_set)}, expected {sorted(expected_names)}"
            )
        wheels = by_type["bdist_wheel"]
        if len(wheels) != 1:
            raise rd.ReceiptError(
                f"PyPI aweb {version} exposes {len(wheels)} wheels, expected exactly one"
            )
        record = wheels[0]
        expected = registry_set[record["filename"]]
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
                "registry_digest_set": registry_set,
                "registry_set_digest": rd.canonical_digest_of_set(registry_set),
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


def _safe_artifact_name(name: object, *, authority: str) -> str:
    if (
        not isinstance(name, str)
        or not name
        or Path(name).name != name
        or "/" in name
        or "\\" in name
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name)
    ):
        raise rd.ReceiptError(f"{authority} carries unsafe artifact filename {name!r}")
    return name


def _github_release_digest_set(metadata: dict, version: str) -> dict[str, str]:
    if not isinstance(metadata, dict) or metadata.get("tag_name") != f"v{version}":
        raise rd.ReceiptError(
            f"GitHub release metadata does not bind exact tag v{version}"
        )
    assets = metadata.get("assets")
    if not isinstance(assets, list) or not assets:
        raise rd.ReceiptError(f"GitHub release v{version} asset set is empty")
    result = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise rd.ReceiptError(f"GitHub release v{version} has malformed asset metadata")
        name = _safe_artifact_name(asset.get("name"), authority="GitHub release")
        digest = str(asset.get("digest") or "").removeprefix("sha256:")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise rd.ReceiptError(
                f"GitHub API records no sha256 digest for v{version}/{name}"
            )
        if name in result:
            raise rd.ReceiptError(f"GitHub release v{version} repeats asset {name}")
        result[name] = digest
    return dict(sorted(result.items()))


def _checksum_set(body: bytes) -> dict[str, str]:
    try:
        lines = body.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise rd.ReceiptError(f"checksums.txt is not UTF-8: {exc}") from exc
    result = {}
    for raw in lines:
        parts = raw.split()
        if len(parts) != 2:
            raise rd.ReceiptError(f"checksums.txt carries malformed line {raw!r}")
        digest, raw_name = parts
        name = _safe_artifact_name(raw_name.lstrip("*"), authority="checksums.txt")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise rd.ReceiptError(f"checksums.txt carries invalid digest for {name}")
        if name in result:
            raise rd.ReceiptError(f"checksums.txt repeats {name}")
        result[name] = digest
    if not result:
        raise rd.ReceiptError("checksums.txt digest set is empty")
    return dict(sorted(result.items()))


def _validate_pypi_record(record: object, version: str) -> tuple[str, str]:
    if not isinstance(record, dict):
        raise rd.ReceiptError(f"PyPI aweb {version} has malformed release file metadata")
    filename = _safe_artifact_name(record.get("filename"), authority="PyPI")
    if record.get("packagetype") not in {"bdist_wheel", "sdist"}:
        raise rd.ReceiptError(
            f"PyPI aweb {version}/{filename} has unsupported package type "
            f"{record.get('packagetype')!r}"
        )
    if record.get("yanked") is not False:
        raise rd.ReceiptError(f"PyPI aweb {version}/{filename} is yanked or ambiguous")
    digest = (record.get("digests") or {}).get("sha256") or ""
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise rd.ReceiptError(f"PyPI aweb {version}/{filename} has no sha256 digest")
    url = record.get("url")
    parsed = urllib.parse.urlsplit(url) if isinstance(url, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or parsed.netloc != "files.pythonhosted.org"
        or parsed.query
        or parsed.fragment
        or Path(urllib.parse.unquote(parsed.path)).name != filename
    ):
        raise rd.ReceiptError(
            f"PyPI aweb {version}/{filename} has unsafe or mismatched URL {url!r}"
        )
    return filename, digest


def _validate_aw_version_proof(proof: object, version: str) -> dict:
    if not isinstance(proof, dict) or set(proof) != {"version_output", "module_version"}:
        raise rd.ReceiptError(f"published aw version proof has wrong fields: {proof!r}")
    output = proof["version_output"]
    module = proof["module_version"]
    lines = output.splitlines() if isinstance(output, str) else []
    if (
        len(lines) != 3
        or lines[0] != f"aw {version}"
        or not re.fullmatch(
            r"  commit: [0-9a-f]{40} \(github\.com/awebai/aw\)", lines[1]
        )
        or not re.fullmatch(r"  built:  \S+", lines[2])
    ):
        raise rd.ReceiptError(
            f"published aw version output does not bind expected version/provenance: {output!r}"
        )
    expected_module = (
        f"v{version}+dirty" if version == DIRTY_FLEET_AW_VERSION else f"v{version}"
    )
    if module != expected_module:
        raise rd.ReceiptError(
            f"published aw module version {module!r} is not expected {expected_module!r}"
        )
    return {"version_output": output, "module_version": module}


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


class JourneyExecutionFailure(RuntimeError):
    def __init__(self, message: str, runtime_proof: dict):
        super().__init__(message)
        self.runtime_proof = runtime_proof


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
        temporary_directory=tempfile.TemporaryDirectory,
    ):
        self._resolver = resolver or CliServerArtifactResolver()
        self._journey = journey or _run_real_stack_journey
        if evidence_root is _DEFAULT_EVIDENCE:
            evidence_root = os.environ.get(
                "AWEB_SKEW_EVIDENCE_DIR",
                str(REPO_ROOT / ".release-runs" / "skew-cli-server"),
            )
        self._evidence_root = Path(evidence_root) if evidence_root is not None else None
        self._temporary_directory = temporary_directory

    def run(self, cell: rd.SkewCell) -> None:
        self.run_evidenced(cell)

    def run_evidenced(self, cell: rd.SkewCell) -> dict:
        _validate_cell(cell)
        evidence = None
        journey_error = None
        try:
            with self._temporary_directory(prefix="aweb-skew-cli-server-") as tmp:
                root = Path(tmp)
                aw = self._resolver.resolve(
                    cell.a, cell.a_kind, cell.artifacts["a"], root
                )
                server = self._resolver.resolve(
                    cell.b, cell.b_kind, cell.artifacts["b"], root
                )
                identity = cell_document(cell)
                evidence = {
                    "schema": "aweb.release.skew-cell-evidence.v1",
                    "cell": identity,
                    "artifacts": [aw.evidence, server.evidence],
                }
                try:
                    runtime = self._journey(aw, server, cell.direction, identity)
                    evidence["runtime"] = validate_runtime_proof(
                        runtime, server, identity
                    )
                    evidence["outcome"] = "green"
                except Exception as exc:
                    journey_error = exc
                    if isinstance(exc, JourneyExecutionFailure):
                        try:
                            evidence["runtime"] = validate_runtime_proof(
                                exc.runtime_proof, server, identity
                            )
                        except Exception as proof_exc:
                            journey_error = proof_exc
                    evidence["outcome"] = "red"
                    evidence["error"] = str(journey_error)
        except Exception as exc:
            if evidence is None:
                raise
            evidence["outcome"] = "red"
            evidence["error"] = f"artifact temporary-directory cleanup failed: {exc}"
            self._write_evidence(evidence)
            raise SkewJourneyFailure(evidence["error"], evidence) from exc

        if journey_error is not None:
            self._write_evidence(evidence)
            raise SkewJourneyFailure(str(journey_error), evidence) from journey_error
        # Green publication is deliberately outside the artifact/proof temporary
        # context: visible green evidence means its exact outer cleanup succeeded.
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


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _run_real_stack_journey(
    aw: ResolvedArtifact, server: ResolvedArtifact, direction: str, identity: dict
) -> None:
    env = os.environ.copy()
    proof_path = server.path.parent / "server-runtime-proof.json"
    proof_path.unlink(missing_ok=True)
    identity_json = _canonical_json(identity)
    env.update({
        "AW_BIN": str(aw.path),
        "AWEB_E2E_SERVER_WHEEL": str(server.path),
        "AW_SKEW_DIRECTION": direction,
        "AW_SKEW_CELL_IDENTITY_JSON": identity_json.decode(),
        "AW_SKEW_CELL_IDENTITY_SHA256": _sha256(identity_json),
        "AWEB_SKEW_RUNTIME_PROOF_PATH": str(proof_path),
        "AWEB_SKEW_EXPECTED_SERVER_VERSION": server.version,
        "AWEB_SKEW_EXPECTED_SERVER_WHEEL_SHA256": server.evidence["payload_sha256"],
        "AWEB_SKEW_EXPECTED_MCP_VERSION": locked_mcp_version(),
    })
    result = subprocess.run(
        ["make", "cli-server-skew-cell"],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    proof = _read_runtime_proof(proof_path)
    if result.returncode != 0:
        raise JourneyExecutionFailure(
            _summarize_journey_failure(
                result.returncode, result.stdout, result.stderr
            ),
            proof,
        )
    return proof


def _read_runtime_proof(proof_path: Path) -> dict:
    if not proof_path.is_file():
        raise rd.ReceiptError(
            "real-stack journey produced no controlled-runtime server proof"
        )
    try:
        return json.loads(proof_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise rd.ReceiptError(
            f"controlled-runtime server proof is unreadable: {exc}"
        ) from exc


def validate_runtime_proof(
    proof: dict, server: ResolvedArtifact, identity: dict
) -> dict:
    expected_keys = {
        "cell_identity_sha256",
        "container_id",
        "image_id",
        "installed_distributions",
        "installed_distributions_sha256",
        "mcp_version",
        "ports",
        "project",
        "server_version",
        "wheel_sha256",
    }
    if not isinstance(proof, dict) or set(proof) != expected_keys:
        raise rd.ReceiptError(
            f"runtime server proof must carry exactly {sorted(expected_keys)}, got {proof!r}"
        )
    inventory = proof["installed_distributions"]
    valid_inventory = (
        isinstance(inventory, dict)
        and bool(inventory)
        and all(
            isinstance(name, str)
            and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name)
            and isinstance(version, str)
            and bool(version)
            for name, version in inventory.items()
        )
    )
    inventory_digest = _sha256(_canonical_json(inventory)) if valid_inventory else ""
    identity_digest = _sha256(_canonical_json(identity))
    ports = proof["ports"]
    valid_ports = (
        isinstance(ports, dict)
        and set(ports) == {"aweb", "awid", "library", "postgres"}
        and all(
            isinstance(value, int)
            and not isinstance(value, bool)
            and 1 <= value <= 65535
            for value in ports.values()
        )
        and len(set(ports.values())) == 4
    )
    project_pattern = rf"aweb-skew-{identity_digest[:20]}-[0-9a-f]{{16}}"
    if (
        proof["server_version"] != server.version
        or proof["wheel_sha256"] != server.evidence.get("payload_sha256")
        or proof["mcp_version"] != locked_mcp_version()
        or not valid_inventory
        or inventory.get("aweb") != server.version
        or inventory.get("mcp") != proof["mcp_version"]
        or proof["installed_distributions_sha256"] != inventory_digest
        or proof["cell_identity_sha256"] != identity_digest
        or not valid_ports
        or not re.fullmatch(r"[0-9a-f]{64}", proof["wheel_sha256"])
        or not re.fullmatch(r"[0-9a-f]{64}", proof["container_id"])
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", proof["image_id"])
        or not re.fullmatch(project_pattern, proof["project"])
    ):
        raise rd.ReceiptError(
            f"runtime server proof does not bind exact cell/wheel/dependencies/container: {proof!r}"
        )
    return dict(proof)


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
    first_supported_controls = [
        row for row in evidence
        if (row.get("runtime") or {}).get("server_version")
        == FIRST_SUPPORTED_SERVER_VERSION
    ]
    if not first_supported_controls:
        raise rd.ReceiptError(
            f"support measurement lacks positive server {FIRST_SUPPORTED_SERVER_VERSION} controls"
        )
    _require_uniform_dependency_posture(
        negative_evidence + first_supported_controls
    )
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


def _require_uniform_dependency_posture(evidence: list[dict]) -> None:
    postures = {}
    for row in evidence:
        runtime = row.get("runtime") or {}
        inventory = runtime.get("installed_distributions")
        if not isinstance(inventory, dict) or "aweb" not in inventory:
            raise rd.ReceiptError(
                "CLI/server skew evidence lacks the full installed-distribution inventory"
            )
        dependencies = {name: version for name, version in inventory.items() if name != "aweb"}
        digest = _sha256(_canonical_json(dependencies))
        postures.setdefault(digest, []).append({
            "cell": row.get("cell"),
            "server_version": inventory["aweb"],
        })
    if len(postures) != 1:
        raise rd.ReceiptError(
            f"CLI/server controls differ in dependency resolution beyond the server wheel: {postures!r}"
        )


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
        try:
            _validate_aw_version_proof(
                {
                    "version_output": artifact.get("version_output"),
                    "module_version": artifact.get("module_version"),
                },
                DIRTY_FLEET_AW_VERSION,
            )
        except rd.ReceiptError as exc:
            raise rd.ReceiptError(
                f"aw {DIRTY_FLEET_AW_VERSION} evidence lacks exact binary version proof: {exc}"
            ) from exc
        if (
            artifact.get("kind") == "candidate"
            or artifact.get("provenance_status") != "rejected-dirty"
            or artifact.get("use") != "installed-fleet-compatibility-only"
            or artifact.get("outer_sha256") != artifact.get("registry_sha256")
            or artifact.get("outer_sha256") != artifact.get("checksums_recorded_sha256")
            or artifact.get("checksums_sha256")
            != artifact.get("checksums_registry_sha256")
            or artifact.get("module_version") != f"v{DIRTY_FLEET_AW_VERSION}+dirty"
            or not isinstance(artifact.get("registry_digest_set"), dict)
            or not artifact.get("registry_digest_set")
            or artifact.get("registry_set_digest")
            != rd.canonical_digest_of_set(artifact.get("registry_digest_set", {}))
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
