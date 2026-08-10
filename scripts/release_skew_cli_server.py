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

import release_channel_pi_skew as measurement_inputs
import release_driver as rd

PublishedServerAuthority = measurement_inputs.PublishedServerAuthority
expected_published_server_authority_report = (
    measurement_inputs.expected_published_server_authority_report
)
_atomic_write_text = measurement_inputs._atomic_write_text
_require_child_identity = measurement_inputs._require_child_identity
_require_envelope = measurement_inputs._require_envelope
_require_unanchored_measurement = measurement_inputs._require_unanchored_measurement
ENVELOPE_SCHEMA = measurement_inputs.ENVELOPE_SCHEMA

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
CONTROL_SCHEMA = "aweb.release.cli-server-skew-control.v1"
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
    return rd.skew_cell_preimage(cell)


class JourneyExecutionFailure(RuntimeError):
    def __init__(self, message: str, runtime_proof: dict):
        super().__init__(message)
        self.runtime_proof = runtime_proof


class SkewJourneyFailure(Exception):
    def __init__(self, message: str, evidence: dict):
        super().__init__(message)
        self.evidence = evidence


_DEFAULT_EVIDENCE = object()


def _negative_control_cells(matrix: dict) -> list[rd.SkewCell]:
    rd.validate_skew_matrix_document(matrix)
    preimage = matrix["preimage"]
    if preimage["moving"] != ["aw"] or set(preimage["staged"]) != {"aw"}:
        raise rd.ReceiptError(
            "CLI/server negative controls require the frozen candidate-aw matrix"
        )
    staged = {"aw": rd.ReceiptEntry(**preimage["staged"]["aw"])}
    return rd.compute_skew_cells(
        EDGE,
        moving={"aw"},
        staged=staged,
        support={"supported_versions": {
            "server": [NEGATIVE_SERVER_VERSION]
        }},
        published_versions={"server": NEGATIVE_SERVER_VERSION},
    )


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
        self._matrix: dict | None = None
        self._cells: dict[str, rd.SkewCell] = {}
        self._cell_evidence: dict[str, dict] = {}
        self._control_evidence: dict[str, dict] = {}
        self._finished = False

    def freeze_matrix(self, document: dict) -> Path:
        cells = rd.validate_skew_matrix_document(document)
        edge = document["preimage"]["edge"]
        if edge != {
            "a": "aw", "b": "server", "journey": JOURNEY,
            "artifacts": ARTIFACTS, "direction": DIRECTION,
        } or any(_cell_invalid(cell) for cell in cells):
            raise rd.ReceiptError(
                "CLI/server child accepts only its exact frozen edge matrix"
            )
        if self._matrix is not None and self._matrix != document:
            raise rd.ReceiptError("CLI/server child was given two matrices")
        if self._evidence_root is None:
            raise rd.ReceiptError("CLI/server matrix requires an evidence root")
        path = self._evidence_root / f"matrix-{document['matrix_id']}.json"
        if path.exists():
            try:
                stored = json.loads(path.read_bytes())
            except (OSError, json.JSONDecodeError) as exc:
                raise rd.ReceiptError("CLI/server matrix evidence is unreadable") from exc
            if stored != document or path.read_bytes() != _canonical_json(stored):
                raise rd.ReceiptError("CLI/server matrix evidence is stale or tampered")
        else:
            self._atomic_json(path, document)
        self._matrix = json.loads(json.dumps(document))
        self._cells = {rd.skew_cell_identity(cell): cell for cell in cells}
        return path

    def _frozen_cell_id(self, cell: rd.SkewCell) -> str:
        if self._matrix is None:
            raise rd.ReceiptError("CLI/server cell arrived before its frozen matrix")
        # Membership is decided by the CANONICAL IDENTITY, not by comparing
        # cell objects. skew_cell_preimage covers every SkewCell field, so an
        # identity match is a full content match - and it survives the fact that
        # the driver runs as __main__ while every child does `import
        # release_driver`, which makes TWO SkewCell classes. Dataclass equality
        # is class-scoped, so object comparison refused every genuine member the
        # first time this edge executed in a release-run.
        identity = rd.skew_cell_identity(cell)
        if identity not in self._cells:
            raise rd.ReceiptError(
                "CLI/server cell is not an exact member of the frozen matrix"
            )
        return identity

    def record_control(
        self, matrix: dict, cell: rd.SkewCell, evidence: dict
    ) -> Path:
        if matrix != self._matrix:
            raise rd.ReceiptError(
                "CLI/server control does not bind the frozen matrix"
            )
        expected = {
            rd.skew_cell_identity(item): item
            for item in _negative_control_cells(matrix)
        }
        cell_id = rd.skew_cell_identity(cell)
        if expected.get(cell_id) != cell:
            raise rd.ReceiptError(
                "CLI/server control is not an exact negative cell"
            )
        if (
            not isinstance(evidence, dict)
            or evidence.get("schema")
                != "aweb.release.skew-cell-evidence.v1"
            or evidence.get("cell") != rd.skew_cell_preimage(cell)
            or evidence.get("outcome") != "red"
            or not any(
                marker in str(evidence.get("error", ""))
                for marker in NEGATIVE_FEATURE_MARKERS
            )
        ):
            raise rd.ReceiptError(
                "CLI/server negative control evidence is not the reviewed red class"
            )
        report = {
            key: value for key, value in evidence.items() if key != "schema"
        }
        report.update({
            "schema": CONTROL_SCHEMA,
            "matrix_id": matrix["matrix_id"],
            "cell_id": cell_id,
        })
        report["control_id"] = rd.canonical_json_digest(report)
        path = self._evidence_root / "controls" / (
            f"{matrix['matrix_id']}-{cell_id}.json"
        )
        self._atomic_json(path, report)
        self._control_evidence[cell_id] = {
            "path": path,
            "sha256": _sha256(path.read_bytes()),
            "cell": cell,
        }
        return path

    def run(self, cell: rd.SkewCell) -> dict:
        cell_id = self._frozen_cell_id(cell)
        target = self._evidence_root / "cells" / (
            f"{self._matrix['matrix_id']}-{cell_id}.json"
        )
        if target.exists():
            raise rd.ReceiptError("CLI/server frozen cell already has evidence")
        evidence = self.run_evidenced(cell, publish=False)
        report = {
            **evidence,
            "schema": "aweb.release.cli-server-skew-cell.v2",
            "matrix_id": self._matrix["matrix_id"],
            "cell_id": cell_id,
        }
        report["report_id"] = rd.canonical_json_digest(report)
        path = self._write_matrix_report(report)
        self._cell_evidence[cell_id] = {
            "path": path,
            "sha256": _sha256(path.read_bytes()),
        }
        return evidence

    def run_evidenced(self, cell: rd.SkewCell, *, publish: bool = True) -> dict:
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
            if publish:
                self._write_evidence(evidence)
            raise SkewJourneyFailure(evidence["error"], evidence) from exc

        if journey_error is not None:
            if publish:
                self._write_evidence(evidence)
            raise SkewJourneyFailure(str(journey_error), evidence) from journey_error
        # Green publication is deliberately outside the artifact/proof temporary
        # context: visible green evidence means its exact outer cleanup succeeded.
        if publish:
            self._write_evidence(evidence)
        return evidence

    @staticmethod
    def _atomic_json(path: Path, document: dict) -> Path:
        body = _canonical_json(document)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(body)
        os.replace(temporary, path)
        return path

    def _write_matrix_report(self, report: dict) -> Path:
        path = self._evidence_root / "cells" / (
            f"{self._matrix['matrix_id']}-{report['cell_id']}.json"
        )
        return self._atomic_json(path, report)

    def _validate_effect_time_evidence(self) -> None:
        if set(self._cell_evidence) != set(self._cells):
            raise rd.ReceiptError(
                "CLI/server effect-time evidence inventory is not exact"
            )
        for cell_id in self._cells:
            expected_path = self._evidence_root / "cells" / (
                f"{self._matrix['matrix_id']}-{cell_id}.json"
            )
            evidence = self._cell_evidence[cell_id]
            if (
                not isinstance(evidence, dict)
                or set(evidence) != {"path", "sha256"}
                or evidence["path"] != expected_path
                or expected_path.is_symlink()
            ):
                raise rd.ReceiptError(
                    f"CLI/server effect-time evidence inventory drifted for {cell_id}"
                )
            try:
                observed = _sha256(expected_path.read_bytes())
            except OSError as exc:
                raise rd.ReceiptError(
                    f"CLI/server effect-time evidence is unreadable for {cell_id}: {exc}"
                ) from exc
            if observed != evidence["sha256"]:
                raise rd.ReceiptError(
                    f"CLI/server effect-time report digest changed for {cell_id}"
                )

    def _validate_effect_time_controls(self) -> list[rd.SkewCell]:
        if not self._control_evidence:
            return []
        expected = {
            rd.skew_cell_identity(cell): cell
            for cell in _negative_control_cells(self._matrix)
        }
        if set(self._control_evidence) != set(expected):
            raise rd.ReceiptError(
                "CLI/server effect-time control inventory is not exact"
            )
        for cell_id, cell in expected.items():
            path = self._evidence_root / "controls" / (
                f"{self._matrix['matrix_id']}-{cell_id}.json"
            )
            recorded = self._control_evidence[cell_id]
            if (
                set(recorded) != {"path", "sha256", "cell"}
                or recorded["path"] != path
                or recorded["cell"] != cell
                or path.is_symlink()
                or _sha256(path.read_bytes()) != recorded["sha256"]
            ):
                raise rd.ReceiptError(
                    f"CLI/server effect-time control evidence drifted for {cell_id}"
                )
        return [expected[cell_id] for cell_id in sorted(expected)]

    def finish_matrix(self, document: dict) -> Path:
        if document != self._matrix:
            raise rd.ReceiptError(
                "CLI/server finish request does not equal its frozen matrix"
            )
        if self._finished:
            raise rd.ReceiptError("CLI/server frozen matrix already finished")
        self._validate_effect_time_evidence()
        control_cells = self._validate_effect_time_controls()
        measurement = aggregate_frozen_matrix(
            self._evidence_root / f"matrix-{document['matrix_id']}.json",
            self._evidence_root,
            control_cells=control_cells,
        )
        path = self._evidence_root / (
            f"aggregate-{document['matrix_id']}-{measurement['measurement_id']}.json"
        )
        self._atomic_json(path, measurement)
        self._finished = True
        return path

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


def _cell_invalid(cell: rd.SkewCell) -> bool:
    return (
        cell.edge_id != EDGE_ID
        or cell.edge_a != "aw"
        or cell.edge_b != "server"
        or cell.journey != JOURNEY
        or cell.artifacts != ARTIFACTS
        or cell.declared_direction != DIRECTION
        or cell.direction not in ("a-to-b", "b-to-a")
        or cell.a.get("component") != "aw"
        or cell.b.get("component") != "server"
    )


def _validate_cell(cell: rd.SkewCell) -> None:
    if _cell_invalid(cell):
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


def _validate_report_artifact(artifact: dict, side: dict, kind: str,
                              locator: str) -> dict:
    if not isinstance(artifact, dict):
        raise rd.ReceiptError("CLI/server report artifact is not an object")
    component = side.get("component")
    common = {"component", "version", "kind", "payload_name", "payload_sha256"}
    if (
        artifact.get("component") != component
        or artifact.get("version") != side.get("version")
        or artifact.get("kind") != kind
        or not re.fullmatch(r"[0-9a-f]{64}", artifact.get("payload_sha256", ""))
    ):
        raise rd.ReceiptError(
            f"CLI/server {component} artifact does not bind its frozen side"
        )
    if kind == "candidate":
        expected_fields = common | {
            "lane_ref", "outer_sha256", "digest_set", "archive_payload_sha256",
        }
        digest_set = side.get("digest_set")
        payload_digest = (
            artifact.get("payload_sha256") if component == "server"
            else artifact.get("archive_payload_sha256")
        )
        if (
            set(artifact) != expected_fields
            or artifact.get("lane_ref") != side.get("lane_ref")
            or artifact.get("digest_set") != digest_set
            or artifact.get("outer_sha256")
                != str((side.get("lane_ref") or {}).get("zip_digest", "")).removeprefix("sha256:")
            or not isinstance(digest_set, dict)
            or any(not re.fullmatch(r"[0-9a-f]{64}", value or "")
                   for value in digest_set.values())
            or side.get("digest") != rd.canonical_digest_of_set(digest_set)
            or digest_set.get(artifact.get("payload_name")) != payload_digest
        ):
            raise rd.ReceiptError(
                f"CLI/server candidate {component} artifact identity drifted"
            )
        rd.LaneRef.from_dict(side.get("lane_ref"))
        return artifact
    registry = "github-release:awebai/aw" if component == "aw" else "pypi:aweb"
    registry_set = artifact.get("registry_digest_set")
    base = common | {
        "registry", "registry_digest_set", "registry_set_digest",
        "outer_sha256", "registry_sha256",
    }
    expected_fields = (
        base | {"url"}
        if component == "server"
        else base | {
            "tag", "checksums_sha256", "checksums_registry_sha256",
            "checksums_recorded_sha256", "version_output", "module_version",
        }
    )
    if component == "aw" and artifact.get("version") == DIRTY_FLEET_AW_VERSION:
        expected_fields |= {"provenance_status", "use"}
    safe_server_url = True
    if component == "server":
        parsed = urllib.parse.urlsplit(artifact.get("url", ""))
        safe_server_url = (
            parsed.scheme == "https"
            and parsed.netloc == "files.pythonhosted.org"
            and not parsed.query and not parsed.fragment
            and Path(urllib.parse.unquote(parsed.path)).name
                == artifact.get("payload_name")
        )
    expected_registry_names = (
        set(rd.expected_lane_payload_names(artifact["version"])[0])
        if component == "aw" else {
            f"aweb-{artifact['version']}-py3-none-any.whl",
            f"aweb-{artifact['version']}.tar.gz",
        }
    )
    if (
        set(artifact) != expected_fields
        or artifact.get("registry") != registry
        or locator != registry
        or not isinstance(registry_set, dict) or not registry_set
        or set(registry_set) != expected_registry_names
        or any(not re.fullmatch(r"[0-9a-f]{64}", value or "")
               for value in registry_set.values())
        or not safe_server_url
        or artifact.get("registry_set_digest")
            != rd.canonical_digest_of_set(registry_set)
        or registry_set.get(artifact.get("payload_name"))
            != artifact.get("outer_sha256")
        or artifact.get("registry_sha256") != artifact.get("outer_sha256")
        or (component == "aw" and (
            artifact.get("tag") != f"v{artifact['version']}"
            or _validate_aw_version_proof({
                "version_output": artifact.get("version_output"),
                "module_version": artifact.get("module_version"),
            }, artifact["version"]) is None
        ))
    ):
        raise rd.ReceiptError(
            f"CLI/server published {component} artifact identity drifted"
        )
    return artifact


def aggregate_frozen_matrix(
    matrix_path: Path,
    evidence_root: Path,
    *,
    control_cells: list[rd.SkewCell] | None = None,
) -> dict:
    matrix_path = Path(matrix_path)
    matrix_body = matrix_path.read_bytes()
    document = json.loads(matrix_body)
    if matrix_body != _canonical_json(document):
        raise rd.ReceiptError("CLI/server matrix is not canonical JSON")
    cells = rd.validate_skew_matrix_document(document)
    matrix_id = document["matrix_id"]
    if matrix_path.name != f"matrix-{matrix_id}.json":
        raise rd.ReceiptError("CLI/server matrix filename does not equal its identity")
    expected = {
        f"{matrix_id}-{rd.skew_cell_identity(cell)}.json": cell
        for cell in cells
    }
    cell_dir = Path(evidence_root) / "cells"
    try:
        entries = list(cell_dir.iterdir())
    except OSError as exc:
        raise rd.ReceiptError(f"CLI/server cell evidence is unreadable: {exc}") from exc
    actual = {
        item.name: item for item in entries
        if item.is_file() and not item.is_symlink()
    }
    if set(actual) != set(expected) or len(entries) != len(expected):
        raise rd.ReceiptError(
            "CLI/server report-file set does not equal the frozen matrix; "
            f"missing={sorted(set(expected) - set(actual))}, "
            f"extra={sorted(set(actual) - set(expected))}"
        )
    candidates: dict[str, dict] = {}
    published_identities: dict[tuple[str, str], dict] = {}
    dependency_postures = set()
    reports = []
    for filename, cell in expected.items():
        body = actual[filename].read_bytes()
        try:
            report = json.loads(body)
        except json.JSONDecodeError as exc:
            raise rd.ReceiptError(f"{filename}: report is malformed") from exc
        if body != _canonical_json(report):
            raise rd.ReceiptError(f"{filename}: report is not canonical JSON")
        cell_id = rd.skew_cell_identity(cell)
        without_id = {key: value for key, value in report.items() if key != "report_id"}
        if (
            not isinstance(report, dict)
            or set(report) != {
                "schema", "matrix_id", "cell_id", "cell", "artifacts",
                "runtime", "outcome", "report_id",
            }
            or report.get("schema") != "aweb.release.cli-server-skew-cell.v2"
            or report.get("matrix_id") != matrix_id
            or report.get("cell_id") != cell_id
            or report.get("cell") != rd.skew_cell_preimage(cell)
            or report.get("outcome") != "green"
            or report.get("report_id") != rd.canonical_json_digest(without_id)
            or not isinstance(report.get("artifacts"), list)
            or len(report["artifacts"]) != 2
        ):
            raise rd.ReceiptError(
                f"{filename}: report does not bind its exact frozen cell"
            )
        artifacts = []
        for artifact, side, kind, locator in (
            (report["artifacts"][0], cell.a, cell.a_kind, cell.artifacts["a"]),
            (report["artifacts"][1], cell.b, cell.b_kind, cell.artifacts["b"]),
        ):
            validated = _validate_report_artifact(artifact, side, kind, locator)
            artifacts.append(validated)
            if kind == "candidate":
                prior = candidates.setdefault(side["component"], validated)
                if prior != validated:
                    raise rd.ReceiptError(
                        f"candidate {side['component']} identity differs across cells"
                    )
            else:
                key = (side["component"], side["version"])
                prior = published_identities.setdefault(key, validated)
                if prior != validated:
                    raise rd.ReceiptError(
                        f"published {side['component']} {side['version']} identity "
                        "differs across cells"
                    )
        server_artifact = next(
            artifact for artifact in artifacts if artifact["component"] == "server"
        )
        server = ResolvedArtifact(
            component="server", version=server_artifact["version"],
            path=Path(server_artifact["payload_name"]), evidence=server_artifact,
        )
        validate_runtime_proof(report["runtime"], server, report["cell"])
        dependencies = {
            name: version
            for name, version in report["runtime"]["installed_distributions"].items()
            if name != "aweb"
        }
        dependency_postures.add(_sha256(_canonical_json(dependencies)))
        reports.append({
            "cell_id": cell_id,
            "report_id": report["report_id"],
            "file_sha256": _sha256(body),
        })
    controls = []
    expected_controls = {
        f"{matrix_id}-{rd.skew_cell_identity(cell)}.json": cell
        for cell in (control_cells or [])
    }
    if expected_controls:
        control_dir = Path(evidence_root) / "controls"
        try:
            control_entries = list(control_dir.iterdir())
        except OSError as exc:
            raise rd.ReceiptError(
                f"CLI/server control evidence is unreadable: {exc}"
            ) from exc
        actual_controls = {
            item.name: item for item in control_entries
            if item.is_file() and not item.is_symlink()
        }
        if (
            set(actual_controls) != set(expected_controls)
            or len(control_entries) != len(expected_controls)
        ):
            raise rd.ReceiptError(
                "CLI/server control-file set is not exact; "
                f"missing={sorted(set(expected_controls) - set(actual_controls))}, "
                f"extra={sorted(set(actual_controls) - set(expected_controls))}"
            )
        for filename in sorted(expected_controls):
            cell = expected_controls[filename]
            body = actual_controls[filename].read_bytes()
            try:
                report = json.loads(body)
            except json.JSONDecodeError as exc:
                raise rd.ReceiptError(
                    f"{filename}: control report is malformed"
                ) from exc
            cell_id = rd.skew_cell_identity(cell)
            without_id = {
                key: value for key, value in report.items()
                if key != "control_id"
            }
            if (
                body != _canonical_json(report)
                or set(report) != {
                    "schema", "matrix_id", "cell_id", "cell", "artifacts",
                    "runtime", "outcome", "error", "control_id",
                }
                or report.get("schema") != CONTROL_SCHEMA
                or report.get("matrix_id") != matrix_id
                or report.get("cell_id") != cell_id
                or report.get("cell") != rd.skew_cell_preimage(cell)
                or report.get("outcome") != "red"
                or not any(
                    marker in str(report.get("error", ""))
                    for marker in NEGATIVE_FEATURE_MARKERS
                )
                or report.get("control_id")
                    != rd.canonical_json_digest(without_id)
                or not isinstance(report.get("artifacts"), list)
                or len(report["artifacts"]) != 2
            ):
                raise rd.ReceiptError(
                    f"{filename}: control does not bind the exact reviewed red cell"
                )
            artifacts = []
            for artifact, side, kind, locator in (
                (report["artifacts"][0], cell.a, cell.a_kind, cell.artifacts["a"]),
                (report["artifacts"][1], cell.b, cell.b_kind, cell.artifacts["b"]),
            ):
                artifacts.append(
                    _validate_report_artifact(artifact, side, kind, locator)
                )
            server_artifact = next(
                artifact for artifact in artifacts
                if artifact["component"] == "server"
            )
            server = ResolvedArtifact(
                component="server",
                version=server_artifact["version"],
                path=Path(server_artifact["payload_name"]),
                evidence=server_artifact,
            )
            validate_runtime_proof(report["runtime"], server, report["cell"])
            dependencies = {
                name: version
                for name, version in report["runtime"][
                    "installed_distributions"
                ].items()
                if name != "aweb"
            }
            dependency_postures.add(_sha256(_canonical_json(dependencies)))
            controls.append({
                "cell_id": cell_id,
                "control_id": report["control_id"],
                "file_sha256": _sha256(body),
                "error": report["error"],
            })

    expected_candidates = set(document["preimage"]["staged"])
    if set(candidates) != expected_candidates:
        raise rd.ReceiptError(
            f"CLI/server candidates {sorted(candidates)} do not equal frozen "
            f"{sorted(expected_candidates)}"
        )
    if len(dependency_postures) != 1:
        raise rd.ReceiptError(
            "CLI/server runtime dependency posture differs across matrix cells"
        )
    edge_data = document["preimage"]["edge"]
    measurement = {
        "schema": "aweb.runtime-support-measurement.v1",
        "completeness": "unanchored-local-measurement",
        "status": "incomplete-unanchored",
        "support_complete": False,
        "anchor": None,
        "matrix_id": matrix_id,
        "edge": {"a": edge_data["a"], "b": edge_data["b"]},
        "journey": edge_data["journey"],
        "artifacts": edge_data["artifacts"],
        "direction": edge_data["direction"],
        "staged_manifest_digest": document["preimage"]["staged_manifest_digest"],
        "supported_versions": document["preimage"]["support"]["supported_versions"],
        "published_versions": document["preimage"]["published_versions"],
        "candidates": candidates,
        "published_identities": [
            published_identities[key] for key in sorted(published_identities)
        ],
        "reports": reports,
        "controls": controls,
    }
    measurement["measurement_id"] = rd.canonical_json_digest(measurement)
    return measurement


def validate_measurement_input(document: dict) -> dict:
    """Apply the frozen shared measurement-input schema to the aw edge."""
    return measurement_inputs.validate_measurement_input(document, component="aw")


def measure_support(
    *,
    measurement_input: dict,
    measurement_input_bytes: bytes,
    supported_versions: dict[str, list[str]],
    negative_server: str,
    published_authority,
    harness,
) -> dict:
    """Run the known-red control, then the candidate-aw supported matrix."""
    document = validate_measurement_input(measurement_input)
    canonical_input = json.dumps(
        document, sort_keys=True, separators=(",", ":")
    ).encode()
    if measurement_input_bytes != canonical_input:
        raise rd.ReceiptError(
            "CLI/server measurement input bytes are not the canonical encoding "
            "of the validated document"
        )
    measurement_input_digest = _sha256(measurement_input_bytes)

    server_support = supported_versions.get("server") or []
    if set(supported_versions) != {"server"}:
        raise rd.ReceiptError(
            "a candidate-aw measurement takes a supported set for the server "
            f"only, got {sorted(supported_versions)}"
        )
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

    entries = document["entries"]
    published = entries["server"]
    if server_support[-1] != published["version"]:
        raise rd.ReceiptError(
            "measured server support set must end at the published server "
            f"{published['version']!r} bound by the measurement input"
        )
    moving = {
        name for name, entry in entries.items()
        if entry["kind"] == "candidate"
    }
    if moving != {"aw"}:
        raise rd.ReceiptError(
            f"CLI/server measurement moving set must derive as ['aw'], got "
            f"{sorted(moving)}"
        )
    candidate = entries["aw"]
    staged = {"aw": rd.ReceiptEntry(
        version=candidate["version"],
        digest=candidate["digest"],
        phase="staged",
        digest_set=candidate["digest_set"],
        lane_ref=candidate["lane_ref"],
    )}
    published_versions = {"server": published["version"]}

    if published_authority is None:
        raise rd.ReceiptError(
            "CLI/server measurement requires the published-server authority "
            "resolver; the exact PyPI registry projection must be consumed"
        )
    published_report = published_authority.resolve(published)

    matrix = rd.freeze_skew_matrix(
        EDGE, moving=moving, staged=staged,
        support={"supported_versions": supported_versions},
        published_versions=published_versions,
        staged_manifest_digest=measurement_input_digest,
    )
    freeze = getattr(harness, "freeze_matrix", None)
    record_control = getattr(harness, "record_control", None)
    finish = getattr(harness, "finish_matrix", None)
    if freeze is None or record_control is None or finish is None:
        raise rd.ReceiptError(
            "CLI/server measurement requires the frozen matrix lifecycle"
        )
    freeze(matrix)

    negative_cells = rd.compute_skew_cells(
        EDGE,
        moving=moving,
        staged=staged,
        support={"supported_versions": {"server": [negative_server]}},
        published_versions={"server": negative_server},
    )
    negative_evidence = []
    for negative in negative_cells:
        try:
            green = harness.run_evidenced(negative, publish=False)
        except SkewJourneyFailure as exc:
            failure = exc.evidence.get("error", "")
            if not any(marker in failure for marker in NEGATIVE_FEATURE_MARKERS):
                raise rd.ReceiptError(
                    f"negative control server {negative_server} did not fail "
                    f"on the required distinct-ID/lock feature: {failure}"
                ) from exc
            negative_evidence.append(exc.evidence)
            record_control(matrix, negative, exc.evidence)
        else:
            raise rd.ReceiptError(
                f"negative control server {negative_server} was green for "
                f"{negative.direction}: {green!r}"
            )

    supported_cells = rd.validate_skew_matrix_document(matrix)
    evidence = [harness.run(item) for item in supported_cells]
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
    aggregate_path = finish(matrix)
    measurement_bytes = Path(aggregate_path).read_bytes()
    measurement = json.loads(measurement_bytes)
    _require_unanchored_measurement(
        measurement, matrix_id=matrix["matrix_id"]
    )
    child_id = _require_child_identity(measurement)
    if measurement_bytes != _canonical_json(measurement):
        raise rd.ReceiptError(
            "CLI/server measurement child is not canonical bytes"
        )

    evidence_root = getattr(harness, "_evidence_root", None)
    if evidence_root is None:
        raise rd.ReceiptError(
            "CLI/server measurement cannot independently reaggregate without "
            "its exact evidence root"
        )
    root = Path(evidence_root)
    independent = aggregate_frozen_matrix(
        root / f"matrix-{matrix['matrix_id']}.json",
        root,
        control_cells=negative_cells,
    )
    canonical_child = _canonical_json(independent)
    if measurement_bytes != canonical_child:
        raise rd.ReceiptError(
            "CLI/server measurement bytes do not equal the canonical bytes "
            "independently reaggregated from the frozen matrix, cell reports, "
            "and negative-control inventory"
        )

    envelope = {
        "schema": ENVELOPE_SCHEMA,
        "policy": "additive-only",
        "component": "aw",
        "measurement_input_id": document["manifest_id"],
        "measurement_input_sha256": measurement_input_digest,
        "published_server_authority": published_report,
        "supported_versions": {
            name: list(versions)
            for name, versions in sorted(supported_versions.items())
        },
        "measurement_id": child_id,
        "measurement_sha256": _sha256(measurement_bytes),
        "measurement": measurement,
    }
    envelope["envelope_id"] = rd.canonical_json_digest(envelope)
    return envelope


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


def _require_output_envelope(
    document: dict,
    *,
    measurement_input_id: str,
    measurement_input_digest: str,
    supported_versions: dict[str, list[str]],
    expected_published_server_authority: dict,
) -> str:
    status = _require_envelope(
        document,
        component="aw",
        measurement_input_id=measurement_input_id,
        measurement_input_digest=measurement_input_digest,
        supported_versions=supported_versions,
        expected_published_server_authority=(
            expected_published_server_authority
        ),
    )
    child = document["measurement"]
    _require_unanchored_measurement(child, matrix_id=child.get("matrix_id"))
    _require_child_identity(child)
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="verb", required=True)
    measure = sub.add_parser("measure")
    measure.add_argument(
        "--measurement-input", required=True,
        help="canonical aweb.measurement-input-manifest.v1 for aw<->server; "
             "NOT a release staged manifest",
    )
    measure.add_argument("--supported-server", action="append", required=True)
    measure.add_argument("--negative-server", default=NEGATIVE_SERVER_VERSION)
    measure.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    manifest_path = Path(args.measurement_input)
    body = manifest_path.read_bytes()
    try:
        measurement_input = validate_measurement_input(json.loads(body))
        expected_authority = expected_published_server_authority_report(
            measurement_input["entries"]["server"]
        )
        document = measure_support(
            measurement_input=measurement_input,
            measurement_input_bytes=body,
            supported_versions={"server": args.supported_server},
            negative_server=args.negative_server,
            published_authority=PublishedServerAuthority(),
            harness=CliServerSkewHarness(),
        )
        status = _require_output_envelope(
            document,
            measurement_input_id=measurement_input["manifest_id"],
            measurement_input_digest=_sha256(body),
            supported_versions={"server": args.supported_server},
            expected_published_server_authority=expected_authority,
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(
            output, json.dumps(document, indent=2, sort_keys=True) + "\n"
        )
        print(f"measurement {output} sha256:{_sha256(output.read_bytes())}")
        print(f"status: {status}")
        return 0
    except (KeyError, ValueError, rd.ReceiptError, SkewJourneyFailure) as exc:
        print(f"BLOCKED: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
