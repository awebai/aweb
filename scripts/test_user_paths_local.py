#!/usr/bin/env python3
"""Prepare and run the three isolated local selections in docs/local-user-paths.md."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import uuid

from fetch_released_aw import freeze_release
from local_suite_slots import Scope, SuiteLabel, suite_slot
from test_server_local import (
    Interrupted,
    Refused,
    check_docker,
    interrupted,
    invoke,
    pinned_docker_environment,
)

ROOT = Path(__file__).resolve().parents[1]
RELEASES = ("1.36.58", "1.36.40")


class Lane(StrEnum):
    RELEASED = "head-1.36.58"
    OLDER = "head-1.36.40"
    FORWARD_REVERSE = "forward-reverse"


@dataclass(frozen=True)
class Source:
    commit: str
    tree: str


@dataclass(frozen=True)
class LaneResult:
    lane: Lane
    evidence: Path
    exit_code: int


def command(
    arguments: list[str], *, root: Path = ROOT, environ: dict[str, str] | None = None
) -> str:
    result = invoke(arguments, cwd=root, env=environ, timeout=None)
    if result.returncode:
        raise Refused(
            f"Local user-path preparation exited {result.returncode}: {result.stdout.strip()}\n"
            "Resolve the preparation error and rerun make test-user-paths-local."
        )
    return result.stdout.strip()


def source_identity(*, root: Path) -> Source:
    """The archived context and reused image must describe the committed checkout."""
    if command(["git", "status", "--porcelain", "--untracked-files=normal"], root=root):
        raise Refused(
            "Local user paths require a clean source checkout. Commit or remove the changes and rerun make test-user-paths-local."
        )
    return Source(
        commit=command(["git", "rev-parse", "--verify", "HEAD"], root=root),
        tree=command(["git", "rev-parse", "--verify", "HEAD^{tree}"], root=root),
    )


def inspect_runtime(*, reference: str, source: Source, environ: dict[str, str]) -> str:
    records = json.loads(
        command(["docker", "image", "inspect", reference], environ=environ)
    )
    if (
        not isinstance(records, list)
        or len(records) != 1
        or not isinstance(records[0], dict)
    ):
        raise Refused(
            "Docker returned invalid runtime metadata. Inspect the image and rerun make test-user-paths-local."
        )
    record = records[0]
    config = record.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    expected = {
        "aweb.user-paths-ready": "1",
        "aweb.user-paths-source-tree": source.tree,
        "aweb.user-paths-source-sha": source.commit,
    }
    if not isinstance(labels, dict) or any(
        labels.get(key) != value for key, value in expected.items()
    ):
        raise Refused(
            "Runtime image does not match this source commit and tree. Unset USER_PATHS_RUNTIME_IMAGE and remove the stale local runtime tag, then rerun make test-user-paths-local."
        )
    image = record.get("Id")
    if not isinstance(image, str) or not image.startswith("sha256:"):
        raise Refused(
            "Docker returned no immutable runtime image ID. Inspect the image and rerun make test-user-paths-local."
        )
    return image


def prepare_runtime(
    *,
    root: Path,
    source: Source,
    evidence: Path,
    environ: dict[str, str],
    reference: str | None,
) -> str:
    if reference:
        return inspect_runtime(reference=reference, source=source, environ=environ)
    selected = "aweb-user-paths-local:" + source.commit
    existing = command(["docker", "image", "ls", "-q", selected], environ=environ)
    if not existing:
        # Archive only the committed input; ignored builds and local keys never enter Docker's context.
        with tempfile.TemporaryDirectory(prefix="aweb-user-paths-build-") as temporary:
            context = Path(temporary) / "context"
            context.mkdir()
            archive = Path(temporary) / "source.tar"
            command(
                ["git", "archive", "--format=tar", "-o", str(archive), source.commit],
                root=root,
            )
            command(["tar", "-xf", str(archive), "-C", str(context)])
            # docker build uses the admitted daemon's builder unless these override it.
            # https://docs.docker.com/build/builders/#difference-between-docker-build-and-docker-buildx-build
            build_environment = {
                key: value
                for key, value in environ.items()
                if key not in ("BUILDX_BUILDER", "BUILDKIT_HOST")
            }
            with (evidence / "runtime-build.log").open("w") as log:
                result = invoke(
                    [
                        "docker",
                        "build",
                        "--progress=plain",
                        "-t",
                        selected,
                        "--build-arg",
                        "USER_PATHS_SOURCE_TREE=" + source.tree,
                        "--build-arg",
                        "USER_PATHS_SOURCE_SHA=" + source.commit,
                        "-f",
                        str(context / "candidate-gate/Dockerfile"),
                        str(context),
                    ],
                    env=build_environment,
                    stdout=log.fileno(),
                    timeout=None,
                )
            if result.returncode:
                raise Refused(
                    f"Runtime build exited {result.returncode}. Inspect {evidence / 'runtime-build.log'} and rerun make test-user-paths-local."
                )
    return inspect_runtime(reference=selected, source=source, environ=environ)


def prepare_service_images(*, environ: dict[str, str]) -> None:
    for reference in ("postgres:17", "redis:7"):
        if not command(["docker", "image", "ls", "-q", reference], environ=environ):
            command(["docker", "pull", reference], environ=environ)


def export_candidate(*, image: str, destination: Path, environ: dict[str, str]) -> None:
    """The runtime build produces the Linux candidate; a stopped container only exports it."""
    name = "aweb-user-paths-export-" + uuid.uuid4().hex[:12]
    try:
        command(
            [
                "docker",
                "create",
                "--name",
                name,
                "--network",
                "none",
                "--entrypoint",
                "/opt/user-paths/aw",
                image,
                "version",
            ],
            environ=environ,
        )
        command(
            ["docker", "cp", name + ":/opt/user-paths/aw", str(destination)],
            environ=environ,
        )
        destination.chmod(0o700)
    finally:
        previous = {
            sig: signal.signal(sig, signal.SIG_IGN)
            for sig in (signal.SIGINT, signal.SIGTERM)
        }
        try:
            command(["docker", "rm", "-f", "-v", name], environ=environ)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


def run_lanes(
    *,
    root: Path,
    evidence: Path,
    source: Source,
    image: str,
    candidate: Path,
    metadata: dict[str, Path],
    environ: dict[str, str],
) -> list[LaneResult]:
    """Each stack process owns its project, all teardown and its original evidence."""
    rows: list[LaneResult] = []
    for lane in Lane:
        directory = evidence / lane.value
        directory.mkdir(parents=True)
        env = {
            key: value
            for key, value in environ.items()
            if not key.startswith(("USER_PATHS_", "CANDIDATE_"))
        }
        version = RELEASES[1] if lane is Lane.OLDER else RELEASES[0]
        env.update(
            USER_PATHS_RUNTIME_IMAGE=image,
            USER_PATHS_EVIDENCE=str(directory / "stack"),
            USER_PATHS_LATEST_METADATA=str(metadata[version]),
            USER_PATHS_LATEST_SHA256=hashlib.sha256(
                metadata[version].read_bytes()
            ).hexdigest(),
        )
        if lane is Lane.FORWARD_REVERSE:
            env.update(
                USER_PATHS_CANDIDATE_BIN=str(candidate),
                USER_PATHS_CANDIDATE_SHA=source.commit,
            )
        try:
            # Builds and earlier lanes can consume the initial disk reserve.
            env = check_docker(environ=env)
            with (directory / "lane.log").open("w") as log:
                result = invoke(
                    ["bash", str(root / "scripts/e2e-user-paths.sh")],
                    cwd=root,
                    env=env,
                    stdout=log.fileno(),
                    timeout=None,
                    termination_grace_seconds=120,
                )
        except Refused as error:
            (directory / "preflight.log").write_text(str(error) + "\n")
            print(
                f"{lane.value}: NOT_RUN (preflight failed) evidence={directory}",
                flush=True,
            )
            for pending in list(Lane)[len(rows) + 1 :]:
                print(
                    f"{pending.value}: NOT_RUN (earlier preflight failed)", flush=True
                )
            raise
        except Interrupted as error:
            code = 128 + error.number
            (directory / "exit.json").write_text(json.dumps({"exit": code}) + "\n")
            print(
                f"{lane.value}: INTERRUPTED exit={code} evidence={directory}",
                flush=True,
            )
            for pending in list(Lane)[len(rows) + 1 :]:
                print(f"{pending.value}: NOT_RUN (interrupted)", flush=True)
            raise
        row = LaneResult(lane=lane, evidence=directory, exit_code=result.returncode)
        rows.append(row)
        print(
            f"{lane.value}: {'PASS' if row.exit_code == 0 else 'FAIL'} exit={row.exit_code} evidence={directory}",
            flush=True,
        )
        (directory / "exit.json").write_text(json.dumps({"exit": row.exit_code}) + "\n")
    return rows


def main() -> int:
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    lanes_started = False
    try:
        with suite_slot(scope=Scope.WHOLE, label=SuiteLabel.USER_PATHS, root=ROOT):
            # Disk admission precedes every build/pull/project operation, on the same pinned endpoint.
            selected = check_docker()
            with pinned_docker_environment(environ=selected):
                source = source_identity(root=ROOT)
                bind_root = Path(
                    selected.get(
                        "AWEB_DOCKER_BIND_ROOT",
                        "/private/tmp"
                        if Path("/private/tmp").is_dir()
                        else tempfile.gettempdir(),
                    )
                ).resolve(strict=True)
                evidence = Path(
                    tempfile.mkdtemp(prefix="aweb-user-paths-local-", dir=bind_root)
                )
                selected["AWEB_DOCKER_BIND_ROOT"] = str(bind_root)
                print(
                    f"Local user paths: source={source.commit} Docker={selected['DOCKER_HOST']} evidence={evidence}",
                    flush=True,
                )
                image = prepare_runtime(
                    root=ROOT,
                    source=source,
                    evidence=evidence,
                    environ=selected,
                    reference=selected.get("USER_PATHS_RUNTIME_IMAGE"),
                )
                prepare_service_images(environ=selected)
                metadata = {
                    version: freeze_release(evidence / "metadata", version=version)
                    for version in RELEASES
                }
                candidate = evidence / "candidate-aw"
                export_candidate(image=image, destination=candidate, environ=selected)
                (evidence / "inputs.json").write_text(
                    json.dumps(
                        {
                            "source_sha": source.commit,
                            "source_tree": source.tree,
                            "runtime_image": image,
                            "candidate_sha256": hashlib.sha256(
                                candidate.read_bytes()
                            ).hexdigest(),
                            "docker_host": selected["DOCKER_HOST"],
                            "releases": {
                                version: str(path) for version, path in metadata.items()
                            },
                        },
                        indent=2,
                    )
                    + "\n"
                )
                if source_identity(root=ROOT) != source:
                    raise Refused(
                        "Source changed during preparation. Restore the selected commit and rerun make test-user-paths-local."
                    )
                lanes_started = True
                rows = run_lanes(
                    root=ROOT,
                    evidence=evidence,
                    source=source,
                    image=image,
                    candidate=candidate,
                    metadata=metadata,
                    environ=selected,
                )
                return 1 if any(row.exit_code for row in rows) else 0
    except Interrupted as error:
        if not lanes_started:
            for lane in Lane:
                print(f"{lane.value}: NOT_RUN (preparation interrupted)", flush=True)
        print(
            f"Local user paths interrupted by signal {error.number}; inspect the current lane log for its cleanup result.",
            file=sys.stderr,
        )
        return 128 + error.number
    except (Refused, OSError, ValueError, subprocess.SubprocessError) as error:
        if not lanes_started:
            for lane in Lane:
                print(f"{lane.value}: NOT_RUN (preparation failed)", flush=True)
        print(
            f"Local user paths refused: {error}\nInspect the preparation output or lane log and rerun make test-user-paths-local.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
