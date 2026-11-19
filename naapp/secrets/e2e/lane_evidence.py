"""Owned Docker-visible runtime directories and value-free bootstrap evidence."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path

import pytest

from aweb_secrets.erasure import ErasureFailure


class BootstrapOperation(StrEnum):
    PROVISION = "provision_database"
    INITIALIZE = "initialize_erasure"


class BootstrapError(StrEnum):
    UNCLASSIFIED = "unclassified_child_failure"
    INVALID_ARGUMENTS = "operator_arguments_invalid"
    DATABASE_ACCESS = "operator_database_access_failed"


_SQLSTATES = frozenset(
    {"28P01", "28000", "3D000", "42P04", "42710", "42501", "08001", "08006", "53300", "57P03"}
)
_ERRORS = frozenset(
    {reason.value for reason in ErasureFailure}
    | {reason.value for reason in BootstrapError}
    | {"postgres_" + state for state in _SQLSTATES}
)


def _shared_directory(raw: str, *, setting: str) -> Path:
    path = Path(raw)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_dir()
        or not os.access(path, os.W_OK | os.X_OK)
    ):
        raise ValueError(f"{setting} must name an existing absolute writable directory.")
    return path


def create_runtime_directory(
    factory: pytest.TempPathFactory, *, environment: Mapping[str, str]
) -> Path:
    """Use the daemon-shared mount in a gate; local standalone pytest owns its fallback."""
    supplied = environment.get("AWEB_DOCKER_BIND_ROOT")
    if supplied is not None:
        root = _shared_directory(supplied, setting="AWEB_DOCKER_BIND_ROOT")
        runtime = Path(tempfile.mkdtemp(prefix="secrets-owner-", dir=root))
    else:
        docker_host = environment.get("DOCKER_HOST", "")
        if "CANDIDATE_LOG_DIR" in environment or (
            docker_host and not docker_host.startswith("unix://")
        ):
            raise ValueError(
                "Set AWEB_DOCKER_BIND_ROOT to the directory shared with the Docker daemon."
            )
        runtime = _shared_directory(str(factory.mktemp("owner-acts")), setting="pytest runtime")
    runtime.chmod(0o755)
    return runtime


def _error_code(stderr: str) -> str:
    for line in stderr.splitlines():
        prefix = line.partition(":")[0]
        if prefix in {reason.value for reason in ErasureFailure}:
            return prefix
        match = re.search(r"(?:ERROR|FATAL):\s+([A-Z0-9]{5})(?:\s|$)", line)
        if match and match[1] in _SQLSTATES:
            return "postgres_" + match[1]
    if (
        stderr.strip()
        == "Invalid erasure operator arguments; check the role, schema and backup lifetime."
    ):
        return BootstrapError.INVALID_ARGUMENTS
    if (
        stderr.strip()
        == "Erasure operation failed. Keep Secrets stopped and check operator database access."
    ):
        return BootstrapError.DATABASE_ACCESS
    return BootstrapError.UNCLASSIFIED


def record_bootstrap(
    runtime: Path, *, operation: BootstrapOperation, result: subprocess.CompletedProcess[str]
) -> Path:
    """Retain only closed error identifiers and counts, never child text or arguments."""
    record = {
        "operation": operation.value,
        "exit_code": result.returncode,
        "error_code": _error_code(result.stderr) if result.returncode else None,
        "stdout_bytes": len(result.stdout.encode()),
        "stderr_bytes": len(result.stderr.encode()),
    }
    evidence = runtime / "bootstrap-evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", prefix="bootstrap-", suffix=".json", dir=evidence, delete=False
    ) as output:
        json.dump(record, output, sort_keys=True)
        output.write("\n")
        return Path(output.name)


def _read_record(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise ValueError("Bootstrap evidence must be a bounded regular metadata file.")
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError):
        raise ValueError("Bootstrap evidence could not be read as metadata.") from None
    expected = {"operation", "exit_code", "error_code", "stdout_bytes", "stderr_bytes"}
    if (
        not isinstance(record, dict)
        or set(record) != expected
        or not isinstance(record["operation"], str)
        or record["operation"] not in {operation.value for operation in BootstrapOperation}
        or not (record["error_code"] is None or isinstance(record["error_code"], str))
        or record["error_code"] not in _ERRORS | {None}
        or any(
            type(record[name]) is not int for name in ("exit_code", "stdout_bytes", "stderr_bytes")
        )
        or record["stdout_bytes"] < 0
        or record["stderr_bytes"] < 0
        or (record["exit_code"] == 0) != (record["error_code"] is None)
    ):
        raise ValueError("Bootstrap evidence does not match the value-free record schema.")
    return record


def retain_bootstrap_evidence(runtime: Path, *, environment: Mapping[str, str]) -> Path | None:
    """Export validated metadata to the existing shared gate logs before stack cleanup."""
    supplied = environment.get("CANDIDATE_LOG_DIR")
    if supplied is None:
        return None
    root = _shared_directory(supplied, setting="CANDIDATE_LOG_DIR")
    records = [
        _read_record(path) for path in sorted((runtime / "bootstrap-evidence").glob("*.json"))
    ]
    destination = Path(tempfile.mkdtemp(prefix="secrets-owner-evidence-", dir=root))
    (destination / "bootstrap.json").write_text(
        json.dumps({"scope": "bootstrap_only", "records": records}, sort_keys=True) + "\n"
    )
    return destination
