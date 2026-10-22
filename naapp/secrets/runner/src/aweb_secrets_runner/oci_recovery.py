"""Stop stale local OCI containers; never open credentials or rearm a dispatch."""

import os
from pathlib import Path

from .errors import Refused
from .oci_platform import require_memory_directory
from .oci_prepare import BinaryPin, RuncPreparation, _tool
from .oci_workspace import JOB_DIRECTORY, read_marker, remove_private_tree, workspace_lock


async def stop_container(engine: BinaryPin, state: Path, container: str) -> None:
    if not JOB_DIRECTORY.fullmatch(container):
        raise Refused("oci_recovery_required")
    executable = engine.check()
    require_memory_directory(state)
    root = ("--root", str(state), "--rootless=true", "--log", "/dev/null")
    await _tool(executable, *root, "kill", "--all", container, "KILL", accept_failure=True)
    await _tool(executable, *root, "delete", "--force", container, accept_failure=True)
    if any(state.iterdir()):
        raise Refused("oci_cleanup_required")


async def recover(runtime: RuncPreparation) -> tuple[str, ...]:
    """Under the workspace lock, stop old containers then remove only owned trees.

    Unknown or inconsistent data is retained for operator reconciliation. The
    marker binds cleanup to the originally checked engine, not a new pin. No
    journal, identity, job arguments or credential value is read by recovery.
    """
    cleaned = []
    try:
        with workspace_lock(runtime.workspace) as (workspace, parent_fd):
            engine = runtime.engine.check()
            for entry in sorted(workspace.iterdir()):
                if not JOB_DIRECTORY.fullmatch(entry.name):
                    raise Refused("oci_recovery_required")
                require_memory_directory(entry)
                if not any(entry.iterdir()):
                    # Crash between exclusive mkdir and its first marker: only
                    # an empty directory can be removed without that marker.
                    os.rmdir(entry.name, dir_fd=parent_fd)
                    cleaned.append(entry.name)
                    continue
                marker = read_marker(entry)
                if not marker["prepared"] or marker["engine"] != {
                    "path": str(engine),
                    "sha256": runtime.engine.sha256,
                }:
                    # SIGKILL can interrupt the public unpacker too. Without
                    # a completed-preparation receipt we cannot prove its
                    # process group stopped, so retain rather than race it.
                    raise Refused("oci_recovery_required")
                state = entry / "state"
                if state.is_symlink():
                    raise Refused("oci_recovery_required")
                has_state = False
                if state.exists():
                    require_memory_directory(state)
                    has_state = any(state.iterdir())
                if marker["container"] is not None:
                    if not has_state:
                        # The launcher may still be between spawn and state
                        # creation after its worker died. Empty state is not
                        # proof that this container-marked launch terminated.
                        raise Refused("oci_recovery_required")
                    await stop_container(runtime.engine, state, marker["container"])
                elif has_state:
                    raise Refused("oci_recovery_required")
                remove_private_tree(parent_fd, entry.name)
                cleaned.append(entry.name)
        return tuple(cleaned)
    except (OSError, ValueError, RecursionError):
        raise Refused("oci_recovery_required") from None
