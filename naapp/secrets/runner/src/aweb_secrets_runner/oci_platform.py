"""Verify the local storage prerequisite; this grants no OCI execution authority."""

import ctypes
import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path

from .errors import Refused
from .filesystem import FileGuard

_TMPFS_MAGIC = 0x01021994


def require_memory_directory(path: Path) -> Path:
    """Require a runner-owned 0700 Linux tmpfs directory, without following its leaf.

    The bundle AND the runtime's internal state must independently pass this
    check. A directory name under /run or /tmp is not evidence of its filesystem.
    tmpfs can be swapped by the trusted host; this is not a secure-erasure claim.
    """
    if sys.platform != "linux":
        raise Refused("runner_runtime_unavailable")
    try:
        # FileGuard validates every ancestor's ownership and write authority.
        resolved = FileGuard().directory(path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise Refused("oci_state_invalid")
            library = ctypes.CDLL(None, use_errno=True)
            fstatfs = library.fstatfs
            fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
            fstatfs.restype = ctypes.c_int
            # Linux statfs starts with a native signed long f_type on both
            # 32- and 64-bit ABIs. The opaque buffer exceeds its ABI structure;
            # none of its platform-dependent remaining fields are interpreted.
            result = ctypes.create_string_buffer(512)
            if fstatfs(fd, result) != 0 or ctypes.c_long.from_buffer(result).value != _TMPFS_MAGIC:
                raise Refused("oci_state_invalid")
            return resolved
        finally:
            os.close(fd)
    except (OSError, ValueError, AttributeError, Refused):
        raise Refused("oci_state_invalid") from None


def require_runc_environment(environment: Mapping[str, str | None]) -> None:
    """Check runc's known HOME capability without opening unknown credentials.

    The selected runtime must independently be pinned and qualified. This is
    runtime-specific, not a universal job/1 HOME requirement. Other declared
    credentials stay unknown until every runtime/file check has completed.
    """
    home = environment.get("HOME")
    if not isinstance(home, str) or not home or "\0" in home:
        raise Refused("oci_environment_unsupported")
