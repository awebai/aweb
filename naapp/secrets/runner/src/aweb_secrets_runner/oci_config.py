"""Protected operator choices for the existing daemonless OCI runtime."""

import re
from pathlib import Path
from typing import Any

from .errors import Refused
from .oci_prepare import BinaryPin, RuncPreparation


def _path(value: Any) -> Path:
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise ValueError("path")
    path = Path(value)
    if ".." in path.parts:
        raise ValueError("path")
    return path


def _pin(value: Any) -> BinaryPin:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValueError("pin")
    digest = value["sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("digest")
    return BinaryPin(_path(value["path"]), digest)


def runtime_config(value: Any) -> RuncPreparation:
    """Parse public local pins only; no opening, spawning or service authority."""
    try:
        if (
            not isinstance(value, dict)
            or set(value) != {"kind", "engine", "unpacker", "supervisor", "images", "workspace"}
            or value["kind"] != "runc"
        ):
            raise ValueError("runtime")
        return RuncPreparation(
            engine=_pin(value["engine"]),
            unpacker=_pin(value["unpacker"]),
            supervisor=_pin(value["supervisor"]),
            images=_path(value["images"]),
            workspace=_path(value["workspace"]),
        )
    except (ValueError, TypeError, KeyError):
        raise Refused("runtime_config_invalid") from None
