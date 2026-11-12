"""Public host pins and private per-run key cleanup."""

import base64
from pathlib import Path
import struct

from .errors import Infrastructure

KEY_FILES = ("ssh-key", "ssh-key.pub", "ssh-host-key", "ssh-host-key.pub")


def public_key(path):
    try:
        fields = Path(path).read_text().split()
        if len(fields) < 2 or fields[0] != "ssh-ed25519":
            raise ValueError("expected Ed25519")
        blob = base64.b64decode(fields[1], validate=True)
        length = struct.unpack(">I", blob[:4])[0]
        if blob[4 : 4 + length] != b"ssh-ed25519":
            raise ValueError("unexpected wire type")
        offset = 4 + length
        size = struct.unpack(">I", blob[offset : offset + 4])[0]
        if size != 32 or len(blob) != offset + 4 + size:
            raise ValueError("unexpected key length")
        return " ".join(fields[:2])
    except (OSError, ValueError, IndexError, struct.error):
        raise Infrastructure(
            "local SSH host public key is missing or invalid"
        ) from None


def forget(directory):
    directory = Path(directory)
    for root in [directory, directory / "restore"]:
        for name in KEY_FILES:
            (root / name).unlink(missing_ok=True)
