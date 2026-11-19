"""Prepare a container test stack's Library: its manifest template published from
the stack's origin, and its installation grant-read key.

Run inside the built Library image as root, with the stack's fixture volume at
/fixture and its library-source volume over Library's package directory, so the
service later runs as app id "library" at this stack's own origin.
Usage: library_stack_prepare.py <origin>
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path

from stack_manifest import template_at_origin

from library.aweb_manifest import MANIFEST_PATH

# The Library image's service user.
LIBRARY_UID = 10001
GRANT_READ_KEY = Path("/fixture/library/grant-read.hex")


def _write_grant_read_key() -> None:
    GRANT_READ_KEY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(GRANT_READ_KEY.parent, LIBRARY_UID, LIBRARY_UID)
    GRANT_READ_KEY.write_text(secrets.token_hex(32))
    os.chown(GRANT_READ_KEY, LIBRARY_UID, LIBRARY_UID)
    GRANT_READ_KEY.chmod(0o600)


def main(arguments: list[str]) -> None:
    if len(arguments) != 1:
        raise SystemExit("usage: library_stack_prepare.py <origin>")
    template = json.loads(MANIFEST_PATH.read_text())
    MANIFEST_PATH.write_text(json.dumps(template_at_origin(template, arguments[0])))
    _write_grant_read_key()


if __name__ == "__main__":
    main(sys.argv[1:])
