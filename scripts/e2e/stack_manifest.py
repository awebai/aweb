"""An app's committed manifest template, published from a test stack's own origin.

The runtime serves an app's hosted id only at the template's origin or a
loopback origin. A stack that runs an app under its hosted id, because the
clients it drives look the app up by that id, mounts the template rewritten to
the stack's origin: that deployment is then the one the template names.

Usage: stack_manifest.py <template path> <origin>  (rewrites the file in place)
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any


def template_at_origin(template: Mapping[str, Any], origin: str) -> dict[str, Any]:
    """``template`` with ``app.origin`` set to ``origin``."""
    published = json.loads(json.dumps(template))
    published["app"]["origin"] = origin.rstrip("/")
    return published


def main(arguments: list[str]) -> None:
    if len(arguments) != 2:
        raise SystemExit("usage: stack_manifest.py <template path> <origin>")
    path, origin = Path(arguments[0]), arguments[1]
    path.write_text(
        json.dumps(template_at_origin(json.loads(path.read_text()), origin))
    )


if __name__ == "__main__":
    main(sys.argv[1:])
