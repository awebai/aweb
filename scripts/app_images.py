#!/usr/bin/env python3
"""Print the published naapp image that one of aweb's app journeys runs.

tools/app-images.json pins each image the naapp repository publishes as
`<repository>@sha256:<digest>`. The Library and Folio journeys run exactly
those bytes; a reviewed aweb change sets a digest from a naapp release. An
empty digest means the image is not yet published, and the journey refuses
rather than building the app from source.

Usage: app_images.py [--pins PATH] <name>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

PINS = Path(__file__).resolve().parents[1] / "tools/app-images.json"
REFERENCE = re.compile(r"(?P<repository>[a-z0-9][a-z0-9._/-]*)@sha256:(?P<digest>[0-9a-f]{64})?")


class Refused(Exception):
    pass


def reference(name: str, pins: Path = PINS) -> str:
    value = json.loads(pins.read_text()).get(name)
    if not isinstance(value, str):
        raise Refused(f"tools/app-images.json names no {name} image")
    match = REFERENCE.fullmatch(value)
    if match is None or match["repository"].rsplit("/", 1)[-1] != name:
        raise Refused(
            f"tools/app-images.json pins {name} as {value!r}, not as "
            f"<repository>/{name}@sha256:<digest>"
        )
    if match["digest"] is None:
        raise Refused(
            f"tools/app-images.json pins no digest for {match['repository']}: "
            "the naapp image is not yet published. A reviewed aweb change sets "
            "its digest from a naapp release."
        )
    return value


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pins", type=Path, default=PINS)
    parser.add_argument("name")
    args = parser.parse_args(argv)
    try:
        print(reference(args.name, args.pins))
    except Refused as exc:
        print(f"app image refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
