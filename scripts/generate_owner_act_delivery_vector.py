#!/usr/bin/env python3
"""Regenerate the public owner-act delivery vector with its canonical builder."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "docs/vectors/owner-act-delivery-v1.json",
        help="output path (default: the checked-in public vector)",
    )
    args = parser.parse_args()

    sys.path.insert(0, str(ROOT / "naapp-lib"))
    from tests.hooks.owner_act_delivery_vector import build_vector, render

    args.output.write_bytes(render(build_vector()))


if __name__ == "__main__":
    main()
