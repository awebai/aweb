#!/usr/bin/env python3
"""CLI over the train's public-target observation (aben, design section 1).

One implementation of registry reads with fixed semantics - HTTP 404 is
the only absence, any other failure is unavailable rather than absence,
and served evidence must name exactly the queried version. This wrapper
makes that single implementation callable from workflow YAML and shell,
so no inline curl or Python reimplements it.

Usage: observe_public_target.py <target> <version> [--timeout SECONDS]
Exit codes: 0 present, 1 absent, 2 unavailable, 3 malformed observation.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import release_train


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("version")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--base",
        action="append",
        default=[],
        metavar="KIND=URL",
        help="override one registry read base (test fixture seam)",
    )
    args = parser.parse_args()
    bases = dict(item.split("=", 1) for item in args.base) or None
    try:
        present = release_train.observe_public_target(
            args.target, args.version, bases=bases, timeout=args.timeout
        )
    except release_train.ObservationMalformed as exc:
        print(f"malformed: {exc}", file=sys.stderr)
        return 3
    except release_train.ObservationUnavailable as exc:
        print(f"unavailable: {exc}", file=sys.stderr)
        return 2
    except release_train.ValidationError as exc:
        print(f"malformed: {exc}", file=sys.stderr)
        return 3
    if present:
        print(f"present: {args.target} serves {args.version}")
        return 0
    print(f"absent: {args.target} does not serve {args.version}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
