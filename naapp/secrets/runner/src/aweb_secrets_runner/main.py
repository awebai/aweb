"""Operator command. Never print private keys or response bodies."""

import argparse
import json
import sys
from pathlib import Path

from .errors import Refused
from .registration import register


def main() -> int:
    parser = argparse.ArgumentParser(prog="aweb-secrets-runner")
    commands = parser.add_subparsers(dest="command", required=True)
    registration = commands.add_parser("register", help="register local keys and pin the service")
    registration.add_argument("--origin", required=True)
    registration.add_argument("--code", required=True)
    registration.add_argument("--state-dir", required=True, type=Path)
    registration.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    try:
        identity = register(
            origin=args.origin, code=args.code, state_dir=args.state_dir, ca_file=args.ca_file
        )
    except Refused as error:
        print(error.code, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    print(json.dumps(identity.public(), sort_keys=True))
    return 0
