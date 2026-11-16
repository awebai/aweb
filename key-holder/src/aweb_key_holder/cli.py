"""Local operator commands. The application never receives this private mount."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from .keys import KeyStore, Refused


def main():
    parser = argparse.ArgumentParser(prog="aweb-key-holder")
    parser.add_argument("--state", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init")
    initialize.add_argument("--organisation", required=True)
    descriptor = commands.add_parser("descriptor")
    descriptor.add_argument("--team")
    team = commands.add_parser("create-team-key")
    team.add_argument("name")
    backup = commands.add_parser("backup")
    backup.add_argument("--offline-public-key", required=True)
    args = parser.parse_args()
    try:
        if args.command == "init":
            result = asdict(
                KeyStore.create(args.state, organisation=args.organisation).descriptor()
            )
        else:
            store = KeyStore.open(args.state)
            if args.command == "descriptor":
                result = asdict(store.descriptor(team=args.team))
            elif args.command == "create-team-key":
                result = asdict(store.create_team_key(args.name))
            else:
                sys.stdout.buffer.write(
                    store.encrypted_backup(bytes.fromhex(args.offline_public_key))
                )
                return
        print(json.dumps(result, separators=(",", ":")))
    except Refused as error:
        print(json.dumps({"error": error.code}), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
