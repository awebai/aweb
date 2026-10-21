"""Operator command. Never print private keys or response bodies."""

import argparse
import getpass
import json
import sys
import warnings
from pathlib import Path
from typing import NoReturn

from .errors import Refused
from .registration import register


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # Rejected arguments can contain a credential from an obsolete invocation.
        self.exit(2, "runner_arguments_invalid\n")


def main() -> int:
    parser = _Parser(prog="aweb-secrets-runner")
    commands = parser.add_subparsers(dest="command", required=True)
    registration = commands.add_parser("register", help="register local keys and pin the service")
    registration.add_argument("--origin", required=True)
    registration.add_argument("--state-dir", required=True, type=Path)
    registration.add_argument("--ca-file", type=Path)
    preflight = commands.add_parser("doctor", help="check local identity, user and job pins")
    preflight.add_argument("--config", required=True, type=Path)
    preflight.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "doctor":
            from .doctor import doctor

            print(json.dumps(doctor(args.config, args.state_dir), sort_keys=True))
            return 0
        if sys.stdin.isatty():
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                code = getpass.getpass("Registration code: ")
        else:
            code = sys.stdin.readline(256).rstrip("\r\n")
        identity = register(
            origin=args.origin, code=code, state_dir=args.state_dir, ca_file=args.ca_file
        )
    except (EOFError, UnicodeError, getpass.GetPassWarning):
        print("registration_input_unavailable", file=sys.stderr)
        return 1
    except Refused as error:
        print(error.code, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    print(json.dumps(identity.public(), sort_keys=True))
    return 0
