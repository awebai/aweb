"""Pinned password CLI fixture; credentials and response bytes never reach output."""

import argparse
import base64
import http.client
import os
import ssl
from typing import NoReturn
from urllib.parse import urlsplit


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError


def authenticate() -> bool:
    parser = _Parser(add_help=False, allow_abbrev=False)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--ca-file", required=True)
    args = parser.parse_args()
    origin = urlsplit(args.origin)
    password = os.environ.get("AWEB_SECRETS_E2E_CLI_PASSWORD")
    if (
        origin.scheme != "https"
        or not origin.hostname
        or origin.username is not None
        or origin.password is not None
        or origin.path not in ("", "/")
        or origin.query
        or origin.fragment
        or not args.username
        or ":" in args.username
        or not password
    ):
        return False
    context = ssl.create_default_context(cafile=args.ca_file)
    connection = http.client.HTTPSConnection(
        origin.hostname, origin.port, context=context, timeout=10
    )
    try:
        credential = base64.b64encode(f"{args.username}:{password}".encode()).decode("ascii")
        # Direct HTTPSConnection uses neither proxy environment nor redirects.
        connection.request("GET", "/basic/echo", headers={"Authorization": f"Basic {credential}"})
        return connection.getresponse().status == 200
    finally:
        connection.close()


def main() -> int:
    try:
        accepted = authenticate()
    except (Exception, KeyboardInterrupt):
        # Parsing, TLS and transport exceptions can contain private input.
        accepted = False
    print("authenticated" if accepted else "refused")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
