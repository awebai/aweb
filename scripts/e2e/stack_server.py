"""A test stack's coordination server, with the real HTTPS manifest fetcher.

The fetcher only reaches a pinned internal destination over HTTPS: this pins it
to the stack's one app origin, whose certificates the stack's own CA signs. The
server runs from the source it is given (an image or the locked server project).

Usage: stack_server.py --app-origin URL --ca-file PATH --user-agent NAME
                       (--port N | --fd N)
"""

from __future__ import annotations

import argparse
import socket
from urllib.parse import urlsplit

import uvicorn
from aweb.api import create_app
from aweb.app_manifests import ManifestFetcher
from aweb_naapp.egress import (
    AddressPolicy,
    DnsResolver,
    Egress,
    InternalDestinations,
    parse_destination,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="A test stack's coordination server.")
    parser.add_argument("--app-origin", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--user-agent", required=True)
    listen = parser.add_mutually_exclusive_group(required=True)
    listen.add_argument("--port", type=int)
    listen.add_argument("--fd", type=int)
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    origin = urlsplit(arguments.app_origin)
    if origin.scheme != "https" or origin.hostname is None or origin.port is None:
        raise SystemExit(
            f"--app-origin must be https://host:port, not {arguments.app_origin!r}"
        )
    destination = parse_destination(
        {
            "host": origin.hostname,
            "port": origin.port,
            "path": "/**",
            "methods": ["GET"],
            "network": "internal",
            "cidr": socket.gethostbyname(origin.hostname) + "/32",
        },
        internal_destinations=InternalDestinations.ALLOWED,
    )
    app = create_app()
    app.state.manifest_fetcher = ManifestFetcher(
        egress=Egress(
            addresses=AddressPolicy(internal_destinations=InternalDestinations.ALLOWED),
            resolver=DnsResolver(),
            user_agent=arguments.user_agent,
            ca_file=arguments.ca_file,
        ),
        destination=destination,
    )
    if arguments.fd is not None:
        uvicorn.run(app, fd=arguments.fd)
    else:
        uvicorn.run(app, host="0.0.0.0", port=arguments.port)


if __name__ == "__main__":
    main()
