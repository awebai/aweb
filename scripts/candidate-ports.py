#!/usr/bin/env python3
"""Allocate gate stack ports on the Docker host, before starting the runner."""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import socket
import sys

PORT_VARIABLES = (
    # A2A and OSS federation already used host allocations.
    'AWEB_A2A_E2E_PORT', 'AWID_A2A_E2E_PORT', 'AWEB_A2A_E2E_REDIS',
    'AWEB_A2A_E2E_PG', 'A2A_GW_E2E_PORT', 'AWID_FED_E2E_PORT',
    'AWEB_ALPHA_E2E_PORT', 'AWEB_BETA_E2E_PORT',
    # CLI/Library, federation authority, cross-registry, and journey backends.
    'LIBRARY_E2E_AWID_PORT', 'LIBRARY_E2E_AWEB_PORT',
    'LIBRARY_E2E_LIBRARY_PORT', 'LIBRARY_E2E_POSTGRES_PORT',
    'AWEB_FED_AUTH_AWID_A_PORT', 'AWEB_FED_AUTH_AWID_B_PORT',
    'AWEB_FED_AUTH_AWEB_A1_PORT', 'AWEB_FED_AUTH_AWEB_A2_PORT',
    'AWEB_FED_AUTH_AWEB_B1_PORT', 'AWEB_FED_AUTH_AWEB_B2_PORT',
    'AWEB_FED_AUTH_POSTGRES_A_PORT', 'AWEB_FED_AUTH_POSTGRES_B_PORT',
    'AWEB_CROSS_REGISTRY_AWID_A_PORT', 'AWEB_CROSS_REGISTRY_AWID_B_PORT',
    'AWEB_CROSS_REGISTRY_AWEB_A_PORT', 'AWEB_CROSS_REGISTRY_AWEB_B_PORT',
    'AWEB_E2E_REDIS', 'AWEB_E2E_PG',
)


def allocate(run_id: str, packages: list[str]) -> tuple[dict[str, int], list[str]]:
    # The host chooses ports, not the isolated runner's network namespace.
    # Keep sockets open together so allocations within a run cannot collide.
    ports = {}
    for name in PORT_VARIABLES:
        if value := os.environ.get(name):
            if not value.isdecimal() or not 0 < int(value) <= 65535:
                raise ValueError(f'{name} must be a port between 1 and 65535')
            ports[name] = int(value)
    used = set(ports.values())
    sockets = []
    try:
        def free_port() -> int:
            while True:
                sock = socket.socket()
                sockets.append(sock)
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
                if port not in used:
                    used.add(port)
                    return port

        for name in PORT_VARIABLES:
            if name not in ports:
                ports[name] = free_port()
        rows = [f'{package} {run_id}-naapp-{PurePosixPath(package).name} {free_port()} {free_port()}'
                for package in packages]
        return ports, rows
    finally:
        for sock in sockets:
            sock.close()


if __name__ == '__main__':
    run_id, env_path, naapp_path, *packages = sys.argv[1:]
    ports, rows = allocate(run_id, packages)
    Path(env_path).write_text(''.join(f'{name}={port}\n' for name, port in ports.items()))
    Path(naapp_path).write_text('\n'.join(rows) + '\n')
