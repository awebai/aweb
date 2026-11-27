"""Write docs/vectors/awid-controller-writes-v1.json from the Python client.

Each controller write that aw and the Python awid client both make is sent
through the Python RegistryClient (whose bytes the deployed registry accepts)
against a transport that records the request and answers nothing. The vector
keeps the call's arguments and the exact wire: method, raw path, body bytes and
the signing headers. Keys come from fixed seeds and the timestamp is fixed, so
Ed25519 makes every byte reproducible. Run from the repository root:

    uv run --project awid python scripts/generate_controller_write_vectors.py [--check]

--check regenerates in memory and fails if the file differs.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
from pathlib import Path

import httpx

import awid.registry as registry_module
from awid.did import did_key_from_signing_key, stable_id_from_did_key
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "docs" / "vectors" / "awid-controller-writes-v1.json"
ORIGIN = "https://registry.example.com"
TIMESTAMP = "2026-11-16T12:00:00Z"
DOMAIN = "example.com"
TEAM = "backend"
NAMESPACE_SEED = bytes(range(32))
TEAM_SEED = bytes(range(1, 33))
NEW_TEAM_SEED = bytes(range(2, 34))
MEMBER_SEED = bytes(range(3, 35))
NAMESPACE_DID = did_key_from_signing_key(NAMESPACE_SEED)
TEAM_DID = did_key_from_signing_key(TEAM_SEED)
NEW_TEAM_DID = did_key_from_signing_key(NEW_TEAM_SEED)
MEMBER_DID = did_key_from_signing_key(MEMBER_SEED)
MEMBER_DID_AW = stable_id_from_did_key(MEMBER_DID)
CERTIFICATE_ID = "00000000-0000-4000-8000-000000000001"
SIGNING_HEADERS = (
    "authorization",
    "x-aweb-timestamp",
    "x-aweb-signed-payload",
    "content-type",
)


def certificate() -> str:
    cert = {
        "version": 1,
        "certificate_id": CERTIFICATE_ID,
        "team_id": f"{TEAM}:{DOMAIN}",
        "team_did_key": TEAM_DID,
        "member_did_key": MEMBER_DID,
        "alias": "member",
        "identity_scope": "local",
        "issued_at": TIMESTAMP,
    }
    cert["signature"] = sign_message(TEAM_SEED, canonical_json_bytes(cert))
    return base64.b64encode(canonical_json_bytes(cert)).decode()


# (case name, RegistryClient method, its keyword arguments). Signing keys are
# named by seed so a consumer can rebuild them: "namespace", "team".
CASES = [
    (
        "register_namespace",
        "register_namespace",
        dict(
            domain=DOMAIN,
            controller_did=NAMESPACE_DID,
            controller_signing_key="namespace",
            default_delivery_origin="https://messages.example.com",
        ),
    ),
    (
        "update_namespace_delivery_origin",
        "update_namespace_delivery_origin",
        dict(
            domain=DOMAIN,
            controller_signing_key="namespace",
            default_delivery_origin="https://messages.example.com",
        ),
    ),
    (
        "delete_namespace",
        "delete_namespace",
        dict(domain=DOMAIN, controller_signing_key="namespace", reason="retired"),
    ),
    (
        "register_team",
        "register_team",
        dict(
            domain=DOMAIN,
            name=TEAM,
            display_name="Backend",
            team_did_key=TEAM_DID,
            visibility="private",
            namespace_controller_signing_key="namespace",
        ),
    ),
    (
        "set_team_visibility",
        "set_team_visibility",
        dict(
            domain=DOMAIN,
            name=TEAM,
            visibility="public",
            team_controller_signing_key="team",
        ),
    ),
    (
        "delete_team",
        "delete_team",
        dict(domain=DOMAIN, name=TEAM, namespace_controller_signing_key="namespace"),
    ),
    (
        "rotate_team_key",
        "rotate_team_key",
        dict(
            domain=DOMAIN,
            name=TEAM,
            new_team_did_key=NEW_TEAM_DID,
            namespace_controller_signing_key="namespace",
        ),
    ),
    (
        "register_team_certificate",
        "register_team_certificate",
        dict(
            domain=DOMAIN,
            name=TEAM,
            team_controller_signing_key="team",
            certificate_id=CERTIFICATE_ID,
            member_did_key=MEMBER_DID,
            member_did_aw=None,
            member_address=None,
            alias="member",
            identity_scope="local",
            certificate=certificate(),
        ),
    ),
    (
        "revoke_team_certificate",
        "revoke_team_certificate",
        dict(
            domain=DOMAIN,
            name=TEAM,
            team_controller_signing_key="team",
            certificate_id=CERTIFICATE_ID,
        ),
    ),
    (
        "register_address",
        "register_address",
        dict(
            domain=DOMAIN,
            name="alice",
            did_aw=MEMBER_DID_AW,
            controller_signing_key="namespace",
            current_did_key=MEMBER_DID,
        ),
    ),
    (
        "delete_address",
        "delete_address",
        dict(domain=DOMAIN, name="alice", controller_signing_key="namespace"),
    ),
    (
        "delete_address_escaped_name",
        "delete_address",
        dict(domain=DOMAIN, name="a/b c", controller_signing_key="namespace"),
    ),
]
SEEDS = {"namespace": NAMESPACE_SEED, "team": TEAM_SEED}


class Captured(Exception):
    pass


async def wire(method: str, arguments: dict) -> dict:
    sent: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        raise Captured()

    call = {
        k: (SEEDS[v] if k.endswith("signing_key") else v) for k, v in arguments.items()
    }
    client = RegistryClient(registry_url=ORIGIN, transport=httpx.MockTransport(record))
    try:
        try:
            await getattr(client, method)(**call)
        except Captured:
            pass
    finally:
        await client.aclose()
    [request] = sent
    return {
        "method": request.method,
        "raw_path": request.url.raw_path.decode("ascii"),
        "body_utf8": request.content.decode("utf-8"),
        "headers": {
            name: request.headers[name]
            for name in SIGNING_HEADERS
            if name in request.headers
        },
    }


async def generate() -> dict:
    registry_module._utc_timestamp = lambda: TIMESTAMP
    cases = []
    for name, method, arguments in CASES:
        cases.append(
            {
                "name": name,
                "python_method": method,
                "arguments": arguments,
                "expected": await wire(method, arguments),
            }
        )
    return {
        "description": (
            "Controller writes that aw and the Python awid client both make, as the Python client sends them: "
            "covering-v2 signatures over the exact body bytes sent. Generated by "
            "scripts/generate_controller_write_vectors.py."
        ),
        "registry_origin": ORIGIN,
        "timestamp": TIMESTAMP,
        "seeds_hex": {name: seed.hex() for name, seed in SEEDS.items()},
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    text = json.dumps(asyncio.run(generate()), indent=2, ensure_ascii=False) + "\n"
    if parser.parse_args().check:
        if VECTOR.read_text() != text:
            print(f"{VECTOR} differs from the Python client's bytes", file=sys.stderr)
            return 1
        return 0
    VECTOR.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
