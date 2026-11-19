#!/usr/bin/env python3
"""Real aweb/AWID command-test stack on disposable PostgreSQL and real Redis.

One stack serves a whole test package. Each test owns its namespace and team
keys and registers all state through the real HTTP routes. This process
supplies sockets, storage and an authoritative DNS zone that starts empty.

One JSON line on stdout announces readiness. Then each stdin line is one
command, answered by one stdout line carrying the command's id:

    {"id": 1, "zone": {"domain": "a.test", "controller": "did:key:z..."}}
    {"id": 2, "public_origin": "http://127.0.0.1:61234"}
    {"id": 3, "reset_rate_limits": {}}
    {"id": 1, "ok": true}            or            {"id": 1, "error": "..."}

A zone command publishes only the domain's _awid TXT record; namespaces, teams
and certificates are written by the caller through the registry's routes. A
public_origin command adds a loopback origin to the registry's configured
public origins, as a deployment names the proxy in front of it; a test fronts
the registry that way only for answers the registry cannot give itself. The
registry runs production rate-limit buckets, keyed by client IP, which every
test shares; reset_rate_limits gives a starting test fresh buckets, as its own
stack would have.
stdin EOF closes the services and drops only this fixture's database.
"""

import asyncio
from contextlib import AsyncExitStack
import json
import os
import socket
import sys
from urllib.parse import quote
from uuid import uuid4

import asyncpg
import dns.asyncresolver
from aweb.config import enforce_team_key_pins, require_registered_certificates
from aweb.testing import running_server
from aweb_naapp_testing.network import DnsServer
from awid.did import validate_did
from awid.dns_verify import awid_txt_name, awid_txt_value
from awid.external_authority import FederationAuthorityError, canonical_protocol_domain
from awid.log import canonical_server_origin
from awid.ratelimit import MemoryFixedWindowRateLimiter
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN, running_registry
from redis.asyncio import Redis
from fastapi import FastAPI
import uvicorn


def bind_loopback_listener() -> tuple[socket.socket, str]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock, f"http://127.0.0.1:{sock.getsockname()[1]}"


async def serve_fixture_app(
    app: FastAPI, *, sock: socket.socket, resources: AsyncExitStack
) -> None:
    server = uvicorn.Server(
        uvicorn.Config(app, lifespan="off", log_level="warning", ws="none")
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))

    async def stop():
        server.should_exit = True
        await asyncio.wait_for(task, timeout=10)

    resources.push_async_callback(stop)
    async with asyncio.timeout(30):
        while not server.started:
            if task.done():
                await task
                raise RuntimeError("fixture service exited before listening")
            await asyncio.sleep(0.01)


ZONE_FIELDS = "Send {'zone': {'domain': <name>, 'controller': <did:key>}}."
COMMANDS = "Send exactly one of zone, public_origin or reset_rate_limits."


def publish_zone(zone: DnsServer, request) -> str | None:
    """Publish one domain's _awid record; return the refusal, if any."""
    if not isinstance(request, dict) or set(request) != {"domain", "controller"}:
        return "zone needs exactly domain and controller. " + ZONE_FIELDS
    domain, controller = request["domain"], request["controller"]
    if not isinstance(domain, str):
        return "zone domain is not a string. " + ZONE_FIELDS
    try:
        canonical = canonical_protocol_domain(domain)
    except FederationAuthorityError:
        canonical = None
    if canonical != domain:
        return (
            "zone domain is not a canonical DNS name. "
            "Send lowercase ASCII labels with no trailing dot."
        )
    if (
        not isinstance(controller, str)
        or not controller.startswith("did:key:")
        or not validate_did(controller)
    ):
        return (
            "zone controller is not an Ed25519 did:key. "
            "Send the namespace controller's did:key."
        )
    name = (awid_txt_name(domain), "TXT")
    if name in zone.records:
        return "zone domain is already published. Use a fresh domain for each world."
    zone.records[name] = [f'"{awid_txt_value(controller)}"']
    return None


def add_public_origin(registry: FastAPI, origin) -> str | None:
    """Name a loopback proxy as a registry public origin; return the refusal."""
    if not isinstance(origin, str):
        canonical = None
    else:
        try:
            canonical = canonical_server_origin(origin)
        except ValueError:
            canonical = None
    if (
        canonical is None
        or canonical != origin
        or not origin.startswith("http://127.0.0.1:")
    ):
        return (
            "public_origin is not a canonical http://127.0.0.1 origin. "
            "Send the front's origin as http://127.0.0.1:<port>."
        )
    registry.state.awid_public_origins += (origin,)
    return None


def reset_rate_limits(registry: FastAPI, request) -> str | None:
    """Give the registry fresh production buckets; return the refusal, if any."""
    if request != {}:
        return (
            "reset_rate_limits takes an empty object. Send {'reset_rate_limits': {}}."
        )
    registry.state.rate_limiter = MemoryFixedWindowRateLimiter()
    return None


def apply_command(zone: DnsServer, registry: FastAPI, line: str) -> dict:
    """Run one stdin command and return its acknowledgement."""
    try:
        command = json.loads(line)
    except json.JSONDecodeError:
        return {"error": "command is not JSON. Send one JSON object per line."}
    # bool is an int in Python; an id must be a real integer.
    if not isinstance(command, dict) or type(command.get("id")) is not int:
        return {"error": "command needs an integer id. Give every command its own id."}
    reply = {"id": command["id"]}
    names = set(command) - {"id"}
    if names == {"zone"}:
        refusal = publish_zone(zone, command["zone"])
    elif names == {"public_origin"}:
        refusal = add_public_origin(registry, command["public_origin"])
    elif names == {"reset_rate_limits"}:
        refusal = reset_rate_limits(registry, command["reset_rate_limits"])
    else:
        refusal = "command names no single known operation. " + COMMANDS
    if refusal is None:
        reply["ok"] = True
    else:
        reply["error"] = refusal
    return reply


async def serve_commands(zone: DnsServer, registry: FastAPI) -> None:
    while line := await asyncio.to_thread(sys.stdin.readline):
        print(json.dumps(apply_command(zone, registry, line)), flush=True)


async def main(services: dict[str, str]) -> None:
    host, redis_url = services["PGHOST"], services["REDIS_URL"]
    database = "aw_command_" + uuid4().hex
    user, password = (
        services.get("PGUSER", "postgres"),
        services.get("PGPASSWORD", "postgres"),
    )
    port = int(services.get("PGPORT", "5432"))
    async with AsyncExitStack() as resources:
        admin = await asyncpg.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=services.get("PGDATABASE", "postgres"),
        )
        resources.push_async_callback(admin.close)
        await admin.execute(f'CREATE DATABASE "{database}"')
        resources.push_async_callback(
            admin.execute, f'DROP DATABASE "{database}" WITH (FORCE)'
        )
        dsn = f"postgresql://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}/{database}"
        registry_sock, registry_url = bind_loopback_listener()
        resources.callback(registry_sock.close)
        server_sock, server_url = bind_loopback_listener()
        resources.callback(server_sock.close)
        # Real DNS packets pass through the production domain verifier.
        zone = DnsServer()
        await zone.start()
        resources.callback(zone.close)
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers, resolver.port = ["127.0.0.1"], zone.port
        dns.asyncresolver.default_resolver = resolver
        os.environ.update(
            APP_ENV="development",
            AWEB_DATABASE_URL=dsn,
            AWID_DATABASE_URL=dsn,
            AWID_SERVICE_TOKEN=SERVICE_TOKEN,
            AWID_REGISTRY_URL=REGISTRY_URL,
            AWID_PUBLIC_REGISTRY_URL=registry_url,
            AWEB_PUBLIC_ORIGIN=server_url,
            AWEB_DISCOVERY_ORIGIN=server_url,
            AWEB_REDIS_URL=redis_url,
            AWEB_REQUIRE_REGISTERED_CERTIFICATES="true",
            AWEB_ENFORCE_TEAM_KEY_PINS="true",
        )
        os.environ.pop("AWID_SKIP_DNS_VERIFY", None)
        os.environ.pop("AWID_RATE_LIMIT_DISABLED", None)
        if not require_registered_certificates() or not enforce_team_key_pins():
            raise RuntimeError(
                "Enable registered certificates and team-key pins before publishing fixture readiness"
            )
        redis = await resources.enter_async_context(
            Redis.from_url(redis_url, decode_responses=True)
        )
        registry = await resources.enter_async_context(
            running_registry(dsn, redis=redis)
        )
        registry.app.state.rate_limiter = MemoryFixedWindowRateLimiter()
        registry.app.state.awid_public_origins = (REGISTRY_URL, registry_url)
        await serve_fixture_app(registry.app, sock=registry_sock, resources=resources)
        server = await resources.enter_async_context(
            running_server(
                dsn,
                redis,
                awid_transport=registry.transport,
                public_origin=server_url,
            )
        )
        await serve_fixture_app(server.app, sock=server_sock, resources=resources)
        print(
            json.dumps({"registry_url": registry_url, "server_url": server_url}),
            flush=True,
        )
        await serve_commands(zone, registry.app)


def run() -> None:
    """Run on the PG/Redis the caller supplies: the isolated runner's, or the
    cmd/aw package's disposable pair. Never a host database it was not given."""
    # -P keeps this directory off the path; only this sibling is wanted.
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from disposable_services import require_test_services

    require_test_services()
    if not os.environ.get("PGHOST") or not os.environ.get("REDIS_URL"):
        raise SystemExit(
            "PGHOST and REDIS_URL are required: the isolated runner or the cmd/aw "
            "package's disposable services supply them"
        )
    asyncio.run(main(dict(os.environ)))


if __name__ == "__main__":
    run()
