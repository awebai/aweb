#!/usr/bin/env python3
"""Real aweb/AWID command-test stack on disposable PostgreSQL and real Redis.

The Go caller owns namespace and team keys and registers all state through
the real HTTP routes. This process supplies sockets, storage and an
authoritative DNS zone. One JSON line announces readiness; stdin EOF closes
the services and drops only this fixture's database.
"""

import asyncio
from contextlib import AsyncExitStack
import json
import os
from pathlib import Path
import socket
import sys
from urllib.parse import quote
from uuid import uuid4

import asyncpg
import dns.asyncresolver
from aweb.config import enforce_team_key_pins, require_registered_certificates
from aweb.testing import running_server
from aweb_naapp_testing.network import DnsServer
from awid.ratelimit import MemoryFixedWindowRateLimiter
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN, running_registry
from redis.asyncio import Redis
from fastapi import FastAPI
import uvicorn


async def lose_committed_body(body, reason):
    async for chunk in body:
        if chunk:
            raise ConnectionResetError(reason)
        yield chunk


def fail_after_certificate_registration(
    app: FastAPI, domain: str, destination: Path, *, lose_response: bool
) -> None:
    registration = f"/v1/namespaces/{domain}/teams/backend/certificates"
    signing_key = destination.parent.parent / "signing.key"
    armed = True

    @app.middleware("http")
    async def obstruct_after_registration(request, call_next):
        nonlocal armed
        response = await call_next(request)
        # The recipient key exists by registration; the issuer is registered
        # earlier. The successful response establishes the committed write.
        if (
            armed
            and request.method == "POST"
            and request.url.path == registration
            and 200 <= response.status_code < 300
            and signing_key.is_file()
        ):
            armed = False
            if lose_response:
                response.body_iterator = lose_committed_body(
                    response.body_iterator,
                    "fixture dropped committed certificate response",
                )
            else:
                destination.mkdir(mode=0o700, parents=True)
        return response


def lose_first_grant_revoke_response(app: FastAPI) -> None:
    """The first successful grant revoke commits; its reply is then dropped."""
    armed = True

    @app.middleware("http")
    async def drop_after_revoke(request, call_next):
        nonlocal armed
        response = await call_next(request)
        if (
            armed
            and request.method == "POST"
            and request.url.path.startswith("/v1/identity-grants/")
            and request.url.path.endswith("/revoke")
            and 200 <= response.status_code < 300
        ):
            armed = False
            response.body_iterator = lose_committed_body(
                response.body_iterator,
                "fixture dropped committed grant revoke response",
            )
        return response


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


async def main() -> None:
    # The isolated runner owns these services. Never fall back to a host DB.
    host, redis_url = os.environ["PGHOST"], os.environ["REDIS_URL"]
    database = "aw_command_" + uuid4().hex
    user, password = (
        os.environ.get("PGUSER", "postgres"),
        os.environ.get("PGPASSWORD", "postgres"),
    )
    port = int(os.environ.get("PGPORT", "5432"))
    async with AsyncExitStack() as resources:
        admin = await asyncpg.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=os.environ.get("PGDATABASE", "postgres"),
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
        domain, controller = (
            os.environ["AW_COMMAND_DOMAIN"],
            os.environ["AW_COMMAND_CONTROLLER"],
        )
        # Real DNS packets pass through the production domain verifier.
        zone = DnsServer(
            {("_awid." + domain, "TXT"): [f'"awid=v1; controller={controller};"']}
        )
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
        if destination := os.environ.get("AW_COMMAND_CERTIFICATE_DESTINATION"):
            fail_after_certificate_registration(
                registry.app,
                domain,
                Path(destination),
                lose_response=os.environ.get("AW_COMMAND_CERTIFICATE_RESPONSE_LOSS")
                == "true",
            )
        await serve_fixture_app(registry.app, sock=registry_sock, resources=resources)
        server = await resources.enter_async_context(
            running_server(
                dsn,
                redis,
                awid_transport=registry.transport,
                public_origin=server_url,
            )
        )
        if os.environ.get("AW_COMMAND_GRANT_REVOKE_RESPONSE_LOSS") == "true":
            lose_first_grant_revoke_response(server.app)
        await serve_fixture_app(server.app, sock=server_sock, resources=resources)
        print(
            json.dumps({"registry_url": registry_url, "server_url": server_url}),
            flush=True,
        )
        await asyncio.to_thread(sys.stdin.read)


if __name__ == "__main__":
    asyncio.run(main())
