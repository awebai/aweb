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
import socket
import sys
from urllib.parse import quote
from uuid import uuid4

import asyncpg
import dns.asyncresolver
from aweb.testing import running_server
from aweb_naapp_testing.network import DnsServer
from awid.ratelimit import MemoryFixedWindowRateLimiter
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN, running_registry
from redis.asyncio import Redis
import uvicorn


def listener():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock, f"http://127.0.0.1:{sock.getsockname()[1]}"


async def serve(app, sock, stack):
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_level="warning", ws="none"))
    task = asyncio.create_task(server.serve(sockets=[sock]))

    async def stop():
        server.should_exit = True
        await asyncio.wait_for(task, timeout=10)

    stack.push_async_callback(stop)
    async with asyncio.timeout(30):
        while not server.started:
            if task.done():
                await task
                raise RuntimeError("fixture service exited before listening")
            await asyncio.sleep(0.01)


async def main():
    # The isolated runner owns these services. Never fall back to a host DB.
    host, redis_url = os.environ["PGHOST"], os.environ["REDIS_URL"]
    database = "aw_command_" + uuid4().hex
    user, password = os.environ.get("PGUSER", "postgres"), os.environ.get("PGPASSWORD", "postgres")
    port = int(os.environ.get("PGPORT", "5432"))
    admin = await asyncpg.connect(
        host=host, port=port, user=user, password=password,
        database=os.environ.get("PGDATABASE", "postgres"),
    )
    await admin.execute(f'CREATE DATABASE "{database}"')
    dsn = f"postgresql://{quote(user, safe='')}:{quote(password, safe='')}@{host}:{port}/{database}"
    registry_sock, registry_url = listener()
    server_sock, server_url = listener()
    domain, controller = os.environ["AW_COMMAND_DOMAIN"], os.environ["AW_COMMAND_CONTROLLER"]
    try:
        async with AsyncExitStack() as stack:
            stack.callback(registry_sock.close)
            stack.callback(server_sock.close)
            # Real DNS packets pass through the production domain verifier.
            zone = DnsServer({("_awid." + domain, "TXT"): [f'"awid=v1; controller={controller};"']})
            await zone.start()
            stack.callback(zone.close)
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers, resolver.port = ["127.0.0.1"], zone.port
            dns.asyncresolver.default_resolver = resolver
            os.environ.update(
                APP_ENV="development", AWEB_DATABASE_URL=dsn, AWID_DATABASE_URL=dsn,
                AWID_SERVICE_TOKEN=SERVICE_TOKEN, AWID_REGISTRY_URL=REGISTRY_URL,
                AWID_PUBLIC_REGISTRY_URL=registry_url, AWEB_PUBLIC_ORIGIN=server_url,
                AWEB_DISCOVERY_ORIGIN=server_url, AWEB_REDIS_URL=redis_url,
                AWEB_REQUIRE_REGISTERED_CERTIFICATES="true", AWEB_REQUIRE_TEAM_KEY_PINS="true",
            )
            os.environ.pop("AWID_SKIP_DNS_VERIFY", None)
            redis = await stack.enter_async_context(Redis.from_url(redis_url, decode_responses=True))
            registry = await stack.enter_async_context(running_registry(dsn, redis=redis))
            registry.app.state.rate_limiter = MemoryFixedWindowRateLimiter()
            registry.app.state.awid_public_origins = (REGISTRY_URL, registry_url)
            await serve(registry.app, registry_sock, stack)
            server = await stack.enter_async_context(running_server(
                dsn, redis, awid_transport=registry.transport, public_origin=server_url,
            ))
            await serve(server.app, server_sock, stack)
            print(json.dumps({"registry_url": registry_url, "server_url": server_url}), flush=True)
            await asyncio.to_thread(sys.stdin.read)
    finally:
        await admin.execute(f'DROP DATABASE "{database}" WITH (FORCE)')
        await admin.close()


if __name__ == "__main__":
    asyncio.run(main())
