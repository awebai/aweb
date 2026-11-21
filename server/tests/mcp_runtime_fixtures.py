"""Mount the actual public MCP app with its supported startup/shutdown API."""

from contextlib import asynccontextmanager

from aweb.mcp import create_mcp_app
from starlette.routing import Mount


@asynccontextmanager
async def mounted_mcp(app, *, db_infra, redis, registry_client, hosted_signer=None):
    runtime = create_mcp_app(
        db_infra=db_infra,
        redis=redis,
        registry_client=registry_client,
        hosted_signer=hosted_signer,
        public_origin=getattr(app.state, "public_origin", None),
        streamable_http_path="/",
    )
    await runtime.startup()
    route = Mount("/mcp", app=runtime)
    # The real fixture server already has its SPA fallback. This mount must
    # precede it so signed requests reach the actual MCP auth/tool pipeline.
    app.router.routes.insert(0, route)
    try:
        yield runtime
    finally:
        app.router.routes.remove(route)
        await runtime.shutdown()
