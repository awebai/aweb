from __future__ import annotations

import os
import secrets
import uuid

import typer
import uvicorn

from aweb.auth import hash_api_key
from aweb.config import get_settings
from aweb.db import DatabaseInfra

app = typer.Typer(help="aweb (Agent Web) CLI")


@app.command()
def serve(
    host: str | None = typer.Option(None, help="Host interface to bind"),
    port: int | None = typer.Option(None, help="Port to bind"),
    reload: bool | None = typer.Option(None, help="Enable auto-reload (development only)"),
    log_level: str | None = typer.Option(None, help="Log level for the server"),
) -> None:
    settings = get_settings()
    uvicorn.run(
        "aweb.api:create_app",
        host=host or settings.host,
        port=port or settings.port,
        reload=reload if reload is not None else settings.reload,
        log_level=log_level or settings.log_level,
        factory=True,
    )


def _require_database_url() -> None:
    if os.getenv("AWEB_DATABASE_URL") or os.getenv("DATABASE_URL"):
        return
    typer.echo(
        "Missing DATABASE_URL/AWEB_DATABASE_URL. Example:\n"
        "  export AWEB_DATABASE_URL=postgresql://user:pass@localhost:5432/aweb",
        err=True,
    )
    raise typer.Exit(1)


@app.command()
def seed(
    project_slug: str = typer.Option(..., help="Project slug to seed"),
    agent_1_alias: str = typer.Option("agent-1", help="Alias for agent 1"),
    agent_2_alias: str = typer.Option("agent-2", help="Alias for agent 2"),
    aweb_url: str | None = typer.Option(None, help="If set, prints export AWEB_URL=..."),
    other_project_slug: str | None = typer.Option(
        None, help="If set, seeds a second project identity for cross-project scoping tests"
    ),
    other_agent_alias: str = typer.Option(
        "other-agent", help="Agent alias for other project (when --other-project-slug is set)"
    ),
) -> None:
    """Seed a project, two agents, and an API key (for local dev/conformance)."""

    _require_database_url()

    api_key = f"aw_sk_{secrets.token_hex(16)}"

    async def _run() -> None:
        infra = DatabaseInfra()
        await infra.initialize()
        try:
            db = infra.get_manager("aweb")

            project = await db.fetch_one(
                "SELECT project_id FROM {{tables.projects}} WHERE slug = $1 AND deleted_at IS NULL",
                project_slug,
            )
            if project:
                project_id = project["project_id"]
            else:
                project_id = uuid.uuid4()
                await db.execute(
                    "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
                    project_id,
                    project_slug,
                    project_slug,
                )

            async def ensure_agent(alias: str) -> uuid.UUID:
                row = await db.fetch_one(
                    "SELECT agent_id FROM {{tables.agents}} WHERE project_id = $1 AND alias = $2 AND deleted_at IS NULL",
                    project_id,
                    alias,
                )
                if row:
                    return uuid.UUID(str(row["agent_id"]))
                agent_id = uuid.uuid4()
                await db.execute(
                    "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
                    agent_id,
                    project_id,
                    alias,
                    alias,
                    "agent",
                )
                return agent_id

            agent_1_id = await ensure_agent(agent_1_alias)
            agent_2_id = await ensure_agent(agent_2_alias)

            await db.execute(
                "INSERT INTO {{tables.api_keys}} (project_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4)",
                project_id,
                api_key[:12],
                hash_api_key(api_key),
                True,
            )

            other_api_key: str | None = None
            other_agent_id: uuid.UUID | None = None
            if other_project_slug:
                other_api_key = f"aw_sk_{secrets.token_hex(16)}"
                other_project_id = uuid.uuid4()
                await db.execute(
                    "INSERT INTO {{tables.projects}} (project_id, slug, name) VALUES ($1, $2, $3)",
                    other_project_id,
                    other_project_slug,
                    other_project_slug,
                )
                other_agent_id = uuid.uuid4()
                await db.execute(
                    "INSERT INTO {{tables.agents}} (agent_id, project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4, $5)",
                    other_agent_id,
                    other_project_id,
                    other_agent_alias,
                    other_agent_alias,
                    "agent",
                )
                await db.execute(
                    "INSERT INTO {{tables.api_keys}} (project_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4)",
                    other_project_id,
                    other_api_key[:12],
                    hash_api_key(other_api_key),
                    True,
                )
        finally:
            await infra.close()

        typer.echo("Export the following for aweb conformance tests:")
        if aweb_url:
            typer.echo(f"export AWEB_URL={aweb_url}")
        typer.echo(f"export AWEB_API_KEY={api_key}")
        typer.echo(f"export AWEB_AGENT_1_ID={agent_1_id}")
        typer.echo(f"export AWEB_AGENT_1_ALIAS={agent_1_alias}")
        typer.echo(f"export AWEB_AGENT_2_ID={agent_2_id}")
        typer.echo(f"export AWEB_AGENT_2_ALIAS={agent_2_alias}")
        if other_project_slug:
            typer.echo(f"export AWEB_OTHER_API_KEY={other_api_key}")
            typer.echo(f"export AWEB_OTHER_AGENT_ID={other_agent_id}")
            typer.echo(f"export AWEB_OTHER_AGENT_ALIAS={other_agent_alias}")

    import asyncio

    asyncio.run(_run())
