from __future__ import annotations

import asyncio

import typer
import uvicorn

from .config import get_settings
from .migrate import migrate_from_aweb

app = typer.Typer(help="awid.ai registry service CLI")


@app.command()
def serve(
    host: str | None = typer.Option(None, help="Host interface to bind"),
    port: int | None = typer.Option(None, help="Port to bind"),
    reload: bool | None = typer.Option(None, help="Enable auto-reload (development only)"),
    log_level: str | None = typer.Option(None, help="Log level for the server"),
) -> None:
    settings = get_settings()
    uvicorn.run(
        "awid_service.main:create_app",
        host=host or settings.host,
        port=port or settings.port,
        reload=reload if reload is not None else settings.reload,
        log_level=log_level or settings.log_level,
        factory=True,
    )


@app.command("migrate-from-aweb")
def migrate_from_aweb_command(
    source_schema: str = typer.Option("aweb", help="Source schema to import from"),
    target_schema: str = typer.Option("awid", help="Target schema to import into"),
    include_managed: bool = typer.Option(False, help="Include managed namespaces"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Report migration counts without writing"),
) -> None:
    result = asyncio.run(
        migrate_from_aweb(
            source_schema=source_schema,
            target_schema=target_schema,
            include_managed=include_managed,
            dry_run=dry_run,
        )
    )
    mode = "dry-run" if dry_run else "applied"
    typer.echo(
        "Migration "
        f"({mode}): "
        f"projects={result.projects} "
        f"agents={result.agents} "
        f"did_mappings={result.did_mappings} "
        f"did_log_entries={result.did_log_entries} "
        f"namespaces={result.namespaces} "
        f"addresses={result.addresses} "
        f"replacements={result.replacements}"
    )
