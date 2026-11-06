import asyncio
import json
import os

import httpx
import typer
import uvicorn

from .app_manifests import ManifestFetcher, fetch_app_manifest
from .app_registry import reseed_app_registrations
from .config import get_settings
from .db import DatabaseInfra
from .install_admins import (
    grant_install_admin_on,
    list_install_admins_on,
    revoke_install_admin_on,
)
from .installation_requests import run_installation_verifications
from .installations import verify_pending_installations
from .service_errors import ServiceError
from .workspace_config import get_workspace_id

app = typer.Typer(help="aweb coordination core CLI")
install_admin_cli = typer.Typer(help="Manage standalone installation authority locally as the server operator")
app.add_typer(install_admin_cli, name="install-admin")


def _install_admin_operation(action, *, team_id, principal_did=None, role="admin", force=False):
    async def run():
        infra = DatabaseInfra()
        await infra.initialize(run_migrations=False)
        try:
            async with infra.get_manager().transaction() as tx:
                if action == "grant":
                    return await grant_install_admin_on(tx, team_id=team_id, principal_did=principal_did, role=role, force=force)
                if action == "revoke":
                    return {"revoked": await revoke_install_admin_on(tx, team_id=team_id, principal_did=principal_did, force=force)}
                return await list_install_admins_on(tx, team_id=team_id)
        finally:
            await infra.close()
    try:
        result = asyncio.run(run())
    except ServiceError as exc:
        typer.echo(f"Error: {getattr(exc, 'code', 'admin_grant_failed')}: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(json.dumps(result, default=str, indent=2))


@install_admin_cli.command("grant")
def grant_install_admin_command(
    team_id: str = typer.Option(..., "--team-id"),
    principal_did: str = typer.Option(..., "--principal-did", help="Member's verified Ed25519 did:key"),
    role: str = typer.Option("admin", "--role", help="owner or admin"),
    force: bool = typer.Option(False, "--force", help="Allow demoting the last owner"),
):
    _install_admin_operation("grant", team_id=team_id, principal_did=principal_did, role=role, force=force)


@install_admin_cli.command("revoke")
def revoke_install_admin_command(
    team_id: str = typer.Option(..., "--team-id"),
    principal_did: str = typer.Option(..., "--principal-did"),
    force: bool = typer.Option(False, "--force", help="Allow revoking the last owner"),
):
    _install_admin_operation("revoke", team_id=team_id, principal_did=principal_did, force=force)


@install_admin_cli.command("list")
def list_install_admin_command(team_id: str = typer.Option(..., "--team-id")):
    _install_admin_operation("list", team_id=team_id)


def _resolve_workspace_id(override: str | None) -> str:
    """Resolve workspace_id from override or .aw/workspace.yaml.

    Args:
        override: Explicit workspace_id from --workspace-id flag.

    Returns:
        workspace_id string.

    Raises:
        typer.Exit: If no workspace_id is available.
    """
    workspace_id = get_workspace_id(override=override)
    if not workspace_id:
        typer.echo(
            "Error: No workspace_id available.\n"
            "Either:\n"
            "  - Run 'aw init' or 'aw use' from a git repo to create a .aw/workspace.yaml file\n"
            "  - Pass --workspace-id explicitly",
            err=True,
        )
        raise typer.Exit(1)
    return workspace_id

def _handle_api_call(
    method: str,
    url: str,
    allow_statuses: set[int] | None = None,
    **kwargs,
) -> httpx.Response:
    """
    Execute an HTTP request with proper error handling.
    Handles network errors, timeouts, and HTTP status errors gracefully.

    Args:
        method: HTTP method (GET, POST, DELETE)
        url: Request URL
        allow_statuses: Set of status codes to allow through (e.g., {404, 409})
        **kwargs: Additional arguments passed to httpx
    """
    headers = kwargs.pop("headers", {})

    try:
        if method == "GET":
            resp = httpx.get(url, timeout=30, headers=headers, **kwargs)
        elif method == "POST":
            resp = httpx.post(url, timeout=30, headers=headers, **kwargs)
        elif method == "DELETE":
            resp = httpx.delete(url, timeout=30, headers=headers, **kwargs)
        else:
            raise ValueError(f"Unsupported method: {method}")

        # Allow specific status codes through for caller handling
        if allow_statuses and resp.status_code in allow_statuses:
            return resp

        # Handle common HTTP errors with friendly messages
        if resp.status_code == 401:
            typer.echo("Error: Unauthorized", err=True)
            raise typer.Exit(1)
        elif resp.status_code == 403:
            typer.echo("Error: Forbidden - insufficient permissions", err=True)
            raise typer.Exit(1)
        elif resp.status_code >= 500:
            typer.echo(f"Error: Server error ({resp.status_code})", err=True)
            raise typer.Exit(1)

        return resp

    except httpx.ConnectError:
        api_base = _get_api_base()
        typer.echo(f"Error: Cannot connect to aweb coordination API at {api_base}", err=True)
        typer.echo("Is the server running?", err=True)
        raise typer.Exit(1)
    except httpx.TimeoutException:
        typer.echo("Error: Request timed out", err=True)
        raise typer.Exit(1)
    except httpx.RequestError as e:
        typer.echo(f"Error: Network error - {e}", err=True)
        raise typer.Exit(1)


@app.command()
def serve(
    host: str | None = typer.Option(None, help="Host interface to bind"),
    port: int | None = typer.Option(None, help="Port to bind"),
    reload: bool | None = typer.Option(None, help="Enable auto-reload (development only)"),
    log_level: str | None = typer.Option(None, help="Log level for the server"),
) -> None:
    """
    Start the aweb coordination API server.
    """
    settings = get_settings()

    uvicorn.run(
        "aweb.api:create_app",
        host=host or settings.host,
        port=port or settings.port,
        reload=reload if reload is not None else settings.reload,
        log_level=log_level or settings.log_level,
        factory=True,
    )


@app.command()
def status(
    workspace_id: str | None = typer.Option(
        None, "--workspace-id", help="Workspace ID (reads from .aw/workspace.yaml if not provided)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
) -> None:
    """
    Show workspace status (agent presence, claims, and conflicts).
    """
    resolved_workspace_id = _resolve_workspace_id(workspace_id)
    params = {"workspace_id": resolved_workspace_id}
    resp = _handle_api_call("GET", f"{_get_api_base()}/v1/status", params=params)
    data = resp.json()

    if json_output:
        typer.echo(json.dumps(data, indent=2))
        return

    workspace = data.get("workspace", {})
    typer.echo(f"Workspace: {workspace.get('workspace_id')}")
    typer.echo(f"Timestamp: {data.get('timestamp')}")
    typer.echo("")

    agents = data.get("agents", [])
    if agents:
        typer.echo("Agents:")
        for agent in agents:
            typer.echo(
                f"  {agent.get('alias', '?'):15} status={agent.get('status', '?'):8} "
                f"task={agent.get('current_task_ref') or '-'}"
            )
    else:
        typer.echo("Agents: (none)")

@app.command("reseed-app-registrations")
def reseed_app_registrations_command(
    origin: str = typer.Option(..., "--origin", help="App origin whose installs are reseeded"),
    manifest_file: str | None = typer.Option(
        None,
        "--manifest-file",
        help="Exact manifest bytes to use instead of fetching them from the origin",
    ),
) -> None:
    """
    Recreate every team's app event declarations and emit keys from manifest bytes.

    Applies to each team whose install pins the digest of those bytes. Never
    changes subscriptions. Exits 1 when any team was left unchanged.
    """
    async def _reseed(manifest: bytes):
        infra = DatabaseInfra()
        await infra.initialize(run_migrations=False)
        try:
            return await reseed_app_registrations(infra.get_manager(), origin=origin, manifest=manifest)
        finally:
            await infra.close()

    try:
        if manifest_file:
            with open(manifest_file, "rb") as handle:
                manifest = handle.read()
        else:
            manifest = fetch_app_manifest(origin)
        report = asyncio.run(_reseed(manifest))
    except (OSError, ServiceError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)

    typer.echo(json.dumps(report.__dict__, indent=2))
    if report.digest_mismatch or report.key_conflict:
        raise typer.Exit(1)


@app.command("verify-identity-bindings")
def verify_identity_bindings_command(
    dry_run: bool = typer.Option(False, "--dry-run", help="Verify without writing markers"),
) -> None:
    """Verify pending identity projections after migration; report counts only."""
    from awid.registry import RegistryClient
    from .identity_binding import verify_pending_identity_bindings

    async def _verify():
        settings = get_settings()
        infra = DatabaseInfra()
        await infra.initialize(run_migrations=False)
        try:
            registry = RegistryClient(
                registry_url=settings.awid_registry_url,
                service_token=settings.awid_service_token,
            )
            try:
                return await verify_pending_identity_bindings(
                    infra.get_manager(), registry, dry_run=dry_run,
                )
            finally:
                await registry.aclose()
        finally:
            await infra.close()

    report = asyncio.run(_verify())
    typer.echo(json.dumps(report, sort_keys=True))
    if report["unbound"] or report["awid_error"]:
        raise typer.Exit(1)


@app.command("verify-pending-app-installations")
def verify_pending_app_installations_command(
    team_id: str | None = typer.Option(None, "--team-id", help="Verify only this team's pending installations"),
) -> None:
    """Verify all pending origin pins after the installation migration.

    Deploy operators run this immediately after migration. Failures remain
    pending, keep their scopes and pins, and carry a reason for admin retry.
    """
    async def run():
        infra = DatabaseInfra()
        await infra.initialize(run_migrations=False)
        try:
            return await verify_pending_installations(
                infra.get_manager(), fetcher=ManifestFetcher(), team_id=team_id,
            )
        finally:
            await infra.close()

    try:
        reports = asyncio.run(run())
    except ServiceError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)
    typer.echo(json.dumps({"installations": reports}, indent=2))
    if any(report["outcome"] == "pending" for report in reports):
        raise typer.Exit(1)


@app.command("run-installation-verifications")
def run_installation_verifications_command(
    limit: int = typer.Option(25, min=1, max=1000, help="Maximum queued jobs to process"),
) -> None:
    """Process queued admin re-verifications; run periodically on a worker."""
    async def run():
        infra = DatabaseInfra()
        await infra.initialize(run_migrations=False)
        try:
            return await run_installation_verifications(infra.get_manager(), limit=limit)
        finally:
            await infra.close()
    reports = asyncio.run(run())
    typer.echo(json.dumps({"jobs": reports}, indent=2))
    if any(report["outcome"] == "pending" for report in reports):
        raise typer.Exit(1)


def _get_api_base() -> str:
    return os.getenv("AWEB_API_URL", "http://localhost:8000")
