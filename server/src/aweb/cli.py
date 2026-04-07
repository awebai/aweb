import json
import os

import httpx
import typer
import uvicorn

from .config import get_settings
from .workspace_config import get_workspace_id

app = typer.Typer(help="aweb coordination core CLI")


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

def _get_api_base() -> str:
    return os.getenv("AWEB_API_URL", "http://localhost:8000")
