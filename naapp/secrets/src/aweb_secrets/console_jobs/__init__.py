"""Owner job/runner draft pages on S4 and custody's canonical change writer.

These forms create inert drafts only. Custody renders and confirms their
frozen review and releases one-time runner codes in that same document.
"""

from html import escape
from pathlib import Path

from aweb_naapp.console import ConsoleRoute
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from aweb_secrets.console_changes import ConsoleChanges, _errors
from aweb_secrets.console_ui import _login_redirect, console_page
from aweb_secrets.runners import mint_runner_id

_ASSETS = Path(__file__).parent
_SCRIPT = '<link rel="stylesheet" href="/console-jobs/jobs.css"><script src="/console-jobs/jobs.js" defer></script>'
_STATUS = '<p id="job-status" role="status" aria-live="polite"></p>'


def _input(name: str, label: str, *, kind="text", value="", required=True, extra="") -> str:
    return (
        f'<label for="{name}">{label}</label><input id="{name}" name="{name}" '
        f'type="{kind}" value="{escape(value, quote=True)}" {"required" if required else ""} {extra}>'
    )


def _json(name: str, label: str, value: str) -> str:
    return f'<label for="{name}">{label}</label><textarea id="{name}" name="{name}" rows="4" required spellcheck="false">{escape(value)}</textarea>'


def _job() -> str:
    return (
        "<p>Pin the executable and configure the credentials this job can use. "
        "A draft cannot run until you confirm it with your passkey.</p>"
        + _input("job-id", "Job ID")
        + _input("runner-ids", "Allowed runner IDs (comma-separated)")
        + _input("exec-path", "Executable path on the runner")
        + _input(
            "exec-digest",
            "Executable SHA-256",
            extra='pattern="[0-9a-f]{64}" minlength="64" maxlength="64"',
        )
        + _input("cwd", "Working directory on the runner")
        + _input(
            "timeout", "Time limit (seconds)", kind="number", value="60", extra='min="1" max="3600"'
        )
        + _json("argv", "Arguments (JSON array)", "[]")
        + _json("files", "Additional pinned files (JSON array of path and sha256)", "[]")
        + _json("params", "Parameter constraints (JSON object)", "{}")
        + _json("env", "Environment bindings (JSON object)", "{}")
        + _json(
            "credentials", "Credential slots (JSON array of secret_ref, delivery and mint)", "[]"
        )
        + "<p>Use a secret reference in a credential slot. Credential values are never entered here. "
        "For a durable slot, set delivery to durable and mint to null; "
        "bind its field in the environment with $credential and field.</p>"
        + '<label class="check"><input id="allow-durable" type="checkbox">Allow this job to receive durable credentials</label>'
        + "<p>A durable credential is released to the registered runner only for its approved job.</p>"
        + _input(
            "output-bytes",
            "Maximum result bytes",
            kind="number",
            value="4096",
            extra='min="1" max="16777216"',
        )
        + _json("projection", "Result fields (JSON pointer array)", '["/exit_code"]')
    )


def console_jobs_router(*, changes: ConsoleChanges) -> APIRouter:
    """Mount on the human app, using its exact shared ConsoleChanges instance."""
    router = APIRouter(route_class=ConsoleRoute)

    async def render(request: Request, kind: str, installation_id: str | None = None):
        try:
            current = await changes.console.sessions.current(request)
        except HTTPException as refused:
            return _login_redirect(refused)
        async with _errors(changes.console, current):
            if installation_id is None:
                installation_id = await changes.installation_for_session(current)
                return RedirectResponse(
                    f"/installations/{installation_id}/{kind}s/new", status_code=303
                )
            admitted = await changes._installation(installation_id)
            async with changes.console.db.transaction() as tx:
                await changes._owner(tx, current, admitted)
        title = "Create a job" if kind == "job" else "Register a runner"
        fields = (
            _job()
            if kind == "job"
            else (
                "<p>Register the runner that will execute your pinned jobs. "
                "Confirmation shows a one-time code to register its public keys.</p>"
                + _input("runner-id", "Runner ID", value=mint_runner_id(), extra="readonly")
                + _input("runner-label", "Runner name")
                + _input("allowed-jobs", "Allowed job IDs (comma-separated)", required=False)
            )
        )
        action = "/installations/" + installation_id + "/change-sets"
        return console_page(
            title=title,
            session=current,
            body_html=f'<h1>{title}</h1><form id="definition-draft" data-kind="{kind}" method="post" action="{escape(action, quote=True)}">'
            + fields
            + _input("reason", "Reason for this change", required=False)
            + '<button type="submit">Save a draft for review</button></form>'
            + _STATUS
            + _SCRIPT,
        )

    @router.get("/jobs/new", response_class=HTMLResponse)
    async def job_entry(request: Request):
        return await render(request, "job")

    @router.get("/runners/new", response_class=HTMLResponse)
    async def runner_entry(request: Request):
        return await render(request, "runner")

    @router.get("/installations/{installation_id}/jobs/new", response_class=HTMLResponse)
    async def job_page(installation_id: str, request: Request):
        return await render(request, "job", installation_id)

    @router.get("/installations/{installation_id}/runners/new", response_class=HTMLResponse)
    async def runner_page(installation_id: str, request: Request):
        return await render(request, "runner", installation_id)

    @router.get("/console-jobs/jobs.js")
    async def script():
        return Response((_ASSETS / "jobs.js").read_text(), media_type="text/javascript")

    @router.get("/console-jobs/jobs.css")
    async def style():
        return Response((_ASSETS / "jobs.css").read_text(), media_type="text/css")

    return router
