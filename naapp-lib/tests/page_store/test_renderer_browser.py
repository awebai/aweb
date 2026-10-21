"""Opt-in real PostgreSQL/HTTP/packaged-renderer preservation proof.

The browser dependencies live in renderer/, alongside R1's other browser tests.
See docs/page-renderer.md for the focused command.
"""

import asyncio
import os
import shutil
import socket
from importlib.resources import files
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response

from aweb_naapp.pages import validate_page
from aweb_naapp.pages.render import page_shell
from tests.page_store.test_store import OWNER, SCOPE, create, page, record_change

pytestmark = pytest.mark.skipif(
    os.environ.get("AWEB_PAGE_STORE_BROWSER") != "1",
    reason="Opt-in browser proof: set AWEB_PAGE_STORE_BROWSER=1 (docs/page-renderer.md)",
)
RENDERER = Path(__file__).resolve().parents[2] / "renderer"


async def test_unrelated_store_write_preserves_browser_draft_focus_and_scroll(store):
    assert shutil.which("node"), "Install Node and run npm ci in naapp-lib/renderer"
    assert (RENDERER / "node_modules/@playwright/test").is_dir(), (
        "Run npm ci in naapp-lib/renderer and npx playwright install chromium"
    )
    document = page()
    document["actions"].append(
        {
            "id": "save-note",
            "kind": "edit",
            "label": "Save note",
            "policy_ref": "fixture-edit",
            "operation": "note.save",
            "input_schema": {
                "type": "object",
                "properties": {"note": {"type": "string", "default": "Original note"}},
                "required": ["note"],
                "additionalProperties": False,
            },
        }
    )
    spacer = "\n\n".join(["Context for the inventory note."] * 40)
    document["layout"] = [
        {"id": "before", "type": "text", "props": {"markdown": spacer}},
        {
            "id": "note-form",
            "type": "form",
            "props": {
                "fields": [{"id": "note", "kind": "text", "label": "Note", "required": True}],
                "submit_action": "save-note",
            },
        },
        document["layout"][0],
        {"id": "after", "type": "text", "props": {"markdown": spacer}},
    ]
    await create(store, document)
    app = FastAPI()

    @app.get("/")
    async def shell():
        rendered = page_shell(
            script_path="/assets/store-host.js", asset_origin="https://assets.invalid"
        )
        return HTMLResponse(rendered.html, headers=rendered.headers)

    @app.get("/assets/{name}")
    async def asset(name: str):
        if name == "store-host.js":
            return Response(
                (RENDERER / "tests/page-store-host.mjs").read_bytes(), media_type="text/javascript"
            )
        assert name in {"page-renderer.js", "page-renderer.css"}
        return Response(
            files("aweb_naapp.pages").joinpath("assets", name).read_bytes(),
            media_type="text/css" if name.endswith(".css") else "text/javascript",
        )

    @app.get("/api/page")
    async def snapshot():
        result = await store.read(SCOPE, OWNER)
        assert validate_page(result).valid
        return result

    @app.post("/api/read")
    async def projection(request: Request):
        context = await request.json()
        assert context.pop("page_id") == SCOPE.page_id
        return await store.read_widget(SCOPE, OWNER, **context)

    @app.post("/api/unrelated-write")
    async def unrelated_write():
        return await store.mutate(
            SCOPE,
            OWNER,
            expected_rev=1,
            key="unrelated-browser-write",
            records=[
                {
                    **record_change(),
                    "value": {"label": "Updated through PostgreSQL", "checked": True},
                }
            ],
        )

    # Uvicorn uses this already-bound socket: no fixed ports or another gallery.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
        serving = asyncio.create_task(server.serve(sockets=[listener]))
        process = None
        try:
            async with asyncio.timeout(10):
                while not server.started:
                    if serving.done():
                        await serving
                    await asyncio.sleep(0.01)
            process = await asyncio.create_subprocess_exec(
                "node",
                str(RENDERER / "tests/page-store-browser.mjs"),
                f"http://127.0.0.1:{listener.getsockname()[1]}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=45)
            assert process.returncode == 0, (stdout + stderr).decode()
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            server.should_exit = True
            await asyncio.wait_for(serving, timeout=10)

    assert (await store.read(SCOPE, OWNER))["rev"] == 2
    projected = await store.read_widget(
        SCOPE, OWNER, widget_id="items", expected_page_rev=2, bind={"collection": "items"}
    )
    assert projected["records"][0]["rev"] == 2
    assert projected["records"][0]["value"]["label"] == "Updated through PostgreSQL"
