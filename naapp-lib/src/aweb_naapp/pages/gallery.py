"""Local fixture gallery, exercising the packaged shared renderer.

Run: uv run --extra pages python -m aweb_naapp.pages.gallery --port 8734
Only binds loopback. It has no application credentials or production actions.
"""

from __future__ import annotations

import argparse
import copy
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from aweb_naapp.pages import validate_page
from aweb_naapp.pages.render import page_shell


def gallery_page(locale: str = "en") -> dict:
    return {
        "page_format": "aweb.page/1",
        "page_id": "property-overview",
        "locale": locale,
        "title": "A quieter view of your properties",
        "rev": 1,
        "layout_version": 1,
        "owner": "agent-fixture",
        "policy_ref": "fixture-read",
        "layout": [
            {
                "id": "heading",
                "type": "heading",
                "props": {"level": 2, "text": "Property overview"},
            },
            {
                "id": "intro",
                "type": "text",
                "props": {
                    "markdown": "Keep a **clear** view of what needs attention. Your team’s records, decisions and activity, in one place.\n\n[About this workspace](https://example.com/about)"
                },
            },
            {
                "id": "metrics",
                "type": "grid",
                "props": {"columns": 3, "gap": "medium"},
                "children": [
                    {
                        "id": "occupancy",
                        "type": "stat",
                        "props": {"label": "Occupancy", "value": 82, "unit": "%"},
                    },
                    {
                        "id": "properties",
                        "type": "stat",
                        "props": {"label": "Properties", "value": 12},
                    },
                    {
                        "id": "health",
                        "type": "status_badge",
                        "props": {"label": "Review complete", "tone": "success"},
                    },
                ],
            },
            {
                "id": "future",
                "type": "future_widget",
                "fallback": "A future widget",
                "props": {"ignored": "<script>alert(1)</script>"},
            },
        ],
        "collections": [],
        "actions": [],
        "widget_state": {
            "occupancy": {
                "message": "Updating this month’s projection",
                "progress": 40,
                "busy": True,
            }
        },
    }


ENTRY = b"""import { createPageRenderer } from '/assets/page-renderer.js';
const renderer = createPageRenderer({root: document.querySelector('#page'), destinations: document.querySelector('#destinations'), announcements: document.querySelector('#announcements')});
const page = await fetch('/api/page' + location.search).then(r => r.json());
document.querySelector('#identity').textContent = 'Fixture gallery';
renderer.update(page);
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        locale = "ca" if query.get("locale") == ["ca"] else "en"
        headers: dict[str, str] = {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
        status = 200
        if url.path == "/":
            shell = page_shell(
                script_path="/assets/gallery.js",
                asset_origin="https://assets.example",
                locale=locale,
            )
            body, content_type = shell.html.encode(), "text/html; charset=utf-8"
            headers.update(shell.headers)
        elif url.path == "/api/page":
            page = gallery_page(locale)
            if "vector" in query:
                vectors = json.loads(
                    (
                        Path(__file__).resolve().parents[4] / "docs/vectors/page-format-v1.json"
                    ).read_text()
                )
                case = next(
                    c
                    for c in vectors["cases"]
                    if c["name"] == query["vector"][0] and c.get("render")
                )
                page = copy.deepcopy(vectors["bases"][case["input"]["base"]])
                for patch in case["input"]["patch"]:
                    parts = [
                        v.replace("~1", "/").replace("~0", "~")
                        for v in patch["path"].split("/")[1:]
                    ]
                    parent = page
                    for part in parts[:-1]:
                        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
                    key = parts[-1]
                    if isinstance(parent, list):
                        if key == "-":
                            parent.append(patch["value"])
                        else:
                            parent[int(key)] = patch["value"]
                    else:
                        parent[key] = patch["value"]
            validation = validate_page(page)
            if not validation.valid:
                raise ValueError(validation.errors)
            if query.get("case") == ["unsupported"]:
                page["page_format"] = "aweb.page/2"
            body, content_type = json.dumps(page, ensure_ascii=False).encode(), "application/json"
        elif url.path == "/assets/gallery.js":
            body, content_type = ENTRY, "text/javascript"
        elif url.path in ("/assets/page-renderer.js", "/assets/page-renderer.css"):
            body = (
                files("aweb_naapp.pages")
                .joinpath("assets", url.path.rsplit("/", 1)[1])
                .read_bytes()
            )
            content_type = "text/javascript" if url.path.endswith(".js") else "text/css"
        else:
            status, body, content_type = 404, b"Not found", "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass  # Do not log request targets; link hosts must redact capabilities too.


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8734)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Gallery: http://127.0.0.1:{server.server_port}/ (Catalan: /?locale=ca)", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
