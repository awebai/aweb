"""Loopback fixture gallery for the packaged renderer; no application credentials.

Run: uv run --extra pages python -m aweb_naapp.pages.gallery --port 8734
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
from aweb_naapp.pages.gallery_decisions import (
    additions as decision_additions,
)
from aweb_naapp.pages.gallery_decisions import (
    evidence as decision_evidence,
)
from aweb_naapp.pages.gallery_host import (
    additions,
    asset_server,
    host_get,
    json_response,
    post,
    session,
)
from aweb_naapp.pages.render import page_shell


def gallery_page() -> dict:
    bind = {"collection": "properties"}
    return {
        "page_format": "aweb.page/1",
        "page_id": "property-overview",
        "locale": "en",
        "title": "A quieter view of your properties",
        "rev": 1,
        "layout_version": 1,
        "owner": "agent-fixture",
        "policy_ref": "fixture-read",
        "layout": [
            {
                "id": "heading",
                "type": "heading",
                "props": {"level": 1, "text": "Property overview"},
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
                "id": "bound-metrics",
                "type": "grid",
                "props": {"columns": 2},
                "children": [
                    {
                        "id": "bound-one",
                        "type": "stat",
                        "props": {
                            "label": "Maple House occupancy",
                            "field": "occupancy",
                            "unit": "%",
                        },
                        "bind": {
                            **bind,
                            "all": [{"field": "name", "op": "eq", "value": "Maple House"}],
                        },
                    },
                    {
                        "id": "bound-two",
                        "type": "stat",
                        "props": {
                            "label": "Riverside occupancy",
                            "field": "occupancy",
                            "unit": "%",
                        },
                        "bind": {
                            **bind,
                            "all": [{"field": "name", "op": "eq", "value": "Riverside"}],
                        },
                    },
                ],
            },
            {
                "id": "property-table",
                "type": "table",
                "props": {
                    "columns": [
                        {"field": "name", "label": "Property", "format": "text"},
                        {"field": "occupancy", "label": "Occupancy", "format": "number"},
                        {"field": "updated", "label": "Updated", "format": "date"},
                    ]
                },
                "bind": {**bind, "sort": [{"field": "name", "direction": "asc"}], "limit": 2},
            },
            *[
                {
                    "id": f"property-{kind}",
                    "type": kind,
                    "props": {"fields": {"Property": "name", "Occupancy": "occupancy"}},
                    "bind": bind,
                }
                for kind in ("cards", "list")
            ],
            {
                "id": "activity",
                "type": "activity_timeline",
                "props": {"fields": {"Property": "name", "Reported": "updated"}},
                "bind": bind,
            },
            *[
                {
                    "id": f"chart-{kind}",
                    "type": "chart",
                    "props": {
                        "kind": kind,
                        "x": "name",
                        "series": ["occupancy"],
                        "alternative": "Occupancy by property, percent",
                    },
                    "bind": bind,
                }
                for kind in ("bar", "line", "pie")
            ],
            {
                "id": "future",
                "type": "future_widget",
                "fallback": "A future widget",
                "props": {"ignored": "<script>alert(1)</script>"},
            },
        ],
        "collections": [
            {
                "id": "properties",
                "mode": "owned",
                "schema_version": 1,
                "schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "title": "Property"},
                        "occupancy": {"type": "integer", "title": "Occupancy"},
                        "updated": {"type": "string", "format": "date-time"},
                    },
                    "additionalProperties": False,
                },
                "records": [
                    {
                        "id": f"property-{index}",
                        "rev": 1,
                        "value": {
                            "name": name,
                            "occupancy": occupancy,
                            "updated": "2026-10-20T10:00:00Z",
                        },
                    }
                    for index, (name, occupancy) in enumerate(
                        [("Maple House", 62), ("Oak Terrace", 82), ("Riverside", 95)]
                    )
                ],
            }
        ],
        "actions": [],
        "widget_state": {
            "occupancy": {
                "message": "Updating this month’s projection",
                "progress": 40,
                "busy": True,
            }
        },
    }


def fixture(query: dict) -> dict:
    page = gallery_page()
    if "vector" in query:
        vectors = json.loads(
            (Path(__file__).resolve().parents[4] / "docs/vectors/page-format-v1.json").read_text()
        )
        case = next(
            c for c in vectors["cases"] if c["name"] == query["vector"][0] and c.get("render")
        )
        page = copy.deepcopy(vectors["bases"][case["input"]["base"]])
        for patch in case["input"]["patch"]:
            parts = [v.replace("~1", "/").replace("~0", "~") for v in patch["path"].split("/")[1:]]
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
    if query.get("case") == ["wide-stats"]:
        metrics = page["layout"][2]
        metrics["props"]["columns"] = 4
        metrics["children"][0]["props"].update(value=1234567, unit="EUR")
        metrics["children"].append(
            {
                "id": "decimal-display",
                "type": "stat",
                "props": {"label": "Agent-formatted decimal", "value": "1234567.50", "unit": "EUR"},
            }
        )
    if query.get("case") == ["dialog-hostile"]:
        page["layout"].append(
            {
                "id": "hostile",
                "type": "text",
                "props": {
                    "markdown": '<dialog id="link-confirmation" open>Fake</dialog><style>#link-confirmation{display:none}</style><script>document.querySelector("#link-confirmation").remove()</script>\n\n[Continue](https://example.com/verified)'
                },
            }
        )
    if query.get("state") == ["updated"]:
        page["rev"] = 2
        page["widget_state"]["occupancy"] = {"message": "Projection updated", "busy": False}
    if "vector" not in query:
        additions(page)
        decision_additions(page, query.get("case", [""])[0])
    if query.get("case") == ["dense-table"]:
        collection = page["collections"][0]
        collection["schema"]["properties"].update(
            checkin={"type": "string", "format": "date"},
            amount={"type": "integer"},
            currency={"type": "string"},
            status={"type": "string"},
        )
        for record in collection["records"]:
            record["value"].update(
                checkin="2026-10-20", amount=1234567, currency="EUR", status="Confirmed"
            )
        table = next(w for w in page["layout"] if w["id"] == "property-table")
        table["props"]["columns"].extend(
            [
                {"field": "checkin", "label": "Check-in", "format": "date"},
                {"field": "amount", "label": "Total", "format": "money_minor"},
                {"field": "status", "label": "Status", "format": "status"},
            ]
        )
    if query.get("case") == ["empty"]:
        for collection in page["collections"]:
            # Decision/bundle snapshots require their exact proposal records;
            # independent collection widgets still exercise the empty state.
            if collection["id"] not in {"review-proposals", "review-bundles"}:
                collection["records"] = []
    if query.get("case") == ["authored-language"]:
        # A synthetic authored-content fixture, never translated product chrome.
        page["locale"] = "ca"
        page["title"] = "Resum de les propietats"
        page["layout"][0]["props"]["text"] = "Visió general"
        page["layout"][1]["props"]["markdown"] = (
            "Revisa les propietats i les propostes de l’agent. "
            "[Més informació](https://example.com/about)."
        )
        form = next(w for w in page["layout"] if w["id"] == "note-form")
        form["props"]["fields"][0].update(
            label="Observacions sobre l’estat de la propietat i les reparacions pendents",
            description="Escriu una observació per a la pròxima visita.",
        )
    validation = validate_page(page)
    if not validation.valid:
        raise ValueError(validation.errors)
    return page


def widget_projection(page: dict, bind: dict) -> dict:
    records = copy.deepcopy(
        next(c for c in page["collections"] if c["id"] == bind["collection"])["records"]
    )
    for predicate in bind.get("all", []):

        def matches(record: dict, predicate: dict = predicate) -> bool:
            a, b = record["value"].get(predicate["field"]), predicate["value"]
            return {
                "eq": lambda: a == b,
                "ne": lambda: a != b,
                "lt": lambda: a < b,
                "lte": lambda: a <= b,
                "gt": lambda: a > b,
                "gte": lambda: a >= b,
                "in": lambda: a in b,
            }[predicate["op"]]()

        records = [r for r in records if matches(r)]
    for order in reversed(bind.get("sort", [])):
        records.sort(
            key=lambda r: r["value"].get(order["field"]), reverse=order["direction"] == "desc"
        )
    count = len(records)
    offset, limit = int(bind.get("cursor") or 0), bind.get("limit", 20)
    return {
        "page_rev": page["rev"],
        "records": records[offset : offset + limit],
        "count": count,
        "next_cursor": str(offset + limit) if offset + limit < count else None,
    }


class Handler(BaseHTTPRequestHandler):
    asset_origin = "https://127.0.0.1:8735"

    def do_POST(self) -> None:
        url = urlsplit(self.path)
        post(self, url.path, fixture(parse_qs(url.query)))

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        headers: dict[str, str] = {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
        status = 200
        if url.path == "/api/host":
            host_get(self, self.asset_origin, query.get("case", [""])[0])
            return
        if url.path == "/":
            shell = page_shell(script_path="/assets/gallery.js", asset_origin=self.asset_origin)
            body, content_type = shell.html.encode(), "text/html; charset=utf-8"
            headers.update(shell.headers)
        elif url.path == "/api/decision":
            page = fixture(query)
            _, state = session(self)
            json_response(
                self,
                decision_evidence(page, query["task_id"][0], state, query.get("case", [""])[0]),
            )
            return
        elif url.path in ("/api/page", "/api/widget"):
            page = fixture(query)
            _, state = session(self)
            page["rev"] = max(page["rev"], state["rev"])
            if state["state_updated"] and "vector" not in query:
                page["widget_state"]["occupancy"] = {"message": "Projection updated", "busy": False}
            if (
                url.path == "/api/widget"
                and int(query.get("expected_page_rev", [str(page["rev"])])[0]) != page["rev"]
            ):
                json_response(self, {"code": "revision_conflict"}, 409)
                return
            if url.path == "/api/widget":
                page = widget_projection(page, json.loads(query["bind"][0]))
            elif "vector" not in query:
                # Independent projections: the bootstrap has definitions only.
                for collection in page["collections"]:
                    if collection["id"] not in {"review-proposals", "review-bundles"}:
                        collection["records"] = []
            if url.path == "/api/page" and query.get("case") == ["unsupported"]:
                page["page_format"] = "aweb.page/2"
            body, content_type = json.dumps(page, ensure_ascii=False).encode(), "application/json"
        elif url.path == "/assets/gallery.js":
            body, content_type = (
                files("aweb_naapp.pages").joinpath("assets/gallery-entry.js").read_bytes(),
                "text/javascript",
            )
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
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # Browser navigation may cancel independent widget reads.

    def log_message(self, format: str, *args: object) -> None:
        pass  # Link hosts must not log capability-bearing request targets.


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8734)
    parser.add_argument("--asset-port", type=int)
    args = parser.parse_args()
    asset, temporary = asset_server(args.asset_port or args.port + 1)
    Handler.asset_origin = f"https://127.0.0.1:{asset.server_port}"
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Gallery: http://127.0.0.1:{server.server_port}/", flush=True)
    try:
        server.serve_forever()
    finally:
        asset.shutdown()
        temporary.cleanup()


if __name__ == "__main__":
    main()
