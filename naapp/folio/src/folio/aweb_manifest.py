"""Folio's manifest template, shared by the CLI and hosted gateway.

The canonical committed aweb-app.json declares kids and local event types.
NaappRuntime fills deployment app.id, origin and public keys from settings,
validates the filled document and serves its exact bytes at both discovery URLs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from folio.record_tools import RECORD_TOOLS

MANIFEST_PATH = Path(__file__).resolve().parent / "aweb-app.json"

MANIFEST: dict[str, Any] = {
    "manifest_version": 2,
    "app": {
        "id": "folio",
        "version": "0.1.0",
        "origin": "https://folio.aweb.ai",
        "llms_txt": "/llms.txt",
        "skills": "/skills/",
    },
    "tools": [
        {
            "name": "create",
            "description": "Create a document from raw markdown or a declarative template.",
            "method": "POST",
            "path": "/v1/documents",
            "input_schema": {
                "type": "object",
                "properties": {
                    "slug": {"type": "string"},
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                    "template": {"type": "object"},
                },
                "required": ["slug", "title"],
            },
            "params": [
                {"name": "slug", "in": "body"},
                {"name": "title", "in": "body"},
                {"name": "body", "in": "body"},
                {"name": "template", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["folio:write"],
            "mutation": True,
        },
        {
            "name": "list",
            "description": "List the team's documents.",
            "method": "GET",
            "path": "/v1/documents",
            "input_schema": {"type": "object", "properties": {}},
            "params": [],
            "scopes": ["folio:read"],
            "mutation": False,
        },
        {
            "name": "show",
            "description": "Show a document with its current version body.",
            "method": "GET",
            "path": "/v1/documents/{slug}",
            "input_schema": {
                "type": "object",
                "properties": {"slug": {"type": "string"}},
                "required": ["slug"],
            },
            "params": [{"name": "slug", "in": "path"}],
            "scopes": ["folio:read"],
            "mutation": False,
        },
        {
            "name": "versions",
            "description": "List a document's version history.",
            "method": "GET",
            "path": "/v1/documents/{slug}/versions",
            "input_schema": {
                "type": "object",
                "properties": {"slug": {"type": "string"}},
                "required": ["slug"],
            },
            "params": [{"name": "slug", "in": "path"}],
            "scopes": ["folio:read"],
            "mutation": False,
        },
        {
            "name": "append",
            "description": "Append a new version from raw UTF-8 markdown.",
            "method": "POST",
            "path": "/v1/documents/{slug}/versions",
            "input_schema": {
                "type": "object",
                "properties": {
                    "slug": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["slug", "body"],
            },
            "params": [
                {"name": "slug", "in": "path"},
                {"name": "body", "in": "body"},
            ],
            "body": {
                "mode": "raw",
                "raw_param": "body",
                "content_type": "text/markdown; charset=utf-8",
            },
            "scopes": ["folio:write"],
            "mutation": True,
        },
        {
            "name": "append-template",
            "description": "Append a new version rendered from a declarative template.",
            "method": "POST",
            "path": "/v1/documents/{slug}/versions/template",
            "input_schema": {
                "type": "object",
                "properties": {
                    "slug": {"type": "string"},
                    "name": {"type": "string"},
                    "slots": {"type": "object"},
                },
                "required": ["slug", "name"],
            },
            "params": [
                {"name": "slug", "in": "path"},
                {"name": "name", "in": "body"},
                {"name": "slots", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["folio:write"],
            "mutation": True,
        },
        {
            "name": "present",
            "description": "Mint a present link for a document version.",
            "method": "POST",
            "path": "/v1/present",
            "input_schema": {
                "type": "object",
                "properties": {
                    "slug": {"type": "string"},
                    "version": {"type": "integer"},
                    "ttl_seconds": {"type": "integer"},
                    "editable": {"type": "boolean"},
                },
                "required": ["slug"],
            },
            "params": [
                {"name": "slug", "in": "body"},
                {"name": "version", "in": "body"},
                {"name": "ttl_seconds", "in": "body"},
                {"name": "editable", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["folio:write"],
            "mutation": True,
        },
        {
            "name": "revoke",
            "description": "Revoke a present link.",
            "method": "POST",
            "path": "/v1/present/{token}/revoke",
            "input_schema": {
                "type": "object",
                "properties": {"token": {"type": "string"}},
                "required": ["token"],
            },
            "params": [{"name": "token", "in": "path"}],
            "scopes": ["folio:write"],
            "mutation": True,
        },
        {
            "name": "theme-get",
            "description": "Get the team's presentation theme.",
            "method": "GET",
            "path": "/v1/theme",
            "input_schema": {"type": "object", "properties": {}},
            "params": [],
            "scopes": ["folio:read"],
            "mutation": False,
        },
        {
            "name": "theme-set",
            "description": "Set the team's presentation theme.",
            "method": "PUT",
            "path": "/v1/theme",
            "input_schema": {
                "type": "object",
                "properties": {
                    "tokens": {"type": "object"},
                    "preset": {"type": "string"},
                    "logo": {"type": "object"},
                    "clear_logo": {"type": "boolean"},
                    "header": {"type": "string"},
                    "footer": {"type": "string"},
                },
            },
            "params": [
                {"name": "tokens", "in": "body"},
                {"name": "preset", "in": "body"},
                {"name": "logo", "in": "body"},
                {"name": "clear_logo", "in": "body"},
                {"name": "header", "in": "body"},
                {"name": "footer", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["folio:write"],
            "mutation": True,
        },
        {
            "name": "asset-image",
            "description": "Upload a base64-encoded image asset.",
            "method": "POST",
            "path": "/v1/assets",
            "input_schema": {
                "type": "object",
                "properties": {
                    "content_type": {"type": "string"},
                    "data_base64": {"type": "string"},
                },
                "required": ["content_type", "data_base64"],
            },
            "params": [
                {"name": "content_type", "in": "body"},
                {"name": "data_base64", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["folio:write"],
            "mutation": True,
        },
        {
            "name": "asset-video",
            "description": "Request a direct-upload URL for a video asset.",
            "method": "POST",
            "path": "/v1/assets/video/direct-upload",
            "input_schema": {
                "type": "object",
                "properties": {
                    "content_type": {"type": "string"},
                    "filename": {"type": "string"},
                    "max_duration_seconds": {"type": "integer"},
                },
                "required": ["content_type"],
            },
            "params": [
                {"name": "content_type", "in": "body"},
                {"name": "filename", "in": "body"},
                {"name": "max_duration_seconds", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["folio:write"],
            "mutation": True,
        },
        {
            "name": "asset-get",
            "description": "Get an asset's metadata.",
            "method": "GET",
            "path": "/v1/assets/{asset_id}",
            "input_schema": {
                "type": "object",
                "properties": {"asset_id": {"type": "string"}},
                "required": ["asset_id"],
            },
            "params": [{"name": "asset_id", "in": "path"}],
            "scopes": ["folio:read"],
            "mutation": False,
        },
        {
            "name": "billing",
            "description": "Get the team's usage: documents and the most versions on any document.",
            "method": "GET",
            "path": "/v1/billing",
            "input_schema": {"type": "object", "properties": {}},
            "params": [],
            "scopes": ["folio:read"],
            "mutation": False,
        },
    ],
    "events": [
        {
            "type": "doc.changed",
            "default_delivery_intent": "wake",
            "description": (
                "A document gained a new version. resource_ref is the document slug; "
                "core exact-matches it against a subscription. Payload is metadata only "
                "(version, edit source) — never the document body."
            ),
        }
    ],
    "app_keys": [
        {"kid": "folio:emit-1", "purposes": ["app-event"]},
        {"kid": "folio:grant-read-1", "purposes": ["app-grant-read"]},
    ],
}

MANIFEST["tools"].extend(RECORD_TOOLS)

