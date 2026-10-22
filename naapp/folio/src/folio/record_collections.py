"""Shared-page definitions and Folio's pure record-domain validation."""

import copy
from datetime import date
from urllib.parse import urlsplit

from aweb_naapp.page_store import Scope, StoreError
from aweb_naapp.pages import inline_schema_errors

DISCOVERY_TITLE = "Discoveries and conversations"
TABLE_WIDGET_ID = "records"
DISCOVERY_SCHEMA = {
    "type": "object",
    "properties": {
        "source_url": {"type": "string", "minLength": 1, "maxLength": 2048, "title": "Source"},
        "date": {
            "type": "string", "minLength": 10, "maxLength": 10, "format": "date",
            "title": "Date", "description": "America/Vancouver read or discovery date, not publication date.",
        },
        "finding": {"type": "string", "minLength": 1, "maxLength": 8192, "title": "Finding"},
        "why_relevant": {"type": "string", "minLength": 1, "maxLength": 8192, "title": "Why relevant"},
        "possible_contribution": {"type": "string", "maxLength": 8192, "title": "Possible contribution"},
        "status": {"type": "string", "minLength": 1, "maxLength": 160, "title": "Status"},
        "next_follow_up": {"type": "string", "maxLength": 8192, "title": "Next follow-up"},
        "kind": {"type": "string", "enum": ["awareness", "interaction"], "title": "Kind"},
    },
    "required": ["source_url", "date", "finding", "why_relevant", "status", "kind"],
    "additionalProperties": False,
}


def _field_definitions(schema: dict) -> dict[str, dict]:
    """Folio tables require object field schemas with single-type declarations."""
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise StoreError("schema_invalid", details=[{"pointer": "/schema/properties"}])
    for name, definition in properties.items():
        if not isinstance(definition, dict) or isinstance(definition.get("type"), list):
            escaped = name.replace("~", "~0").replace("/", "~1")
            raise StoreError("schema_invalid", details=[{"pointer": f"/schema/properties/{escaped}"}])
    return properties


def build_collection_page(
    *, page_id: str, collection_id: str, title: str, schema: dict, owner: str,
) -> dict:
    """One owned collection and a stored read-only table, validated by PageStore."""
    if (inline_schema_errors(schema) or schema.get("type") != "object"
            or not isinstance(schema.get("properties"), dict)):
        raise StoreError("schema_invalid", details=[{"pointer": "/schema"}])
    columns = []
    for name, definition in _field_definitions(schema).items():
        kind = "text"
        if name == "source_url":
            kind = "url"
        elif definition.get("format") == "date":
            kind = "date"
        elif definition.get("type") in {"integer", "number"}:
            kind = "number"
        columns.append({"field": name, "label": definition.get("title", name), "format": kind})
    return {
        "page_format": "aweb.page/1", "page_id": page_id, "locale": "en-CA",
        "title": title, "rev": 1, "layout_version": 1,
        "owner": owner, "policy_ref": "folio-team-records",
        "layout": [
            {"id": TABLE_WIDGET_ID, "type": "table", "props": {"columns": columns},
             "bind": {"collection": collection_id, "limit": 50}},
        ],
        "collections": [{"id": collection_id, "schema_version": 1, "schema": copy.deepcopy(schema),
                         "mode": "owned", "records": []}],
        "widget_state": {}, "actions": [],
    }


def _web_source(value: str) -> bool:
    # This validates stored source data, without fetching it. Clickability is
    # decided separately by the shared renderer's stricter safe-link handling.
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127
           for character in value) or "\\" in value:
        return False
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme in {"https", "http"} and bool(parsed.hostname)
            and parsed.username is None and parsed.password is None
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except ValueError:
        return False


def validate_record(scope: Scope, collection: dict, complete_record: dict) -> None:
    """Pure PageStore hook, run on the entire resulting record under its write lock.

    C1 still validates the schema. Folio additionally checks calendar dates and
    source URLs; the hook neither merges patches nor changes record values.
    """
    value = complete_record["value"]
    errors = []
    for name, definition in _field_definitions(collection["schema"]).items():
        if name not in value:
            continue
        invalid = None
        if definition.get("format") == "date" and isinstance(value[name], str):
            try:
                if date.fromisoformat(value[name]).isoformat() != value[name]:
                    invalid = "date_invalid"
            except ValueError:
                invalid = "date_invalid"
        if name == "source_url" and isinstance(value[name], str) and not _web_source(value[name]):
            invalid = "source_url_invalid"
        if invalid:
            escaped = name.replace("~", "~0").replace("/", "~1")
            errors.append({"pointer": f"/value/{escaped}", "code": invalid,
                           "collection": collection["id"], "record_id": complete_record["id"]})
    if errors:
        raise StoreError("schema_invalid", details=errors)
