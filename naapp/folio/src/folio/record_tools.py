"""The shared CLI/MCP mappings for Folio's typed collection operations."""

from pydantic import BaseModel

from folio.record_models import (
    CollectionDefineRequest,
    RecordAddRequest,
    RecordDeleteRequest,
    RecordQueryRequest,
    RecordUpdateRequest,
)


def _tool(name: str, path: str, description: str, model: type[BaseModel], *, write: bool) -> dict:
    schema = model.model_json_schema(by_alias=True)
    return {
        "name": name, "description": description, "method": "POST", "path": path,
        "input_schema": schema,
        "params": [{"name": field, "in": "body"} for field in schema["properties"]],
        "body": {"mode": "json"},
        "scopes": ["folio:write" if write else "folio:read"], "mutation": write,
    }


RECORD_TOOLS = [
    _tool("collection-define", "/v1/collections", "Define a typed collection and its read-only table document.",
          CollectionDefineRequest, write=True),
    _tool("record-add", "/v1/records/add", "Add a validated record; omit record_id for a server-generated ID.",
          RecordAddRequest, write=True),
    _tool("record-update", "/v1/records/update", "Atomically patch supplied fields at expected_rev; omitted fields stay unchanged.",
          RecordUpdateRequest, write=True),
    _tool("record-delete", "/v1/records/delete", "Delete a record only at expected_rev; request_id retries return the original result.",
          RecordDeleteRequest, write=True),
    _tool("record-query", "/v1/records/query", "Query authorized rows; count is all matching rows. Restart after cursor_invalid (409).",
          RecordQueryRequest, write=False),
]
