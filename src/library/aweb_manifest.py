"""library's aweb-app.json manifest — the one declaration the aw CLI dispatcher
and the hosted gateway interpret identically (frozen m1.1 schema). The committed
``aweb-app.json`` is the byte-stable artifact served verbatim; this module is its
authoring source. A test asserts the file equals ``canonical_bytes(MANIFEST)`` so
the two never drift.

Only cert-authed team operations are declared as verbs. Library's public catalog
reads (blueprints / profiles) are unauthenticated discovery endpoints, not
dispatcher verbs. Library emits no events at v0, so there is no events catalog or
event_emitters entry yet.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MANIFEST_PATH = Path(__file__).resolve().parent / "aweb-app.json"

MANIFEST: dict[str, Any] = {
    "manifest_version": 1,
    "app": {
        "id": "library",
        "version": "0.1.0",
        "origin": "https://library.aweb.ai",
        "llms_txt": "/llms.txt",
        "skills": "/skills/",
    },
    "tools": [
        {
            "name": "list-blueprints",
            "description": "Browse the public blueprint catalog, optionally filtered by tag overlap.",
            "method": "GET",
            "path": "/v1/blueprints",
            "input_schema": {"type": "object", "properties": {"tags": {"type": "array"}}},
            "params": [{"name": "tags", "in": "query"}],
            "scopes": ["library:read"],
            "auth": "none",
            "mutation": False,
        },
        {
            "name": "get-blueprint",
            "description": "Get a public blueprint and its profile summaries.",
            "method": "GET",
            "path": "/v1/blueprints/{blueprint_ref}",
            "input_schema": {"type": "object", "properties": {"blueprint_ref": {"type": "string"}}},
            "params": [{"name": "blueprint_ref", "in": "path"}],
            "scopes": ["library:read"],
            "auth": "none",
            "mutation": False,
        },
        {
            "name": "get-profile",
            "description": "Get a public profile's full content from the latest version of a blueprint.",
            "method": "GET",
            "path": "/v1/blueprints/{blueprint_ref}/profiles/{profile_ref}",
            "input_schema": {
                "type": "object",
                "properties": {"blueprint_ref": {"type": "string"}, "profile_ref": {"type": "string"}},
            },
            "params": [
                {"name": "blueprint_ref", "in": "path"},
                {"name": "profile_ref", "in": "path"},
            ],
            "scopes": ["library:read"],
            "auth": "none",
            "mutation": False,
        },
        {
            "name": "publish-blueprint",
            "description": "Publish or update a public blueprint. The body is the canonical import payload directly.",
            "method": "POST",
            "path": "/v1/blueprints/import",
            "input_schema": {
                "type": "object",
                "properties": {
                    "files": {"type": "array"},
                    "schema": {"type": "string"},
                },
                "required": ["files", "schema"],
            },
            "params": [
                {"name": "files", "in": "body"},
                {"name": "schema", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "register",
            "description": "Register the team with library (idempotent; team identified from the cert).",
            "method": "POST",
            "path": "/v1/team/register",
            "input_schema": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "display_name": {"type": "string"},
                },
            },
            "params": [
                {"name": "owner", "in": "body"},
                {"name": "display_name", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "create-shelf-profile",
            "description": "Create a private shelf profile from a profile payload.",
            "method": "POST",
            "path": "/v1/profiles",
            "input_schema": {
                "type": "object",
                "properties": {"files": {"type": "array"}, "tags": {"type": "array"}},
                "required": ["files"],
            },
            "params": [
                {"name": "files", "in": "body"},
                {"name": "tags", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "shelf-version",
            "description": "Add a new content version of an owned shelf profile.",
            "method": "POST",
            "path": "/v1/profiles/{profile_ref}/versions",
            "input_schema": {
                "type": "object",
                "properties": {"profile_ref": {"type": "string"}, "files": {"type": "array"}},
                "required": ["profile_ref", "files"],
            },
            "params": [
                {"name": "profile_ref", "in": "path"},
                {"name": "files", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "update-from-source",
            "description": "Per-part 3-way merge of a shelf profile against a newer version of its source blueprint: pull upstream improvements into un-evolved parts, keep local edits. A real merge mints target_version; nothing pullable is a no-op.",
            "method": "POST",
            "path": "/v1/profiles/{profile_ref}/update-from-source",
            "input_schema": {
                "type": "object",
                "properties": {
                    "profile_ref": {"type": "string"},
                    "target_version": {"type": "string"},
                    "source_blueprint_version": {"type": "string"},
                },
                "required": ["profile_ref", "target_version"],
            },
            "params": [
                {"name": "profile_ref", "in": "path"},
                {"name": "target_version", "in": "body"},
                {"name": "source_blueprint_version", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "import-to-shelf",
            "description": "Copy a public-blueprint profile onto the team's private shelf. Idempotent per source profile: re-import returns the existing copy unchanged.",
            "method": "POST",
            "path": "/v1/shelf/import",
            "input_schema": {
                "type": "object",
                "properties": {
                    "source_blueprint_ref": {"type": "string"},
                    "source_blueprint_version": {"type": "string"},
                    "profile_ref": {"type": "string"},
                    "tags": {"type": "array"},
                },
                "required": ["source_blueprint_ref", "profile_ref"],
            },
            "params": [
                {"name": "source_blueprint_ref", "in": "body"},
                {"name": "source_blueprint_version", "in": "body"},
                {"name": "profile_ref", "in": "body"},
                {"name": "tags", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "publish-profile",
            "description": "Publish a private shelf profile into a public blueprint (new blueprint or a new version of an owned blueprint); blueprint.yaml is library-generated and the profile set accumulates.",
            "method": "POST",
            "path": "/v1/profiles/{profile_ref}/publish",
            "input_schema": {
                "type": "object",
                "properties": {
                    "profile_ref": {"type": "string"},
                    "profile_version": {"type": "string"},
                    "blueprint_version": {"type": "string"},
                    "target_blueprint_ref": {"type": "string"},
                    "new_blueprint": {"type": "object"},
                },
                "required": ["profile_ref", "blueprint_version"],
            },
            "params": [
                {"name": "profile_ref", "in": "path"},
                {"name": "profile_version", "in": "body"},
                {"name": "blueprint_version", "in": "body"},
                {"name": "target_blueprint_ref", "in": "body"},
                {"name": "new_blueprint", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "set-profile-tags",
            "description": "Replace a profile's organizational tags.",
            "method": "PUT",
            "path": "/v1/profiles/{profile_ref}/tags",
            "input_schema": {
                "type": "object",
                "properties": {
                    "profile_ref": {"type": "string"},
                    "tags": {"type": "array"},
                },
                "required": ["profile_ref", "tags"],
            },
            "params": [
                {"name": "profile_ref", "in": "path"},
                {"name": "tags", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "set-blueprint-tags",
            "description": "Replace a blueprint's organizational tags.",
            "method": "PUT",
            "path": "/v1/blueprints/{blueprint_ref}/tags",
            "input_schema": {
                "type": "object",
                "properties": {
                    "blueprint_ref": {"type": "string"},
                    "tags": {"type": "array"},
                },
                "required": ["blueprint_ref", "tags"],
            },
            "params": [
                {"name": "blueprint_ref", "in": "path"},
                {"name": "tags", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "bind",
            "description": "Bind an agent identity to a profile ref/version/digest.",
            "method": "POST",
            "path": "/v1/agents/{agent_id}/profile-binding",
            "input_schema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string"},
                    "profile_ref": {"type": "string"},
                    "profile_version": {"type": "string"},
                    "profile_digest": {"type": "string"},
                    "source_blueprint_ref": {"type": "string"},
                },
                "required": ["agent_id", "profile_ref", "profile_version", "profile_digest"],
            },
            "params": [
                {"name": "agent_id", "in": "path"},
                {"name": "profile_ref", "in": "body"},
                {"name": "profile_version", "in": "body"},
                {"name": "profile_digest", "in": "body"},
                {"name": "source_blueprint_ref", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "get-binding",
            "description": "Get the profile binding for an agent identity.",
            "method": "GET",
            "path": "/v1/agents/{agent_id}/profile-binding",
            "input_schema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string"}},
                "required": ["agent_id"],
            },
            "params": [{"name": "agent_id", "in": "path"}],
            "scopes": ["library:read"],
            "mutation": False,
        },
        {
            "name": "shelf",
            "description": "List the team's shelf working set: each profile's latest version, source provenance, and whether a newer source-blueprint version is available.",
            "method": "GET",
            "path": "/v1/shelf",
            "input_schema": {"type": "object", "properties": {}},
            "params": [],
            "scopes": ["library:read"],
            "mutation": False,
        },
        {
            "name": "materialize",
            "description": "Materialize a profile payload for a local or custodial runtime.",
            "method": "POST",
            "path": "/v1/materialize",
            "input_schema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string"},
                    "profile_ref": {"type": "string"},
                    "runtime_kind": {"type": "string"},
                    "target": {"type": "string"},
                },
                "required": ["runtime_kind", "target"],
            },
            "params": [
                {"name": "agent_id", "in": "body"},
                {"name": "profile_ref", "in": "body"},
                {"name": "runtime_kind", "in": "body"},
                {"name": "target", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "propose",
            "description": "Submit a profile learning proposal. A profile proposal carries the base it evolves from (base_profile_version/digest) and the new version's content (profile-payload.v1); approve mints it.",
            "method": "POST",
            "path": "/v1/proposals",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "profile_ref": {"type": "string"},
                    "profile_version": {"type": "string"},
                    "base_profile_version": {"type": "string"},
                    "base_profile_digest": {"type": "string"},
                    "content": {"type": "object"},
                    "summary": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["target"],
            },
            "params": [
                {"name": "target", "in": "body"},
                {"name": "profile_ref", "in": "body"},
                {"name": "profile_version", "in": "body"},
                {"name": "base_profile_version", "in": "body"},
                {"name": "base_profile_digest", "in": "body"},
                {"name": "content", "in": "body"},
                {"name": "summary", "in": "body"},
                {"name": "rationale", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "proposals",
            "description": "List the team's profile learning proposals.",
            "method": "GET",
            "path": "/v1/proposals",
            "input_schema": {"type": "object", "properties": {}},
            "params": [],
            "scopes": ["library:read"],
            "mutation": False,
        },
        {
            "name": "approve",
            "description": "Approve a profile learning proposal.",
            "method": "POST",
            "path": "/v1/proposals/{proposal_id}/approve",
            "input_schema": {
                "type": "object",
                "properties": {"proposal_id": {"type": "string"}},
                "required": ["proposal_id"],
            },
            "params": [{"name": "proposal_id", "in": "path"}],
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "reject",
            "description": "Reject a profile learning proposal.",
            "method": "POST",
            "path": "/v1/proposals/{proposal_id}/reject",
            "input_schema": {
                "type": "object",
                "properties": {"proposal_id": {"type": "string"}},
                "required": ["proposal_id"],
            },
            "params": [{"name": "proposal_id", "in": "path"}],
            "scopes": ["library:write"],
            "mutation": True,
        },
    ],
}


def canonical_bytes(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no insignificant whitespace, UTF-8.

    Matches the awid signing CanonicalJSON convention so the committed manifest and
    any consumer's serialization are byte-identical.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def read_manifest_bytes() -> bytes:
    """The raw committed manifest bytes — served verbatim, never re-serialized."""
    return MANIFEST_PATH.read_bytes()


def write_manifest_file() -> None:
    """Regenerate the committed canonical manifest file from MANIFEST."""
    MANIFEST_PATH.write_bytes(canonical_bytes(MANIFEST))
