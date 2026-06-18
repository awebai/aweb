"""library's aweb-app.json manifest — the one declaration the aw CLI dispatcher
and the hosted gateway interpret identically (frozen m1.1 schema). The committed
``aweb-app.json`` is the byte-stable artifact served verbatim; this module is its
authoring source. A test asserts the file equals ``canonical_bytes(MANIFEST)`` so
the two never drift.

Only cert-authed team operations are declared as verbs. Library's public catalog
reads (profile packs / profiles) are unauthenticated discovery endpoints, not
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
            "name": "import",
            "description": "Import a local or git profile pack into the team's library.",
            "method": "POST",
            "path": "/v1/profile-packs/import",
            "input_schema": {
                "type": "object",
                "properties": {"pack": {"type": "object"}},
                "required": ["pack"],
            },
            "params": [{"name": "pack", "in": "body"}],
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
                    "source_profile_pack_ref": {"type": "string"},
                },
                "required": ["agent_id", "profile_ref", "profile_version", "profile_digest"],
            },
            "params": [
                {"name": "agent_id", "in": "path"},
                {"name": "profile_ref", "in": "body"},
                {"name": "profile_version", "in": "body"},
                {"name": "profile_digest", "in": "body"},
                {"name": "source_profile_pack_ref", "in": "body"},
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
            "description": "Submit a profile learning proposal.",
            "method": "POST",
            "path": "/v1/proposals",
            "input_schema": {
                "type": "object",
                "properties": {"proposal": {"type": "object"}},
                "required": ["proposal"],
            },
            "params": [{"name": "proposal", "in": "body"}],
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
