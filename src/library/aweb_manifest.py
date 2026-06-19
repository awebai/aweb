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
            "name": "publish-pack",
            "description": "Publish or update a public profile pack. The body is the canonical import payload directly.",
            "method": "POST",
            "path": "/v1/profile-packs/import",
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
            "name": "import-to-shelf",
            "description": "Copy a public-pack profile onto the team's private shelf. Idempotent per source profile: re-import returns the existing copy unchanged.",
            "method": "POST",
            "path": "/v1/shelf/import",
            "input_schema": {
                "type": "object",
                "properties": {
                    "source_profile_pack_ref": {"type": "string"},
                    "source_profile_pack_version": {"type": "string"},
                    "profile_ref": {"type": "string"},
                    "tags": {"type": "array"},
                },
                "required": ["source_profile_pack_ref", "profile_ref"],
            },
            "params": [
                {"name": "source_profile_pack_ref", "in": "body"},
                {"name": "source_profile_pack_version", "in": "body"},
                {"name": "profile_ref", "in": "body"},
                {"name": "tags", "in": "body"},
            ],
            "body": {"mode": "json"},
            "scopes": ["library:write"],
            "mutation": True,
        },
        {
            "name": "publish-profile",
            "description": "Publish a private shelf profile into a public pack (new pack or a new version of an owned pack); pack.yaml is library-generated and the profile set accumulates.",
            "method": "POST",
            "path": "/v1/profiles/{profile_ref}/publish",
            "input_schema": {
                "type": "object",
                "properties": {
                    "profile_ref": {"type": "string"},
                    "profile_version": {"type": "string"},
                    "pack_version": {"type": "string"},
                    "target_pack_ref": {"type": "string"},
                    "new_pack": {"type": "object"},
                },
                "required": ["profile_ref", "pack_version"],
            },
            "params": [
                {"name": "profile_ref", "in": "path"},
                {"name": "profile_version", "in": "body"},
                {"name": "pack_version", "in": "body"},
                {"name": "target_pack_ref", "in": "body"},
                {"name": "new_pack", "in": "body"},
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
            "name": "set-pack-tags",
            "description": "Replace a profile pack's organizational tags.",
            "method": "PUT",
            "path": "/v1/profile-packs/{pack_ref}/tags",
            "input_schema": {
                "type": "object",
                "properties": {
                    "pack_ref": {"type": "string"},
                    "tags": {"type": "array"},
                },
                "required": ["pack_ref", "tags"],
            },
            "params": [
                {"name": "pack_ref", "in": "path"},
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
            "name": "shelf",
            "description": "List the team's shelf working set: each profile's latest version, source provenance, and whether a newer source-pack version is available.",
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
            # PROVISIONAL: re-pinned cross-lane in the evolution work-item when the
            # proposal carries the new version's content for minting (deliberate bump).
            "description": "Submit a profile learning proposal.",
            "method": "POST",
            "path": "/v1/proposals",
            "input_schema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "profile_ref": {"type": "string"},
                    "profile_version": {"type": "string"},
                    "content": {"type": "object"},
                },
                "required": ["target"],
            },
            "params": [
                {"name": "target", "in": "body"},
                {"name": "profile_ref", "in": "body"},
                {"name": "profile_version", "in": "body"},
                {"name": "content", "in": "body"},
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
