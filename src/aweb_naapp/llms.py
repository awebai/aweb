"""Standard, manifest-driven blocks for a naapp's llms.txt: the operations list
and the team-certificate authentication section. An app composes its llms.txt from
its own prose plus these blocks, so the operation set and auth recipe never drift
from the manifest and the /reference page.
"""

from __future__ import annotations

from typing import Any

from aweb_naapp.manifest import cert_tools, public_tools, tool_params


def operation_block(tool: dict[str, Any], verb: str) -> str:
    req, opt = tool_params(tool)
    lines = [
        f"aw {verb} {tool['name']}  ({tool['method']} {tool['path']})",
        f"    {tool['description']}",
    ]
    if req:
        lines.append(f"    required: {', '.join(req)}")
    if opt:
        lines.append(f"    optional: {', '.join(opt)}")
    return "\n".join(lines)


def public_operations(manifest: dict[str, Any], verb: str) -> str:
    return "\n\n".join(operation_block(t, verb) for t in public_tools(manifest))


def cert_operations(manifest: dict[str, Any], verb: str) -> str:
    return "\n\n".join(operation_block(t, verb) for t in cert_tools(manifest))


def auth_section(manifest: dict[str, Any], origin: str, *, reads_phrase: str = "reads") -> str:
    """The plain-text authentication section: public reads need nothing, everything
    else is signed; names the four headers and the v2 envelope, and points at the
    /reference page and the conformance vector. ``reads_phrase`` names the public
    reads in the app's own terms (e.g. "catalog reads")."""
    public_names = ", ".join(t["name"] for t in public_tools(manifest))
    return f"""Public {reads_phrase} ({public_names}) need no auth. Every other
operation is team-scoped and authenticated with your AWID team certificate. When you
call through the aw plugin verbs (or the low-level aw id request --team-auth), aw
signs each request for you with your team member key — you never assemble auth
headers by hand.

For raw HTTP without aw, every team-certificate request carries four headers:
- Authorization: DIDKey <did:key> <signature> — base64 Ed25519 signature (standard alphabet, no padding) over the canonical payload bytes
- X-AWEB-Timestamp: <RFC3339 UTC> — equals the envelope timestamp; 300s replay window
- X-AWEB-Signed-Payload: base64url WITHOUT padding of the canonical JSON envelope — sorted keys, no whitespace; v=2; reserved fields aud, body_sha256, method, path, team_id, timestamp, v
- X-AWID-Team-Certificate: standard base64 of the team certificate JSON

This wire format tracks the aweb team-auth-envelope-v2 conformance vector. The full
signing recipe with per-operation curl is at {origin}/reference."""
