from __future__ import annotations

from aweb_naapp.manifest import canonical_bytes, load_manifest


def _tool(name: str, path: str) -> dict:
    return {"name": name, "method": "POST", "path": path, "scopes": ["example:write"]}


def test_tools_are_keyed_by_the_name_a_consumer_resolves_in_manifest_order() -> None:
    # Go's TrimSpace keeps U+001F, so it stays part of the resolved name.
    first, second = _tool(" create ", "/v1/things"), _tool("archive\x1f", "/v1/archive")
    manifest = load_manifest(canonical_bytes(
        {"manifest_version": 1, "app": {"id": "example", "origin": "https://app.example"},
         "tools": [first, second]}
    ))
    assert manifest.tools_by_name() == {"create": first, "archive\x1f": second}
