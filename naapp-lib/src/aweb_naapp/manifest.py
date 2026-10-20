"""Conventions and helpers for the canonical aweb-app.json manifest.

A naapp declares its cert-authed operations as manifest tools (name, method,
path, params, input_schema). Public discovery reads carry ``auth: none``. These
helpers read that shape; the docs generators render from them so the surface and
the manifest never drift.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no insignificant whitespace, UTF-8.

    Matches the awid signing CanonicalJSON convention so a committed manifest and
    any consumer's serialization are byte-identical.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def write_manifest_file(path: Path, manifest: dict[str, Any]) -> None:
    """Write an app's committed manifest file: the canonical bytes of its authoring
    manifest, whose ``app.origin`` is the hosted origin."""
    path.write_bytes(canonical_bytes(manifest))


def manifest_for_origin(manifest: dict[str, Any], public_origin: str) -> dict[str, Any]:
    """A copy of the manifest with ``app.origin`` set to this deployment's origin."""
    retargeted = copy.deepcopy(manifest)
    retargeted["app"]["origin"] = public_origin.rstrip("/")
    return retargeted


def read_manifest_bytes(path: Path, public_origin: str | None = None) -> bytes:
    """The manifest bytes to serve for a deployment origin.

    The committed file's own origin (the hosted one) gets the committed bytes
    verbatim, never re-serialized. Any other origin, such as a self-hosted
    deployment, gets the same manifest in canonical form with only ``app.origin``
    changed.
    """
    committed = path.read_bytes()
    if public_origin is None:
        return committed
    manifest = json.loads(committed)
    if public_origin.rstrip("/") == manifest["app"]["origin"]:
        return committed
    return canonical_bytes(manifest_for_origin(manifest, public_origin))


def public_tools(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [t for t in manifest["tools"] if t.get("auth") == "none"]


def cert_tools(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [t for t in manifest["tools"] if t.get("auth") != "none"]


def params_by_loc(tool: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p.get("in", "body") for p in tool.get("params", []) if "name" in p}


def tool_params(tool: dict[str, Any]) -> tuple[list[str], list[str]]:
    """A tool's (required, optional) parameter names, in manifest order.

    Path params are required by construction — the route cannot match without
    them — even when the manifest input_schema does not list them in ``required``.
    Treating them as required here (a rendering concern) keeps the served manifest
    digest unchanged.
    """
    schema = tool.get("input_schema") or {}
    path_params = {p["name"] for p in tool.get("params", []) if p.get("in") == "path"}
    required = set(schema.get("required") or []) | path_params
    order: list[str] = [p["name"] for p in tool.get("params", []) if "name" in p]
    for name in schema.get("properties") or {}:
        if name not in order:
            order.append(name)
    req = [n for n in order if n in required]
    opt = [n for n in order if n not in required]
    return req, opt


def example_path(tool: dict[str, Any], values: dict[str, str]) -> str:
    """The path with placeholders replaced by app-supplied example values. Whatever
    is not supplied stays a ``{brace}`` placeholder, so the caller can tell whether
    the result is a genuinely runnable URL (see :func:`is_fully_substituted`)."""
    path = tool["path"]
    for name, value in values.items():
        path = path.replace("{" + name + "}", value)
    return path


def is_fully_substituted(tool: dict[str, Any], values: dict[str, str]) -> bool:
    """True when every path placeholder has an app-supplied example value, so the
    rendered URL is genuinely runnable (no leftover brace)."""
    return "{" not in example_path(tool, values)
