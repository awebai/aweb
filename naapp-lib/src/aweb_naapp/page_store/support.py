"""Internal canonicalization, validation and authenticated identity helpers."""

from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING, Any

from aweb_naapp.page_store.models import Scope, StoreError
from aweb_naapp.pages import validate_page

if TYPE_CHECKING:
    from aweb_naapp.runtime.team_auth import Principal


def canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def decoded(value):
    return json.loads(value) if isinstance(value, str) else copy.deepcopy(value)


def identity(principal: Principal, scope: Scope) -> str:
    if principal.team_id != scope.team_id:
        raise StoreError("resource_not_found", 404)
    return (
        principal.did_aw
        if principal.did_aw_registry_verified and principal.did_aw
        else principal.did_key
    )


def validated(document: dict) -> None:
    result = validate_page(document)
    if not result.valid:
        raise StoreError(
            "schema_invalid",
            details=[
                {"layer": e.layer, "code": e.code, "pointer": e.pointer} for e in result.errors
            ],
        )


def widgets(layout):
    for widget in layout:
        yield widget
        yield from widgets(widget.get("children", []))
