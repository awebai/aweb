"""Every DID a request can carry has a declared maximum length.

The bound is checked on every request model the service mounts, so a route
added later cannot leave one out unnoticed.
"""

from __future__ import annotations

import types
import typing

import pytest
from annotated_types import MaxLen
from fastapi.routing import APIRoute
from pydantic import BaseModel

from awid_service.main import create_app
from awid_service.routes.teams import TeamRotateKeyRequest

# Parsed by the route itself from the raw body, so no route declares it.
_PARSED_BY_HAND = [TeamRotateKeyRequest]


def _models_in(annotation) -> list[type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    found: list[type[BaseModel]] = []
    for arg in typing.get_args(annotation):
        found.extend(_models_in(arg))
    return found


def _carries_text(annotation) -> bool:
    if annotation is str:
        return True
    if typing.get_origin(annotation) in (typing.Union, types.UnionType):
        return any(_carries_text(arg) for arg in typing.get_args(annotation))
    return False


def _request_models() -> list[type[BaseModel]]:
    roots: list[type[BaseModel]] = list(_PARSED_BY_HAND)
    for route in create_app().routes:
        if isinstance(route, APIRoute):
            for param in route.dependant.body_params:
                roots.extend(_models_in(param.field_info.annotation))
    seen: dict[type[BaseModel], None] = {}
    pending = roots
    while pending:
        model = pending.pop()
        if model in seen:
            continue
        seen[model] = None
        for field in model.model_fields.values():
            pending.extend(_models_in(field.annotation))
    return sorted(seen, key=lambda model: f"{model.__module__}.{model.__qualname__}")


def _did_fields() -> list[tuple[str, object]]:
    return [
        (f"{model.__qualname__}.{name}", field)
        for model in _request_models()
        for name, field in model.model_fields.items()
        if ("did" in name or "stable_id" in name) and _carries_text(field.annotation)
    ]


def test_the_request_models_are_found():
    names = {model.__qualname__ for model in _request_models()}
    assert {"AddressRegisterRequest", "AddressReassignRequest", "DidRegisterRequest", "TeamCreateRequest"} <= names


@pytest.mark.parametrize("name,field", _did_fields(), ids=[name for name, _ in _did_fields()])
def test_a_did_field_declares_a_maximum_length(name, field):
    bounds = [item.max_length for item in field.metadata if isinstance(item, MaxLen)]
    assert bounds and bounds[0] <= 256, f"{name} declares no maximum length"


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["did_aw", "current_did_key"])
async def test_an_address_registration_refuses_an_over_long_did_as_too_long(client, field):
    body = {"name": "alice", "did_aw": "did:aw:" + "1" * 20, "current_did_key": "did:key:z" + "1" * 47}
    body[field] = body[field] + "1" * 300
    response = await client.post("/v1/namespaces/example.com/addresses", json=body)
    assert response.status_code == 422, response.text
    errors = [error for error in response.json()["detail"] if error["loc"][-1] == field]
    assert [error["type"] for error in errors] == ["string_too_long"]


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["did_aw", "current_did_key"])
async def test_an_address_reassignment_refuses_an_over_long_did_as_too_long(client, field):
    body = {"did_aw": "did:aw:" + "1" * 20, "current_did_key": "did:key:z" + "1" * 47}
    body[field] = body[field] + "1" * 300
    response = await client.post("/v1/namespaces/example.com/addresses/alice/reassign", json=body)
    assert response.status_code == 422, response.text
    errors = [error for error in response.json()["detail"] if error["loc"][-1] == field]
    assert [error["type"] for error in errors] == ["string_too_long"]
