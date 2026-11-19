"""Released and structured address conflicts cross the real SDK decoder."""

from contextlib import aclosing

import httpx
import pytest

from awid.registry import (
    AddressAlreadyBoundError,
    DIDCurrentKeyMismatchError,
    DIDRegistrationRequiredError,
    RegistryClient,
    RegistryError,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("detail", "code", "error_type"),
    [
        (
            "did_aw must be registered before address assignment",
            "did_registration_required",
            DIDRegistrationRequiredError,
        ),
        (
            "did_aw current key does not match",
            "did_current_key_mismatch",
            DIDCurrentKeyMismatchError,
        ),
        (
            "address already bound to a different did_aw",
            "address_already_bound",
            AddressAlreadyBoundError,
        ),
    ],
)
@pytest.mark.parametrize("format", ["released_detail", "structured_code"])
async def test_address_conflict_uses_typed_refusal(detail, code, error_type, format):
    body = {
        "detail": detail
        if format == "released_detail"
        else {"code": code, "message": "changed prose"}
    }
    async with aclosing(
        RegistryClient(
            "https://registry.example",
            transport=httpx.MockTransport(
                lambda request: httpx.Response(409, json=body)
            ),
        )
    ) as client:
        with pytest.raises(error_type) as caught:
            await client._request_json(
                "POST", "/v1/namespaces/example/addresses", json={}
            )
    assert type(caught.value) is error_type
    assert caught.value.status_code == 409
    assert caught.value.detail == detail


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "content", "body_is_json"),
    [
        (409, b'{"detail":"did_aw current key does not match today"}', True),
        (
            409,
            b'{"detail":{"code":"unknown","message":"did_aw current key does not match"}}',
            True,
        ),
        (503, b'{"detail":"did_aw current key does not match"}', True),
        (409, b"{bad JSON", False),
        (409, b"\xff", False),
    ],
)
async def test_other_registry_failures_remain_failures(status, content, body_is_json):
    async with aclosing(
        RegistryClient(
            "https://registry.example",
            transport=httpx.MockTransport(
                lambda request: httpx.Response(status, content=content)
            ),
        )
    ) as client:
        with pytest.raises(RegistryError) as caught:
            await client._request_json(
                "POST", "/v1/namespaces/example/addresses", json={}
            )
    assert type(caught.value) is RegistryError
    assert caught.value.status_code == status
    assert caught.value.body_is_json is body_is_json
