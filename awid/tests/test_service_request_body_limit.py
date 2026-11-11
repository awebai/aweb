"""The registry service refuses a request body over its limit before parsing it.

The limit defaults to the largest body any route accepts, the rotate route's.
It follows a raised rotate limit, so that route keeps working, and startup
refuses a configured limit below the rotate limit.
"""

from __future__ import annotations

import pytest

from awid_service.attestation_rotation import DEFAULT_ROTATE_MAX_BODY_BYTES
from awid_service.main import DEFAULT_MAX_REQUEST_BODY_BYTES, create_app

ADDRESSES = "/v1/namespaces/example.com/addresses"
MIB = 1024 * 1024


async def _chunks(*parts: bytes):
    for part in parts:
        yield part


@pytest.fixture(autouse=True)
def _no_configured_limits(monkeypatch):
    monkeypatch.delenv("AWID_MAX_REQUEST_BODY_BYTES", raising=False)
    monkeypatch.delenv("AWID_ROTATE_MAX_BODY_BYTES", raising=False)


def test_the_default_limit_is_the_rotate_routes_default():
    assert DEFAULT_MAX_REQUEST_BODY_BYTES == DEFAULT_ROTATE_MAX_BODY_BYTES == 4 * MIB
    assert create_app().state.max_request_body_bytes == 4 * MIB


def test_the_limit_follows_a_raised_rotate_limit(monkeypatch):
    monkeypatch.setenv("AWID_ROTATE_MAX_BODY_BYTES", str(8 * MIB))
    app = create_app()
    assert app.state.rotate_max_body_bytes == 8 * MIB
    assert app.state.max_request_body_bytes == 8 * MIB


def test_a_configured_limit_above_the_rotate_limit_is_used(monkeypatch):
    monkeypatch.setenv("AWID_MAX_REQUEST_BODY_BYTES", str(6 * MIB))
    assert create_app().state.max_request_body_bytes == 6 * MIB


def test_a_configured_limit_below_the_rotate_limit_refuses_to_start(monkeypatch):
    monkeypatch.setenv("AWID_MAX_REQUEST_BODY_BYTES", str(1 * MIB))
    with pytest.raises(ValueError, match="AWID_MAX_REQUEST_BODY_BYTES"):
        create_app()


@pytest.mark.parametrize("value", ["", "0", "-1", "lots"])
def test_a_limit_that_is_not_a_positive_number_of_bytes_refuses_to_start(monkeypatch, value):
    monkeypatch.setenv("AWID_MAX_REQUEST_BODY_BYTES", value)
    with pytest.raises(ValueError, match="AWID_MAX_REQUEST_BODY_BYTES"):
        create_app()


@pytest.mark.asyncio
async def test_a_body_within_the_limit_is_parsed(client):
    response = await client.post(ADDRESSES, content=b"x" * 1024, headers={"content-type": "application/json"})
    assert response.status_code == 422, response.text


@pytest.mark.asyncio
async def test_a_declared_body_over_the_limit_is_refused_before_it_is_parsed(client):
    body = b"x" * (DEFAULT_MAX_REQUEST_BODY_BYTES + 1)
    response = await client.post(ADDRESSES, content=body, headers={"content-type": "application/json"})
    assert response.status_code == 413, response.text
    assert response.json() == {"detail": "Request body too large"}


@pytest.mark.asyncio
async def test_an_undeclared_body_over_the_limit_is_refused_before_it_is_parsed(client):
    body = _chunks(b"x" * DEFAULT_MAX_REQUEST_BODY_BYTES, b"x")
    response = await client.post(ADDRESSES, content=body, headers={"content-type": "application/json"})
    assert "content-length" not in response.request.headers
    assert response.status_code == 413, response.text
    assert response.json() == {"detail": "Request body too large"}
