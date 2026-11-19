"""Deployment-selected address semantics are shared by all federation callers."""

import pytest
from starlette.requests import Request
from aweb.client_address import request_client_address


@pytest.mark.parametrize(
    "configured,header,expected",
    [
        ("", "untrusted, 203.0.113.1", "127.0.0.1"),
        ("X-Client-IP", "untrusted, 203.0.113.1", "203.0.113.1"),
        ("X-Client-IP", "untrusted, ", "127.0.0.1"),
        ("X-Client-IP", "", "127.0.0.1"),
    ],
)
def test_budget_address_uses_only_deployment_selected_header(
    monkeypatch, configured, header, expected
):
    monkeypatch.setenv("AWEB_CLIENT_ADDRESS_HEADER", configured)
    request = Request(
        {
            "type": "http",
            "client": ("127.0.0.1", 1234),
            "headers": [(b"x-client-ip", header.encode())],
        }
    )
    assert request_client_address(request) == expected


def test_missing_http_context_has_no_invented_client_address():
    assert request_client_address(None) == "unknown"
