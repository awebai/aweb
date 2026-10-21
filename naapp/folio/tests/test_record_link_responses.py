"""Every collection-link refusal keeps the shared link privacy headers."""

import json

import pytest
from aweb_naapp.runtime.capability_links.routes import LINK_RESPONSE_HEADERS
from fastapi import HTTPException

from folio.record_link_responses import link_http_refusal


@pytest.mark.parametrize("status,code", [
    (403, "current_member_required"), (503, "current_membership_unavailable"),
    (409, "cursor_invalid"), (404, "link_unavailable"),
])
def test_link_http_refusal_preserves_machine_code_status_and_private_response_headers(status, code):
    error = HTTPException(status_code=status, detail={"code": code})
    response = link_http_refusal(error)
    assert response.status_code == status
    assert json.loads(response.body) == {"detail": {"code": code}}
    for name, value in LINK_RESPONSE_HEADERS.items():
        assert response.headers[name] == value


@pytest.mark.parametrize("cache_header", ["Cache-Control", "cache-control"])
def test_link_privacy_headers_cannot_be_weakened_by_an_upstream_http_refusal(cache_header):
    response = link_http_refusal(HTTPException(status_code=503, detail={"code": "unavailable"},
                                             headers={cache_header: "public", "Retry-After": "3"}))
    assert response.headers["Cache-Control"] == LINK_RESPONSE_HEADERS["Cache-Control"]
    assert response.headers["Retry-After"] == "3"
