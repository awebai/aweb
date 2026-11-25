import httpx

from awid.dns_verify import DnsVerificationError
from awid.registry import RegistryError
from aweb.awid_error_handling import (
    AWID_DEPENDENCY_ERRORS,
    awid_dependency_http_exception,
)


def test_awid_dependency_http_exception_distinguishes_dns_failure():
    err = awid_dependency_http_exception(
        DnsVerificationError("DNS lookup failed for _awid.example.com"),
        operation="AWID team key resolution",
    )

    assert err.status_code == 503
    assert (
        "AWID team key resolution DNS resolution failed (DnsVerificationError)"
        in err.detail
    )
    assert "Retry when the registry is available" in err.detail
    assert "_awid.example.com" not in err.detail


def test_awid_dependency_http_exception_distinguishes_connect_failure():
    err = awid_dependency_http_exception(
        httpx.ConnectError("connection refused"),
        operation="AWID did:aw resolution",
    )

    assert err.status_code == 503
    assert "AWID did:aw resolution upstream unavailable (ConnectError)" in err.detail


def test_a_registry_request_deadline_is_a_dependency_error_and_retryable_503():
    # A caller's own asyncio.timeout around a registry call raises the builtin TimeoutError.
    assert issubclass(TimeoutError, AWID_DEPENDENCY_ERRORS)
    err = awid_dependency_http_exception(
        TimeoutError(), operation="AWID team key resolution"
    )

    assert err.status_code == 503
    assert err.detail.startswith(
        "AWID team key resolution upstream unavailable (TimeoutError)."
    )
    assert "Retry when the registry is available" in err.detail


def test_an_unavailable_registry_is_classified_by_the_transport_failure_behind_it():
    for cause in (httpx.ConnectError("connection refused"), TimeoutError()):
        try:
            raise RegistryError(
                "AWID registry unavailable", status_code=503, code="unavailable"
            ) from cause
        except RegistryError as unavailable:
            err = awid_dependency_http_exception(
                unavailable, operation="AWID did:aw resolution"
            )
        assert err.status_code == 503
        assert err.detail.startswith(
            f"AWID did:aw resolution upstream unavailable ({type(cause).__name__})."
        )
        assert "connection refused" not in err.detail
        assert "Retry when the registry is available" in err.detail


def test_awid_dependency_http_exception_names_unusable_registry_answers():
    not_found = awid_dependency_http_exception(
        RegistryError("not found", status_code=404, detail="Namespace not found"),
        operation="AWID team visibility lookup",
    )
    forbidden = awid_dependency_http_exception(
        RegistryError("forbidden", status_code=403, detail="Forbidden"),
        operation="AWID team visibility lookup",
    )

    expected = {
        "code": "registry_response_unusable",
        "message": (
            "AWID team visibility lookup received an unusable registry response. "
            "Ask the server operator to check the registry."
        ),
    }
    assert (not_found.status_code, not_found.detail) == (422, expected)
    assert (forbidden.status_code, forbidden.detail) == (422, expected)


def test_awid_dependency_http_exception_explains_missing_private_team_trusted_lane():
    err = awid_dependency_http_exception(
        RegistryError(
            "team private",
            status_code=403,
            detail="{'code': 'team_private', 'message': 'Private history requires authority'}",
        ),
        operation="AWID team key resolution",
    )

    assert err.status_code == 503
    assert "AWID_SERVICE_TOKEN" in err.detail
    assert "same >=32-byte" in err.detail
    assert "rerun `aw init`" in err.detail


def test_awid_dependency_http_exception_maps_registry_429_to_retryable_503():
    err = awid_dependency_http_exception(
        RegistryError("rate limited", status_code=429, detail="Too many requests"),
        operation="AWID team visibility lookup",
    )

    assert err.status_code == 503
    assert err.detail.startswith(
        "AWID team visibility lookup upstream rate limited (RegistryError status=429)."
    )
    assert "Retry when the registry is available" in err.detail
    assert "Too many requests" not in err.detail


def test_awid_dependency_http_exception_preserves_registry_5xx_as_retryable_503():
    err = awid_dependency_http_exception(
        RegistryError("upstream down", status_code=503, detail="registry unavailable"),
        operation="AWID team visibility lookup",
    )

    assert err.status_code == 503
    assert err.detail.startswith(
        "AWID team visibility lookup upstream error (RegistryError status=503)."
    )
    assert "Retry when the registry is available" in err.detail
    assert "registry unavailable" not in err.detail


def test_awid_dependency_http_exception_classifies_http_status_error_as_dependency():
    request = httpx.Request("GET", "https://awid.example/v1/lookup")
    response = httpx.Response(503, request=request)
    exc = httpx.HTTPStatusError("upstream 503", request=request, response=response)

    assert isinstance(exc, AWID_DEPENDENCY_ERRORS)
    err = awid_dependency_http_exception(
        exc, operation="AWID federation target identity resolution"
    )

    assert err.status_code == 503
    assert (
        "AWID federation target identity resolution upstream error (HTTPStatusError status=503)"
        in err.detail
    )


def test_awid_dependency_http_exception_names_unusable_http_status_error():
    request = httpx.Request("GET", "https://awid.example/v1/lookup")
    response = httpx.Response(403, request=request)
    exc = httpx.HTTPStatusError("forbidden", request=request, response=response)

    err = awid_dependency_http_exception(
        exc, operation="AWID federation target identity resolution"
    )

    assert err.status_code == 422
    assert err.detail == {
        "code": "registry_response_unusable",
        "message": (
            "AWID federation target identity resolution received an unusable registry response. "
            "Ask the server operator to check the registry."
        ),
    }


def test_awid_dependency_http_exception_maps_http_status_error_429_to_retryable_503():
    request = httpx.Request("GET", "https://awid.example/v1/lookup")
    response = httpx.Response(429, request=request)
    exc = httpx.HTTPStatusError("rate limited", request=request, response=response)

    err = awid_dependency_http_exception(
        exc, operation="AWID federation target identity resolution"
    )

    assert err.status_code == 503
    assert (
        "AWID federation target identity resolution upstream rate limited (HTTPStatusError status=429)"
        in err.detail
    )


def test_awid_dependency_http_exception_does_not_label_unexpected_bug_as_503():
    err = awid_dependency_http_exception(
        RuntimeError("boom"),
        operation="AWID team revocation check",
    )

    assert err.status_code == 500
    assert err.detail == (
        "Unexpected AWID team revocation check dependency error (RuntimeError). "
        "Ask the server operator to investigate."
    )
