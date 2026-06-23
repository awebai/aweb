import httpx

from awid.dns_verify import DnsVerificationError
from awid.registry import RegistryError
from aweb.awid_error_handling import (
    AWID_DEPENDENCY_ERRORS,
    awid_dependency_http_exception,
    awid_registry_not_configured_exception,
)


def test_registry_not_configured_detail_is_site_specific():
    first = awid_registry_not_configured_exception(operation="AWID team key resolution")
    second = awid_registry_not_configured_exception(operation="AWID mail recipient address lookup")

    assert first.status_code == 500
    assert second.status_code == 500
    assert first.detail == "AWID team key resolution registry client not configured"
    assert second.detail == "AWID mail recipient address lookup registry client not configured"
    assert first.detail != second.detail


def test_awid_dependency_http_exception_distinguishes_dns_failure():
    err = awid_dependency_http_exception(
        DnsVerificationError("DNS lookup failed for _awid.example.com"),
        operation="AWID team key resolution",
    )

    assert err.status_code == 503
    assert "AWID team key resolution DNS resolution failed (DnsVerificationError)" in err.detail


def test_awid_dependency_http_exception_distinguishes_connect_failure():
    err = awid_dependency_http_exception(
        httpx.ConnectError("connection refused"),
        operation="AWID did:aw resolution",
    )

    assert err.status_code == 503
    assert "AWID did:aw resolution upstream unavailable (ConnectError)" in err.detail


def test_awid_dependency_http_exception_caps_registry_unactionable_4xx_to_bad_gateway():
    not_found = awid_dependency_http_exception(
        RegistryError("not found", status_code=404, detail="Namespace not found"),
        operation="AWID team visibility lookup",
    )
    forbidden = awid_dependency_http_exception(
        RegistryError("forbidden", status_code=403, detail="Forbidden"),
        operation="AWID team visibility lookup",
    )

    assert not_found.status_code == 502
    assert not_found.detail == "AWID team visibility lookup upstream returned unexpected status (RegistryError status=404): Namespace not found"
    assert forbidden.status_code == 502
    assert forbidden.detail == "AWID team visibility lookup upstream returned unexpected status (RegistryError status=403): Forbidden"


def test_awid_dependency_http_exception_maps_registry_429_to_retryable_503():
    err = awid_dependency_http_exception(
        RegistryError("rate limited", status_code=429, detail="Too many requests"),
        operation="AWID team visibility lookup",
    )

    assert err.status_code == 503
    assert err.detail == "AWID team visibility lookup upstream rate limited (RegistryError status=429): Too many requests"


def test_awid_dependency_http_exception_preserves_registry_5xx_as_retryable_503():
    err = awid_dependency_http_exception(
        RegistryError("upstream down", status_code=503, detail="registry unavailable"),
        operation="AWID team visibility lookup",
    )

    assert err.status_code == 503
    assert err.detail == "AWID team visibility lookup upstream error (RegistryError status=503): registry unavailable"


def test_awid_dependency_http_exception_classifies_http_status_error_as_dependency():
    request = httpx.Request("GET", "https://awid.example/v1/lookup")
    response = httpx.Response(503, request=request)
    exc = httpx.HTTPStatusError("upstream 503", request=request, response=response)

    assert isinstance(exc, AWID_DEPENDENCY_ERRORS)
    err = awid_dependency_http_exception(exc, operation="AWID federation target identity resolution")

    assert err.status_code == 503
    assert "AWID federation target identity resolution upstream error (HTTPStatusError status=503)" in err.detail


def test_awid_dependency_http_exception_caps_http_status_error_unactionable_4xx_to_bad_gateway():
    request = httpx.Request("GET", "https://awid.example/v1/lookup")
    response = httpx.Response(403, request=request)
    exc = httpx.HTTPStatusError("forbidden", request=request, response=response)

    err = awid_dependency_http_exception(exc, operation="AWID federation target identity resolution")

    assert err.status_code == 502
    assert "AWID federation target identity resolution upstream returned unexpected status (HTTPStatusError status=403)" in err.detail


def test_awid_dependency_http_exception_maps_http_status_error_429_to_retryable_503():
    request = httpx.Request("GET", "https://awid.example/v1/lookup")
    response = httpx.Response(429, request=request)
    exc = httpx.HTTPStatusError("rate limited", request=request, response=response)

    err = awid_dependency_http_exception(exc, operation="AWID federation target identity resolution")

    assert err.status_code == 503
    assert "AWID federation target identity resolution upstream rate limited (HTTPStatusError status=429)" in err.detail


def test_awid_dependency_http_exception_does_not_label_unexpected_bug_as_503():
    err = awid_dependency_http_exception(
        RuntimeError("boom"),
        operation="AWID team revocation check",
    )

    assert err.status_code == 500
    assert err.detail == "Unexpected AWID team revocation check dependency error (RuntimeError): boom"
