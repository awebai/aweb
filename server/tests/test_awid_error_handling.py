import httpx

from awid.dns_verify import DnsVerificationError
from awid.registry import RegistryError
from aweb.awid_error_handling import awid_dependency_http_exception, awid_registry_not_configured_exception


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


def test_awid_dependency_http_exception_preserves_registry_4xx():
    err = awid_dependency_http_exception(
        RegistryError("not found", status_code=404, detail="Namespace not found"),
        operation="AWID team visibility lookup",
    )

    assert err.status_code == 404
    assert err.detail == "AWID team visibility lookup returned error (RegistryError status=404): Namespace not found"


def test_awid_dependency_http_exception_does_not_label_unexpected_bug_as_503():
    err = awid_dependency_http_exception(
        RuntimeError("boom"),
        operation="AWID team revocation check",
    )

    assert err.status_code == 500
    assert err.detail == "Unexpected AWID team revocation check dependency error (RuntimeError): boom"
