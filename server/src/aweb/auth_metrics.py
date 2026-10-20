"""Legacy authentication usage, exported through the Prometheus registry.

Embedding hosts choose how to expose their registry; no public metrics route is
installed here. No signatures, credentials, identifiers or raw targets are kept.
"""
import re

from fastapi import Request
from prometheus_client import Counter

LEGACY_REQUEST_AUTH_ACCEPTED = Counter(
    "aweb_legacy_request_auth_accepted_total",
    "Requests successfully authenticated with the legacy compact v1 envelope.",
    ("auth_family", "method", "route", "client_version"),
)
CERTIFICATE_AUTH_ACCEPTED = Counter(
    "aweb_certificate_auth_accepted_total",
    "Accepted team certificates and declared client verifier support (adoption telemetry only).",
    ("certificate_version", "client_version", "client_supports_v2"),
)
_CLIENT_VERSION = re.compile(r"(?:^|\s)aw/(dev|\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]{1,40})?)(?:\s|$)")


def count_certificate_auth(request: Request, version: int) -> None:
    if getattr(request.state, "certificate_auth_counted", False):
        return
    request.state.certificate_auth_counted = True
    match = _CLIENT_VERSION.search(request.headers.get("User-Agent", "")[:256])
    support = "2" in request.headers.get("X-AWEB-Certificate-Versions", "")[:32].replace(" ", "").split(",")
    CERTIFICATE_AUTH_ACCEPTED.labels(str(version), match.group(1) if match else "unknown", str(support).lower()).inc()


def count_legacy_request_auth(request: Request, family: str) -> None:
    # Dependencies may authenticate the same request more than once.
    if getattr(request.state, "legacy_request_auth_counted", False):
        return
    request.state.legacy_request_auth_counted = True
    route = getattr(request.scope.get("route"), "path", "unmatched")
    match = _CLIENT_VERSION.search(request.headers.get("User-Agent", "")[:256])
    version = match.group(1) if match else "unknown"
    LEGACY_REQUEST_AUTH_ACCEPTED.labels(family, request.method, route, version).inc()
