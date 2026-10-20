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
_CLIENT_VERSION = re.compile(r"(?:^|\s)aw/(dev|\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]{1,40})?)(?:\s|$)")


NONCE_FREE_REQUEST_AUTH_ACCEPTED = Counter(
    "aweb_nonce_free_request_auth_accepted_total",
    "Successfully authenticated v2 requests without a nonce.",
    ("auth_family", "method", "route", "client_version"),
)
REQUEST_AUTH_REPLAY_DETECTED = Counter(
    "aweb_request_auth_replay_detected_total",
    "Repeated verified v2 signatures, without recording credentials.",
    ("auth_family", "method", "route", "client_version", "mode"),
)


def _labels(request: Request, family: str) -> tuple[str, str, str, str]:
    route = getattr(request.scope.get("route"), "path", "unmatched")
    match = _CLIENT_VERSION.search(request.headers.get("User-Agent", "")[:256])
    return family, request.method, route, match.group(1) if match else "unknown"


def count_nonce_free_request_auth(request: Request, family: str) -> None:
    if getattr(request.state, "nonce_free_request_auth_counted", False):
        return
    request.state.nonce_free_request_auth_counted = True
    NONCE_FREE_REQUEST_AUTH_ACCEPTED.labels(*_labels(request, family)).inc()


def count_request_auth_replay(request: Request, family: str, mode: str) -> None:
    REQUEST_AUTH_REPLAY_DETECTED.labels(*_labels(request, family), mode).inc()


def count_legacy_request_auth(request: Request, family: str) -> None:
    # Dependencies may authenticate the same request more than once.
    if getattr(request.state, "legacy_request_auth_counted", False):
        return
    request.state.legacy_request_auth_counted = True
    LEGACY_REQUEST_AUTH_ACCEPTED.labels(*_labels(request, family)).inc()
