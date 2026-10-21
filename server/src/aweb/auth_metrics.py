"""Request authentication usage, exported through the Prometheus registry.

Embedding hosts choose how to expose their registry; no public metrics route is
installed here. No signatures, credentials, identifiers or raw targets are kept.
"""
import re
from threading import Lock

from fastapi import Request
from prometheus_client import Counter

LEGACY_REQUEST_AUTH_ACCEPTED = Counter(
    "aweb_legacy_request_auth_accepted_total",
    "Requests successfully authenticated with the legacy compact v1 envelope.",
    ("auth_family", "method", "route", "client_version"),
)
_CLIENT_VERSION = re.compile(
    r"(aw|aweb-channel|aweb-pi|aweb-wake|aweb-channel-core|aweb-python|aweb-cloud)/"
    r"(dev|[0-9]{1,8}\.[0-9]{1,8}\.[0-9]{1,8}(?:[-+][A-Za-z0-9.-]{1,40})?)"
)
_MAX_CLIENT_VERSIONS = 32
_SEEN_CLIENT_VERSIONS: dict[str, set[str]] = {}
_CLIENT_VERSION_LOCK = Lock()


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


def _client_label(request: Request) -> str:
    # Self-reported, unsigned measurement ONLY. Never use this for authentication,
    # authorization, routing, rate limits or feature selection.
    explicit = request.headers.get("X-AWEB-Client-Version")
    agent = request.headers.get("User-Agent", "")
    if explicit is None and not agent:
        return "unknown"
    tokens = [explicit.strip()] if explicit is not None else agent[:256].split()
    for token in tokens:
        if len(token) > 96:
            continue
        match = _CLIENT_VERSION.fullmatch(token)
        if match and len(match.group(2)) <= 64:
            product = match.group(1)
            version = re.split(r"[-+]", match.group(2), maxsplit=1)[0]
            with _CLIENT_VERSION_LOCK:
                seen = _SEEN_CLIENT_VERSIONS.setdefault(product, set())
                if version not in seen and len(seen) >= _MAX_CLIENT_VERSIONS:
                    return "other"
                seen.add(version)
            return version if product == "aw" else product + "/" + version
    return "other"


def _labels(request: Request, family: str) -> tuple[str, str, str, str]:
    route = getattr(request.scope.get("route"), "path", "unmatched")
    return family, request.method, route, _client_label(request)


def _record(request: Request, counter: Counter, family: str, *extra: str) -> None:
    if request.scope.get("route") is None:
        pending = getattr(request.state, "pending_request_auth_metrics", None)
        if pending is None:
            pending = []
            request.state.pending_request_auth_metrics = pending
        pending.append((counter, family, extra))
        return
    counter.labels(*_labels(request, family), *extra).inc()


def flush_request_auth_metrics(request: Request) -> None:
    """Embedding bridges call after routing, using the same scope/state.

    Authentication before route matching must never label a raw path. The OSS
    body middleware flushes this queue; hosts also flush their native routes.
    """
    pending = getattr(request.state, "pending_request_auth_metrics", ())
    request.state.pending_request_auth_metrics = []
    for counter, family, extra in pending:
        counter.labels(*_labels(request, family), *extra).inc()


def count_nonce_free_request_auth(request: Request, family: str) -> None:
    if getattr(request.state, "nonce_free_request_auth_counted", False):
        return
    request.state.nonce_free_request_auth_counted = True
    _record(request, NONCE_FREE_REQUEST_AUTH_ACCEPTED, family)


def count_request_auth_replay(request: Request, family: str, mode: str) -> None:
    _record(request, REQUEST_AUTH_REPLAY_DETECTED, family, mode)


def count_legacy_request_auth(request: Request, family: str) -> None:
    # Dependencies may authenticate the same request more than once.
    if getattr(request.state, "legacy_request_auth_counted", False):
        return
    request.state.legacy_request_auth_counted = True
    _record(request, LEGACY_REQUEST_AUTH_ACCEPTED, family)
