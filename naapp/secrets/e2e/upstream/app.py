"""A test-only upstream that checks each of secrets' auth schemes for real.

It holds its own copy of every credential, given to it by name when it
starts, and refuses a request whose credential is wrong or missing with 401.
A request that passes gets an echo of what arrived (method, path, query, body
hash, idempotency key, accepted encodings), so a test can see what the broker actually sent.

- ``/bearer/echo…``: ``Authorization: Bearer <token>``.
- ``/basic/echo…``: ``Authorization: Basic base64(user:password)``.
- ``/header/echo…``: ``<name>: <prefix><value>``.
- ``/query/echo…``: ``?<param>=<value>``.
- ``/oauth2/token``: the client-credentials grant, with the client
  authenticated by ``client_secret_basic`` or ``client_secret_post`` and the
  scope checked; ``/oauth2/echo…`` takes only a token it issued, and
  ``/oauth2/stats`` counts issuances.
- ``/sigv4/echo…``: AWS Signature Version 4, recomputed with the upstream's
  own secret key over the request as it arrived, with the region, service,
  key id, date and payload hash checked.

It is never deployed with secrets, and holds no credential of any real
service.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

SIGV4_MAX_SKEW = timedelta(minutes=15)
TOKEN_LIFETIME_SECONDS = 3600
_SIGV4_AUTHORIZATION = re.compile(
    r"AWS4-HMAC-SHA256 Credential=(?P<key_id>[^/]+)/(?P<date>\d{8})/(?P<region>[^/]+)/"
    r"(?P<service>[^/]+)/aws4_request, ?SignedHeaders=(?P<signed>[a-z0-9;-]+), ?"
    r"Signature=(?P<signature>[0-9a-f]{64})"
)


@dataclass(frozen=True)
class UpstreamCredentials:
    """The upstream's own copy of each scheme's credential."""

    bearer: str
    basic_username: str
    basic_password: str
    header_name: str
    header_prefix: str
    header_value: str
    query_param: str
    query_value: str
    oauth_client_id: str
    oauth_client_secret: str
    oauth_scope: str
    sigv4_access_key_id: str
    sigv4_secret_access_key: str
    sigv4_region: str
    sigv4_service: str


def _equal(given: str | None, expected: str) -> bool:
    return given is not None and hmac.compare_digest(given.encode(), expected.encode())


def _basic(header: str | None) -> tuple[str, str] | None:
    if header is None or not header.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(header.removeprefix("Basic "), validate=True).decode()
    except ValueError:
        return None
    username, separator, password = decoded.partition(":")
    return (username, password) if separator else None


def _url(request: Request) -> str:
    raw_path = request.scope["raw_path"].decode("latin-1")
    query = request.scope["query_string"].decode("latin-1")
    host = request.headers.get("host", "")
    return f"https://{host}{raw_path}" + (f"?{query}" if query else "")


def _sigv4_valid(
    request: Request, body: bytes, creds: UpstreamCredentials, now: datetime
) -> bool:
    match = _SIGV4_AUTHORIZATION.fullmatch(request.headers.get("authorization", ""))
    if match is None:
        return False
    if (match["key_id"], match["region"], match["service"]) != (
        creds.sigv4_access_key_id,
        creds.sigv4_region,
        creds.sigv4_service,
    ):
        return False
    amz_date = request.headers.get("x-amz-date", "")
    try:
        signed_at = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return False
    if amz_date[:8] != match["date"] or abs(now - signed_at) > SIGV4_MAX_SKEW:
        return False
    if request.headers.get("x-amz-content-sha256") != hashlib.sha256(body).hexdigest():
        return False
    signed = match["signed"].split(";")
    if "host" not in signed or any(name not in request.headers for name in signed):
        return False
    received = AWSRequest(
        method=request.method,
        url=_url(request),
        data=body,
        headers={name: request.headers[name] for name in signed},
    )
    received.context["timestamp"] = amz_date
    signer = SigV4Auth(
        Credentials(creds.sigv4_access_key_id, creds.sigv4_secret_access_key),
        creds.sigv4_service,
        creds.sigv4_region,
    )
    expected = signer.signature(
        signer.string_to_sign(received, signer.canonical_request(received)), received
    )
    return hmac.compare_digest(expected, match["signature"])


def create_upstream(
    creds: UpstreamCredentials, *, now: Callable[[], datetime] = lambda: datetime.now(UTC)
) -> FastAPI:
    """The upstream. ``now`` is its clock, against which SigV4 dates are checked."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    issued: set[str] = set()
    stats = {"issued": 0}

    async def bearer(request: Request, body: bytes) -> bool:
        return _equal(request.headers.get("authorization"), f"Bearer {creds.bearer}")

    async def basic(request: Request, body: bytes) -> bool:
        pair = _basic(request.headers.get("authorization"))
        return pair is not None and _equal(pair[0], creds.basic_username) and _equal(
            pair[1], creds.basic_password
        )

    async def header(request: Request, body: bytes) -> bool:
        return _equal(request.headers.get(creds.header_name), creds.header_prefix + creds.header_value)

    async def query(request: Request, body: bytes) -> bool:
        return _equal(request.query_params.get(creds.query_param), creds.query_value)

    async def oauth2(request: Request, body: bytes) -> bool:
        given = request.headers.get("authorization", "")
        return given.startswith("Bearer ") and any(
            _equal(given.removeprefix("Bearer "), token) for token in issued
        )

    async def sigv4(request: Request, body: bytes) -> bool:
        return _sigv4_valid(request, body, creds, now())

    schemes: dict[str, tuple[str, Callable[[Request, bytes], Awaitable[bool]]]] = {
        "bearer": ("bearer", bearer),
        "basic": ("basic", basic),
        "header": ("header", header),
        "query": ("query", query),
        "oauth2": ("oauth2-client-credentials", oauth2),
        "sigv4": ("aws-sigv4", sigv4),
    }

    @app.post("/oauth2/token")
    async def token(request: Request) -> Response:
        form = {key: values[0] for key, values in parse_qs((await request.body()).decode()).items()}
        client = _basic(request.headers.get("authorization"))
        if client is None:
            client = (form.get("client_id", ""), form.get("client_secret", ""))
        if not (_equal(client[0], creds.oauth_client_id) and _equal(client[1], creds.oauth_client_secret)):
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        if form.get("grant_type") != "client_credentials":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        if form.get("scope") != creds.oauth_scope:
            return JSONResponse({"error": "invalid_scope"}, status_code=400)
        access_token = secrets.token_urlsafe(32)
        issued.add(access_token)
        stats["issued"] += 1
        return JSONResponse(
            {"access_token": access_token, "token_type": "Bearer", "expires_in": TOKEN_LIFETIME_SECONDS},
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/oauth2/stats")
    async def oauth2_stats() -> dict[str, int]:
        return dict(stats)

    @app.api_route("/{scheme}/echo{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def echo(scheme: str, rest: str, request: Request) -> Response:
        if scheme not in schemes:
            return JSONResponse({"error": "not_found"}, status_code=404)
        name, check = schemes[scheme]
        body = await request.body()
        if not await check(request, body):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return JSONResponse(
            {
                "scheme": name,
                "method": request.method,
                "path": request.url.path,
                "query": request.scope["query_string"].decode("latin-1"),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "idempotency_key": request.headers.get("idempotency-key"),
                "accept_encoding": request.headers.get("accept-encoding"),
            }
        )

    return app
