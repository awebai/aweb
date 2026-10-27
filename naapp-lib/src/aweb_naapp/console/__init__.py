"""The console session for an app-origin human page.

A person logs in with a passkey through B3, on the routes
:func:`console_login_router` serves; the login then opens a session here. The session lives at most 15 minutes, in a host-only
``__Host-`` cookie that is ``Secure``, ``HttpOnly`` and ``SameSite=Strict``.
Every state-changing request carries the session's CSRF token in
``X-CSRF-Token``. Only hashes of both tokens are stored.

Console routes use :class:`ConsoleRoute`: every response carries the console
headers (a strict CSP with ``frame-ancestors 'none'``, ``Referrer-Policy:
no-referrer`` and ``Cache-Control: no-store``). The console is served on the
human origin of :func:`aweb_naapp.runtime.origins.split_origins`, which refuses
any request carrying team-auth, so the console never accepts agent credentials.

Each person logs in to a scope of their own. The app says which scopes may log
in on its console; any other scope is refused exactly as a failed login is.

Installed with the ``runtime`` extra.
"""

import hashlib
import hmac
import logging
import secrets
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pydantic import BaseModel

from aweb_naapp import ratelimit
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.runtime.approvals import AuthenticationFailed
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable
from aweb_naapp.runtime.passkeys import ContactChangeRefused, EnrolmentRefused, Passkeys

if TYPE_CHECKING:
    from aweb_naapp.runtime.credential_audit import CredentialAudit

logger = logging.getLogger(__name__)

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_naapp_console"

MAX_SESSION = timedelta(minutes=15)
COOKIE_NAME = "__Host-console"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
LOGIN_REFUSED = "login_refused"
LOGIN_BUCKET = "console.login.client"

CONSOLE_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; "
        "frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


@dataclass(frozen=True)
class IssuedSession:
    """A freshly opened session: the cookie token and its CSRF token, once."""

    token: str
    csrf_token: str
    expires_at: datetime
    max_age: int


@dataclass(frozen=True)
class ConsoleSession:
    subject: str
    scope: str
    evidence_ref: str
    expires_at: datetime
    token_sha256: bytes


async def apply_console_migrations(db: AsyncDatabaseManager) -> None:
    await ratelimit.apply_ratelimit_migrations(db)
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


async def _housekeeping(table: str, work: Awaitable[Any]) -> None:
    """Run a housekeeping delete after the request's writes have committed.

    A failure leaves rows for a later prune and must not fail a request whose
    work is already done, so it is logged, by table and error type only.
    """
    try:
        await work
    except Exception as error:
        logger.warning("console prune of %s failed: %s", table, type(error).__name__)


ScopeAdmission = Callable[[str], Awaitable[bool]]


class ConsoleSessions:
    """Console sessions for the scopes ``scopes`` admits, logged in through ``passkeys``.

    A session lasts while its subject can still log in: on every request it is
    refused, and closed, once the subject is no longer the scope's in-effect
    approver, the exact passkey behind its login evidence is revoked, or the
    app no longer admits the scope.
    """

    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        passkeys: Passkeys,
        scopes: ScopeAdmission,
        ttl: timedelta = MAX_SESSION,
    ) -> None:
        if not timedelta(0) < ttl <= MAX_SESSION:
            raise ValueError("a console session lasts more than 0 and at most 15 minutes")
        self._db = db
        self._ttl = ttl
        self.passkeys = passkeys
        self.scopes = scopes

    async def open(self, *, subject: str, scope: str, evidence_ref: str) -> IssuedSession:
        """Open a session for a subject whose passkey login B3 has verified."""
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        async with self._db.transaction() as tx:
            expires_at = await tx.fetch_value(
                """
                INSERT INTO {{tables.console_sessions}}
                  (token_sha256, csrf_sha256, subject, scope, evidence_ref, expires_at)
                VALUES ($1, $2, $3, $4, $5, NOW() + $6)
                RETURNING expires_at
                """,
                _sha256(token),
                _sha256(csrf_token),
                subject,
                scope,
                evidence_ref,
                self._ttl,
            )
        # A session that has ended is refused already; dropping it, after the
        # insert has committed and skipping rows another transaction holds,
        # bounds the table without ever waiting on a login.
        await _housekeeping(
            "console_sessions",
            self._db.execute(
                """
                DELETE FROM {{tables.console_sessions}} WHERE token_sha256 IN (
                    SELECT token_sha256 FROM {{tables.console_sessions}}
                    WHERE expires_at <= NOW() OR closed_at IS NOT NULL FOR UPDATE SKIP LOCKED)
                """
            ),
        )
        return IssuedSession(token, csrf_token, expires_at, int(self._ttl.total_seconds()))

    def set_cookie(self, response: Response, issued: IssuedSession) -> None:
        response.set_cookie(
            COOKIE_NAME,
            issued.token,
            max_age=issued.max_age,
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )

    def clear_cookie(self, response: Response) -> None:
        response.set_cookie(
            COOKIE_NAME, "", max_age=0, path="/", secure=True, httponly=True, samesite="strict"
        )

    def _required(self) -> HTTPException:
        response = Response()
        self.clear_cookie(response)
        return HTTPException(
            status_code=401,
            detail="console_session_required",
            headers={"Set-Cookie": response.headers["set-cookie"]},
        )

    async def current(self, request: Request) -> ConsoleSession:
        """The request's open session; a state change must also carry its CSRF token."""
        token = request.cookies.get(COOKIE_NAME)
        if not token:
            raise self._required()
        row = await self._db.fetch_one(
            """
            SELECT * FROM {{tables.console_sessions}}
            WHERE token_sha256 = $1 AND closed_at IS NULL AND expires_at > NOW()
            """,
            _sha256(token),
        )
        if row is None:
            raise self._required()
        if not (
            await self.passkeys.login_evidence_is_current(
                row["scope"], row["subject"], row["evidence_ref"]
            )
            and await self.scopes(row["scope"])
        ):
            await self._close(bytes(row["token_sha256"]))
            raise self._required()
        if request.method not in SAFE_METHODS:
            supplied = request.headers.get(CSRF_HEADER, "")
            if not hmac.compare_digest(_sha256(supplied), bytes(row["csrf_sha256"])):
                raise HTTPException(status_code=403, detail="csrf_token_required")
        return ConsoleSession(
            subject=row["subject"],
            scope=row["scope"],
            evidence_ref=row["evidence_ref"],
            expires_at=row["expires_at"],
            token_sha256=bytes(row["token_sha256"]),
        )

    async def close(self, session: ConsoleSession) -> None:
        await self._close(session.token_sha256)

    async def _close(self, token_sha256: bytes) -> None:
        await self._db.execute(
            "UPDATE {{tables.console_sessions}} SET closed_at = NOW() WHERE token_sha256 = $1",
            token_sha256,
        )


@dataclass(frozen=True)
class ClientIdentity:
    """How the deployment identifies the client behind a request.

    By default it is the peer address, and any forwarded header is ignored,
    because a client can set one. Behind a proxy, the deployment names the
    header that proxy sets as ``trusted_header``; its last comma-separated
    entry is the address the proxy saw. A request without the header is keyed
    on its peer.
    """

    trusted_header: str | None = None

    def of(self, request: Request) -> str:
        if self.trusted_header is not None:
            value = request.headers.get(self.trusted_header, "")
            last = value.rsplit(",", 1)[-1].strip()
            if last:
                return last
        return request.client.host if request.client is not None else ""


@dataclass(frozen=True)
class LoginVolume:
    requests: int
    throttled: int


class LoginLimiter:
    """A token-bucket limit on login requests per client, metered per scope.

    Each client has a bucket of ``limit`` tokens that refills ``limit`` per
    ``window``, in the shared limiter (:mod:`aweb_naapp.ratelimit`). Login needs
    no prior authentication, so without it a flood of login requests could keep
    evicting the real person's challenge. ``admit`` raises 429 with
    ``Retry-After`` once a client's bucket is empty. Every request, throttled or
    not, is counted for its scope, and volume older than ``volume_retention`` is
    dropped after the request commits, as full buckets are swept.
    """

    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        client_identity: ClientIdentity,
        limit: int,
        window: timedelta,
        volume_retention: timedelta = timedelta(days=30),
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if limit <= 0 or window <= timedelta(0) or volume_retention <= timedelta(0):
            raise ValueError("a login limit, its window and the volume retention must be positive")
        if window.total_seconds() != int(window.total_seconds()):
            raise ValueError("a login window is a whole number of seconds")
        self._db = db
        self._identity = client_identity
        self._limit = limit
        self._window = window
        self._volume_retention = volume_retention
        self._clock = clock

    async def admit(self, request: Request, scope: str) -> None:
        now = self._clock()
        charge = ratelimit.Charge(
            bucket=LOGIN_BUCKET,
            # The client's identity, hashed: bounded whatever a proxy header holds.
            key=_sha256(self._identity.of(request)).hex(),
            capacity=self._limit,
            window_s=int(self._window.total_seconds()),
        )
        async with self._db.transaction() as tx:
            decision = await ratelimit.take(tx, [charge], now=now)
            await tx.execute(
                """
                INSERT INTO {{tables.console_login_volume}} AS v
                    (scope, window_start, requests, throttled)
                VALUES ($1, to_timestamp(floor(extract(epoch FROM NOW()) / $2) * $2), 1, $3)
                ON CONFLICT (scope, window_start) DO UPDATE
                    SET requests = v.requests + 1, throttled = v.throttled + $3
                """,
                scope,
                self._window.total_seconds(),
                int(decision.throttled),
            )
        await self._prune(now)
        if decision.throttled:
            raise HTTPException(
                status_code=429,
                detail="login_rate_limited",
                headers={"Retry-After": str(decision.retry_after_s)},
            )

    async def _prune(self, now: datetime) -> None:
        """Sweep full buckets and drop volume past its retention, after the
        request's writes have committed; rows another transaction holds are left
        for a later prune, so a prune never waits on a login."""
        await _housekeeping("rate_buckets", ratelimit.sweep(self._db, now=now, limit=16))
        await _housekeeping(
            "console_login_volume",
            self._db.execute(
                """
                DELETE FROM {{tables.console_login_volume}} WHERE (scope, window_start) IN (
                    SELECT scope, window_start FROM {{tables.console_login_volume}}
                    WHERE window_start < NOW() - $1::interval FOR UPDATE SKIP LOCKED)
                """,
                self._volume_retention,
            ),
        )

    async def volume(self, scope: str, *, since: timedelta) -> LoginVolume:
        """Login requests for ``scope`` in the buckets that began within ``since``,
        which may not reach past the volume retention."""
        if since > self._volume_retention:
            raise ValueError("volume is kept only for the volume retention")
        row = await self._db.fetch_one(
            """
            SELECT coalesce(sum(requests), 0) AS requests,
                   coalesce(sum(throttled), 0) AS throttled
            FROM {{tables.console_login_volume}}
            WHERE scope = $1 AND window_start > NOW() - $2::interval
            """,
            scope,
            since,
        )
        if row is None:
            return LoginVolume(0, 0)
        return LoginVolume(int(row["requests"]), int(row["throttled"]))


class ConsoleRoute(APIRoute):
    """A route on the console origin: every response, refusals included,
    carries the console headers. Validation errors expose only location and
    type, never submitted input or validator metadata."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def console_handler(request: Request) -> Response:
            try:
                response = await handler(request)
            except HTTPException as error:
                response = JSONResponse(
                    {"detail": error.detail}, error.status_code, headers=error.headers
                )
            except RequestValidationError as error:
                detail = [
                    {"loc": problem["loc"], "type": problem["type"]}
                    for problem in error.errors()
                ]
                response = JSONResponse({"detail": detail}, 422)
            response.headers.update(CONSOLE_HEADERS)
            return response

        return console_handler


class LoginOptionsRequest(BaseModel):
    scope: str


class LoginRequest(BaseModel):
    scope: str
    assertion: dict[str, Any]


def console_login_router(
    *, sessions: ConsoleSessions, limiter: LoginLimiter, prefix: str = ""
) -> APIRouter:
    """The console's passkey login: ``POST /login/options``, ``POST /login`` and
    ``POST /logout``, under ``prefix``.

    A login names its scope, and the sessions' ``scopes`` says whether that
    scope may log in on this console. A scope it refuses gets the same 401 as a failed login and
    is neither metered nor passed to B3. An accepted scope is rate-limited per
    client, and B3 verifies the assertion with user verification required. A
    verified login opens a session for that scope and returns its CSRF token.
    """
    router = APIRouter(prefix=prefix, route_class=ConsoleRoute)
    passkeys = sessions.passkeys

    async def admit(request: Request, scope: str) -> None:
        if not await sessions.scopes(scope):
            raise HTTPException(status_code=401, detail=LOGIN_REFUSED)
        await limiter.admit(request, scope)

    @router.post("/login/options")
    async def login_options(request: Request, body: LoginOptionsRequest) -> dict[str, Any]:
        await admit(request, body.scope)
        try:
            return dict(await passkeys.login_options(body.scope))
        except AuthenticationFailed:
            raise HTTPException(status_code=401, detail=LOGIN_REFUSED) from None

    @router.post("/login")
    async def login(request: Request, response: Response, body: LoginRequest) -> dict[str, str]:
        await admit(request, body.scope)
        try:
            verified = await passkeys.verify_login(body.scope, body.assertion)
        except AuthenticationFailed:
            raise HTTPException(status_code=401, detail=LOGIN_REFUSED) from None
        issued = await sessions.open(
            subject=verified.subject, scope=body.scope, evidence_ref=verified.evidence_ref
        )
        sessions.set_cookie(response, issued)
        return {"csrf_token": issued.csrf_token}

    @router.post("/logout")
    async def logout(
        response: Response, session: Annotated[ConsoleSession, Depends(sessions.current)]
    ) -> dict[str, bool]:
        await sessions.close(session)
        sessions.clear_cookie(response)
        return {"closed": True}

    return router


async def require_json(request: Request) -> None:
    """Refuse a state-changing request whose body is not declared JSON (415)."""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            raise HTTPException(status_code=415, detail="json_required")


async def exact_body(request: Request, fields: set[str]) -> dict[str, Any]:
    """The request's JSON object, which must have exactly ``fields``; anything
    else is refused with 400 and never echoed."""
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="request_invalid") from None
    if not isinstance(body, dict) or set(body) != fields:
        raise HTTPException(status_code=400, detail="request_invalid")
    return body


def text_field(body: dict[str, Any], field: str) -> str:
    """``body[field]`` as a non-empty string, or 400."""
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise HTTPException(status_code=400, detail="request_invalid")
    return value


def credential_router(
    *, passkeys: Passkeys, recorder: "CredentialAudit", prefix: str = ""
) -> APIRouter:
    """B3's credential ceremonies a designated holder reaches through its links:
    ``POST /enrolment/options``, ``POST /enrolment`` and ``POST /contact-proof``,
    under ``prefix``.

    The endpoints are anonymous: the single-use token in the body is the only
    authority, and no session is read or opened. Each takes exactly its JSON
    fields. A token B3 refuses gets a fixed 403 that never echoes it; a change
    the recorder cannot record is refused with 503 and its code, and takes no
    effect.
    """
    router = APIRouter(prefix=prefix, route_class=ConsoleRoute)

    @router.post("/enrolment/options", dependencies=[Depends(require_json)])
    async def enrolment_options(request: Request) -> dict[str, Any]:
        body = await exact_body(request, {"link_token"})
        try:
            return dict(await passkeys.enrolment_options(text_field(body, "link_token")))
        except EnrolmentRefused:
            raise HTTPException(status_code=403, detail="enrolment_refused") from None

    @router.post("/enrolment", dependencies=[Depends(require_json)])
    async def enrolment(request: Request) -> dict[str, str]:
        body = await exact_body(request, {"link_token", "credential"})
        if not isinstance(body["credential"], dict):
            raise HTTPException(status_code=400, detail="request_invalid")
        try:
            token = text_field(body, "link_token")
            prepared = await recorder.prepare_enrolment(token)
            with recorder.prepared(prepared):
                approver = await passkeys.complete_enrolment(
                    token, body["credential"], fence=prepared
                )
        except EnrolmentRefused:
            raise HTTPException(status_code=403, detail="enrolment_refused") from None
        except GovernanceUnavailable as refused:
            raise HTTPException(503, refused.code) from None
        except Refused as refused:
            raise HTTPException(503, refused.code) from None
        return {"scope": approver.scope}

    @router.post("/contact-proof", dependencies=[Depends(require_json)])
    async def contact_proof(request: Request) -> dict[str, str]:
        body = await exact_body(request, {"proof_token"})
        try:
            token = text_field(body, "proof_token")
            prepared = await recorder.prepare_contact_proof(token)
            with recorder.prepared(prepared):
                effective_at = await passkeys.prove_contact(token, fence=prepared)
        except ContactChangeRefused:
            raise HTTPException(status_code=403, detail="contact_proof_refused") from None
        except GovernanceUnavailable as refused:
            raise HTTPException(503, refused.code) from None
        except Refused as refused:
            raise HTTPException(503, refused.code) from None
        return {"effective_at": effective_at.isoformat()}

    return router
