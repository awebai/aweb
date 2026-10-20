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
import secrets
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager
from pydantic import BaseModel

from aweb_naapp.runtime.approvals import AuthenticationFailed
from aweb_naapp.runtime.passkeys import Passkeys

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_naapp_console"

MAX_SESSION = timedelta(minutes=15)
COOKIE_NAME = "__Host-console"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
LOGIN_REFUSED = "login_refused"

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
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MIGRATIONS_MODULE
    ).apply_pending_migrations()


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


ScopeAdmission = Callable[[str], Awaitable[bool]]


class ConsoleSessions:
    """Console sessions for the scopes ``scopes`` admits, logged in through ``passkeys``.

    A session lasts while its subject can still log in: on every request it is
    refused, and closed, once the subject is no longer the scope's in-effect
    approver with an unrevoked passkey, or the app no longer admits the scope.
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
            # A session that has ended is refused already; dropping it bounds the table.
            await tx.execute(
                """
                DELETE FROM {{tables.console_sessions}}
                WHERE expires_at <= NOW() OR closed_at IS NOT NULL
                """
            )
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

    async def current(self, request: Request) -> ConsoleSession:
        """The request's open session; a state change must also carry its CSRF token."""
        token = request.cookies.get(COOKIE_NAME)
        if not token:
            raise HTTPException(status_code=401, detail="console_session_required")
        row = await self._db.fetch_one(
            """
            SELECT * FROM {{tables.console_sessions}}
            WHERE token_sha256 = $1 AND closed_at IS NULL AND expires_at > NOW()
            """,
            _sha256(token),
        )
        if row is None:
            raise HTTPException(status_code=401, detail="console_session_required")
        if not (
            await self.passkeys.can_log_in(row["scope"], row["subject"])
            and await self.scopes(row["scope"])
        ):
            await self._close(bytes(row["token_sha256"]))
            raise HTTPException(status_code=401, detail="console_session_required")
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
    """A fixed-window limit on login requests per client, metered per scope.

    A client's window starts at its first request and lasts ``window``.

    Login needs no prior authentication, so without it a flood of login
    requests could keep evicting the real person's challenge. ``admit`` raises
    429 with ``Retry-After`` once a client has made ``limit`` requests in the
    current window. Every request, throttled or not, is counted for its scope,
    and volume older than ``volume_retention`` is dropped as new volume is written.
    """

    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        client_identity: ClientIdentity,
        limit: int,
        window: timedelta,
        volume_retention: timedelta = timedelta(days=30),
    ) -> None:
        if limit <= 0 or window <= timedelta(0) or volume_retention <= timedelta(0):
            raise ValueError("a login limit, its window and the volume retention must be positive")
        self._db = db
        self._identity = client_identity
        self._limit = limit
        self._window = window
        self._volume_retention = volume_retention

    async def admit(self, request: Request, scope: str) -> None:
        client = self._identity.of(request)
        async with self._db.transaction() as tx:
            # Windows that have ended no longer limit anyone; dropping them bounds the table.
            await tx.execute(
                """
                DELETE FROM {{tables.console_login_attempts}}
                WHERE window_start + $1 <= NOW()
                """,
                self._window,
            )
            row = await tx.fetch_one(
                """
                INSERT INTO {{tables.console_login_attempts}} AS a
                    (client_key, window_start, attempts)
                VALUES ($1, NOW(), 1)
                ON CONFLICT (client_key) DO UPDATE SET attempts = a.attempts + 1
                RETURNING attempts,
                    ceil(extract(epoch FROM window_start + $2 - NOW()))::int AS retry_after
                """,
                client,
                self._window,
            )
            if row is None:
                raise RuntimeError("the login attempt was not counted")
            throttled = row["attempts"] > self._limit
            await tx.execute(
                "DELETE FROM {{tables.console_login_volume}} WHERE window_start < NOW() - $1::interval",
                self._volume_retention,
            )
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
                int(throttled),
            )
        if throttled:
            raise HTTPException(
                status_code=429,
                detail="login_rate_limited",
                headers={"Retry-After": str(max(1, row["retry_after"]))},
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
    carries the console headers."""

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
                response = JSONResponse({"detail": jsonable_encoder(error.errors())}, 422)
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
