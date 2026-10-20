"""The console session for an app-origin human page.

A person logs in with a passkey through B3; the login route then opens a
session here. The session lives at most 15 minutes, in a host-only
``__Host-`` cookie that is ``Secure``, ``HttpOnly`` and ``SameSite=Strict``.
Every state-changing request carries the session's CSRF token in
``X-CSRF-Token``. Only hashes of both tokens are stored.

Console routes use :class:`ConsoleRoute`: every response carries the console
headers (a strict CSP with ``frame-ancestors 'none'``, ``Referrer-Policy:
no-referrer`` and ``Cache-Control: no-store``), and a request carrying any
team-auth header is refused, so the console never accepts agent credentials.

Installed with the ``runtime`` extra.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MIGRATIONS_MODULE = "aweb_naapp_console"

MAX_SESSION = timedelta(minutes=15)
COOKIE_NAME = "__Host-console"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
TEAM_AUTH_HEADERS = ("authorization",)
TEAM_AUTH_PREFIX = "x-aweb-"

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


class ConsoleSessions:
    def __init__(self, db: AsyncDatabaseManager, *, ttl: timedelta = MAX_SESSION) -> None:
        if not timedelta(0) < ttl <= MAX_SESSION:
            raise ValueError("a console session lasts more than 0 and at most 15 minutes")
        self._db = db
        self._ttl = ttl

    async def open(self, *, subject: str, scope: str, evidence_ref: str) -> IssuedSession:
        """Open a session for a subject whose passkey login B3 has verified."""
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        expires_at = await self._db.fetch_value(
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
        await self._db.execute(
            "UPDATE {{tables.console_sessions}} SET closed_at = NOW() WHERE token_sha256 = $1",
            session.token_sha256,
        )


def _carries_team_auth(request: Request) -> bool:
    return any(
        name in TEAM_AUTH_HEADERS or name.startswith(TEAM_AUTH_PREFIX)
        for name in (key.lower() for key in request.headers.keys())
    )


class ConsoleRoute(APIRoute):
    """A route on the console origin: console headers, and no team-auth."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def console_handler(request: Request) -> Response:
            if _carries_team_auth(request):
                response: Response = JSONResponse({"detail": "team_auth_not_accepted"}, 403)
            else:
                try:
                    response = await handler(request)
                except HTTPException as error:
                    response = JSONResponse(
                        {"detail": error.detail}, error.status_code, headers=error.headers
                    )
            response.headers.update(CONSOLE_HEADERS)
            return response

        return console_handler
