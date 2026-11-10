"""Shared handoff factory: exact LOGIN, retained certificate and signed sessions.

All remote admission precedes effect transactions. App callbacks retain their
own holding authority; this module never reads app tables or invents a scope.
"""

import base64
import hmac
import json
import secrets
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime

from awid.team_certificate import TeamCertificateError, decode_team_certificate
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pgdbm import AsyncDatabaseManager

from aweb_naapp.console import (
    MAX_SESSION,
    ConsoleRoute,
    KeyBoundConsoleSession,
    LoginLimiter,
    _prune_sessions,
    require_json,
)
from aweb_naapp.console.handoff_authority import HandoffAuthority, PublicScope
from aweb_naapp.console.handoff_credential import (
    _BROWSER,
    _hash,
    _id,
    _scope,
    _token,
    credential_handoff_router,
)
from aweb_naapp.console.handoff_store import HandoffStart, HandoffStore, handoff_start_router
from aweb_naapp.console.handoff_wire import (
    HandoffWireRefused,
    console_payload,
    verify_console_request,
)
from aweb_naapp.runtime.approvals import AuthenticationFailed
from aweb_naapp.runtime.approvals.request import parse_request_json
from aweb_naapp.runtime.human_member import HumanMemberProof
from aweb_naapp.runtime.passkeys import Passkeys
from aweb_naapp.runtime.passkeys.service import _client_challenge
from aweb_naapp.runtime.team_auth import Principal


def _required() -> HTTPException:
    return HTTPException(401, "console_session_required")


def _refused() -> HTTPException:
    return HTTPException(403, "handoff_refused")


async def _body(request: Request, fields: set[str]) -> dict:
    raw = await request.body()
    try:
        if len(raw) > 64 * 1024:
            raise ValueError()
        body = parse_request_json(raw)
        if not isinstance(body, dict) or set(body) != fields:
            raise ValueError()
        return body
    except (ValueError, TypeError, RecursionError):
        raise _refused() from None


def _scope_for(row) -> PublicScope:
    return PublicScope(**_scope(row))


class _RequestBinding:
    def __init__(self, factory, target, proof, identity):
        self.factory, self.target, self.proof, self.identity = factory, target, proof, identity
        self.session = None
        self.prepared = None

    async def prepare(self, tx, session, pairs):
        if session is not self.session:
            raise _required()
        self.proof.require_fresh()
        prior = self.prepared
        target = prior[1] if prior is not None and prior[0] is tx else self.target
        try:
            held = await self.factory.authority.hold_session_target(
                tx,
                target,
                approver_pairs=pairs,
            )
        except HTTPException as exc:
            if exc.status_code == 403 and exc.detail == "owner_required":
                raise HTTPException(403, "role_not_held") from None
            raise
        # All B3 rows/credentials are already in the canonical held union.
        if not await self.factory.passkeys.login_evidence_is_current(
            session.scope,
            session.subject,
            session.evidence_ref,
            tx=tx,
            hold=False,
        ):
            raise _required()
        if self.factory.authority.holding_identity(self.target) != self.identity:
            raise HTTPException(403, "role_not_held")
        row = await tx.fetch_one(
            "SELECT scope,subject,evidence_ref,expires_at,closed_at,client_key "
            "FROM {{tables.console_sessions}} WHERE token_sha256=$1 FOR SHARE",
            session.token_sha256,
        )
        if (
            row is None
            or row["closed_at"] is not None
            or row["client_key"] is None
            or (row["scope"], row["subject"], row["evidence_ref"], row["expires_at"])
            != (session.scope, session.subject, session.evidence_ref, session.expires_at)
            or session.expires_at <= datetime.now(UTC)
        ):
            raise _required()
        self.proof.require_fresh()
        self.prepared = tx, held
        return held

    async def check(self, tx, session, *, hold):
        if session is not self.session:
            return False
        if hold:
            pairs = (
                self.prepared[1].approver_pairs
                if self.prepared is not None and self.prepared[0] is tx
                else [(session.scope, session.subject)]
            )
            await self.prepare(tx, session, pairs)
        if self.prepared is None or self.prepared[0] is not tx:
            return False
        if not await self.factory.authority.check_session_target(tx, self.prepared[1]):
            return False
        if not await self.factory.passkeys.login_evidence_is_current(
            session.scope,
            session.subject,
            session.evidence_ref,
            tx=tx,
            hold=False,
        ):
            raise _required()
        row = await tx.fetch_one(
            "SELECT scope,subject,evidence_ref,expires_at,closed_at,client_key "
            "FROM {{tables.console_sessions}} WHERE token_sha256=$1"
            + (" FOR SHARE" if hold else ""),
            session.token_sha256,
        )
        self.proof.require_fresh()
        return (
            row is not None
            and row["closed_at"] is None
            and row["client_key"] is not None
            and (row["scope"], row["subject"], row["evidence_ref"], row["expires_at"])
            == (session.scope, session.subject, session.evidence_ref, session.expires_at)
            and session.expires_at > datetime.now(UTC)
        )


class ConsoleHandoffs:
    """Factory-owned dependencies, explicit preparation and a non-locking fence.

    Mount api_router on the pinned API origin and human_router on the pinned
    passkey origin. Console consumers use current and prepare; their final
    session_is_current(hold=False) reuses the original prepared app/B3 handle.
    """

    def __init__(
        self,
        *,
        db: AsyncDatabaseManager,
        passkeys: Passkeys,
        authority: HandoffAuthority,
        principal: Callable[[Request], Awaitable[Principal]],
        human_member: Callable[..., Awaitable[HumanMemberProof]],
        limiter: LoginLimiter,
    ):
        self.db, self.passkeys, self.authority = db, passkeys, authority
        self.principal, self.human_member, self.limiter = principal, human_member, limiter
        self.store = HandoffStore(db)

    async def prune(self) -> None:
        """Bounded post-commit cleanup, never part of request authentication."""
        await _prune_sessions(self.db)
        await self.store.prune()

    async def _target(self, scope):
        try:
            return await self.authority.session_target(scope)
        except HTTPException as exc:
            if exc.status_code == 403 and exc.detail == "owner_required":
                raise HTTPException(403, "role_not_held") from None
            raise

    async def _proof(self, target, certificate):
        try:
            decoded = decode_team_certificate(certificate or "")
        except TeamCertificateError:
            raise HTTPException(403, "principal_not_member") from None
        return await self.human_member(
            target.team_id,
            principal=target.public_scope.principal,
            certificate=decoded,
        )

    async def check_holding_member(self, scope: PublicScope) -> HumanMemberProof:
        """Refresh shared retained evidence for the app's browser admission.

        Scope selects no authority. The app supplies its actual holding and
        separately prepares role/B3/session fences. Retain this proof's original
        deadline through those waits and recheck it at the final effect fence.
        Legacy holdings with no artifact require a fresh certificate handoff.
        """
        target = await self._target(scope)
        row = await self.db.fetch_one(
            "SELECT holding_identity,member_certificate FROM {{tables.console_holding_certificates}} "
            "WHERE installation_id=$1 AND role=$2 AND principal=$3",
            scope.installation_id,
            scope.role,
            scope.principal,
        )
        if row is None or row["holding_identity"] != self.authority.holding_identity(target):
            raise HTTPException(403, "principal_not_member")
        proof = await self._proof(target, row["member_certificate"])
        proof.require_fresh()
        return proof

    async def _context(self, row):
        target = await self._target(_scope_for(row))
        if row["login_evidence_ref"] and not await self.passkeys.login_evidence_is_current(
            row["b3_scope"],
            row["subject"],
            row["login_evidence_ref"],
            hold=False,
        ):
            raise _required()
        if (target.b3_scope, target.subject) != (row["b3_scope"], row["subject"]):
            raise _required()
        if self.authority.holding_identity(target) != row["holding_identity"]:
            raise HTTPException(403, "role_not_held")
        proof = await self._proof(target, row["member_certificate"])
        return target, proof

    async def _hold(self, tx, row, target, proof):
        try:
            held = await self.authority.hold_session_target(
                tx,
                target,
                approver_pairs=[(target.b3_scope, target.subject)],
            )
        except HTTPException as exc:
            if exc.status_code == 403 and exc.detail == "owner_required":
                raise HTTPException(403, "role_not_held") from None
            raise
        if row["login_evidence_ref"] and not await self.passkeys.login_evidence_is_current(
            row["b3_scope"],
            row["subject"],
            row["login_evidence_ref"],
            tx=tx,
            hold=False,
        ):
            raise _required()
        proof.require_fresh()
        return held

    async def _start(self, start: HandoffStart, signer: Principal, request: Request):
        target = await self._target(start.scope)
        if target.team_id != signer.team_id:
            raise HTTPException(403, "principal_not_member")
        certificate = request.headers.get("X-AWID-Team-Certificate", "")
        proof = await self._proof(target, certificate)
        async with self.db.transaction() as tx:
            await self._hold(tx, {"login_evidence_ref": None}, target, proof)
            created = await self.store.create(start, tx=tx)
            await tx.execute(
                "UPDATE {{tables.console_handoffs}} SET team_id=$2,b3_scope=$3,subject=$4,"
                "holding_identity=$5,member_certificate=$6 WHERE handoff_id=$1",
                _id(created["handoff_id"]),
                target.team_id,
                target.b3_scope,
                target.subject,
                self.authority.holding_identity(target),
                certificate,
            )
            proof.require_fresh()
        await self.store.prune()
        return created

    def api_router(self):
        return handoff_start_router(
            store=self.store,
            limiter=self.limiter,
            principal=self.principal,
            session_start=self._start,
        )

    async def prepare(self, tx, session, *, approver_pairs: Sequence[tuple[str, str]]):
        if not isinstance(session, KeyBoundConsoleSession):
            raise _required()
        binding = session._binding
        if not isinstance(binding, _RequestBinding) or binding.factory is not self:
            raise _required()
        return await binding.prepare(tx, session, approver_pairs)

    async def current(self, request: Request) -> KeyBoundConsoleSession:
        try:
            lookup = console_payload(request).get("session_id")
            lookup = _token(lookup)
        except (HandoffWireRefused, HTTPException):
            raise _required() from None
        digest = _hash(lookup)
        async with self.db.transaction() as tx:
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.console_sessions}} WHERE token_sha256=$1 "
                "AND client_key IS NOT NULL AND closed_at IS NULL AND expires_at>clock_timestamp()",
                digest,
            )
            if row is None:
                raise _required()
            try:
                nonce = await verify_console_request(
                    request,
                    origin=self.passkeys.rp.origin,
                    client_key=row["client_key"],
                    domain="handoff-session",
                    subject_field="session_id",
                    subject=lookup,
                    now=datetime.now(UTC),
                )
            except HandoffWireRefused:
                raise _required() from None
            if request.method != "GET" and not hmac.compare_digest(
                _hash(request.headers.get("X-CSRF-Token", "")),
                bytes(row["csrf_sha256"]),
            ):
                raise _required()
            inserted = await tx.fetch_value(
                "INSERT INTO {{tables.console_session_nonces}} VALUES($1,$2) "
                "ON CONFLICT DO NOTHING RETURNING nonce",
                digest,
                nonce,
            )
            if inserted is None:
                raise _required()
        # No network occurs inside the nonce/effect transactions.
        scope = _scope_for(row)
        target = await self._target(scope)
        if not await self.passkeys.login_evidence_is_current(
            row["scope"],
            row["subject"],
            row["evidence_ref"],
            hold=False,
        ):
            raise _required()
        proof = await self._proof(target, row["member_certificate"])
        binding = _RequestBinding(self, target, proof, row["holding_identity"])
        session = KeyBoundConsoleSession(
            row["subject"],
            row["scope"],
            row["evidence_ref"],
            row["expires_at"],
            digest,
            scope.installation_id,
            scope.role,
            scope.principal,
            binding,
        )
        binding.session = session
        # The exact retired LOGIN is checked before any changed digest.
        if self.authority.holding_identity(target) != row["holding_identity"]:
            raise HTTPException(403, "role_not_held")
        proof.require_fresh()
        if session.expires_at <= datetime.now(UTC):
            raise _required()
        # Dependency admission also fences reads. The handle belongs only to
        # this short transaction; an effect caller prepares its own complete
        # union in its original transaction and cannot borrow this one.
        async with self.db.transaction() as tx:
            await binding.prepare(tx, session, [(session.scope, session.subject)])
            if not await binding.check(tx, session, hold=False):
                raise _required()
        return session

    async def _row(self, handoff_id):
        row = await self.db.fetch_one(
            "SELECT * FROM {{tables.console_handoffs}} WHERE handoff_id=$1 AND purpose='session' "
            "AND expires_at>clock_timestamp() AND completed_at IS NULL AND released_at IS NULL",
            _id(handoff_id),
        )
        if row is None or not row["member_certificate"]:
            raise _refused()
        return row

    async def _browser_row(self, handoff_id, request):
        row = await self._row(handoff_id)
        if request.headers.get("Origin") != self.passkeys.rp.origin or not all(
            (
                row["browser_sha256"],
                row["csrf_sha256"],
                hmac.compare_digest(
                    _hash(request.cookies.get(_BROWSER, "")), bytes(row["browser_sha256"] or b"")
                ),
                hmac.compare_digest(
                    _hash(request.headers.get("X-CSRF-Token", "")), bytes(row["csrf_sha256"] or b"")
                ),
            )
        ):
            raise _refused()
        return row

    async def _collect(self, handoff_id, request):
        candidate = await self.db.fetch_one(
            "SELECT * FROM {{tables.console_handoffs}} WHERE handoff_id=$1",
            _id(handoff_id),
        )
        if candidate is None or candidate["purpose"] != "session":
            return None  # The existing credential collector owns the other purpose.
        if (
            candidate["released_at"] is not None
            or candidate["completed_at"] is None
            or candidate["expires_at"] <= datetime.now(UTC)
        ):
            raise _refused()
        body = await _body(request, {"v", "code", "verifier"})
        if type(body["v"]) is not int or body["v"] != 1:
            raise _refused()
        code, verifier = _token(body["code"]), _token(body["verifier"])
        try:
            await verify_console_request(
                request,
                origin=self.passkeys.rp.origin,
                client_key=candidate["client_key"],
                domain="handoff-result",
                subject_field="handoff_id",
                subject=handoff_id,
                now=datetime.now(UTC),
            )
        except HandoffWireRefused:
            raise _refused() from None
        target, proof = await self._context(candidate)
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        async with self.db.transaction() as tx:
            held = await self._hold(tx, candidate, target, proof)
            row = await tx.fetch_one(
                "SELECT * FROM {{tables.console_handoffs}} WHERE handoff_id=$1 FOR UPDATE",
                _id(handoff_id),
            )
            if (
                row["released_at"] is not None
                or row["completed_at"] is None
                or row["expires_at"] <= datetime.now(UTC)
                or not hmac.compare_digest(_hash(code), bytes(row["code_sha256"] or b""))
                or not hmac.compare_digest(_hash(verifier), bytes(row["verifier_sha256"]))
            ):
                raise _refused()
            expires = await tx.fetch_value(
                "INSERT INTO {{tables.console_sessions}} "
                "(token_sha256,csrf_sha256,subject,scope,evidence_ref,expires_at,client_key,"
                "public_scope,holding_identity,member_certificate) VALUES "
                "($1,$2,$3,$4,$5,clock_timestamp()+$6,$7,$8::jsonb,$9,$10) RETURNING expires_at",
                _hash(token),
                _hash(csrf),
                row["subject"],
                row["b3_scope"],
                row["login_evidence_ref"],
                MAX_SESSION,
                row["client_key"],
                json.dumps(_scope(row)),
                row["holding_identity"],
                row["member_certificate"],
            )
            await tx.execute(
                "UPDATE {{tables.console_handoffs}} SET released_at=clock_timestamp(),"
                "member_certificate=NULL WHERE handoff_id=$1",
                _id(handoff_id),
            )
            if not await self.authority.check_session_target(tx, held):
                raise _required()
            proof.require_fresh()
        await self.prune()
        return {
            "purpose": "session",
            "session_id": token,
            "csrf_token": csrf,
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
            "scope": _scope(row),
        }

    def human_router(self):
        router = APIRouter(route_class=ConsoleRoute)
        router.include_router(
            credential_handoff_router(
                store=self.store,
                rp=self.passkeys.rp,
                admits=self._credential_admits,
                limiter=self.limiter,
                session_result=self._collect,
            )
        )

        async def limited(request: Request):
            await self.limiter.admit(request, "console.handoff")

        @router.get("/handoff/{handoff_id}/session", dependencies=[Depends(limited)])
        async def state(handoff_id: str, request: Request, response: Response):
            row = await self._row(handoff_id)
            await self._context(row)
            browser = request.cookies.get(_BROWSER) or secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(32)
            claimed = await self.db.fetch_value(
                "UPDATE {{tables.console_handoffs}} SET browser_sha256=$2,csrf_sha256=$3 "
                "WHERE handoff_id=$1 AND completed_at IS NULL AND expires_at>clock_timestamp() "
                "AND (browser_sha256 IS NULL OR browser_sha256=$2) RETURNING handoff_id",
                _id(handoff_id),
                _hash(browser),
                _hash(csrf),
            )
            if claimed is None:
                raise _refused()
            response.set_cookie(
                _BROWSER,
                browser,
                secure=True,
                httponly=True,
                samesite="strict",
                path="/",
                max_age=600,
            )
            return {"scope": _scope(row), "csrf_token": csrf}

        @router.post(
            "/handoff/{handoff_id}/session/options",
            dependencies=[Depends(limited), Depends(require_json)],
        )
        async def options(handoff_id: str, request: Request):
            await _body(request, set())
            row = await self._browser_row(handoff_id, request)
            await self._context(row)
            try:
                options = dict(await self.passkeys.login_options(row["b3_scope"]))
            except AuthenticationFailed:
                raise _required() from None
            changed = await self.db.fetch_value(
                "UPDATE {{tables.console_handoffs}} SET challenge=$2 WHERE handoff_id=$1 "
                "AND completed_at IS NULL AND expires_at>clock_timestamp() RETURNING handoff_id",
                _id(handoff_id),
                options["challenge"],
            )
            if changed is None:
                raise _refused()
            return options

        @router.post(
            "/handoff/{handoff_id}/session/login",
            dependencies=[Depends(limited), Depends(require_json)],
        )
        async def login(handoff_id: str, request: Request):
            body = await _body(request, {"assertion"})
            row = await self._browser_row(handoff_id, request)
            target, proof = await self._context(row)
            challenge = await self.db.fetch_value(
                "UPDATE {{tables.console_handoffs}} SET challenge=NULL WHERE handoff_id=$1 "
                "AND challenge=$2 AND completed_at IS NULL AND expires_at>clock_timestamp() RETURNING $2::text",
                _id(handoff_id),
                row["challenge"],
            )
            try:
                if challenge is None or _client_challenge(
                    body["assertion"]
                ) != base64.urlsafe_b64decode(challenge + "=" * (-len(challenge) % 4)):
                    raise AuthenticationFailed("wrong handoff challenge")
                verified = await self.passkeys.verify_login(row["b3_scope"], body["assertion"])
            except (AuthenticationFailed, ValueError, TypeError, KeyError):
                raise _required() from None
            if verified.subject != row["subject"]:
                raise _required()
            async with self.db.transaction() as tx:
                held = await self._hold(tx, row, target, proof)
                if not await self.passkeys.login_evidence_is_current(
                    target.b3_scope,
                    verified.subject,
                    verified.evidence_ref,
                    tx=tx,
                    hold=False,
                ):
                    raise _required()
                changed = await tx.fetch_value(
                    "UPDATE {{tables.console_handoffs}} SET login_evidence_ref=$2 WHERE handoff_id=$1 "
                    "AND completed_at IS NULL AND expires_at>clock_timestamp() RETURNING handoff_id",
                    _id(handoff_id),
                    verified.evidence_ref,
                )
                if changed is None:
                    raise _refused()
                # Refresh only after this exact holding's own successful LOGIN.
                scope = target.public_scope
                await tx.execute(
                    "INSERT INTO {{tables.console_holding_certificates}} VALUES($1,$2,$3,$4,$5,$6,$7) "
                    "ON CONFLICT(installation_id,role,principal) DO UPDATE SET "
                    "holding_identity=$4,b3_scope=$5,subject=$6,member_certificate=$7",
                    scope.installation_id,
                    scope.role,
                    scope.principal,
                    row["holding_identity"],
                    target.b3_scope,
                    target.subject,
                    row["member_certificate"],
                )
                if not await self.authority.check_session_target(tx, held):
                    raise _required()
                proof.require_fresh()
            return {"logged_in": True}

        @router.post(
            "/handoff/{handoff_id}/session/allow",
            dependencies=[Depends(limited), Depends(require_json)],
        )
        async def allow(handoff_id: str, request: Request):
            body = await _body(request, {"allow"})
            if body["allow"] is not True:
                raise _refused()
            row = await self._browser_row(handoff_id, request)
            if not row["login_evidence_ref"]:
                raise _refused()
            target, proof = await self._context(row)
            code = secrets.token_urlsafe(32)
            async with self.db.transaction() as tx:
                held = await self._hold(tx, row, target, proof)
                changed = await tx.fetch_value(
                    "UPDATE {{tables.console_handoffs}} SET code_sha256=$2,completed_at=clock_timestamp() "
                    "WHERE handoff_id=$1 AND completed_at IS NULL AND expires_at>clock_timestamp() RETURNING handoff_id",
                    _id(handoff_id),
                    _hash(code),
                )
                if changed is None or not await self.authority.check_session_target(tx, held):
                    raise _refused()
                proof.require_fresh()
            from urllib.parse import urlencode

            return {
                "redirect_uri": row["redirect_uri"]
                + "?"
                + urlencode({"handoff_id": handoff_id, "code": code})
            }

        return router

    async def _credential_admits(self, scope):
        try:
            await self.authority.credential_target(PublicScope(**scope))
        except (HTTPException, LookupError):
            return False
        return True
