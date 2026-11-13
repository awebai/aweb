"""The shared request-origin prepare/receipt mounts; no signing auth parser."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from math import ceil
from typing import Any
from urllib.parse import urlencode

from awid.log import require_canonical_server_origin
from fastapi import APIRouter, HTTPException, Request

from aweb_naapp.console import (
    ConsoleRoute,
    ConsoleSession,
    ConsoleSessions,
    LoginLimiter,
    require_json,
)
from aweb_naapp.console.handoff_wire import HandoffWireRefused, loopback_redirect
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.runtime.approvals import ApprovalRefused, RequestNotCanonical, parse_request_json
from aweb_naapp.runtime.origins import _host, _origin_hosts
from aweb_naapp.runtime.passkeys import ProofContextUnavailable

from .catalog import operation_spec
from .service import ProtectedSigner
from .types import (
    AdmittedHuman,
    OperationReceipt,
    OwnerActOperation,
    ProtectedKeyContext,
    ReceiptReader,
    RestrictedRequester,
    RevokeHumanRole,
    SignerRefused,
)

Requester = Callable[[Request, RevokeHumanRole | OwnerActOperation], Awaitable[RestrictedRequester]]
Reader = Callable[[Request, str], Awaitable[ReceiptReader]]
_FIELDS = {"operation_id", "operation", "variant", "scope", "audience", "subject"}
_SCOPE = {"v", "kind", "service_id", "authority", "human", "generation"}


def parse_operation(body: Any) -> RevokeHumanRole | OwnerActOperation:
    """The closed catalog selects the typed codec; possession is not authority."""
    try:
        if not isinstance(body, dict) or not _FIELDS <= set(body) <= _FIELDS | {"redirect_uri"}:
            raise ValueError()
        definition = operation_spec(body["operation"], body["variant"])
        scope, subject = body["scope"], body["subject"]
        if not isinstance(scope, dict) or set(scope) != _SCOPE or not isinstance(subject, dict):
            raise ValueError()
        authority, human = scope["authority"], scope["human"]
        if type(scope["v"]) is not int or scope["v"] != 1 or scope["kind"] != "protected_key":
            raise ValueError()
        if (
            not isinstance(authority, dict)
            or set(authority) != {"kind", "id", "domain"}
            or not isinstance(human, dict)
            or set(human) != {"id", "domain"}
        ):
            raise ValueError()
        if not all(isinstance(v, str) and v for v in [body["operation_id"], body["audience"]]):
            raise ValueError()
        context = ProtectedKeyContext(
            scope["service_id"],
            authority["kind"],
            authority["id"],
            authority["domain"],
            human["id"],
            human["domain"],
            scope["generation"],
        )
        redirect = loopback_redirect(body["redirect_uri"]) if "redirect_uri" in body else None
        if definition.codec.decode_intent is None:
            raise SignerRefused("operation_not_served")
        return definition.codec.decode_intent(body, context, redirect)
    except HandoffWireRefused:
        raise SignerRefused("redirect_uri_refused") from None
    except (ValueError, TypeError, KeyError, ProofContextUnavailable) as exc:
        if isinstance(exc, SignerRefused):
            raise
        raise SignerRefused("request_invalid") from None


def receipt_json(receipt: OperationReceipt) -> dict[str, Any]:
    if receipt.state == "pending":
        return {"state": "pending", "reason": receipt.code, "expires_at": receipt.expires_at}
    if receipt.state == "committed":
        return {"state": "committed", "result": receipt.result}
    return {"state": receipt.state, "code": receipt.code}


def _retry_after_headers(error: SignerRefused) -> dict[str, str] | None:
    """Diagnostic only: invalid hints never mask the original refusal.

    Keep standard delta-seconds representable on all supported clients. A
    caller still checks this hint against its original operation deadline.
    """
    value = error.retry_after_seconds
    if value is None or type(value) not in (int, float) or not 0 <= value <= 2**31 - 1:
        return None
    return {"Retry-After": str(ceil(value))}


def _http(error: Exception) -> HTTPException:
    if isinstance(error, HTTPException):
        if error.status_code == 429:
            return error
        if error.status_code == 415:
            return HTTPException(415, "json_required")
        code = {401: "requester_invalid", 403: "scope_refused", 503: "receipt_unavailable"}.get(
            error.status_code
        )
        if code:
            return HTTPException(error.status_code, code)
        if 400 <= error.status_code < 500:
            return HTTPException(401, "requester_invalid")
        return HTTPException(503, "receipt_unavailable")
    if isinstance(error, SignerRefused):
        status, code = {
            "request_invalid": (400, "request_invalid"),
            "redirect_uri_refused": (400, "redirect_uri_refused"),
            "operation_refused": (400, "operation_refused"),
            "operation_not_served": (400, "operation_not_served"),
            "requester_invalid": (401, "requester_invalid"),
            "scope_refused": (403, "scope_refused"),
            "authority_changed": (403, "authority_changed"),
            "policy_changed": (403, "policy_changed"),
            "live_approval_required": (403, "live_approval_required"),
            "admission_policy_missing": (403, "admission_policy_missing"),
            "admission_limit_reached": (403, "admission_limit_reached"),
            "subject_ineligible": (403, "subject_ineligible"),
            "operation_not_found": (404, "operation_not_found"),
            "operation_conflict": (409, "operation_conflict"),
            "evidence_unavailable": (503, "receipt_unavailable"),
            "receipt_unavailable": (503, "receipt_unavailable"),
        }.get(error.code, (403, "operation_refused"))
        return HTTPException(
            status, code, headers=_retry_after_headers(error) if status == 503 else None
        )
    if isinstance(error, (Refused, RequestNotCanonical)):
        return HTTPException(400, "request_invalid")
    if isinstance(error, ApprovalRefused):
        return HTTPException(403, "operation_refused")
    return HTTPException(503, "receipt_unavailable")


class ProtectedOperationsHTTP:
    """Attach once through ConsoleHandoffs.api_router or a standalone router.

    Requester/reader callbacks authenticate the actual restricted credential,
    configured request origin/service and exact scope. .4 supplies covering-v2
    verification; this module never replaces it or interprets cookies as actors.
    Both callbacks return trusted types, which the shared service independently
    checks against current SQL authority. They perform no signing or approvals.
    """

    def __init__(
        self,
        signer: ProtectedSigner,
        *,
        request_origin: str,
        requester: Requester,
        reader: Reader,
        limiter: LoginLimiter,
        executor: Callable[[Request, str], Awaitable[RestrictedRequester]] | None = None,
        policy_reader: Callable[[Request, str], Awaitable[dict[str, Any]]] | None = None,
        human_sessions: ConsoleSessions | None = None,
        human_csrf_key: str | None = None,
    ):
        require_canonical_server_origin(request_origin)
        self.signer, self.requester, self.reader, self.limiter = signer, requester, reader, limiter
        self.policy_reader, self.executor = policy_reader, executor
        self.hosts = _origin_hosts(request_origin)
        if (human_sessions is None) != (human_csrf_key is None):
            raise ValueError("human sessions and CSRF storage key must be configured together")
        if human_sessions is not None and (
            human_sessions._db is not signer.db
            or human_sessions.passkeys is not signer.passkeys
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", human_csrf_key or "")
        ):
            raise ValueError("human mount needs the same database/B3 and an explicit CSRF key")
        self.human_sessions, self.human_csrf_key = human_sessions, human_csrf_key
        self.human_origin = signer.passkeys.rp.origin
        self.human_hosts = _origin_hosts(self.human_origin)

    async def _guard(self, request: Request) -> None:
        await self.limiter.admit(
            request, "protected-operations", bucket="protected.operations.client"
        )
        if _host(request.scope) not in self.hosts:
            raise HTTPException(403, "scope_refused")
        if request.headers.get("cookie") or any(
            k.lower().startswith("x-console-") for k in request.headers
        ):
            raise HTTPException(401, "requester_invalid")

    def api_router(self) -> APIRouter:
        router = APIRouter(route_class=ConsoleRoute)

        if self.policy_reader is not None:
            @router.get("/protected-admission-policies")
            async def admission_policy(request: Request):
                try:
                    await self._guard(request)
                    if set(request.query_params) != {"team_id"} or len(request.query_params.getlist("team_id")) != 1:
                        raise SignerRefused("request_invalid")
                    async for chunk in request.stream():
                        if chunk:
                            raise SignerRefused("request_invalid")
                    request._body = b""
                    assert self.policy_reader is not None
                    return await self.policy_reader(request, request.query_params["team_id"])
                except Exception as error:
                    raise _http(error) from None

        @router.post("/protected-operations")
        async def prepare(request: Request):
            try:
                await self._guard(request)
                await require_json(request)
                raw = bytearray()
                async for chunk in request.stream():
                    raw.extend(chunk)
                    if len(raw) > 64 * 1024:
                        raise SignerRefused("request_invalid")
                # Starlette Request.body() uses _body as its cache. The real
                # covering-verifier route test pins these exact cached bytes.
                request._body = bytes(raw)
                operation = parse_operation(parse_request_json(bytes(raw)))
                requester = await self.requester(request, operation)
                if type(requester) is not RestrictedRequester:
                    raise HTTPException(401, "requester_invalid")
                prepared = await self.signer.prepare(operation, requester=requester)
                result = asdict(prepared)
                frozen = prepared.payload
                result["payload"] = {
                    "policy": {"ref": frozen["policy_ref"], "version": frozen["policy_version"]},
                    "request": frozen,
                }
                return result
            except Exception as error:
                raise _http(error) from None

        if self.executor is not None:
            @router.post("/protected-operations/{operation_id}/execute")
            async def execute_request(operation_id: str, request: Request):
                try:
                    await self._guard(request)
                    async for chunk in request.stream():
                        if chunk:
                            raise SignerRefused("request_invalid")
                    request._body = b""
                    assert self.executor is not None
                    requester = await self.executor(request, operation_id)
                    if type(requester) is not RestrictedRequester:
                        raise SignerRefused("requester_invalid")
                    return receipt_json(await self.signer.execute_request(operation_id, requester=requester))
                except Exception as error:
                    raise _http(error) from None

        @router.get("/protected-operations/{operation_id}")
        async def receipt(operation_id: str, request: Request):
            try:
                await self._guard(request)
                async for chunk in request.stream():
                    if chunk:
                        raise SignerRefused("request_invalid")
                request._body = b""
                reader = await self.reader(request, operation_id)
                if type(reader) is not ReceiptReader:
                    raise HTTPException(401, "requester_invalid")
                return receipt_json(await self.signer.receipt(operation_id, reader=reader))
            except Exception as error:
                raise _http(error) from None

        return router

    async def page_context(self, handoff_id: str) -> dict[str, str] | None:
        """Public stored routing facts for the one existing page dispatcher.

        This grants no session, payload read or signing authority. The caller
        serves its existing page once; the human JSON routes reauthenticate.
        """
        if self.human_sessions is None:
            return None
        retained = await self.signer.lookup_handoff(handoff_id)
        if retained is None or not await self.human_sessions.scopes(retained["login_scope"]):
            return None
        assert self.human_csrf_key is not None
        return {"b3_scope": retained["login_scope"], "csrf_key": self.human_csrf_key}

    async def _human(self, handoff_id, request):
        if self.human_sessions is None:
            raise HTTPException(503, "human_admission_unavailable")
        await self.limiter.admit(request, "protected-human", bucket="protected.human.client")
        if _host(request.scope) not in self.human_hosts or (
            request.method != "GET" and request.headers.get("Origin") != self.human_origin
        ):
            raise HTTPException(403, "scope_refused")
        if request.headers.get("authorization") or any(
            name.lower().startswith("x-console-") for name in request.headers
        ):
            raise HTTPException(401, "console_session_required")
        # current() checks the genuine shared LOGIN, current credential/scope,
        # and, for every POST, its original console CSRF token.
        session = await self.human_sessions.current(request)
        if type(session) is not ConsoleSession:
            raise HTTPException(401, "console_session_required")
        retained = await self.signer.lookup_handoff(handoff_id)
        if retained is None:
            raise SignerRefused("operation_not_found")
        if session.scope != retained["login_scope"]:
            raise HTTPException(401, "console_session_required")
        human = AdmittedHuman(
            retained["context"].human_id, session.subject, session.scope, retained["context"]
        )
        return retained["operation_id"], human, session

    @staticmethod
    def _human_error(error):
        # Human authentication has its existing codes, distinct from restricted
        # requester credentials. Never send callback exception details.
        if isinstance(error, HTTPException) and error.detail in {
            "console_session_required",
            "csrf_token_required",
            "scope_refused",
            "human_admission_unavailable",
            "json_required",
        }:
            return error
        if isinstance(error, SignerRefused) and error.code == "console_session_required":
            return HTTPException(401, "console_session_required")
        return _http(error)

    async def _human_body(self, request, fields):
        await require_json(request)
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 64 * 1024:
                raise SignerRefused("request_invalid")
        body = parse_request_json(bytes(raw))
        if not isinstance(body, dict) or set(body) != fields:
            raise SignerRefused("request_invalid")
        return body

    def human_router(self) -> APIRouter:
        """Only governance JSON; console owns the existing HTML page and LOGIN."""
        router = APIRouter(route_class=ConsoleRoute)

        @router.get("/handoff/{handoff_id}/governance")
        async def state(handoff_id: str, request: Request):
            try:
                operation_id, human, session = await self._human(handoff_id, request)
                prepared = await self.signer.inspect(
                    operation_id, human=human, human_session=session
                )
                receipt = await self.signer.receipt(
                    operation_id, reader=human, human_session=session
                )
                result = asdict(prepared)
                frozen = prepared.payload
                result["payload"] = {
                    "policy": {"ref": frozen["policy_ref"], "version": frozen["policy_version"]},
                    "request": frozen,
                }
                return {"mode": "governance", **result, **receipt_json(receipt)}
            except Exception as error:
                raise self._human_error(error) from None

        @router.post("/handoff/{handoff_id}/governance/options")
        async def options(handoff_id: str, request: Request):
            try:
                operation_id, human, session = await self._human(handoff_id, request)
                await self._human_body(request, set())
                return dict(
                    await self.signer.approval_options(
                        operation_id, human=human, human_session=session
                    )
                )
            except Exception as error:
                raise self._human_error(error) from None

        @router.post("/handoff/{handoff_id}/governance/execute")
        async def execute(handoff_id: str, request: Request):
            try:
                operation_id, human, session = await self._human(handoff_id, request)
                body = await self._human_body(request, {"assertion"})
                if not isinstance(body["assertion"], dict):
                    raise SignerRefused("request_invalid")
                prepared = await self.signer.inspect(
                    operation_id, human=human, human_session=session
                )
                receipt = await self.signer.execute(
                    operation_id, body["assertion"], human=human, human_session=session
                )
                result = receipt_json(receipt)
                redirect = prepared.payload.get("redirect_uri")
                if receipt.state == "committed" and redirect is not None:
                    result["redirect_uri"] = redirect + "?" + urlencode({"handoff_id": handoff_id})
                return result
            except Exception as error:
                raise self._human_error(error) from None

        return router
