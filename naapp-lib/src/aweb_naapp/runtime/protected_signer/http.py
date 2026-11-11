"""The shared request-origin prepare/receipt mounts; no signing auth parser."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import asdict
from typing import Any

from awid.log import require_canonical_server_origin
from fastapi import APIRouter, HTTPException, Request

from aweb_naapp.console import ConsoleRoute, LoginLimiter, require_json
from aweb_naapp.console.handoff_wire import HandoffWireRefused, loopback_redirect
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.runtime.approvals import ApprovalRefused, RequestNotCanonical, parse_request_json
from aweb_naapp.runtime.origins import _host, _origin_hosts
from aweb_naapp.runtime.passkeys import ProofContextUnavailable

from .service import ProtectedSigner
from .types import (
    OperationReceipt,
    ProtectedKeyContext,
    ReceiptReader,
    RestrictedRequester,
    RevokeHumanRole,
    SignerRefused,
)

Requester = Callable[[Request, RevokeHumanRole], Awaitable[RestrictedRequester]]
Reader = Callable[[Request, str], Awaitable[ReceiptReader]]
_FIELDS = {"operation_id", "operation", "variant", "scope", "audience", "subject"}
_SCOPE = {"v", "kind", "service_id", "authority", "human", "generation"}
_SUBJECT = {"app_id", "installation_id", "role", "principal"}


def parse_operation(body: Any) -> RevokeHumanRole:
    """One closed operation. Envelope possession is not effect authority."""
    try:
        if not isinstance(body, dict) or not _FIELDS <= set(body) <= _FIELDS | {"redirect_uri"}:
            raise ValueError()
        if body["operation"] != "human-role.revoke" or body["variant"] != "default":
            raise SignerRefused("operation_refused")
        scope, subject = body["scope"], body["subject"]
        if (
            not isinstance(scope, dict)
            or set(scope) != _SCOPE
            or not isinstance(subject, dict)
            or set(subject) != _SUBJECT
        ):
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
        if not all(
            isinstance(v, str) and v
            for v in [body["operation_id"], body["audience"], *subject.values()]
        ):
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
        return RevokeHumanRole(
            body["operation_id"],
            context,
            body["audience"],
            subject["app_id"],
            subject["installation_id"],
            subject["role"],
            subject["principal"],
            redirect,
        )
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


def _http(error: Exception) -> HTTPException:
    if isinstance(error, HTTPException):
        if error.status_code == 429:
            return error
        if error.status_code == 415:
            return HTTPException(415, "json_required")
        code = {401: "requester_invalid", 403: "scope_refused", 503: "receipt_unavailable"}.get(
            error.status_code
        )
        return HTTPException(error.status_code if code else 503, code or "receipt_unavailable")
    if isinstance(error, SignerRefused):
        status = {"scope_refused": 403, "operation_not_found": 404, "operation_conflict": 409}.get(
            error.code, 400
        )
        return HTTPException(status, error.code)
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
    ):
        require_canonical_server_origin(request_origin)
        self.signer, self.requester, self.reader, self.limiter = signer, requester, reader, limiter
        self.hosts = _origin_hosts(request_origin)

    async def _guard(self, request: Request) -> None:
        await self.limiter.admit(request, "protected-operations")
        if _host(request.scope) not in self.hosts:
            raise HTTPException(403, "scope_refused")
        if request.headers.get("cookie") or any(
            k.lower().startswith("x-console-") for k in request.headers
        ):
            raise HTTPException(401, "requester_invalid")

    def api_router(self) -> APIRouter:
        router = APIRouter(route_class=ConsoleRoute)

        @router.post("/protected-operations")
        async def prepare(request: Request):
            try:
                await self._guard(request)
                await require_json(request)
                raw = bytearray()
                async for chunk in request.stream():
                    raw.extend(chunk)
                    if len(raw) > 1024 * 1024:
                        raise SignerRefused("request_invalid")
                # Keep Starlette's exact cached bytes for the existing covering
                # parser; do not reserialize the authenticated HTTP body.
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
