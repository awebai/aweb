"""Identity-signed holder operations. No pages, passkeys, mail or signer RPC."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from http import HTTPStatus

from approval_service.canonical import InvalidJSON, parse
from approval_service.grading import watch_metadata
from approval_service.verify import Refused as ApprovalRefused
from awid.id_certificates import IDCertificateError, decode_id_chain_header
from awid.request_body_limit import RequestBodyLimitMiddleware
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jsonschema import ValidationError
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from .auth import Caller, authenticate
from .binding_refresh import HolderBindingRefresher
from .enrollment import HOLDER_BINDING, Holder, HolderAnswer, WireObject
from .refusals import Refusal, Refused, describe_refusal

logger = logging.getLogger(__name__)


def refusal_response(
    error: ApprovalRefused, *, cause: Exception | None = None
) -> JSONResponse:
    """Render the README refusal contract and log the real server-side cause."""
    failure = describe_refusal(error)
    if failure.status >= HTTPStatus.INTERNAL_SERVER_ERROR:
        logger.error(
            "Holder authority or storage failure (%r)",
            failure.code,
            exc_info=cause or error,
        )
    body = {"error": {"code": failure.code}}
    if failure.advice is not None:
        body["error"]["message"] = failure.advice
    return JSONResponse(
        body, status_code=failure.status, headers={"Cache-Control": "no-store"}
    )


def create_app(holder: Holder) -> FastAPI:
    """Mount only identity-signed holder operations and their refusal boundary."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        async with watch_metadata(holder.grading):
            yield

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=4 * 1024 * 1024)

    @app.middleware("http")
    async def no_store(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(Refused)
    @app.exception_handler(ApprovalRefused)
    async def refused(_request: Request, error: ApprovalRefused) -> JSONResponse:
        return refusal_response(error)

    @app.exception_handler(ValidationError)
    @app.exception_handler(InvalidJSON)
    async def invalid(_request: Request, _error: Exception) -> JSONResponse:
        return refusal_response(Refused(Refusal.REQUEST_INVALID))

    @app.exception_handler(sqlite3.OperationalError)
    async def storage_failure(
        _request: Request, error: sqlite3.OperationalError
    ) -> JSONResponse:
        return refusal_response(Refused(Refusal.STORAGE_UNAVAILABLE), cause=error)

    async def input_for(
        request: Request,
    ) -> tuple[Caller, WireObject, list[WireObject]]:
        caller = await authenticate(request, origin=holder.origin)
        try:
            header = request.headers.get("X-AWID-ID-Chain", "")
            bundle = decode_id_chain_header(header) if header else {"certificates": []}
        except IDCertificateError as error:
            raise Refused(Refusal.IDENTITY_CHAIN_REQUIRED) from error
        value = parse(caller.body)
        return caller, value, bundle["certificates"]

    @app.post("/v1/humans")
    async def humans(request: Request) -> JSONResponse:
        caller, value, chain = await input_for(request)
        await holder.admit(caller, chain)
        if "request_bytes" in value:
            result = await holder.present(caller, value, chain=chain)
            return JSONResponse(result, headers={"Cache-Control": "no-store"})
        if set(value) != {"person", "identity_key", "approver"}:
            raise Refused(Refusal.REQUEST_INVALID)
        status, result = await holder.prepare(caller, chain=chain, **value)
        return JSONResponse(
            result, status_code=status, headers={"Cache-Control": "no-store"}
        )

    @app.post("/v1/enrollments/{person}", response_model=None)
    async def enrollment_start(person: str, request: Request) -> HolderAnswer:
        caller, value, chain = await input_for(request)
        await holder.admit(caller, chain)
        holder.require_approval()
        if (
            set(value) != {"requester"}
            or value["requester"] != caller.descriptor
            or caller.identity != person
        ):
            raise Refused(Refusal.REQUESTER_MISMATCH)
        return await holder.enroll_existing(caller, person=person, chain=chain)

    @app.post("/v1/enrollments/{person}/binding")
    async def binding(person: str, request: Request) -> JSONResponse:
        caller, value, chain = await input_for(request)
        if set(value) != {"material", "registration_count"}:
            raise Refused(Refusal.REQUEST_INVALID)
        admitted, current = await holder.enrollment_admission(
            person, caller, chain, purpose=HOLDER_BINDING
        )
        result = holder.bind_registration(
            person, **value, caller=caller, admitted=admitted, current=current
        )
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.post("/v1/enrollments/{person}/finish")
    async def finish(person: str, request: Request) -> JSONResponse:
        caller, value, chain = await input_for(request)
        result = await holder.finish(person, value, caller=caller, chain=chain)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.post("/v1/enrollments/{person}/activate")
    async def activate(person: str, request: Request) -> JSONResponse:
        caller, value, chain = await input_for(request)
        if value != {}:
            raise Refused(Refusal.REQUEST_INVALID)
        result = await holder.activate(person, caller=caller, chain=chain)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.post("/v1/enrollments/{person}/refresh-binding", response_model=None)
    async def refresh_binding(person: str, request: Request) -> WireObject:
        caller, value, chain = await input_for(request)
        try:
            return await HolderBindingRefresher(holder=holder).packet(
                person=person, caller=caller, body=value, chain=chain
            )
        except (Refused, ApprovalRefused) as error:
            logger.info("Holder binding refresh refused (%s)", error.code)
            raise

    return app
