"""Identity-signed holder operations. No pages, passkeys, mail or signer RPC."""

import logging
import sqlite3

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jsonschema import ValidationError

from awid.id_certificates import IDCertificateError, decode_id_chain_header
from awid.request_body_limit import RequestBodyLimitMiddleware
from approval_service.canonical import InvalidJSON, parse
from approval_service.verify import Refused as ApprovalRefused

from .auth import authenticate
from .keys import Refused

logger = logging.getLogger(__name__)


def create_app(holder):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=4 * 1024 * 1024)

    @app.middleware("http")
    async def no_store(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(Refused)
    @app.exception_handler(ApprovalRefused)
    async def refused(_request, error):
        code = error.code
        if code in {
            "request_invalid",
            "identity_key_mismatch",
            "registration_count_mismatch",
            "certificate_mismatch",
        }:
            status = 400
        elif code in {
            "status_unavailable",
            "issuer_unavailable",
            "identity_unavailable",
        }:
            status = 503
        elif code in {
            "state_changed",
            "enrollment_changed",
            "person_already_exists",
            "nonce_conflict",
            "registration_changed",
            "creation_changed",
            "fresh_enrollment_required",
            "enrollment_expired",
        }:
            status = 409
        elif code == "enrollment_unknown":
            status = 404
        elif code in {
            "approver_not_active",
            "target_is_approver",
            "bootstrap_closed",
            "operation_not_served",
        }:
            status = 403
        else:
            status = 401
        return JSONResponse(
            {"error": {"code": code}},
            status_code=status,
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(ValidationError)
    @app.exception_handler(InvalidJSON)
    async def invalid(_request, _error):
        return JSONResponse(
            {"error": {"code": "request_invalid"}},
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(sqlite3.OperationalError)
    async def storage_failure(_request, error):
        logger.exception("Holder storage unavailable", exc_info=error)
        return JSONResponse(
            {"error": {"code": "storage_unavailable"}},
            status_code=503,
            headers={"Cache-Control": "no-store"},
        )

    async def input_for(request):
        caller = await authenticate(request, origin=holder.origin)
        try:
            bundle = decode_id_chain_header(request.headers.get("X-AWID-ID-Chain", ""))
        except IDCertificateError as error:
            raise Refused("identity_chain_required") from error
        value = parse(caller.body)
        return caller, value, bundle["certificates"]

    @app.post("/v1/humans")
    async def humans(request: Request):
        caller, value, chain = await input_for(request)
        if "request_bytes" in value:
            result = await holder.present(caller, value, chain=chain)
            return JSONResponse(result, headers={"Cache-Control": "no-store"})
        if set(value) != {"person", "identity_key", "approver"}:
            raise Refused("request_invalid")
        status, result = await holder.prepare(caller, chain=chain, **value)
        return JSONResponse(
            result, status_code=status, headers={"Cache-Control": "no-store"}
        )

    @app.post("/v1/enrollments/{person}/binding")
    async def binding(person: str, request: Request):
        caller, value, chain = await input_for(request)
        if set(value) != {"material", "registration_count"}:
            raise Refused("request_invalid")
        admitted = await holder.admit(caller, chain)
        result = holder.bind_registration(
            person, **value, caller=caller, admitted=admitted
        )
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.post("/v1/enrollments/{person}/finish")
    async def finish(person: str, request: Request):
        caller, value, chain = await input_for(request)
        result = await holder.finish(person, value, caller=caller, chain=chain)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.post("/v1/enrollments/{person}/activate")
    async def activate(person: str, request: Request):
        caller, value, chain = await input_for(request)
        if value != {}:
            raise Refused("request_invalid")
        result = await holder.activate(person, caller=caller, chain=chain)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    return app
