"""Identity-signed holder operations. No pages, passkeys, mail or signer RPC."""

import logging
import sqlite3
from contextlib import asynccontextmanager

from approval_service.canonical import InvalidJSON, parse
from approval_service.grading import watch_metadata
from approval_service.verify import Refused as ApprovalRefused
from awid.id_certificates import IDCertificateError, decode_id_chain_header
from awid.request_body_limit import RequestBodyLimitMiddleware
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jsonschema import ValidationError

from .auth import authenticate
from .keys import HOLDER_REFUSAL_MESSAGES, Refused

logger = logging.getLogger(__name__)


def create_app(holder):
    @asynccontextmanager
    async def lifespan(_app):
        async with watch_metadata(holder.grading):
            yield

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
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
            "human_approval_unavailable",
            "human_approval_invalid",
            "human_approval_source_required",
            "human_approval_hardware_grading_required",
        }:
            status = 503
        elif code in {
            "state_changed",
            "enrollment_changed",
            "person_already_exists",
            "enrollment_replacement_unavailable",
            "nonce_conflict",
            "registration_changed",
            "creation_changed",
            "fresh_enrollment_required",
            "enrollment_expired",
            "attestation_assessment_unavailable",
        }:
            status = 409
        elif code == "enrollment_unknown":
            status = 404
        elif code in {
            "approver_not_active",
            "person_retired",
            "target_is_approver",
            "bootstrap_closed",
            "operation_not_served",
            "approval_not_configured",
        }:
            status = 403
        else:
            status = 401
        body = {"error": {"code": code}}
        if code in HOLDER_REFUSAL_MESSAGES:
            body["error"]["message"] = HOLDER_REFUSAL_MESSAGES[code]
        if code == "enrollment_replacement_unavailable":
            body["error"]["message"] = (
                "Replacing a lost enrolled key is not implemented. Ask the operator "
                "to revoke the old ID, issue a new ID and enrol again. Enrol two keys."
            )
        return JSONResponse(
            body,
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
            header = request.headers.get("X-AWID-ID-Chain", "")
            bundle = decode_id_chain_header(header) if header else {"certificates": []}
        except IDCertificateError as error:
            raise Refused("identity_chain_required") from error
        value = parse(caller.body)
        return caller, value, bundle["certificates"]

    @app.post("/v1/humans")
    async def humans(request: Request):
        caller, value, chain = await input_for(request)
        await holder.admit(caller, chain)
        if "request_bytes" in value:
            result = await holder.present(caller, value, chain=chain)
            return JSONResponse(result, headers={"Cache-Control": "no-store"})
        if set(value) != {"person", "identity_key", "approver"}:
            raise Refused("request_invalid")
        status, result = await holder.prepare(caller, chain=chain, **value)
        return JSONResponse(
            result, status_code=status, headers={"Cache-Control": "no-store"}
        )

    @app.post("/v1/enrollments/{person}")
    async def enrollment_start(person: str, request: Request):
        caller, value, chain = await input_for(request)
        await holder.admit(caller, chain)
        holder.require_approval()
        if (
            set(value) != {"requester"}
            or value["requester"] != caller.descriptor
            or caller.identity != person
        ):
            raise Refused("requester_mismatch")
        return await holder.enroll_existing(caller, person=person, chain=chain)

    @app.post("/v1/enrollments/{person}/binding")
    async def binding(person: str, request: Request):
        caller, value, chain = await input_for(request)
        if set(value) != {"material", "registration_count"}:
            raise Refused("request_invalid")
        admitted, current = await holder.enrollment_admission(
            person, caller, chain, purpose="holder_binding"
        )
        result = holder.bind_registration(
            person, **value, caller=caller, admitted=admitted, current=current
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
