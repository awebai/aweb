"""Inert, detached submission bytes and the independent S8 equality hash.

Dispatch only within an authenticated submission carrying these inputs. A
resubmission supplies them again and must match the committed intent before
any outbound request is built. This stores no raw request, grants no authority
and does not replace K4's initial authenticated-byte audit commitments.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from aweb_naapp.egress import EgressRefused, canonical_url
from aweb_naapp.runtime.approvals import RequestNotCanonical, canonical_request
from aweb_naapp.runtime.approvals.request import DOMAIN_PREFIX
from pgdbm.core import TransactionManager

from aweb_secrets.admission import Admission, AdmissionRefused, UseRequest
from aweb_secrets.use_approval import MAX_REASON_LENGTH, BrokerOpen
from aweb_secrets.use_context import use_context

_DOMAIN = b"aweb.secrets.broker-request/1\n"
_HEADER = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FIELDS = {"request_id", "operation", "params", "method", "url", "headers", "data", "reason"}


def _require(condition: bool) -> None:
    if not condition:
        raise AdmissionRefused("params_invalid", 400)


def _headers(value: Any) -> list[list[str]]:
    _require(isinstance(value, list))
    result = []
    for entry in value:
        _require(isinstance(entry, str) and ":" in entry)
        name, content = entry.split(":", 1)
        content = content.lstrip(" \t")
        _require(_HEADER.fullmatch(name) is not None)
        _require(not any(c in content for c in ("\r", "\n", "\x00")))
        result.append([name, content])
    return result


@dataclass(frozen=True, repr=False)
class BrokerInput:
    """Canonical inert bytes. Views are fresh copies, never caller-owned models."""

    _canonical: bytes

    @classmethod
    def from_body(
        cls, secret_ref: str, body: Mapping[str, Any], *, operation_digest: str | None = None
    ) -> BrokerInput:
        _require(isinstance(secret_ref, str) and bool(secret_ref))
        _require(isinstance(body, Mapping) and not (body.keys() - _FIELDS))
        request_id = body.get("request_id")
        reason = body.get("reason", "")
        _require(isinstance(request_id, str) and bool(request_id))
        _require(isinstance(reason, str) and len(reason) <= MAX_REASON_LENGTH)
        headers = _headers(body.get("headers", []))
        operation, params, open_request = body.get("operation"), None, None
        try:
            if "operation" in body:
                _require(isinstance(operation, str) and bool(operation))
                # Discovery may miss a definition before S8 classifies the
                # caller's grant. This remains inert; the service must match
                # a resolved pin before persisting a dispatch context.
                _require(
                    operation_digest is None
                    or (
                        isinstance(operation_digest, str)
                        and _DIGEST.fullmatch(operation_digest) is not None
                    )
                )
                _require(not ({"method", "url", "data"} & body.keys()))
                params = body.get("params", {})
                _require(isinstance(params, Mapping))
            else:
                _require(operation_digest is None and "params" not in body)
                method, url = body.get("method"), body.get("url")
                _require(
                    isinstance(method, str) and method in {"GET", "POST", "PUT", "PATCH", "DELETE"}
                )
                _require(isinstance(url, str))
                url = str(canonical_url(url))
                data = body.get("data", "")
                _require(isinstance(data, str | dict))
                raw = (
                    data.encode("utf-8")
                    if isinstance(data, str)
                    else json.dumps(
                        data,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                )
                open_request = {
                    "method": method,
                    "url": url,
                    "body_b64": base64.b64encode(raw).decode("ascii"),
                }
            model = {
                "secret": secret_ref,
                "request_id": request_id,
                "operation": operation,
                "operation_digest": operation_digest,
                "params": params,
                "open": open_request,
                "headers": headers,
                "reason": reason,
            }
            canonical = canonical_request(model)[len(DOMAIN_PREFIX) :]
            # Detect invalid UTF-8 scalar text before any projection or send.
            canonical.decode("utf-8").encode("utf-8")
        except (
            RequestNotCanonical,
            UnicodeError,
            ValueError,
            TypeError,
            RecursionError,
            EgressRefused,
        ):
            raise AdmissionRefused("params_invalid", 400) from None
        return cls(canonical)

    def _model(self) -> dict[str, Any]:
        return json.loads(self._canonical)

    @property
    def request(self) -> UseRequest:
        model = self._model()
        return UseRequest(
            model["secret"],
            model["request_id"],
            hashlib.sha256(_DOMAIN + self._canonical).digest(),
            model["operation"],
            model["params"],
        )

    @property
    def operation_digest(self) -> str | None:
        return self._model()["operation_digest"]

    @property
    def reason(self) -> str:
        return self._model()["reason"]

    @property
    def headers(self) -> tuple[tuple[str, str], ...]:
        return tuple((name, value) for name, value in self._model()["headers"])

    @property
    def open_call(self) -> BrokerOpen | None:
        model = self._model()
        opened = model["open"]
        if opened is None:
            return None
        return BrokerOpen(
            opened["method"],
            opened["url"],
            tuple(name for name, _ in model["headers"]),
            base64.b64decode(opened["body_b64"], validate=True),
        )

    async def check_binding(
        self, tx: TransactionManager, *, admission: Admission, dispatch_id: UUID
    ) -> None:
        """After authority preparation, before S3/credential release; no new locks."""
        scope = admission.installation
        try:
            stored = await use_context(tx, dispatch_id)
        except LookupError:
            raise AdmissionRefused("grant_missing") from None
        context = stored.commitments.context
        if (
            stored.intent_id,
            context.app_id,
            context.installation_id,
            context.team_id,
            context.generation,
            context.tool,
        ) != (
            admission.intent_id,
            scope.app_id,
            scope.installation_id,
            scope.team_id,
            scope.generation,
            "request",
        ):
            raise AdmissionRefused("grant_missing")
        intent = await tx.fetch_one(
            "SELECT request_id, request_sha256, operation_id, operation_digest FROM {{tables.intents}}"
            " WHERE intent_id=$1 AND installation_id=$2 AND team_id=$3",
            admission.intent_id,
            scope.installation_id,
            scope.team_id,
        )
        request = self.request
        if intent is None or (
            intent["request_id"],
            bytes(intent["request_sha256"]),
            intent["operation_id"],
            intent["operation_digest"],
        ) != (
            request.request_id,
            request.request_sha256,
            request.operation_id,
            self.operation_digest,
        ):
            raise AdmissionRefused("idempotency_conflict", 409)
