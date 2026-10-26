"""Explicit agent-visible outcomes (decision 86), independent of HTTP status.

request_ref is a stored intent locator, never send authority. Mutation callers
retain their original request_id; list/describe pass None. These helpers neither
allocate IDs nor poll, admit or dispatch. Callers supply already-projected results.
"""

from __future__ import annotations

from typing import Any


def _envelope(state: str, request_id: str | None) -> dict[str, Any]:
    if request_id is not None and (not isinstance(request_id, str) or not request_id):
        raise ValueError("request_id is the original nonempty ID or None for a read")
    return {"state": state, "request_id": request_id}


def _use(state: str, request_id: str | None, request_ref: str) -> dict[str, Any]:
    if not request_id or not isinstance(request_ref, str) or not request_ref:
        raise ValueError("a use outcome needs its original request_id and intent locator")
    return {**_envelope(state, request_id), "request_ref": request_ref}


def completed(
    result: Any, *, request_id: str | None, request_ref: str | None = None
) -> dict[str, Any]:
    response = {**_envelope("completed", request_id), "result": result}
    if request_ref is not None:
        response.update(_use("completed", request_id, request_ref))
    return response


def awaiting_approval(*, request_id: str, request_ref: str, approval_ref: str) -> dict[str, Any]:
    if not isinstance(approval_ref, str) or not approval_ref:
        raise ValueError("a pending outcome needs its approval locator")
    return {**_use("awaiting_approval", request_id, request_ref), "approval_ref": approval_ref}


def refused(code: str, *, request_id: str | None) -> dict[str, Any]:
    return {**_envelope("refused", request_id), "code": code}


def outcome_unknown(*, request_id: str, request_ref: str) -> dict[str, Any]:
    return {**_use("outcome_unknown", request_id, request_ref), "reconcile_ref": request_ref}


def result_withheld(code: str, *, request_id: str, request_ref: str) -> dict[str, Any]:
    return {**_use("result_withheld", request_id, request_ref), "code": code}
