"""The frozen request an approve_only use is approved on (secrets §10.4).

`use_approval_request` builds the `aweb.secrets.use-approval/1` object B2
freezes and its approver signs: who asks, for which secret at which version,
to do exactly what, under which grant and policy, and until when. The console
renders the approval from these bytes alone, so an open request is approvable
only when its whole body fits in them as text.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from aweb_naapp.roles import principal_key
from aweb_naapp.runtime.team_auth import Principal

from aweb_secrets.secret import SecretRecord

REQUEST_TYPE = "aweb.secrets.use-approval"
REQUEST_VERSION = 1
# The console shows an open request's body in full or not at all (§10.4).
MAX_RENDERED_BODY_BYTES = 64 * 1024
# The requester's reason is untrusted text shown to the approver.
MAX_REASON_LENGTH = 1024
_TIME = "%Y-%m-%dT%H:%M:%SZ"


class UseApprovalRefused(Exception):
    """The use cannot be put to an approver. `code` is the refusal code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


class ApprovalUnrenderable(UseApprovalRefused):
    """An open request whose body the console cannot show in full."""

    def __init__(self, detail: str) -> None:
        super().__init__("approval_unrenderable", detail)


@dataclass(frozen=True)
class BrokerOperation:
    """A named operation at its current digest, with its typed parameters."""

    operation_id: str
    operation_digest: str
    params: Mapping[str, Any]


@dataclass(frozen=True)
class BrokerOpen:
    """An open request: the exact method, URL, header names and body."""

    method: str
    canonical_url: str
    header_names: Sequence[str]
    body: bytes


@dataclass(frozen=True)
class RunJob:
    """A job on a runner, at its current digest, with its parameters."""

    runner_id: str
    job_id: str
    job_digest: str
    params: Mapping[str, Any]
    credential_delivery: str


def _time(at: datetime) -> str:
    if at.tzinfo is None:
        raise ValueError("approval times must be timezone-aware")
    return at.astimezone(UTC).strftime(_TIME)


def _requester(principal: Principal) -> dict[str, Any]:
    requester: dict[str, Any] = {
        "principal": principal_key(principal).principal_did,
        "member_did_key": principal.did_key,
        "certificate_id": principal.certificate_id,
        "alias": principal.alias,
    }
    if principal.did_aw is not None:
        requester["did_aw"] = principal.did_aw
    return requester


def _rendered_body(body: bytes) -> str:
    """The body as the text the approver reads in full: UTF-8 JSON or text of
    at most 64 KiB, or the request is unrenderable."""
    if len(body) > MAX_RENDERED_BODY_BYTES:
        raise ApprovalUnrenderable("the body is larger than the console shows in full")
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApprovalUnrenderable("the body is not UTF-8 text") from exc


def _action(action: BrokerOperation | BrokerOpen | RunJob) -> tuple[str, str, dict[str, Any]]:
    if isinstance(action, BrokerOperation):
        return (
            "broker",
            "broker",
            {
                "operation_id": action.operation_id,
                "operation_digest": action.operation_digest,
                "params": dict(action.params),
            },
        )
    if isinstance(action, BrokerOpen):
        return (
            "broker",
            "broker",
            {
                "method": action.method,
                "canonical_url": action.canonical_url,
                "header_names": sorted({name.lower() for name in action.header_names}),
                "body_sha256": hashlib.sha256(action.body).hexdigest(),
                "body_preview": _rendered_body(action.body),
            },
        )
    return (
        "run_job",
        "run_job",
        {
            "runner_id": action.runner_id,
            "job_id": action.job_id,
            "job_digest": action.job_digest,
            "params": dict(action.params),
            "credential_delivery": action.credential_delivery,
        },
    )


def use_approval_request(
    *,
    installation_id: str,
    install_generation: int,
    team_id: str,
    requester: Principal,
    secret: SecretRecord,
    secret_version: int,
    policy_digest: str,
    grant_id: str,
    request_id: str,
    reason: str,
    issued_at: datetime,
    ttl: timedelta,
    action: BrokerOperation | BrokerOpen | RunJob,
) -> dict[str, Any]:
    """The `aweb.secrets.use-approval/1` object for one use, as B2 freezes it.

    Times are whole seconds in UTC; the approval expires `ttl` after it is
    issued. The reason is refused, never truncated, past its bound."""
    if ttl <= timedelta(0):
        raise ValueError("an approval's ttl must be positive")
    if len(reason) > MAX_REASON_LENGTH:
        raise UseApprovalRefused("params_invalid", "the reason is longer than its bound")
    issued = issued_at.replace(microsecond=0)
    kind, key, body = _action(action)
    return {
        "v": REQUEST_VERSION,
        "type": REQUEST_TYPE,
        "installation_id": installation_id,
        "install_generation": install_generation,
        "team_id": team_id,
        "requester": _requester(requester),
        "secret": {
            "secret_id": secret.secret_id,
            "secret_ref": secret.ref,
            "version": secret_version,
            "kind": secret.kind,
            "backend": secret.backend,
        },
        "policy_digest": policy_digest,
        "grant_id": grant_id,
        "request_id": request_id,
        "reason": reason,
        "issued_at": _time(issued),
        "expires_at": _time(issued + ttl),
        "action": kind,
        key: body,
    }


__all__ = [
    "MAX_REASON_LENGTH",
    "MAX_RENDERED_BODY_BYTES",
    "REQUEST_TYPE",
    "ApprovalUnrenderable",
    "BrokerOpen",
    "BrokerOperation",
    "RunJob",
    "UseApprovalRefused",
    "use_approval_request",
]
