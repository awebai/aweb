"""The internal B1 submission and value-free member-tool reply boundary.

The router constructs submissions after the shared guard has authenticated and
matched the tool. No type here grants admission, consumes an approval or opens
a credential. Result projection accepts only the broker's already handled
response; raw upstream bytes and response-audit commitments have no input seam.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from aweb_naapp.hooks.commitment import RequestBytes
from aweb_naapp.runtime.authorization import Authorization

from aweb_secrets import tool_results
from aweb_secrets.responses import BrokeredResult


@dataclass(frozen=True, repr=False)
class MemberSubmission:
    authorization: Authorization
    inbound: RequestBytes
    signed_trace_id: str | None = None


@dataclass(frozen=True)
class ToolReply:
    status: int
    body: Mapping[str, Any]
    headers: Mapping[str, str] = field(default_factory=dict)


class JobRunRequests(Protocol):
    async def submit(self, *, job: str, submission: MemberSubmission) -> ToolReply: ...


def broker_result_reply(result: BrokeredResult, *, request_id: str, request_ref: str) -> ToolReply:
    """Project sanitized entity bytes losslessly, including an empty response.

    This envelope is also the persisted S3 result. An upstream error status is
    still a definite completed effect. Withholding retains only safe metadata;
    it is never encoded as an empty successful body.
    """
    projected: dict[str, Any] = {
        "status": result.status,
        "headers": [[name, value] for name, value in result.headers],
        "body": None,
        "truncated": result.truncated,
        "upstream_bytes": result.upstream_bytes,
        "redaction_count": result.redaction_count,
    }
    if result.disposition == "withheld":
        if result.body is not None or result.withheld_reason is None:
            raise ValueError("withheld broker result requires a reason and no entity")
        body = tool_results.result_withheld(
            result.withheld_reason, request_id=request_id, request_ref=request_ref
        )
        body["result"] = projected
    elif result.disposition == "returned" and isinstance(result.body, bytes):
        try:
            projected["body"] = result.body.decode("utf-8")
            projected["body_encoding"] = "utf8"
        except UnicodeDecodeError:
            projected["body"] = base64.b64encode(result.body).decode("ascii")
            projected["body_encoding"] = "base64"
        body = tool_results.completed(projected, request_id=request_id, request_ref=request_ref)
    else:
        raise ValueError("broker result requires a handled disposition")
    return ToolReply(200, body)
