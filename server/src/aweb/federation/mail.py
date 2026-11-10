"""Outbound federated mail transport."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx

from awid.federation_errors import federation_error_spec
from awid.log import canonical_server_origin
from awid.id_certificates import encode_id_chain_header
from aweb.messaging.chat_policy import HumanChatRefused

from aweb.messaging.address_auth import refuse_same_origin_nonresident

from .envelope import FederatedDeliveryRequest, FederationEnvelope
from .transport import DestinationRefused

logger = logging.getLogger(__name__)

MAX_FEDERATION_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_FEDERATION_ERROR_BYTES = 64 * 1024
MAX_LOGGED_ERROR_CHARS = 256
MAX_REFUSED_RECIPIENTS = 32
MAX_REFUSED_RECIPIENT_CHARS = 320


def _safe_error_text(content: bytes) -> str:
    text = content.decode("utf-8", errors="replace")
    sanitized = "".join(" " if not char.isprintable() else char for char in text)
    return " ".join(sanitized.split())


async def _read_bounded_response(response: httpx.Response, max_bytes: int) -> bytes:
    # httpx decompresses each raw chunk before yielding it, so an encoded bomb
    # can allocate past max_bytes before this function can inspect the result.
    content_encoding = response.headers.get("Content-Encoding", "").strip().lower()
    if content_encoding not in {"", "identity"}:
        raise ValueError("unsupported HTTP Content-Encoding")

    if response.is_stream_consumed:
        content = response.content
        if len(content) > max_bytes:
            raise ValueError(f"HTTP response exceeds maximum size of {max_bytes} bytes")
        return content

    content = bytearray()
    async for chunk in response.aiter_raw(chunk_size=64 * 1024):
        if len(content) + len(chunk) > max_bytes:
            raise ValueError(f"HTTP response exceeds maximum size of {max_bytes} bytes")
        content.extend(chunk)
    return bytes(content)


class FederatedMailDeliveryError(RuntimeError):
    """A remote delivery attempt failed.

    ``reason`` is a fixed token or a typed federation refusal reason; it never
    carries text the remote answered with.
    """

    def __init__(self, origin: str, reason: str, *, status_code: int = 502) -> None:
        super().__init__(f"Federated mail delivery to {origin} failed: {reason}")
        self.reason = reason
        self.status_code = status_code


def _transport_failure_reason(exc: Exception) -> str:
    if isinstance(exc, DestinationRefused):
        return "delivery_origin_refused"
    if isinstance(exc, (TimeoutError, httpx.TimeoutException)):
        return "delivery_timeout"
    if isinstance(exc, httpx.RequestError):
        return "delivery_origin_unreachable"
    # The remaining failures are this module's own response bounds.
    return str(exc)


async def deliver_federated_message(
    *,
    delivery_origin: str,
    envelope: FederationEnvelope,
    signature: str,
    transport: httpx.AsyncBaseTransport,
    id_chain: dict | None = None,
    timeout: float = 10.0,
    own_origins: set[str] | None = None,
) -> dict[str, Any]:
    """POST a sender-signed mail/chat envelope to a remote aweb delivery origin.

    The request goes through ``transport`` alone: the delivery origin comes from
    a record another party publishes, and the transport decides which origins
    and addresses are connected to.
    """
    if not isinstance(transport, httpx.AsyncBaseTransport):
        raise TypeError("federated delivery requires a transport")
    origin = canonical_server_origin(delivery_origin)
    origins = set(own_origins or ())
    if envelope.sender_delivery_origin:
        origins.add(canonical_server_origin(envelope.sender_delivery_origin))
    refuse_same_origin_nonresident(origin, origins=origins)
    request_body = FederatedDeliveryRequest(
        envelope=envelope,
        signature=signature,
    ).model_dump(mode="json", exclude_none=True)
    try:
        async with asyncio.timeout(timeout):
            async with httpx.AsyncClient(
                transport=transport,
                timeout=timeout,
                follow_redirects=False,
            ) as client:
                async with client.stream(
                    "POST",
                    f"{origin}/v1/federation/messages",
                    json=request_body,
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                        **({"X-AWID-ID-Chain": encode_id_chain_header(id_chain)} if id_chain is not None else {}),
                    },
                ) as response:
                    max_bytes = (
                        MAX_FEDERATION_RESPONSE_BYTES
                        if 200 <= response.status_code < 300
                        else MAX_FEDERATION_ERROR_BYTES
                    )
                    content = await _read_bounded_response(response, max_bytes)
    except (httpx.RequestError, TimeoutError, ValueError) as exc:
        reason = _transport_failure_reason(exc)
        logger.warning(
            "Federated delivery to %s failed: %s (%s)",
            origin, reason, _safe_error_text(str(exc).encode("utf-8"))[:MAX_LOGGED_ERROR_CHARS],
        )
        raise FederatedMailDeliveryError(origin, reason, status_code=502) from exc

    if response.status_code < 200 or response.status_code >= 300:
        try:
            answer = json.loads(content)
        except (ValueError, RecursionError):
            answer = None
        if not isinstance(answer, dict):
            answer = {}
        # Preserve this application refusal across the chat federation hop.
        if (envelope.type == "chat" and response.status_code == 422
                and answer.get("reason") == HumanChatRefused.reason
                and answer.get("retryable") is False):
            raise HumanChatRefused(_refused_recipients(answer.get("recipients")))
        logger.warning(
            "Federated delivery to %s answered HTTP %d: %s",
            origin, response.status_code, _safe_error_text(content)[:MAX_LOGGED_ERROR_CHARS],
        )
        raise FederatedMailDeliveryError(
            origin,
            _typed_refusal_reason(answer) or f"HTTP {response.status_code}",
            status_code=response.status_code if 400 <= response.status_code < 500 else 502,
        )

    try:
        data = json.loads(content)
    except Exception as exc:
        raise FederatedMailDeliveryError(origin, "invalid JSON", status_code=502) from exc
    if not isinstance(data, dict):
        raise FederatedMailDeliveryError(origin, "invalid response", status_code=502)
    return data


def _typed_refusal_reason(answer: dict) -> str | None:
    """The answer's reason when it is one the federation protocol defines."""
    reason = answer.get("reason")
    if not isinstance(reason, str):
        return None
    try:
        return federation_error_spec(reason).reason
    except ValueError:
        return None


def _refused_recipients(recipients) -> list[str]:
    """The recipient names of a human chat refusal, when all are short printable strings."""
    if (isinstance(recipients, list)
            and len(recipients) <= MAX_REFUSED_RECIPIENTS
            and all(isinstance(name, str) and name.isprintable()
                    and len(name) <= MAX_REFUSED_RECIPIENT_CHARS for name in recipients)):
        return recipients
    return []
