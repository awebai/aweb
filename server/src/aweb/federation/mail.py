"""Outbound federated mail transport."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from awid.log import canonical_server_origin

from .envelope import FederatedDeliveryRequest, FederationEnvelope


MAX_FEDERATION_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_FEDERATION_ERROR_BYTES = 64 * 1024


def _safe_error_text(content: bytes) -> str:
    text = content.decode("utf-8", errors="replace")
    sanitized = "".join(" " if not char.isprintable() else char for char in text)
    return " ".join(sanitized.split())


async def _read_bounded_response(response: httpx.Response, max_bytes: int) -> bytes:
    # httpx decompresses each raw chunk before yielding it, so an encoded bomb
    # can allocate past max_bytes before this function can inspect the result.
    content_encoding = response.headers.get("Content-Encoding", "").strip().lower()
    if content_encoding not in {"", "identity"}:
        raise ValueError(f"unsupported HTTP Content-Encoding: {content_encoding}")

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
    """Raised when a remote mail delivery attempt fails."""

    def __init__(self, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


async def deliver_federated_message(
    *,
    delivery_origin: str,
    envelope: FederationEnvelope,
    signature: str,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """POST a sender-signed mail/chat envelope to a remote aweb delivery origin."""
    origin = canonical_server_origin(delivery_origin)
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
                    },
                ) as response:
                    max_bytes = (
                        MAX_FEDERATION_RESPONSE_BYTES
                        if 200 <= response.status_code < 300
                        else MAX_FEDERATION_ERROR_BYTES
                    )
                    content = await _read_bounded_response(response, max_bytes)
    except (httpx.RequestError, TimeoutError, ValueError) as exc:
        raise FederatedMailDeliveryError(
            f"Federated mail delivery to {origin} failed: {exc}",
            status_code=502,
        ) from exc

    if response.status_code < 200 or response.status_code >= 300:
        detail = _response_detail(response.status_code, content)
        raise FederatedMailDeliveryError(
            f"Federated mail delivery to {origin} failed: {detail}",
            status_code=response.status_code if 400 <= response.status_code < 500 else 502,
        )

    try:
        data = json.loads(content)
    except Exception as exc:
        raise FederatedMailDeliveryError(
            f"Federated mail delivery to {origin} returned invalid JSON",
            status_code=502,
        ) from exc
    if not isinstance(data, dict):
        raise FederatedMailDeliveryError(
            f"Federated mail delivery to {origin} returned invalid response",
            status_code=502,
        )
    return data


async def deliver_federated_mail(
    *,
    delivery_origin: str,
    envelope: FederationEnvelope,
    signature: str,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    return await deliver_federated_message(
        delivery_origin=delivery_origin,
        envelope=envelope,
        signature=signature,
        transport=transport,
        timeout=timeout,
    )


def _response_detail(status_code: int, content: bytes) -> str:
    try:
        data = json.loads(content)
    except Exception:
        text = _safe_error_text(content)
        return text or f"HTTP {status_code}"
    if isinstance(data, dict):
        detail = data.get("detail") or data.get("error")
        if detail:
            return _safe_error_text(str(detail).encode("utf-8"))
    return f"HTTP {status_code}"
