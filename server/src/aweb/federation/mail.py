"""Outbound federated mail transport."""

from __future__ import annotations

from typing import Any

import httpx

from awid.log import canonical_server_origin

from .envelope import FederatedDeliveryRequest, FederationEnvelope


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
        async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
            response = await client.post(
                f"{origin}/v1/federation/messages",
                json=request_body,
                headers={"Accept": "application/json"},
            )
    except httpx.RequestError as exc:
        raise FederatedMailDeliveryError(
            f"Federated mail delivery to {origin} failed: {exc}",
            status_code=502,
        ) from exc

    if response.status_code < 200 or response.status_code >= 300:
        detail = _response_detail(response)
        raise FederatedMailDeliveryError(
            f"Federated mail delivery to {origin} failed: {detail}",
            status_code=response.status_code if 400 <= response.status_code < 500 else 502,
        )

    try:
        data = response.json()
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


def _response_detail(response: httpx.Response) -> str:
    try:
        data = response.json()
    except Exception:
        text = response.text.strip()
        return text or f"HTTP {response.status_code}"
    if isinstance(data, dict):
        detail = data.get("detail") or data.get("error")
        if detail:
            return str(detail)
    return f"HTTP {response.status_code}"
