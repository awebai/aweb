"""Hosted custodial signing hooks for MCP message sends."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal

from awid.signing import canonical_json_bytes, verify_did_key_signature


MessageType = Literal["mail", "chat"]


@dataclass(frozen=True)
class HostedMessageSigningResult:
    """Signature material returned by a hosted custody signer."""

    from_did: str
    signature: str
    signed_payload: str
    signing_key_id: str | None = None


HostedMessageSigner = Callable[
    [...],
    Awaitable[HostedMessageSigningResult | dict[str, Any] | None],
]


class HostedMessageSigningError(RuntimeError):
    """Raised when a hosted custodial message cannot be signed safely."""


def canonical_signed_payload(payload: dict[str, Any]) -> str:
    """Return the canonical JSON string used for message signing."""
    return canonical_json_bytes(payload).decode("utf-8")


def _result_field(result: HostedMessageSigningResult | dict[str, Any], field: str) -> Any:
    if isinstance(result, dict):
        return result.get(field)
    return getattr(result, field)


async def sign_hosted_message(
    *,
    auth: Any,
    signer: HostedMessageSigner | None,
    message_type: MessageType,
    payload: dict[str, Any],
) -> HostedMessageSigningResult | None:
    """Sign an MCP message payload when auth came through the trusted proxy.

    Direct OSS clients keep today's unsigned behavior. Hosted/custodial MCP
    sends fail closed because delivering an unsigned message would silently
    downgrade the verified-message security property.
    """
    if not getattr(auth, "trusted_proxy", False):
        return None
    if signer is None:
        raise HostedMessageSigningError("hosted custodial signer is not configured")
    workspace_id = getattr(auth, "workspace_id", None)
    if not workspace_id:
        raise HostedMessageSigningError("hosted custodial signer requires workspace_id")

    expected_payload = canonical_signed_payload(payload)
    result = await signer(
        agent_id=getattr(auth, "agent_id", None),
        workspace_id=workspace_id,
        team_id=getattr(auth, "team_id", None),
        message_type=message_type,
        payload=dict(payload),
    )
    if result is None:
        raise HostedMessageSigningError("hosted custodial signer returned no signature")

    from_did = str(_result_field(result, "from_did") or "").strip()
    signature = str(_result_field(result, "signature") or "").strip()
    signing_key_id = str(_result_field(result, "signing_key_id") or "").strip() or None
    signed_payload = str(_result_field(result, "signed_payload") or "")
    if not from_did:
        raise HostedMessageSigningError("hosted custodial signer returned empty from_did")
    if from_did != (getattr(auth, "did_key", "") or "").strip():
        raise HostedMessageSigningError("hosted custodial signer returned mismatched from_did")
    if signing_key_id and signing_key_id != from_did:
        raise HostedMessageSigningError("hosted custodial signer returned mismatched signing_key_id")
    if not signature:
        raise HostedMessageSigningError("hosted custodial signer returned empty signature")
    if signed_payload != expected_payload:
        try:
            returned_payload = json.loads(signed_payload)
        except Exception as exc:
            raise HostedMessageSigningError(
                "hosted custodial signer returned invalid signed_payload"
            ) from exc
        if returned_payload != payload:
            raise HostedMessageSigningError(
                "hosted custodial signer returned signed_payload for different fields"
            )
        raise HostedMessageSigningError("hosted custodial signer returned non-canonical signed_payload")

    try:
        verify_did_key_signature(
            did_key=from_did,
            payload=signed_payload.encode("utf-8"),
            signature_b64=signature,
        )
    except Exception as exc:
        raise HostedMessageSigningError("hosted custodial signer returned invalid signature") from exc

    return HostedMessageSigningResult(
        from_did=from_did,
        signature=signature,
        signing_key_id=signing_key_id,
        signed_payload=signed_payload,
    )
