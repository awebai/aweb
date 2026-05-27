"""Hosted custodial signing/encryption hooks for MCP message sends."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal

from awid.signing import canonical_payload, verify_did_key_signature


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


@dataclass(frozen=True)
class HostedMessageEncryptionResult:
    """Encrypted v2 envelope material returned by hosted custody."""

    encrypted_envelope: dict[str, Any]
    content_mode: str = "encrypted_v2"
    message_version: int = 2


HostedMessageEncryptor = Callable[
    [...],
    Awaitable[HostedMessageEncryptionResult | dict[str, Any] | None],
]


class HostedMessageEncryptionError(RuntimeError):
    """Raised when a hosted custodial message cannot be encrypted safely."""


@dataclass(frozen=True)
class HostedMessageDecryptionResult:
    """Plaintext material returned by hosted custody for an encrypted row."""

    subject: str = ""
    body: str = ""
    decryptable: bool = True
    content_notice: str | None = None


HostedMessageDecryptor = Callable[
    [...],
    Awaitable[HostedMessageDecryptionResult | dict[str, Any] | None],
]


class HostedMessageDecryptionError(RuntimeError):
    """Raised when hosted custodial message content cannot be decrypted safely."""


def canonical_signed_payload(payload: dict[str, Any]) -> str:
    """Return the canonical JSON string used for message signing."""
    return canonical_payload(payload).decode("utf-8")


def _result_field(result: HostedMessageSigningResult | dict[str, Any], field: str) -> Any:
    if isinstance(result, dict):
        return result.get(field)
    return getattr(result, field)


def _encryption_result_field(
    result: HostedMessageEncryptionResult | dict[str, Any],
    field: str,
) -> Any:
    if isinstance(result, dict):
        return result.get(field)
    return getattr(result, field)


def _decryption_result_field(
    result: HostedMessageDecryptionResult | dict[str, Any],
    field: str,
) -> Any:
    if isinstance(result, dict):
        return result.get(field)
    return getattr(result, field)


async def encrypt_hosted_message(
    *,
    auth: Any,
    encryptor: HostedMessageEncryptor | None,
    message_type: MessageType,
    payload: dict[str, Any],
    recipient: dict[str, Any],
) -> HostedMessageEncryptionResult | None:
    """Encrypt an MCP message payload when auth came through hosted custody."""
    if not getattr(auth, "trusted_proxy", False):
        return None
    if encryptor is None:
        raise HostedMessageEncryptionError("hosted custodial encryptor is not configured")
    workspace_id = getattr(auth, "workspace_id", None)
    if not workspace_id:
        raise HostedMessageEncryptionError("hosted custodial encryptor requires workspace_id")

    result = await encryptor(
        agent_id=getattr(auth, "agent_id", None),
        workspace_id=workspace_id,
        team_id=getattr(auth, "team_id", None),
        message_type=message_type,
        payload=dict(payload),
        recipient=dict(recipient),
    )
    if result is None:
        raise HostedMessageEncryptionError("hosted custodial encryptor returned no envelope")

    content_mode = str(_encryption_result_field(result, "content_mode") or "").strip()
    message_version = int(_encryption_result_field(result, "message_version") or 0)
    encrypted_envelope = _encryption_result_field(result, "encrypted_envelope")
    if content_mode != "encrypted_v2" or message_version != 2:
        raise HostedMessageEncryptionError("hosted custodial encryptor returned non-v2 content")
    if not isinstance(encrypted_envelope, dict):
        raise HostedMessageEncryptionError("hosted custodial encryptor returned no encrypted envelope")
    if str(encrypted_envelope.get("kind") or "").strip() != message_type:
        raise HostedMessageEncryptionError("hosted custodial encryptor returned wrong envelope kind")
    if str(encrypted_envelope.get("message_id") or "").strip() != str(payload.get("message_id") or "").strip():
        raise HostedMessageEncryptionError("hosted custodial encryptor returned mismatched message_id")
    if str(encrypted_envelope.get("conversation_id") or "").strip() != str(payload.get("conversation_id") or "").strip():
        raise HostedMessageEncryptionError("hosted custodial encryptor returned mismatched conversation_id")
    return HostedMessageEncryptionResult(
        encrypted_envelope=encrypted_envelope,
        content_mode=content_mode,
        message_version=message_version,
    )


async def decrypt_hosted_message_row(
    *,
    auth: Any,
    decryptor: HostedMessageDecryptor | None,
    message_type: MessageType,
    row: dict[str, Any],
) -> HostedMessageDecryptionResult | None:
    """Decrypt an MCP message row when auth came through hosted custody."""
    if not getattr(auth, "trusted_proxy", False):
        return None
    if str(row.get("content_mode") or "legacy_plaintext_v1") != "encrypted_v2":
        return None
    if decryptor is None:
        raise HostedMessageDecryptionError("hosted custodial decryptor is not configured")
    workspace_id = getattr(auth, "workspace_id", None)
    if not workspace_id:
        raise HostedMessageDecryptionError("hosted custodial decryptor requires workspace_id")

    result = await decryptor(
        agent_id=getattr(auth, "agent_id", None),
        workspace_id=workspace_id,
        team_id=getattr(auth, "team_id", None),
        message_type=message_type,
        row=dict(row),
    )
    if result is None:
        return HostedMessageDecryptionResult(
            decryptable=False,
            content_notice="Encrypted message content is not available to this hosted identity.",
        )
    subject = str(_decryption_result_field(result, "subject") or "")
    body = str(_decryption_result_field(result, "body") or "")
    decryptable = bool(_decryption_result_field(result, "decryptable"))
    notice = _decryption_result_field(result, "content_notice")
    return HostedMessageDecryptionResult(
        subject=subject,
        body=body if decryptable else "",
        decryptable=decryptable,
        content_notice=(str(notice) if notice else None),
    )


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
