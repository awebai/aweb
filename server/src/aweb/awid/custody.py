"""Encrypted key storage and server-side signing for custodial identities."""

from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timezone
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aweb.awid.signing import canonical_json_bytes, canonical_payload, sign_message

logger = logging.getLogger(__name__)

_AES_KEY_LEN = 32
_NONCE_LEN = 12
_UNSET = object()
_cached_custody_key: bytes | None | object = _UNSET
_cached_custody_key_error: ValueError | None = None
_cached_namespace_controller_key: bytes | None | object = _UNSET
_cached_namespace_controller_key_error: ValueError | None = None


class CustodyError(RuntimeError):
    """Base error for custodial signing failures."""


class SelfCustodialError(CustodyError):
    """Raised when a self-custodial agent attempts server-side signing."""

    def __init__(self, message: str = "Only custodial agents may use this endpoint") -> None:
        super().__init__(message)


def encrypt_signing_key(private_key: bytes, master_key: bytes) -> bytes:
    if len(master_key) != _AES_KEY_LEN:
        raise ValueError(f"Master key must be {_AES_KEY_LEN} bytes, got {len(master_key)}")
    nonce = secrets.token_bytes(_NONCE_LEN)
    aesgcm = AESGCM(master_key)
    ciphertext = aesgcm.encrypt(nonce, private_key, None)
    return nonce + ciphertext


def decrypt_signing_key(encrypted: bytes, master_key: bytes) -> bytes:
    if len(master_key) != _AES_KEY_LEN:
        raise ValueError(f"Master key must be {_AES_KEY_LEN} bytes, got {len(master_key)}")
    nonce = encrypted[:_NONCE_LEN]
    ciphertext = encrypted[_NONCE_LEN:]
    aesgcm = AESGCM(master_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def reset_custody_key_cache() -> None:
    global _cached_custody_key
    global _cached_custody_key_error
    global _cached_namespace_controller_key
    global _cached_namespace_controller_key_error
    _cached_custody_key = _UNSET
    _cached_custody_key_error = None
    _cached_namespace_controller_key = _UNSET
    _cached_namespace_controller_key_error = None


def _get_hex_key_from_env(
    *,
    env_name: str,
    cached_value_name: str,
    cached_error_name: str,
) -> bytes | None:
    global_vars = globals()
    cached_value = global_vars[cached_value_name]
    cached_error = global_vars[cached_error_name]
    if cached_value is not _UNSET:
        if cached_error is not None:
            raise cached_error
        return cached_value

    key_hex = os.environ.get(env_name, "")
    if not key_hex:
        global_vars[cached_value_name] = None
        return None
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        error = ValueError(f"{env_name} must be a hex-encoded 32 bytes")
        global_vars[cached_error_name] = error
        raise error
    if len(key_bytes) != _AES_KEY_LEN:
        error = ValueError(
            f"{env_name} must be 32 bytes (64 hex chars), got {len(key_bytes)} bytes"
        )
        global_vars[cached_error_name] = error
        raise error
    global_vars[cached_value_name] = key_bytes
    return key_bytes


def get_custody_key() -> bytes | None:
    return _get_hex_key_from_env(
        env_name="AWEB_CUSTODY_KEY",
        cached_value_name="_cached_custody_key",
        cached_error_name="_cached_custody_key_error",
    )


def get_namespace_controller_key() -> bytes | None:
    return _get_hex_key_from_env(
        env_name="AWEB_NAMESPACE_CONTROLLER_KEY",
        cached_value_name="_cached_namespace_controller_key",
        cached_error_name="_cached_namespace_controller_key_error",
    )


async def _load_custodial_signing_key(agent_id: str, db) -> tuple[bytes, str]:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT signing_key_enc, custody, did
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND deleted_at IS NULL
        """,
        UUID(agent_id),
    )
    if row is None:
        raise ValueError(f"Agent {agent_id} not found")
    if row["custody"] != "custodial":
        raise SelfCustodialError("Only custodial agents may use this endpoint")

    master_key = get_custody_key()
    if master_key is None:
        raise CustodyError(
            f"AWEB_CUSTODY_KEY not set — cannot sign for custodial agent {agent_id}"
        )

    if row["signing_key_enc"] is None:
        raise CustodyError(
            f"Custodial agent {agent_id} has no signing key — "
            f"was likely created without AWEB_CUSTODY_KEY set"
        )

    try:
        private_key = decrypt_signing_key(bytes(row["signing_key_enc"]), master_key)
    except Exception:
        raise CustodyError(
            f"Failed to decrypt signing key for custodial agent {agent_id} — "
            f"AWEB_CUSTODY_KEY may have been rotated"
        )

    did_key = (row["did"] or "").strip()
    if not did_key:
        raise CustodyError(
            f"Custodial agent {agent_id} has no did:key configured"
        )

    return private_key, did_key


async def sign_on_behalf(
    agent_id: str, message_fields: dict, db
) -> tuple[str, str, str, str] | None:
    """Sign a message on behalf of a custodial agent.

    Returns (from_did, signature, signing_key_id, signed_payload) for custodial
    agents, or None for non-custodial agents (who sign client-side).

    Raises CustodyError if the agent is custodial but server-side signing is
    misconfigured.
    """
    try:
        private_key, from_did = await _load_custodial_signing_key(agent_id, db)
    except SelfCustodialError:
        return None
    signing_key_id = from_did
    signed_fields = {**message_fields, "from_did": from_did}
    payload = canonical_payload(signed_fields)
    sig = sign_message(private_key, payload)
    return from_did, sig, signing_key_id, payload.decode("utf-8")


async def sign_arbitrary_payload(
    agent_id: str, payload: dict, db
) -> tuple[str, str, str]:
    """Sign an arbitrary JSON payload for a custodial agent.

    Returns ``(did_key, signature, timestamp)`` where ``timestamp`` is also
    injected into the canonical JSON payload before signing.
    """
    private_key, did_key = await _load_custodial_signing_key(agent_id, db)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    signed_payload = {**payload, "timestamp": timestamp}
    signature = sign_message(private_key, canonical_json_bytes(signed_payload))
    return did_key, signature, timestamp


async def destroy_signing_key(agent_id: str, db) -> None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        UPDATE {{tables.agents}}
        SET signing_key_enc = NULL
        WHERE agent_id = $1 AND deleted_at IS NULL
        RETURNING agent_id
        """,
        UUID(agent_id),
    )
    if row is None:
        raise ValueError(f"Agent {agent_id} not found")
