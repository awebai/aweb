"""Encrypted key storage and server-side signing for custodial identities."""

from __future__ import annotations

import logging
import os
import secrets
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aweb.awid.signing import canonical_payload, sign_message

logger = logging.getLogger(__name__)

_AES_KEY_LEN = 32
_NONCE_LEN = 12


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


def get_custody_key() -> bytes | None:
    key_hex = os.environ.get("AWEB_CUSTODY_KEY", "")
    if not key_hex:
        return None
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("AWEB_CUSTODY_KEY must be a hex-encoded 32 bytes")
    if len(key_bytes) != _AES_KEY_LEN:
        raise ValueError(
            f"AWEB_CUSTODY_KEY must be 32 bytes (64 hex chars), got {len(key_bytes)} bytes"
        )
    return key_bytes


async def sign_on_behalf(
    agent_id: str, message_fields: dict, db
) -> tuple[str, str, str, str] | None:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT signing_key_enc, custody, did
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND deleted_at IS NULL
        """,
        UUID(agent_id),
    )
    if row is None or row["custody"] != "custodial":
        return None

    master_key = get_custody_key()
    if master_key is None:
        raise RuntimeError(
            f"AWEB_CUSTODY_KEY not set — cannot sign for custodial agent {agent_id}"
        )

    if row["signing_key_enc"] is None:
        raise RuntimeError(
            f"Custodial agent {agent_id} has no signing key — "
            f"was likely created without AWEB_CUSTODY_KEY set"
        )

    try:
        private_key = decrypt_signing_key(bytes(row["signing_key_enc"]), master_key)
    except Exception:
        logger.error("Failed to decrypt signing key for agent %s", agent_id)
        return None

    from_did = row["did"] or ""
    signing_key_id = from_did
    signed_fields = {**message_fields, "from_did": from_did}
    payload = canonical_payload(signed_fields)
    sig = sign_message(private_key, payload)
    return from_did, sig, signing_key_id, payload.decode("utf-8")


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
