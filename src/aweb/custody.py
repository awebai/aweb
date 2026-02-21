"""Encrypted key storage and server-side signing for custodial agents.

AES-256-GCM encryption with a master key from AWEB_CUSTODY_KEY env var.
When the env var is not set, custodial signing is disabled and messages
are stored unsigned.
"""

from __future__ import annotations

import logging
import os
import secrets
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aweb.signing import canonical_payload, sign_message

logger = logging.getLogger(__name__)

_AES_KEY_LEN = 32
_NONCE_LEN = 12  # AES-256-GCM standard nonce length


def encrypt_signing_key(private_key: bytes, master_key: bytes) -> bytes:
    """Encrypt an Ed25519 private key (seed) with AES-256-GCM.

    Returns nonce || ciphertext+tag.
    """
    if len(master_key) != _AES_KEY_LEN:
        raise ValueError(f"Master key must be {_AES_KEY_LEN} bytes, got {len(master_key)}")
    nonce = secrets.token_bytes(_NONCE_LEN)
    aesgcm = AESGCM(master_key)
    ciphertext = aesgcm.encrypt(nonce, private_key, None)
    return nonce + ciphertext


def decrypt_signing_key(encrypted: bytes, master_key: bytes) -> bytes:
    """Decrypt an AES-256-GCM encrypted signing key. Returns the raw private key (seed)."""
    if len(master_key) != _AES_KEY_LEN:
        raise ValueError(f"Master key must be {_AES_KEY_LEN} bytes, got {len(master_key)}")
    nonce = encrypted[:_NONCE_LEN]
    ciphertext = encrypted[_NONCE_LEN:]
    aesgcm = AESGCM(master_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def get_custody_key() -> bytes | None:
    """Read the custody master key from AWEB_CUSTODY_KEY env var.

    Returns None if not set or empty. Raises ValueError if set but invalid.
    """
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


async def sign_on_behalf(agent_id: str, message_fields: dict, db) -> tuple[str, str, str] | None:
    """Decrypt an agent's custodial signing key and sign a message.

    Returns (from_did, signature, signing_key_id) or None if the agent
    is not custodial, has no encrypted key, or AWEB_CUSTODY_KEY is not set.
    """
    master_key = get_custody_key()
    if master_key is None:
        return None

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
        return None
    if row["signing_key_enc"] is None:
        return None
    if row["custody"] != "custodial":
        return None

    private_key = decrypt_signing_key(bytes(row["signing_key_enc"]), master_key)
    payload = canonical_payload(message_fields)
    sig = sign_message(private_key, payload)
    from_did = row["did"] or ""
    return from_did, sig, from_did


async def destroy_signing_key(agent_id: str, db) -> None:
    """Remove the encrypted signing key for an agent (e.g., on graduation to self-custodial).

    Raises ValueError if the agent is not found.
    """
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
