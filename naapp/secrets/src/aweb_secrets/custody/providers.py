"""Key providers: a local key file for local runs, and AWS KMS for hosted deployments."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from aweb_naapp.key_file import KeyFileError, read_key_file
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .sealing import DataKey, additional_data

_KEY_HEX = re.compile(rb"[0-9a-fA-F]{64}\n?")
_NONCE_BYTES = 12


class LocalKeyFileProvider:
    """A key-encryption key held in a local key file: 32 bytes as 64 hex characters.

    The file is read once, when the provider is made, through the shared key
    file checks: it must be a regular file that neither group nor others can
    write. Anything else refuses with :class:`KeyFileError`, so a service
    configured with a bad key file fails at startup."""

    def __init__(self, path: Path) -> None:
        content = read_key_file(path)
        if not _KEY_HEX.fullmatch(content):
            raise KeyFileError(
                f"key file {path} must hold 64 hex characters, optionally newline-terminated"
            )
        self._kek = AESGCM(bytes.fromhex(content.rstrip(b"\n").decode()))
        self.key_id = "local:" + hashlib.sha256(content.rstrip(b"\n").lower()).hexdigest()[:16]

    def __repr__(self) -> str:
        return f"LocalKeyFileProvider(key_id={self.key_id!r})"

    def generate_data_key(self, context: Mapping[str, str]) -> DataKey:
        data_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(_NONCE_BYTES)
        wrapped = nonce + self._kek.encrypt(nonce, data_key, additional_data(context))
        return DataKey(plaintext=data_key, wrapped=wrapped, key_id=self.key_id)

    def decrypt_data_key(self, wrapped: bytes, key_id: str, context: Mapping[str, str]) -> bytes:
        if key_id != self.key_id:
            raise ValueError("sealed under another key-encryption key")
        nonce, ciphertext = wrapped[:_NONCE_BYTES], wrapped[_NONCE_BYTES:]
        return self._kek.decrypt(nonce, ciphertext, additional_data(context))


class AwsKmsProvider:
    """A key-encryption key in AWS KMS, used through GenerateDataKey and Decrypt.

    The bound context is the KMS encryption context, so KMS itself refuses to
    unwrap a data key under any other context, and its audit trail records
    the context of every unwrap."""

    def __init__(
        self, key_id: str, client: Any | None = None, region_name: str | None = None
    ) -> None:
        if client is None:
            import boto3
            from botocore.config import Config

            # Sealing runs while the ingest transaction holds a row lock, so every
            # KMS call is bounded: one attempt plus at most two retries.
            client = boto3.client(
                "kms",
                region_name=region_name,
                config=Config(
                    connect_timeout=2,
                    read_timeout=5,
                    retries={"total_max_attempts": 3, "mode": "standard"},
                ),
            )
        self.key_id = key_id
        self.client = client

    def __repr__(self) -> str:
        return f"AwsKmsProvider(key_id={self.key_id!r})"

    def generate_data_key(self, context: Mapping[str, str]) -> DataKey:
        response = self.client.generate_data_key(
            KeyId=self.key_id, KeySpec="AES_256", EncryptionContext=dict(context)
        )
        return DataKey(
            plaintext=response["Plaintext"],
            wrapped=response["CiphertextBlob"],
            key_id=response["KeyId"],
        )

    def decrypt_data_key(self, wrapped: bytes, key_id: str, context: Mapping[str, str]) -> bytes:
        response = self.client.decrypt(
            CiphertextBlob=wrapped, KeyId=key_id, EncryptionContext=dict(context)
        )
        return bytes(response["Plaintext"])
