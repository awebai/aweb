"""Custody of secret values: envelope sealing at rest behind a key provider."""

from aweb_naapp.signing_key import KeyFileError

from .providers import AwsKmsProvider, LocalKeyFileProvider
from .sealing import (
    CustodyUnavailable,
    DataKey,
    KeyProvider,
    Plaintext,
    SealContext,
    SealedValue,
    seal,
    seal_canary,
    unseal,
)
from .store import SecretOpener, SecretSealer, apply_custody_migrations

__all__ = [
    "AwsKmsProvider",
    "CustodyUnavailable",
    "DataKey",
    "KeyFileError",
    "KeyProvider",
    "LocalKeyFileProvider",
    "Plaintext",
    "SealContext",
    "SealedValue",
    "SecretOpener",
    "SecretSealer",
    "apply_custody_migrations",
    "seal",
    "seal_canary",
    "unseal",
]
