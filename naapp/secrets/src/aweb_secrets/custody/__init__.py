"""Custody of secret values: envelope sealing at rest behind a key provider."""

from aweb_naapp.key_file import KeyFileError

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
from .store import (
    Custody,
    Description,
    Health,
    SecretOpener,
    SecretSealer,
    apply_custody_migrations,
)

__all__ = [
    "AwsKmsProvider",
    "Custody",
    "CustodyUnavailable",
    "DataKey",
    "Description",
    "Health",
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
