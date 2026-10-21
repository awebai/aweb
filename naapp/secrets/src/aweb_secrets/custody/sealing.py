"""Envelope sealing of secret values, bound to the secret version they belong to.

Each value is encrypted with AES-256-GCM under a fresh data key. A key
provider generates that data key and returns it wrapped by its
key-encryption key. The bound context ``{app, installation_id, team_id,
secret_id, version}`` is both the GCM additional data and the provider's
encryption context, so a sealed value, or its wrapped data key, copied to
another secret or version does not unseal.

Every failure to seal or unseal is :class:`CustodyUnavailable`. It names the
kind of failure, never a value, and there is no fallback.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_BYTES = 12


class CustodyUnavailable(Exception):
    """A value could not be sealed or unsealed; the request is refused."""

    code = "custody_unavailable"


@dataclass(frozen=True)
class SealContext:
    """The secret version a sealed value belongs to."""

    installation_id: str
    team_id: str
    secret_id: str
    version: int

    def bound(self) -> dict[str, str]:
        """The encryption context: every value a string, as KMS requires."""
        return {
            "app": "secrets",
            "installation_id": self.installation_id,
            "team_id": self.team_id,
            "secret_id": self.secret_id,
            "version": str(self.version),
        }


@dataclass(frozen=True)
class DataKey:
    """A fresh data key, in the clear and wrapped by the key-encryption key ``key_id``."""

    plaintext: bytes
    wrapped: bytes
    key_id: str

    def __repr__(self) -> str:
        return f"DataKey(key_id={self.key_id!r})"


class KeyProvider(Protocol):
    """Generates data keys under one key-encryption key and unwraps them again."""

    def generate_data_key(self, context: Mapping[str, str]) -> DataKey: ...

    def decrypt_data_key(
        self, wrapped: bytes, key_id: str, context: Mapping[str, str]
    ) -> bytes: ...


@dataclass(frozen=True)
class SealedValue:
    """What is kept at rest for one value: never the value or its data key in the clear."""

    key_id: str
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes


class Plaintext:
    """An unsealed value. It does not show itself in reprs, strings or logs.

    Python cannot zero memory, so the value's bytes, and a data key's, live
    until garbage collection. The controls are this redacting wrapper and never
    logging, persisting or returning a value."""

    __slots__ = ("_value",)

    def __init__(self, value: bytes) -> None:
        self._value = value

    def reveal(self) -> bytes:
        return self._value

    def __repr__(self) -> str:
        return "Plaintext(<redacted>)"

    __str__ = __repr__


def additional_data(context: Mapping[str, str]) -> bytes:
    """The canonical bytes of a bound context."""
    return json.dumps(dict(context), sort_keys=True, separators=(",", ":")).encode()


def seal(provider: KeyProvider, context: SealContext, value: bytes) -> SealedValue:
    """``value`` encrypted under a fresh data key, bound to ``context``."""
    bound = context.bound()
    try:
        key = provider.generate_data_key(bound)
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(key.plaintext).encrypt(nonce, value, additional_data(bound))
    except Exception as exc:
        raise CustodyUnavailable(f"sealing failed: {type(exc).__name__}") from None
    return SealedValue(
        key_id=key.key_id, wrapped_key=key.wrapped, nonce=nonce, ciphertext=ciphertext
    )


def unseal(provider: KeyProvider, context: SealContext, sealed: SealedValue) -> Plaintext:
    """The value ``sealed`` holds, only under the context it was sealed for."""
    bound = context.bound()
    try:
        data_key = provider.decrypt_data_key(sealed.wrapped_key, sealed.key_id, bound)
        value = AESGCM(data_key).decrypt(sealed.nonce, sealed.ciphertext, additional_data(bound))
    except Exception as exc:
        raise CustodyUnavailable(f"unsealing failed: {type(exc).__name__}") from None
    return Plaintext(value)


_CANARY_CONTEXT = SealContext(
    installation_id="health-canary", team_id="health-canary", secret_id="health-canary", version=1
)


def seal_canary(provider: KeyProvider) -> None:
    """Seal and unseal a random probe; raises :class:`CustodyUnavailable` unless it round-trips."""
    probe = os.urandom(16)
    if unseal(provider, _CANARY_CONTEXT, seal(provider, _CANARY_CONTEXT, probe)).reveal() != probe:
        raise CustodyUnavailable("the canary did not round-trip")
