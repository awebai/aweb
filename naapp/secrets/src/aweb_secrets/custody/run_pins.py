"""Pinned whole-value equivalence; envelopes contain random MAC keys only.

Provider work runs outside transactions. SQL publication/disposal belongs to
run_pin_store and the caller's existing authority/dispatch transaction.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from .sealing import (
    CustodyUnavailable,
    KeyProvider,
    Plaintext,
    SealContext,
    SealedValue,
    seal,
    unseal,
)

if TYPE_CHECKING:
    from .opening import BackendObservation

_DOMAIN = b"aweb.secrets.run-redaction/1\n"


def key_context(context: SealContext, dispatch_id: UUID) -> SealContext:
    return SealContext(
        context.installation_id,
        context.team_id,
        f"run_redaction_key:{dispatch_id}:{context.secret_id}",
        context.version,
    )


def observation_pin(observation: BackendObservation | None) -> str | None:
    """Canonical value-free binding, credential epoch and remote observation."""
    if observation is None:
        return None

    def encode(value: Any) -> str:
        if isinstance(value, datetime):
            return value.isoformat()
        raise TypeError("unsupported observation metadata")

    return json.dumps(asdict(observation), sort_keys=True, separators=(",", ":"), default=encode)


@dataclass(frozen=True, repr=False)
class PreparedRunPin:
    context: SealContext
    dispatch_id: UUID
    grant_id: str
    observation: str | None
    credential_version: int | None
    digest: bytes
    sealed_key: SealedValue

    def columns(self) -> tuple[Any, ...]:
        return (
            self.context.installation_id,
            self.context.team_id,
            self.dispatch_id,
            self.context.secret_id,
            self.context.version,
            self.grant_id,
            self.observation,
            self.credential_version,
            self.digest,
            self.sealed_key.key_id,
            self.sealed_key.wrapped_key,
            self.sealed_key.nonce,
            self.sealed_key.ciphertext,
        )

    @classmethod
    def from_row(cls, row: Any) -> PreparedRunPin:
        return cls(
            SealContext(row["installation_id"], row["team_id"], row["secret_id"], row["version"]),
            row["dispatch_id"],
            row["grant_id"],
            row["observation"],
            row["credential_version"],
            bytes(row["digest"]),
            SealedValue(
                row["key_id"],
                bytes(row["wrapped_key"]),
                bytes(row["nonce"]),
                bytes(row["ciphertext"]),
            ),
        )


class RunPins:
    """Native sealing capability composed only into assignment/result handling."""

    def __init__(self, provider: KeyProvider) -> None:
        self._provider = provider

    async def prepare(
        self,
        context: SealContext,
        dispatch_id: UUID,
        value: Plaintext,
        *,
        observation: BackendObservation | None,
        grant_id: str,
    ) -> PreparedRunPin:
        key = secrets.token_bytes(32)
        sealed_key = await asyncio.to_thread(
            seal, self._provider, key_context(context, dispatch_id), key
        )
        return PreparedRunPin(
            context,
            dispatch_id,
            grant_id,
            observation_pin(observation),
            None if observation is None else observation.binding.credential_context.version,
            hmac.digest(key, _DOMAIN + value.reveal(), "sha256"),
            sealed_key,
        )

    async def matches(self, pin: PreparedRunPin, value: Plaintext) -> bool:
        key = (
            await asyncio.to_thread(
                unseal, self._provider, key_context(pin.context, pin.dispatch_id), pin.sealed_key
            )
        ).reveal()
        if len(key) != 32 or len(pin.digest) != 32:
            raise CustodyUnavailable("invalid run equivalence key")
        return hmac.compare_digest(hmac.digest(key, _DOMAIN + value.reveal(), "sha256"), pin.digest)
