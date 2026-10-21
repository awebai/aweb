"""Use-time 1Password observation and exact-version opening.

SDK reads run outside every held authority transaction/lock. The final checker
does DB reads only under the caller's already-held authority; it never takes
new locks, allocates, invalidates, activates or emits. Rotation reconciliation
is a separate pre-S3 transaction. After S3 dispatching commits, open() rereads
the exact binding before returning bytes; failures belong to not_sent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_secrets.secret import SecretRecord, sealed_shape

from .onepassword import OnePasswordReference, OnePasswordSDK, SecretVersionChanged
from .sealing import CustodyUnavailable, Plaintext, SealContext
from .store import (
    _BACKEND_CREDENTIAL_SHAPE,
    BACKEND_CREDENTIAL_ID,
    BackendCredentialOpener,
    SecretOpener,
)


@dataclass(frozen=True)
class ActiveOnePasswordBinding:
    """Value-free local authority snapshot, never a new planner/authority token."""

    context: SealContext
    credential_context: SealContext
    reference: OnePasswordReference
    item_version: int
    version_ref: str
    shape_json: str


@dataclass(frozen=True)
class BackendObservation:
    """A validated remote version seen under an exact local binding/epoch.

    Carries no plaintext, token or fingerprint. Internal data, never accepted
    from request JSON. A changed item_version does not authorize activation.
    """

    binding: ActiveOnePasswordBinding
    item_version: int
    updated_at: datetime | None = None


async def active_binding(
    reader: AsyncDatabaseManager | TransactionManager, context: SealContext
) -> ActiveOnePasswordBinding:
    """One scoped DB snapshot. No authority locks or network calls are taken."""
    if type(context.version) is not int or context.version <= 0:
        raise CustodyUnavailable("no usable 1Password binding")
    row = await reader.fetch_one(
        "SELECT s.record, c.immutable_shape, v.binding, v.credential_version, v.version_ref"
        " FROM {{tables.secrets}} s"
        " JOIN {{tables.custody_secrets}} c USING (installation_id,team_id,secret_id)"
        " JOIN {{tables.onepassword_versions}} v USING (installation_id,team_id,secret_id)"
        " JOIN {{tables.onepassword_credentials}} p USING (installation_id,team_id)"
        " JOIN {{tables.custody_secrets}} tc ON tc.installation_id=p.installation_id"
        " AND tc.team_id=p.team_id AND tc.secret_id=p.credential_id"
        " JOIN {{tables.sealed_versions}} token ON token.installation_id=tc.installation_id"
        " AND token.team_id=tc.team_id AND token.secret_id=tc.secret_id"
        " AND token.version=v.credential_version"
        " WHERE s.installation_id=$1 AND s.team_id=$2 AND s.secret_id=$3"
        " AND v.version=$4 AND s.active_version=v.version AND s.state='active'"
        " AND c.disabled_at IS NULL AND v.destroyed_at IS NULL"
        " AND p.active_version=v.credential_version AND tc.disabled_at IS NULL"
        " AND tc.immutable_shape=$5::jsonb",
        context.installation_id,
        context.team_id,
        context.secret_id,
        context.version,
        json.dumps(_BACKEND_CREDENTIAL_SHAPE),
    )
    if row is None:
        raise CustodyUnavailable("no usable 1Password binding")
    try:
        record = SecretRecord.from_after(json.loads(row["record"]))
        after = json.loads(row["binding"])
        shape = json.loads(row["immutable_shape"])
        if (
            record.backend != "onepassword"
            or record.secret_id != context.secret_id
            or shape != sealed_shape(record)
            or set(after)
            != {
                "v",
                "secret_id",
                "version",
                "credential_version",
                "vault_id",
                "item_id",
                "fields",
                "item_version",
            }
            or type(after["v"]) is not int
            or after["v"] != 1
            or after["secret_id"] != context.secret_id
            or type(after["version"]) is not int
            or after["version"] != context.version
            or type(after["credential_version"]) is not int
            or after["credential_version"] != row["credential_version"]
            or type(after["item_version"]) is not int
            or after["item_version"] <= 0
        ):
            raise ValueError
        reference = OnePasswordReference.from_config(
            record.kind, {key: after[key] for key in ("vault_id", "item_id", "fields")}
        )
        return ActiveOnePasswordBinding(
            context,
            SealContext(
                context.installation_id,
                context.team_id,
                BACKEND_CREDENTIAL_ID,
                row["credential_version"],
            ),
            reference,
            after["item_version"],
            row["version_ref"],
            json.dumps(shape, sort_keys=True, separators=(",", ":")),
        )
    except Exception:
        raise CustodyUnavailable("unusable 1Password binding") from None


class OnePasswordOpener:
    """Backend-private read capability; holds the active-only token opener.

    Has no Custody or console preview capability and no token/value cache.
    The app composes this behind its shared opener based on the fenced backend.
    """

    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        credential_opener: BackendCredentialOpener,
    ) -> None:
        self._db = db
        self._credential_opener = credential_opener
        self._sdk = OnePasswordSDK()

    async def observe(self, context: SealContext) -> BackendObservation:
        """Read and validate once outside all held transactions/locks; retain no bytes."""
        binding = await active_binding(self._db, context)
        credential = await self._credential_opener.open(binding.credential_context)
        read = await self._sdk.read(binding.reference, credential=credential)
        return BackendObservation(binding, read.item_version, read.updated_at)

    async def check_observation(
        self,
        tx: TransactionManager,
        context: SealContext,
        observation: BackendObservation,
    ) -> None:
        """DB-only final comparison after separate reconciliation, never a writer."""
        current = await active_binding(tx, context)
        if (
            observation.binding != current
            or type(observation.item_version) is not int
            or observation.item_version <= 0
        ):
            raise CustodyUnavailable("the backend observation is stale")
        if observation.item_version != current.item_version:
            raise SecretVersionChanged(observation.item_version)

    async def open(self, context: SealContext) -> Plaintext:
        """Fresh reread after dispatching commits, before any value release.

        Failure/mismatch closes the original S3 attempt as not_sent. A caller
        must never substitute the newly observed value into that attempt.
        """
        binding = await active_binding(self._db, context)
        credential = await self._credential_opener.open(binding.credential_context)
        read = await self._sdk.read(
            binding.reference, credential=credential, expected_item_version=binding.item_version
        )
        if await active_binding(self._db, context) != binding:
            raise CustodyUnavailable("the backend binding changed")
        return read.value


class UseSecretOpener:
    """Common use-time API, selected by the authoritative scoped secret record.

    Composition injects only native opening and active credential opening.
    Console preview is deliberately absent. Native and 1Password retain the
    same SealContext/Plaintext seam; no request field chooses the backend.
    """

    def __init__(
        self,
        db: AsyncDatabaseManager,
        *,
        native: SecretOpener,
        credential_opener: BackendCredentialOpener,
    ) -> None:
        self._db = db
        self._native = native
        self._onepassword = OnePasswordOpener(db, credential_opener=credential_opener)

    async def _backend(
        self, reader: AsyncDatabaseManager | TransactionManager, context: SealContext
    ) -> str:
        if type(context.version) is not int or context.version <= 0:
            raise CustodyUnavailable("no usable secret version")
        row = await reader.fetch_one(
            "SELECT s.record, c.immutable_shape FROM {{tables.secrets}} s"
            " JOIN {{tables.custody_secrets}} c USING (installation_id,team_id,secret_id)"
            " WHERE s.installation_id=$1 AND s.team_id=$2 AND s.secret_id=$3"
            " AND s.active_version=$4 AND s.state='active' AND c.disabled_at IS NULL",
            context.installation_id,
            context.team_id,
            context.secret_id,
            context.version,
        )
        if row is None:
            raise CustodyUnavailable("no usable secret version")
        try:
            record = SecretRecord.from_after(json.loads(row["record"]))
            if record.secret_id != context.secret_id or json.loads(
                row["immutable_shape"]
            ) != sealed_shape(record):
                raise ValueError
            return record.backend
        except Exception:
            raise CustodyUnavailable("unusable secret record") from None

    async def observe(self, context: SealContext) -> BackendObservation | None:
        """Before S3, outside all authority transactions/locks. No plaintext is retained."""
        if await self._backend(self._db, context) == "onepassword":
            return await self._onepassword.observe(context)
        return None

    async def check_observation(
        self,
        tx: TransactionManager,
        context: SealContext,
        observation: BackendObservation | None,
    ) -> None:
        backend = await self._backend(tx, context)
        if backend == "onepassword":
            if observation is None:
                raise CustodyUnavailable("a backend observation is required")
            await self._onepassword.check_observation(tx, context, observation)
        elif observation is not None:
            raise CustodyUnavailable("the backend observation does not match")

    async def open(self, context: SealContext) -> Plaintext:
        """Exact active version only; backend failures have no native fallback."""
        if await self._backend(self._db, context) == "onepassword":
            return await self._onepassword.open(context)
        plaintext = await self._native.open(context)
        await self._backend(self._db, context)
        return plaintext
