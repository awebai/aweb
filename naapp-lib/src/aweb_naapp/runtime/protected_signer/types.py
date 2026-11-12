"""Trusted embedding ports and the first closed protected-operation type.

Actors are built by authenticated server adapters, never deserialized as evidence.
The authority adapter still validates their current association in the effect tx.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol
from uuid import UUID

from pgdbm.core import TransactionManager

from aweb_naapp.runtime.passkeys.proof import ProtectedKeyContext


class SignerRefused(ValueError):
    def __init__(self, code: str, *, retry_after_seconds: float | None = None):
        self.code = code
        self.retry_after_seconds = retry_after_seconds
        super().__init__(code)


@dataclass(frozen=True)
class RestrictedRequester:
    principal: str
    context: ProtectedKeyContext


@dataclass(frozen=True)
class AdmittedHuman:
    principal: str
    subject: str
    b3_scope: str
    context: ProtectedKeyContext


@dataclass(frozen=True)
class ReceiptReader:
    principal: str
    context: ProtectedKeyContext


Actor = RestrictedRequester | AdmittedHuman | ReceiptReader
AuthorityUse = Literal["prepare", "approval", "execute", "receipt"]


class CurrentAuthority(Protocol):
    """Per-call evidence: remote observation precedes all effect locks.

    prepare holds current authority/key/policy rows before B3/B2 locks; check
    is local and nonlocking. require_fresh checks original evidence deadlines
    synchronously. Receipt authorization may survive a generation change but
    never a loss of the reader's current scope. No callback signs anything.
    """

    @property
    def team_key_did(self) -> str: ...
    async def prepare(self, tx: TransactionManager, actor: Actor) -> None: ...
    async def check(self, tx: TransactionManager, actor: Actor) -> None: ...
    def require_fresh(self) -> None: ...


class AuthorityProvider(Protocol):
    async def observe(
        self, context: ProtectedKeyContext, *, purpose: AuthorityUse
    ) -> CurrentAuthority: ...


@dataclass(frozen=True)
class RevokeHumanRole:
    operation_id: str
    context: ProtectedKeyContext
    audience: str
    app_id: str
    installation_id: str
    role: str
    principal: str
    redirect_uri: str | None = None

    def __post_init__(self):
        if str(UUID(self.operation_id)) != self.operation_id:
            raise SignerRefused("request_invalid")
        if self.context.authority_kind != "team_controller":
            raise SignerRefused("scope_refused")
        if self.redirect_uri is not None:
            from aweb_naapp.console.handoff_wire import HandoffWireRefused, loopback_redirect

            try:
                loopback_redirect(self.redirect_uri)
            except HandoffWireRefused:
                raise SignerRefused("redirect_uri_refused") from None

    def intent(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "operation": "human-role.revoke",
            "variant": "default",
            **({"redirect_uri": self.redirect_uri} if self.redirect_uri is not None else {}),
            "scope": self.context.fields(),
            "audience": self.audience,
            "subject": {
                "app_id": self.app_id,
                "installation_id": self.installation_id,
                "role": self.role,
                "principal": self.principal,
            },
        }


@dataclass(frozen=True)
class CatalogOperation:
    """A registered artifact codec, with a frozen, schema-checked subject.

    The operation table selects the verifier's vocabulary; neither a caller
    field nor an embedding can select arbitrary signing bytes.
    """

    operation_id: str
    context: ProtectedKeyContext
    audience: str
    operation: str
    variant: str
    subject: Mapping[str, Any]
    redirect_uri: str | None = None
    _subject_bytes: bytes = field(init=False, repr=False)

    def __post_init__(self):
        from awid.log import require_canonical_server_origin
        from awid.signing import canonical_json_bytes

        from aweb_naapp.hooks.strictjson import Refused

        from .catalog import operation_spec
        from .codecs import validate_subject

        spec = operation_spec(self.operation, self.variant)
        if not spec.consumer_available:
            raise SignerRefused("operation_refused")
        if self.context.authority_kind != spec.key_role:
            raise SignerRefused("scope_refused")
        try:
            if str(UUID(self.operation_id)) != self.operation_id:
                raise ValueError()
            require_canonical_server_origin(self.audience)
            subject = validate_subject(self.operation, self.variant, self.subject)
            object.__setattr__(self, "_subject_bytes", canonical_json_bytes(subject))
        except (ValueError, TypeError, Refused):
            raise SignerRefused("request_invalid") from None
        if self.redirect_uri is not None:
            from aweb_naapp.console.handoff_wire import HandoffWireRefused, loopback_redirect

            try:
                loopback_redirect(self.redirect_uri)
            except HandoffWireRefused:
                raise SignerRefused("redirect_uri_refused") from None

    @property
    def spec(self):
        from .catalog import operation_spec

        return operation_spec(self.operation, self.variant)

    def intent(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "operation": self.operation,
            "variant": self.variant,
            **({"redirect_uri": self.redirect_uri} if self.redirect_uri is not None else {}),
            "scope": self.context.fields(),
            "audience": self.audience,
            "subject": json.loads(self._subject_bytes),
        }


# Source-compatible name for the initial registered owner-act constructor.
OwnerActOperation = CatalogOperation


def owner_act_operation(operation):
    """Keep the released RevokeHumanRole constructor and wire source-compatible."""
    if type(operation) is RevokeHumanRole:
        return OwnerActOperation(
            operation.operation_id,
            operation.context,
            operation.audience,
            "human-role.revoke",
            "default",
            operation.intent()["subject"],
            operation.redirect_uri,
        )
    if type(operation) is OwnerActOperation:
        return operation
    raise SignerRefused("operation_refused")


class ControllerCustody(Protocol):
    """Existing local protected key adapter: closed operation, no export/sign(bytes).

    Synchronous/local only. No artifact escapes before the caller's SQL commit.
    The adapter must independently match act/team/audience/complete subject to
    the typed operation and provisioned key before signing.
    Network custody needs a separately specified idempotent protocol.
    """

    def sign_operation(self, operation: CatalogOperation, fields: Mapping[str, Any]) -> bytes: ...

    def sign_owner_act(
        self, operation: RevokeHumanRole | OwnerActOperation, fields: Mapping[str, Any]
    ) -> bytes: ...


@dataclass(frozen=True)
class PreparedOperation:
    operation_id: str
    handoff_id: str
    digest: str
    payload: Mapping[str, Any]
    expires_at: str


@dataclass(frozen=True)
class OperationReceipt:
    operation_id: str
    state: Literal["pending", "committed", "refused", "unknown"]
    result: Mapping[str, str] | None = None
    code: str | None = None
    expires_at: str | None = None
