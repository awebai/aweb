"""Trusted embedding ports and the first closed protected-operation type.

Actors are built by authenticated server adapters, never deserialized as evidence.
The authority adapter still validates their current association in the effect tx.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Protocol
from uuid import UUID

from pgdbm.core import TransactionManager

from aweb_naapp.runtime.passkeys.proof import ProtectedKeyContext


class SignerRefused(ValueError):
    def __init__(self, code: str, *, retry_after_seconds: float | None = None):
        self.code = code
        self.retry_after_seconds = retry_after_seconds
        super().__init__(code)


_SELF_REMOVAL_SEAL = object()


@dataclass(frozen=True)
class _SelfRemovalAdmission:
    """An embedding's one admitted self request; never deserialized from JSON.

    The embedding mints this only after the actual member proof and fresh
    membership checks. It does not confer a general requester grant.
    """

    context: ProtectedKeyContext
    operation_id: str
    certificate_id: str
    principal: str
    key_did: str
    deadline: float
    read_only: bool
    _intent: bytes = field(repr=False)
    _seal: object = field(repr=False, compare=False)


def _admitted_self_removal(operation, *, principal, key_did, deadline, read_only=False):
    intent = operation.intent()
    subject = intent.get("subject", {})
    if (intent.get("operation") != "team.agent.remove" or intent.get("variant") != "default"
        or operation.context.authority_kind != "team_controller" or subject.get("root_id_or_self") != "self"
        or subject.get("member_id") != principal or not principal or not key_did
        or type(deadline) not in (int, float) or not math.isfinite(deadline) or type(read_only) is not bool):
        raise SignerRefused("scope_refused")
    try:
        operation_id, certificate_id = intent["operation_id"], subject["certificate_id"]
        if str(UUID(operation_id)) != operation_id or str(UUID(certificate_id)) != certificate_id:
            raise ValueError()
        from awid.signing import canonical_json_bytes

        return _SelfRemovalAdmission(operation.context, operation_id, certificate_id, principal,
            key_did, float(deadline), read_only, canonical_json_bytes(intent), _SELF_REMOVAL_SEAL)
    except (ValueError, TypeError, KeyError):
        raise SignerRefused("scope_refused") from None


def _checked_self_removal(actor, *, operation=None, operation_id=None):
    cap = getattr(actor, "self_removal", None)
    if cap is None:
        return None
    if (type(cap) is not _SelfRemovalAdmission or cap._seal is not _SELF_REMOVAL_SEAL
        or cap.context != actor.context or cap.principal != actor.principal or cap.key_did != actor.key_did):
        raise SignerRefused("scope_refused")
    intent = json.loads(cap._intent)
    if (cap.operation_id != intent["operation_id"] or cap.certificate_id != intent["subject"]["certificate_id"]
        or cap.principal != intent["subject"]["member_id"] or cap.context.fields() != intent["scope"]
        or not math.isfinite(cap.deadline) or type(cap.read_only) is not bool):
        raise SignerRefused("scope_refused")
    if operation_id is not None and cap.operation_id != operation_id:
        raise SignerRefused("scope_refused")
    if operation is not None:
        from awid.signing import canonical_json_bytes

        if operation.context != cap.context or canonical_json_bytes(operation.intent()) != cap._intent:
            raise SignerRefused("scope_refused")
    return cap


@dataclass(frozen=True)
class RestrictedRequester:
    principal: str
    context: ProtectedKeyContext
    key_did: str | None = None
    self_removal: _SelfRemovalAdmission | None = field(default=None, repr=False)


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
    key_did: str | None = None
    self_removal: _SelfRemovalAdmission | None = field(default=None, repr=False)


Actor = RestrictedRequester | AdmittedHuman | ReceiptReader
AuthorityUse = Literal["prepare", "approval", "execute", "receipt"]


_EFFECT_ADMISSION = object()


@dataclass(frozen=True, init=False)
class VerifiedProtectedEffect:
    """An exact B2/B3 admission in its original effect transaction.

    The shared executor must construct this only after current authority,
    retained exact-act UV and B2's single-use admission. Root endorsement
    mints this port only inside its original effect transaction. It is never
    parsed from a worker request, receipt, bare context or browser callback.
    """

    operation_id: str
    operation: str
    variant: str
    audience: str
    context: ProtectedKeyContext
    human: AdmittedHuman
    transaction_id: int
    evidence_ref: str
    expires_at: datetime
    _subject: bytes = field(repr=False)
    _intent: bytes = field(repr=False)

    def __init__(
        self,
        *,
        operation_id,
        operation,
        variant,
        audience,
        context,
        human,
        transaction_id,
        evidence_ref,
        expires_at,
        subject_bytes,
        intent_bytes,
        _admission=None,
    ):
        if _admission is not _EFFECT_ADMISSION:
            raise SignerRefused("proof_invalid")
        for name, value in (
            ("operation_id", operation_id),
            ("operation", operation),
            ("variant", variant),
            ("audience", audience),
            ("context", context),
            ("human", human),
            ("transaction_id", transaction_id),
            ("evidence_ref", evidence_ref),
            ("expires_at", expires_at),
            ("_subject", subject_bytes),
            ("_intent", intent_bytes),
        ):
            object.__setattr__(self, name, value)

    @property
    def subject(self) -> dict[str, Any]:
        return json.loads(self._subject)

    async def require_in(self, tx, operation, *, clock):
        """A consumer checks exact admission inside the original transaction.

        This does not read remote authority, renew a gesture, or apply an
        effect. The consumer still holds and checks its own current state and
        final authority fence through commit. Recheck after every later await.
        """
        from awid.signing import canonical_json_bytes

        if type(self) is not VerifiedProtectedEffect:
            raise SignerRefused("proof_invalid")
        intent = operation.intent()
        if (
            operation.operation_id != self.operation_id
            or operation.context != self.context
            or intent["operation"] != self.operation
            or canonical_json_bytes(intent) != self._intent
        ):
            raise SignerRefused("operation_mismatch")
        self._require_deadline(clock)
        transaction_id = await tx.fetch_value("SELECT txid_current()")
        if type(transaction_id) is not int or transaction_id != self.transaction_id:
            raise SignerRefused("proof_invalid")
        self._require_deadline(clock)

    def _require_deadline(self, clock):
        now = clock()
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise SignerRefused("proof_invalid")
        if now >= self.expires_at:
            raise SignerRefused("gesture_expired")


def _verified_effect(operation, human, transaction_id, evidence_ref, expires_at):
    from awid.signing import canonical_json_bytes

    if (
        type(human) is not AdmittedHuman
        or human.context != operation.context
        or human.principal != operation.context.human_id
        or not human.subject
        or not human.b3_scope
    ):
        raise SignerRefused("scope_refused")
    if (
        type(transaction_id) is not int
        or transaction_id <= 0
        or not isinstance(evidence_ref, str)
        or not evidence_ref
        or not isinstance(expires_at, datetime)
        or expires_at.utcoffset() is None
    ):
        raise SignerRefused("proof_invalid")
    intent = operation.intent()
    return VerifiedProtectedEffect(
        _admission=_EFFECT_ADMISSION,
        operation_id=operation.operation_id,
        operation=intent["operation"],
        variant=intent["variant"],
        audience=intent["audience"],
        context=operation.context,
        human=human,
        transaction_id=transaction_id,
        evidence_ref=evidence_ref,
        expires_at=expires_at,
        subject_bytes=canonical_json_bytes(intent["subject"]),
        intent_bytes=canonical_json_bytes(intent),
    )


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
    result: Mapping[str, Any] | None = None
    code: str | None = None
    expires_at: str | None = None
