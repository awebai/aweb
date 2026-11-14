"""Sealed owner-session initiation; provenance never substitutes for exact UV."""

import json
from dataclasses import dataclass, field
from uuid import UUID

from awid.did import public_key_from_did
from awid.signing import canonical_json_bytes

from aweb_naapp.console import ConsoleSession

from .types import AdmittedHuman, SignerRefused

_SEAL = object()
_SELECTION = {"operation_id", "operation", "variant", "team_id", "certificate_id"}


def owner_selection(value):
    from .catalog import operation_spec

    try:
        if type(value) is not dict or set(value) != _SELECTION:
            raise ValueError()
        if not all(type(item) is str and item for item in value.values()):
            raise ValueError()
        for name in ("operation_id", "certificate_id"):
            if str(UUID(value[name])) != value[name]:
                raise ValueError()
        if not operation_spec(value["operation"], value["variant"]).owner_initiable:
            raise SignerRefused("operation_not_served")
        return dict(value)
    except (ValueError, TypeError, KeyError) as error:
        if isinstance(error, SignerRefused):
            raise
        raise SignerRefused("request_invalid") from None


@dataclass(frozen=True)
class OwnerInitiation:
    human: AdmittedHuman
    session: ConsoleSession = field(repr=False)
    key_did: str
    _selection: bytes = field(repr=False)
    _seal: object = field(repr=False, compare=False)

    @property
    def principal(self):
        return self.key_did

    @property
    def context(self):
        return self.human.context

    @property
    def selection(self):
        return json.loads(self._selection)

    @property
    def operation_id(self):
        return self.selection["operation_id"]


def _admitted_owner_initiation(selection, *, human, session, host_key_did):
    """Only a host adapter with an admitted human console session calls this.

    The engine independently checks current owner/session/credential rows under
    the operation lock. This port grants only prepare, never signing or release.
    """
    selection = owner_selection(selection)
    if (type(human) is not AdmittedHuman or type(session) is not ConsoleSession
        or (session.subject, session.scope) != (human.subject, human.b3_scope)
        or human.principal != human.context.human_id or not human.subject or not human.b3_scope
        or human.context.authority_kind != "team_controller" or selection["team_id"] != human.context.authority_id):
        raise SignerRefused("scope_refused")
    try:
        if type(host_key_did) is not str:
            raise ValueError()
        public_key_from_did(host_key_did)
    except (ValueError, TypeError):
        raise SignerRefused("operation_not_served") from None
    return OwnerInitiation(human, session, host_key_did, canonical_json_bytes(selection), _SEAL)


def _checked_owner_initiation(actor, *, operation=None):
    if type(actor) is not OwnerInitiation:
        return None
    if actor._seal is not _SEAL:
        raise SignerRefused("scope_refused")
    selection = owner_selection(actor.selection)
    if operation is not None:
        subject = operation.intent()["subject"]
        if (operation.context != actor.context or operation.operation_id != selection["operation_id"]
            or (operation.operation, operation.variant) != (selection["operation"], selection["variant"])
            or subject.get("team_id") != selection["team_id"] or subject.get("certificate_id") != selection["certificate_id"]):
            raise SignerRefused("operation_conflict")
    return actor
