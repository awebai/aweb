"""Consumer codecs attached to definitions, with no operation-name dispatch."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, timedelta
from uuid import uuid4

from awid.did import public_key_from_did

from aweb_naapp.hooks.owner_act import owner_act_signing_bytes

from .identity_artifacts import (
    admission_artifact,
    admission_signing_bytes,
    root_artifact,
    root_signing_bytes,
    validate_admission_subject,
    validate_root_subject,
)
from .removal import removal_artifact, removal_signing_bytes, validate_removal_subject
from .types import SignerRefused


@dataclass(frozen=True)
class OperationCodec:
    parse_subject: Callable
    build_artifact: Callable
    signing_bytes: Callable
    authority_field: str
    subject_schema: dict | None = None


def _stamp(now):
    return now.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _root(operation, key, now):
    return root_artifact(operation, key, _stamp(now))


def _admission(operation, key, now):
    return admission_artifact(operation, key, _stamp(now))


def _removal(operation, key, now):
    return removal_artifact(operation, key, _stamp(now))


_REVOKE_FIELDS = {"app_id", "installation_id", "role", "principal"}


def _revoke_subject(subject):
    if type(subject) is not dict or set(subject) != _REVOKE_FIELDS or not all(isinstance(v, str) and v for v in subject.values()):
        raise ValueError()
    return dict(subject)


def _owner_artifact(operation, key, now):
    public_key_from_did(key)
    return {"v": 1, "type": "aweb.owner-act", "act": operation.operation,
        "team_id": operation.context.authority_id, "team_key_did": key, "aud": operation.audience,
        "subject": operation.intent()["subject"], "nonce": uuid4().hex, "issued_at": _stamp(now),
        "expires_at": _stamp(now + timedelta(seconds=600))}


def _owner_signing(operation, artifact):
    if (artifact.get("act") != operation.operation or artifact.get("team_id") != operation.context.authority_id
        or artifact.get("aud") != operation.audience or artifact.get("subject") != operation.intent()["subject"]):
        raise SignerRefused("operation_mismatch")
    return owner_act_signing_bytes(artifact)


ROOT_CODEC = OperationCodec(validate_root_subject, _root, root_signing_bytes, "issuer_key", {
    "fields": {
        "domain": {"pattern": r"[a-z0-9.-]+"},
        "root_id": {"pattern": r"did:aw:[1-9A-HJ-NP-Za-km-z]+"},
        "root_key": {"pattern": r"did:key:z[1-9A-HJ-NP-Za-km-z]+"},
        "teams": {"pattern": r"[^\s:]+:[^\s:]+", "list": True, "maxItems": 4096},
        "deployment_label": {"pattern": r"[^\x00-\x1f]{1,128}"},
    }, "required": ["domain", "root_id", "root_key", "teams", "deployment_label"],
})
ADMISSION_CODEC = OperationCodec(validate_admission_subject, _admission, admission_signing_bytes, "team_did_key")
REMOVAL_CODEC = OperationCodec(validate_removal_subject, _removal, removal_signing_bytes, "controller_did")
REVOKE_CODEC = OperationCodec(_revoke_subject, _owner_artifact, _owner_signing, "team_key_did", {
    "fields": {field: {"pattern": r"[\s\S]+"} for field in sorted(_REVOKE_FIELDS)},
    "required": sorted(_REVOKE_FIELDS),
})
