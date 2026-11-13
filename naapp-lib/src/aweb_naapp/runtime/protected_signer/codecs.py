"""Closed codecs for the existing revoke and OATS root/admission operations.

Each uses its consumer's existing bytes. A worker cannot select a serializer,
key reference, generic artifact or arbitrary signing payload.
"""

from datetime import UTC, timedelta
from uuid import uuid4

from awid.did import public_key_from_did

from aweb_naapp.hooks.owner_act import owner_act_signing_bytes

from .catalog import operation_spec
from .identity_artifacts import identity_artifact, identity_signing_bytes, validate_identity_subject
from .types import SignerRefused, owner_act_operation

_REVOKE = {"app_id", "installation_id", "role", "principal"}


def validate_subject(operation, variant, subject):
    spec = operation_spec(operation, variant)
    if not spec.consumer_available:
        raise SignerRefused("operation_refused")
    try:
        if operation in {"identity.root.endorse", "team.agent.admit"}:
            return validate_identity_subject(operation, variant, subject)
        # Keep the released parser's closed revoke shape. The existing owner
        # act codec validates its full grammar before any pending B2 state.
        if operation == "human-role.revoke" and variant == "default":
            if type(subject) is not dict or set(subject) != _REVOKE or not all(isinstance(v, str) and v for v in subject.values()):
                raise ValueError()
            return dict(subject)
    except (ValueError, TypeError, KeyError):
        raise SignerRefused("request_invalid") from None
    raise SignerRefused("operation_refused")


def artifact_for(operation, key, now):
    public_key_from_did(key)
    validate_subject(operation.operation, operation.variant, operation.intent()["subject"])
    stamp = now.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    if operation.operation in {"identity.root.endorse", "team.agent.admit"}:
        return identity_artifact(operation, key, stamp)
    return {"v": 1, "type": "aweb.owner-act", "act": operation.operation,
        "team_id": operation.context.authority_id, "team_key_did": key, "aud": operation.audience,
        "subject": operation.intent()["subject"], "nonce": uuid4().hex, "issued_at": stamp,
        "expires_at": (now + timedelta(seconds=600)).astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")}


def signing_bytes(operation, artifact):
    validate_subject(operation.operation, operation.variant, operation.intent()["subject"])
    if operation.operation in {"identity.root.endorse", "team.agent.admit"}:
        return identity_signing_bytes(operation, artifact)
    if (artifact.get("act") != operation.operation or artifact.get("team_id") != operation.context.authority_id
        or artifact.get("aud") != operation.audience or artifact.get("subject") != operation.intent()["subject"]):
        raise SignerRefused("operation_mismatch")
    return owner_act_signing_bytes(artifact)


def authority_key(operation, artifact):
    operation = owner_act_operation(operation)
    operation_spec(operation.operation, operation.variant)
    if operation.operation == "identity.root.endorse":
        return artifact.get("issuer_key")
    if operation.operation == "team.agent.admit":
        return artifact.get("team_did_key")
    return artifact.get("team_key_did")


def presentation_schema(operation, variant):
    operation_spec(operation, variant)
    if operation == "identity.root.endorse":
        return {"fields": {
            "domain": {"pattern": r"[a-z0-9.-]+"},
            "root_id": {"pattern": r"did:aw:[1-9A-HJ-NP-Za-km-z]+"},
            "root_key": {"pattern": r"did:key:z[1-9A-HJ-NP-Za-km-z]+"},
            "teams": {"pattern": r"[^\s:]+:[^\s:]+", "list": True, "maxItems": 4096},
            "deployment_label": {"pattern": r"[^\x00-\x1f]{1,128}"},
        }, "required": ["domain", "root_id", "root_key", "teams", "deployment_label"]}
    if operation == "human-role.revoke":
        return {"fields": {field: {"pattern": r"(?s).+"} for field in sorted(_REVOKE)}, "required": sorted(_REVOKE)}
    # Bounded admission has no approval page. The same table rule rejects one.
    return None
