"""Closed artifact codecs selected by the one signer operation table.

Each family uses its existing consumer wire. Caller-supplied bytes, route
labels and serializers are never accepted as an operation or a codec.
"""

from datetime import timedelta

from awid.did import public_key_from_did
from awid.log_key_record import (
    LOG_KEY_FIELDS,
    build_log_key_record,
    log_key_record_signing_bytes,
    validate_log_key_subject,
)
from awid.team_server_record import (
    RECORD_FIELDS,
    build_team_server_record,
    canonical_team_server_url,
    record_signing_bytes,
)
from awid.utc_timestamps import parse_utc_seconds

from aweb_naapp.hooks.owner_act import owner_act_signing_bytes, validate_owner_act_subject
from aweb_naapp.hooks.strictjson import Refused

from .catalog import operation_spec
from .types import SignerRefused, owner_act_operation


def validate_subject(operation, variant, subject):
    spec = operation_spec(operation, variant)
    if not spec.consumer_available:
        raise SignerRefused("operation_refused")
    try:
        if operation in {"identity.root.endorse", "team.agent.admit"}:
            from .identity_artifacts import validate_identity_subject

            return validate_identity_subject(operation, variant, subject)
        if spec.family == "owner_act":
            return validate_owner_act_subject(operation, subject)
        if spec.family == "log_key_record":
            return validate_log_key_subject(subject)
        if spec.family == "server_record":
            if type(subject) is not dict or set(subject) != {"server_url"}:
                raise ValueError()
            canonical_team_server_url(subject["server_url"])
            return dict(subject)
    except (ValueError, TypeError, Refused):
        raise SignerRefused("request_invalid") from None
    raise SignerRefused("operation_refused")


def artifact_for(operation, key, now):
    import uuid

    spec = operation_spec(operation.operation, operation.variant)
    subject = validate_subject(
        operation.operation, operation.variant, operation.intent()["subject"]
    )
    public_key_from_did(key)
    if operation.operation in {"identity.root.endorse", "team.agent.admit"}:
        from .identity_artifacts import identity_artifact

        return identity_artifact(operation, key, _stamp(now))
    if spec.family == "owner_act":
        return {
            "v": 1,
            "type": "aweb.owner-act",
            "act": operation.operation,
            "team_id": operation.context.authority_id,
            "team_key_did": key,
            "aud": operation.audience,
            "subject": subject,
            "nonce": uuid.uuid4().hex,
            "issued_at": _stamp(now),
            "expires_at": _stamp(now + timedelta(seconds=600)),
        }
    if spec.family == "server_record":
        return build_team_server_record(
            operation.context.authority_id, key, subject["server_url"], now
        )
    if spec.family == "log_key_record":
        if subject["team_id"] != operation.context.authority_id:
            raise SignerRefused("scope_refused")
        return build_log_key_record(subject, key)
    raise SignerRefused("operation_refused")


def signing_bytes(operation, artifact):
    spec = operation_spec(operation.operation, operation.variant)
    subject = validate_subject(
        operation.operation, operation.variant, operation.intent()["subject"]
    )
    if operation.operation in {"identity.root.endorse", "team.agent.admit"}:
        from .identity_artifacts import identity_signing_bytes

        return identity_signing_bytes(operation, artifact)
    if spec.family == "owner_act":
        if (
            artifact.get("act") != operation.operation
            or artifact.get("team_id") != operation.context.authority_id
            or artifact.get("aud") != operation.audience
            or artifact.get("subject") != subject
        ):
            raise SignerRefused("operation_mismatch")
        return owner_act_signing_bytes(artifact)
    if spec.family == "server_record":
        try:
            if (
                type(artifact) is not dict
                or set(artifact) != RECORD_FIELDS
                or type(artifact["v"]) is not int
                or artifact["v"] != 1
                or artifact["type"] != "aweb.team-server"
                or artifact["team_id"] != operation.context.authority_id
                or artifact["server_url"] != subject["server_url"]
            ):
                raise ValueError()
            public_key_from_did(artifact["team_did_key"])
            parse_utc_seconds(artifact["issued_at"])
            return record_signing_bytes(artifact)
        except (ValueError, TypeError, KeyError):
            raise SignerRefused("operation_mismatch") from None
    if spec.family == "log_key_record":
        try:
            if (
                type(artifact) is not dict
                or set(artifact) != LOG_KEY_FIELDS
                or artifact["team_id"] != operation.context.authority_id
                or any(artifact[name] != value for name, value in subject.items())
            ):
                raise ValueError()
            return log_key_record_signing_bytes(artifact)
        except (ValueError, TypeError, KeyError):
            raise SignerRefused("operation_mismatch") from None
    raise SignerRefused("operation_refused")


def authority_key(operation, artifact):
    # Retained requests preserve the released RevokeHumanRole constructor.
    # Normalize codec selection through its existing bridge, not custody input.
    operation = owner_act_operation(operation)
    family = operation_spec(operation.operation, operation.variant).family
    if operation.operation == "identity.root.endorse":
        return artifact.get("issuer_key")
    if family == "member_certificate" and operation.operation == "team.agent.admit":
        return artifact.get("team_did_key")
    if family in {"owner_act", "log_key_record"}:
        return artifact.get("team_key_did")
    if family == "server_record":
        return artifact.get("team_did_key")
    raise SignerRefused("operation_refused")


def _stamp(now):
    from datetime import UTC

    return now.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def presentation_schema(operation, variant):
    from aweb_naapp.hooks.owner_act import _subject_schema

    spec = operation_spec(operation, variant)
    if operation == "identity.root.endorse" and variant == "default":
        return {
            "fields": {
                "domain": {"pattern": r"[a-z0-9.-]+"},
                "root_id": {"pattern": r"did:aw:[1-9A-HJ-NP-Za-km-z]+"},
                "root_key": {"pattern": r"did:key:z[1-9A-HJ-NP-Za-km-z]+"},
                "teams": {"pattern": r"[^\s:]+:[^\s:]+", "list": True, "maxItems": 4096},
                "deployment_label": {"pattern": r"[^\x00-\x1f]{1,128}"},
            },
            "required": ["domain", "root_id", "root_key", "teams", "deployment_label"],
        }
    if spec.family == "owner_act":
        return _subject_schema(operation)
    if spec.family == "server_record":
        return {
            "fields": {"server_url": {"pattern": r"https?://[^\s]+"}},
            "required": ["server_url"],
        }
    if spec.family == "log_key_record":
        return {
            "fields": {
                "team_id": {"pattern": r"[^\s:]+:[^\s:]+"},
                "key_id": {"pattern": r"sha256:[A-Za-z0-9+/]{43}"},
                "public_key": {"pattern": r"[A-Za-z0-9+/]{43}"},
                "created_at": {
                    "pattern": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
                },
            },
            "required": ["team_id", "key_id", "public_key", "created_at"],
        }
    return None
