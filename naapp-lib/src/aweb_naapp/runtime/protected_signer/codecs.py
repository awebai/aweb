"""Compatibility entry points; every selector resolves its one definition."""

from copy import deepcopy

from awid.did import public_key_from_did

from .catalog import operation_spec
from .types import SignerRefused, owner_act_operation


def validate_subject(operation, variant, subject):
    definition = operation_spec(operation, variant)
    try:
        return definition.codec.parse_subject(subject)
    except (ValueError, TypeError, KeyError):
        raise SignerRefused("request_invalid") from None


def artifact_for(operation, key, now):
    public_key_from_did(key)
    validate_subject(operation.operation, operation.variant, operation.intent()["subject"])
    return operation.spec.codec.build_artifact(operation, key, now)


def signing_bytes(operation, artifact):
    validate_subject(operation.operation, operation.variant, operation.intent()["subject"])
    return operation.spec.codec.signing_bytes(operation, artifact)


def authority_key(operation, artifact):
    operation = owner_act_operation(operation)
    if operation.spec.needs_human and artifact.get("type") == "aweb.protected-artifact-intent":
        artifact = artifact["template"]
    return artifact.get(operation.spec.codec.authority_field)


def presentation_schema(operation, variant):
    return deepcopy(operation_spec(operation, variant).codec.subject_schema)
