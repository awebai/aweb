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
from .removal import (
    removal_artifact,
    removal_signing_bytes,
    validate_owner_removal_subject,
    validate_removal_subject,
)
from .types import SignerRefused


@dataclass(frozen=True)
class OperationCodec:
    parse_subject: Callable
    build_artifact: Callable
    signing_bytes: Callable
    authority_field: str
    subject_schema: dict | None = None
    decode_intent: Callable | None = None
    go_verifier: str = ""
    presentation: dict | None = None


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


def catalog_intent(body, context, redirect):
    from .types import CatalogOperation

    return CatalogOperation(body["operation_id"], context, body["audience"], body["operation"],
        body["variant"], body["subject"], redirect)


def revoke_intent(body, context, redirect):
    from .types import RevokeHumanRole, owner_act_operation

    subject = body["subject"]
    legacy = RevokeHumanRole(body["operation_id"], context, body["audience"], subject["app_id"],
        subject["installation_id"], subject["role"], subject["principal"], redirect)
    owner_act_operation(legacy)
    return legacy


ROOT_CODEC = OperationCodec(validate_root_subject, _root, root_signing_bytes, "issuer_key", {
    "fields": {
        "domain": {"pattern": r"[a-z0-9.-]+"},
        "root_id": {"pattern": r"did:aw:[1-9A-HJ-NP-Za-km-z]+"},
        "root_key": {"pattern": r"did:key:z[1-9A-HJ-NP-Za-km-z]+"},
        "teams": {"pattern": r"[^\s:]+:[^\s:]+", "list": True, "maxItems": 4096},
        "deployment_label": {"pattern": r"[^\x00-\x1f]{1,128}"},
    }, "required": ["domain", "root_id", "root_key", "teams", "deployment_label"],
}, decode_intent=catalog_intent, go_verifier="endorsementDiffers", presentation={
    "exact": {"/artifact": ["v", "type", "id", "domain", "parent", "kind", "issuer_key", "issued_at"],
        "/artifact/parent": ["kind", "id"]},
    "constants": {"/artifact/v": 1, "/artifact/type": "aweb.id-certificate",
        "/artifact/kind": "agent", "/artifact/parent/kind": "identity"},
    "equals": [["/artifact/id", "/subject/root_id"], ["/artifact/domain", "/subject/domain"],
        ["/subject/domain", "/scope/authority/domain"], ["/scope/authority/id", "/scope/human/id"],
        ["/artifact/parent/id", "/scope/authority/id"], ["/registry", "/audience"]],
    "nonempty": ["/artifact/issuer_key"], "timestamps": ["/artifact/issued_at"],
    "nullable_patterns": {"/expected_head": "sha256:[0-9a-f]{64}"},
    "statement": "/responsibility_statement",
    "admission_policy": ["/admission_policy", "/scope/service_id", "/subject/teams"],
})
ADMISSION_CODEC = OperationCodec(validate_admission_subject, _admission, admission_signing_bytes, "team_did_key", decode_intent=catalog_intent, go_verifier="admissionArtifactDiffers")
REMOVAL_CODEC = OperationCodec(validate_removal_subject, _removal, removal_signing_bytes, "controller_did", decode_intent=catalog_intent, go_verifier="removalArtifactDiffers")
OWNER_REMOVAL_CODEC = OperationCodec(validate_owner_removal_subject, _removal, removal_signing_bytes, "controller_did", {
    "fields": {
        "team_id": {"pattern": r"[^\s:]+:[^\s:]+"},
        "member_id": {"pattern": r"did:(aw:[1-9A-HJ-NP-Za-km-z]+|key:z[1-9A-HJ-NP-Za-km-z]+)"},
        "certificate_id": {"pattern": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"},
        "expected_membership": {"object": {"fields": {
            "member_did_key": {"pattern": r"did:key:z[1-9A-HJ-NP-Za-km-z]+"},
            "member_did_aw": {"nullable": True, "pattern": r"did:aw:[1-9A-HJ-NP-Za-km-z]+"},
            "member_address": {"nullable": True, "pattern": r"[\s\S]{1,512}"},
            "alias": {"pattern": r"[^\x00-\x1f]{1,128}"},
            "identity_scope": {"enum": ["local", "global"]}},
            "required": ["member_did_key", "member_did_aw", "member_address", "alias", "identity_scope"]}},
    }, "required": ["team_id", "member_id", "certificate_id", "expected_membership"],
}, decode_intent=catalog_intent, go_verifier="ownerRemovalArtifactDiffers", presentation={
    "exact": {"/artifact": ["controller_did", "request"],
        "/artifact/request": ["v", "type", "aud", "method", "path", "domain", "operation", "team_name", "certificate_id", "timestamp", "body_sha256"]},
    "constants": {"/artifact/request/v": 2, "/artifact/request/type": "aweb.awid-controller-request",
        "/artifact/request/method": "POST", "/artifact/request/operation": "revoke_certificate"},
    "equals": [["/artifact/request/aud", "/audience"], ["/subject/team_id", "/scope/authority/id"],
        ["/artifact/request/domain", "/scope/authority/domain"], ["/artifact/request/certificate_id", "/subject/certificate_id"]],
    "enums": {"/target_kind": ["agent", "kind not verified"]},
    "templates": {"/subject/team_id": "{/artifact/request/team_name}:{/artifact/request/domain}",
        "/artifact/request/path": "/v1/namespaces/{/artifact/request/domain}/teams/{/artifact/request/team_name}/certificates/revoke"},
    "json_sha256": {"/artifact/request/body_sha256": {"certificate_id": "/subject/certificate_id"}},
    "nonempty": ["/artifact/controller_did", "/requester_key"], "timestamps": ["/artifact/request/timestamp"],
})
REVOKE_CODEC = OperationCodec(_revoke_subject, _owner_artifact, _owner_signing, "team_key_did", {
    "fields": {field: {"pattern": r"[\s\S]+"} for field in sorted(_REVOKE_FIELDS)},
    "required": sorted(_REVOKE_FIELDS),
}, decode_intent=revoke_intent, go_verifier="ownerActArtifactDiffers", presentation={
    "constants": {"/artifact/v": 1, "/artifact/type": "aweb.owner-act"},
    "equals": [["/artifact/act", "/operation"], ["/artifact/team_id", "/scope/authority/id"],
        ["/artifact/aud", "/audience"], ["/artifact/subject", "/subject"]],
})
