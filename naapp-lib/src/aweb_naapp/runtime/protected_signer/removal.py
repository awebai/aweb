"""Closed member removal onto the existing AWID certificate-revoke request.

These codecs confer no requester, membership or controller authority. The
embedding must admit the current root or exact self membership and confirm
revocation before releasing an active-count reservation.
"""

import json
from uuid import UUID

from awid.did import public_key_from_did
from awid.id_tree_requests import covering_payload
from awid.log import require_canonical_server_origin
from awid.signing import canonical_json_bytes
from awid.utc_timestamps import parse_utc_seconds

from .identity_artifacts import _stable, _team, _text
from .types import SignerRefused

REMOVE_FIELDS = {"team_id", "root_id_or_self", "member_id", "certificate_id", "expected_membership"}
MEMBERSHIP_FIELDS = {"member_did_key", "member_did_aw", "member_address", "alias", "identity_scope"}


def validate_removal_subject(subject, *, owner_approved=False):
    """Snapshot the exact membership projection, preserving explicit nulls."""
    try:
        if type(subject) is not dict or set(subject) != (REMOVE_FIELDS - {"root_id_or_self"} if owner_approved else REMOVE_FIELDS):
            raise ValueError()
        _team(subject["team_id"])
        if not owner_approved and subject["root_id_or_self"] != "self":
            _stable(subject["root_id_or_self"])
        certificate_id = subject["certificate_id"]
        if type(certificate_id) is not str or str(UUID(certificate_id)) != certificate_id:
            raise ValueError()
        expected = subject["expected_membership"]
        if type(expected) is not dict or set(expected) != MEMBERSHIP_FIELDS:
            raise ValueError()
        public_key_from_did(expected["member_did_key"])
        _text(expected["alias"], 128)
        if expected["identity_scope"] == "local":
            if expected["member_did_aw"] is not None or expected["member_address"] is not None:
                raise ValueError()
            member_id = expected["member_did_key"]
        elif expected["identity_scope"] == "global":
            _stable(expected["member_did_aw"])
            if expected["member_address"] is not None:
                _text(expected["member_address"], 512)
            member_id = expected["member_did_aw"]
        else:
            raise ValueError()
        if subject["member_id"] != member_id:
            raise ValueError()
        return json.loads(canonical_json_bytes(subject))
    except (ValueError, TypeError, KeyError):
        raise SignerRefused("request_invalid") from None


def validate_owner_removal_subject(subject):
    return validate_removal_subject(subject, owner_approved=True)


def removal_artifact(operation, controller_did, timestamp):
    """The retained artifact wraps an existing covering-v2 registry request.

    Only its canonical request is signed, using AWID's existing serializer.
    The wrapper pins controller selection within the protected B2 digest.
    """
    subject = operation.spec.codec.parse_subject(operation.intent()["subject"]) if hasattr(operation, "spec") else validate_removal_subject(operation.intent()["subject"])
    c = operation.context
    if c.authority_kind != "team_controller" or subject["team_id"] != c.authority_id:
        raise SignerRefused("scope_refused")
    public_key_from_did(controller_did)
    parse_utc_seconds(timestamp)
    require_canonical_server_origin(operation.audience)
    name, domain = subject["team_id"].split(":", 1)
    if domain != c.authority_domain:
        raise SignerRefused("scope_refused")
    body = canonical_json_bytes({"certificate_id": subject["certificate_id"]})
    signing = covering_payload(aud=operation.audience,
        path=f"/v1/namespaces/{domain}/teams/{name}/certificates/revoke",
        domain=domain, operation="revoke_certificate", body=body, timestamp=timestamp,
        claims={"team_name": name, "certificate_id": subject["certificate_id"]})
    return {"controller_did": controller_did, "request": json.loads(signing)}


def removal_signing_bytes(operation, artifact):
    try:
        if type(artifact) is not dict or set(artifact) != {"controller_did", "request"}:
            raise ValueError()
        expected = removal_artifact(operation, artifact["controller_did"], artifact["request"]["timestamp"])
        if artifact != expected:
            raise ValueError()
        return canonical_json_bytes(expected["request"])
    except (ValueError, TypeError, KeyError):
        raise SignerRefused("operation_mismatch") from None
