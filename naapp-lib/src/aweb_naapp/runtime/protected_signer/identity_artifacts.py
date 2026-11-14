"""Typed projections onto existing ID and team certificate wires, not signing JSON."""

import re
from uuid import UUID, uuid4

from awid.did import public_key_from_did, validate_stable_id
from awid.id_certificates import id_certificate_signing_bytes
from awid.signing import canonical_json_bytes
from awid.team_ids import parse_team_id
from awid.utc_timestamps import parse_utc_seconds

from .types import SignerRefused

ROOT_FIELDS = {"domain", "root_id", "root_key", "teams", "deployment_label"}
ADMIT_FIELDS = {"team_id", "root_id", "root_key", "child_id", "child_key", "member_alias", "admission_policy_digest", "expected_policy_version"}
_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")


def _stable(value):
    if type(value) is not str or validate_stable_id(value) != value:
        raise ValueError()


def _text(value, maximum):
    if type(value) is not str or not 0 < len(value) <= maximum or value != value.strip() or any(ord(c) < 32 for c in value):
        raise ValueError()


def _team(value):
    namespace, name = parse_team_id(value)
    if value != name + ":" + namespace or len(namespace) > 253 or not _DOMAIN.fullmatch(namespace):
        raise ValueError()


def validate_root_subject(subject):
    if type(subject) is not dict or set(subject) != ROOT_FIELDS:
        raise ValueError()
    _stable(subject["root_id"])
    public_key_from_did(subject["root_key"])
    domain, teams = subject["domain"], subject["teams"]
    if type(domain) is not str or len(domain) > 253 or not _DOMAIN.fullmatch(domain):
        raise ValueError()
    if type(teams) is not list or not teams or not all(type(t) is str for t in teams) or teams != sorted(set(teams)):
        raise ValueError()
    for team in teams:
        _team(team)
    _text(subject["deployment_label"], 128)
    return dict(subject)


def validate_admission_subject(subject):
    if type(subject) is not dict or set(subject) != ADMIT_FIELDS:
        raise ValueError()
    _stable(subject["root_id"])
    public_key_from_did(subject["root_key"])
    _team(subject["team_id"])
    if subject["child_id"] is not None:
        _stable(subject["child_id"])
    public_key_from_did(subject["child_key"])
    _text(subject["member_alias"], 128)
    version, digest = subject["expected_policy_version"], subject["admission_policy_digest"]
    if type(version) is not int or not 0 < version < 2**53 or type(digest) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError()
    return dict(subject)


def root_artifact(operation, key, stamp):
    subject, c = operation.intent()["subject"], operation.context
    public_key_from_did(key)
    parse_utc_seconds(stamp)
    if c.authority_id != c.human_id or c.authority_domain != subject["domain"] or c.human_domain != subject["domain"]:
        raise SignerRefused("scope_refused")
    return {"v": 1, "type": "aweb.id-certificate", "id": subject["root_id"], "domain": subject["domain"],
        "parent": {"kind": "identity", "id": c.human_id}, "kind": "agent", "issuer_key": key, "issued_at": stamp}


def admission_artifact(operation, key, stamp, *, certificate_id=None):
    subject, c = operation.intent()["subject"], operation.context
    public_key_from_did(key)
    parse_utc_seconds(stamp)
    if subject["team_id"] != c.authority_id:
        raise SignerRefused("scope_refused")
    certificate_id = str(uuid4()) if certificate_id is None else certificate_id
    if str(UUID(certificate_id)) != certificate_id:
        raise ValueError()
    fields = {"version": 1, "certificate_id": certificate_id, "team_id": subject["team_id"], "team_did_key": key,
        "member_did_key": subject["child_key"], "alias": subject["member_alias"],
        "identity_scope": "local" if subject["child_id"] is None else "global", "issued_at": stamp}
    if subject["child_id"] is not None:
        fields["member_did_aw"] = subject["child_id"]
    return fields


def root_signing_bytes(operation, artifact):
    try:
        if type(artifact) is not dict or artifact != root_artifact(operation, artifact["issuer_key"], artifact["issued_at"]):
            raise ValueError()
        return id_certificate_signing_bytes(artifact)
    except (TypeError, ValueError, KeyError):
        raise SignerRefused("operation_mismatch") from None


def admission_signing_bytes(operation, artifact):
    try:
        if type(artifact) is not dict or artifact != admission_artifact(operation, artifact["team_did_key"], artifact["issued_at"],
            certificate_id=artifact["certificate_id"]):
            raise ValueError()
        return canonical_json_bytes(artifact)
    except (TypeError, ValueError, KeyError):
        raise SignerRefused("operation_mismatch") from None
