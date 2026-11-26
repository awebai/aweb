"""P0 public DTO grammar only: no trust, capability advertisement or message effects.

A structurally valid DTO is not authorization. Implementing tasks must perform
identity, consent, current-policy and custody checks under the commit fence.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ._profile import PROFILE

MAX_BYTES = 1024 * 1024
MAX_SAFE = 9007199254740991


class ContractError(ValueError):
    def __init__(self, code: str, field: str = "record"):
        self.code = code
        self.field = field
        super().__init__(f"{code}: {field}")


@dataclass(frozen=True)
class ContractRecord:
    """Named closed-schema DTO. `value` is untrusted until service verification."""
    schema: str
    value: dict[str, Any]


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("invalid", "duplicate key")
        result[key] = value
    return result


def _safe_json(value: Any, depth: int = 0) -> None:
    if depth > 64:
        raise ContractError("invalid", "depth")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -MAX_SAFE <= value <= MAX_SAFE:
            raise ContractError("invalid", "integer")
    elif type(value) is str:
        value.encode("utf-8", errors="strict")
    elif type(value) is list:
        for item in value:
            _safe_json(item, depth + 1)
    elif type(value) is dict:
        for key, item in value.items():
            _safe_json(key, depth + 1)
            _safe_json(item, depth + 1)
    else:
        raise ContractError("invalid", "json type")


def _match(rule: Any, value: Any, field: str) -> None:
    if isinstance(rule, dict):
        if "enum" in rule:
            if type(value) is not str or value not in rule["enum"]:
                raise ContractError("invalid", field)
        elif "integer_const" in rule:
            if type(value) is not int or value != rule["integer_const"]:
                raise ContractError("invalid", field)
        elif "ref" in rule:
            _validate(rule["ref"], value)
        elif "array" in rule:
            if type(value) is not list or len(value) > 4096:
                raise ContractError("invalid", field)
            for item in value:
                _match(rule["array"], item, field)
        elif "one_of" in rule:
            matched = 0
            for variant in rule["one_of"]:
                try:
                    _match(variant, value, field)
                    matched += 1
                except ContractError:
                    pass
            if matched != 1:
                raise ContractError("invalid", field)
        return
    if rule in ("uint", "positive_uint", "limit"):
        low, high = (1, 200) if rule == "limit" else (int(rule == "positive_uint"), MAX_SAFE)
        if type(value) is not int or not low <= value <= high:
            raise ContractError("invalid", field)
        return
    if rule == "bool":
        if type(value) is not bool:
            raise ContractError("invalid", field)
        return
    if rule == "json_object":
        if type(value) is not dict:
            raise ContractError("invalid", field)
        return
    if rule == "string":
        if type(value) is not str:
            raise ContractError("invalid", field)
        return
    if rule in ("didkey_list", "didaw_list"):
        if type(value) is not str:
            raise ContractError("invalid", field)
        items = value.split(",") if value else []
        if items != sorted(set(items)):
            raise ContractError("invalid", field)
        for item in items:
            _match("didkey" if rule == "didkey_list" else "didaw", item, field)
        return
    if type(value) is not str or not value:
        raise ContractError("invalid", field)
    patterns = {
        "platform_kind": r"[a-z][a-z0-9_]{0,31}",
        "uuid": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "teamid": r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)",
        "hash": r"sha256:[0-9a-f]{64}",
        "commitment": r"commitment:[0-9a-f]{64}",
        "did": r"did:(?:aw:[A-Za-z0-9._:-]+|key:z[1-9A-HJ-NP-Za-km-z]+)",
        "didaw": r"did:aw:[A-Za-z0-9._:-]+",
        "didkey": r"did:key:z[1-9A-HJ-NP-Za-km-z]+",
        "timestamp": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        "opaque": r"[A-Za-z0-9._:-]{1,256}",
        "signature": r"[A-Za-z0-9+/]{86}",
    }
    if rule in patterns and re.fullmatch(patterns[rule], value) is None:
        raise ContractError("invalid", field)
    if rule == "timestamp":
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as error:
            raise ContractError("invalid", field) from error
    if rule == "signature":
        try:
            decoded = base64.b64decode(value + "==", validate=True)
            if len(decoded) != 64 or base64.b64encode(decoded).decode().rstrip("=") != value:
                raise ValueError()
        except ValueError as error:
            raise ContractError("invalid", field) from error


def _validate(schema: str, value: Any) -> None:
    spec = PROFILE["schemas"].get(schema)
    if spec is None:
        raise ContractError("unsupported", schema)
    if type(value) is not dict:
        raise ContractError("invalid", schema)
    required, optional = spec["required"], spec["optional"]
    if required.keys() - value.keys() or value.keys() - (required.keys() | optional.keys()):
        raise ContractError("invalid", schema)
    if "version" in required and value.get("version") not in required["version"]["enum"]:
        raise ContractError("unsupported", "version")
    for key, item in value.items():
        _match((required | optional)[key], item, key)
    _relations(schema, value)


def _relations(schema: str, v: dict[str, Any]) -> None:
    """Only local shape relations; no inference of custody or authorization."""
    if schema == "SignedArtifact":
        require_canonical_signed_payload(v["signed_payload"].encode("utf-8"))
    if schema == "BridgedParticipant" and v["subject"].startswith("did:"):
        raise ContractError("invalid", "guest subject")
    if schema == "ResolveRequest":
        selector_fields = v.keys() - {"version"}
        if selector_fields not in ({"team_id", "selector"}, {"session_id", "participant"}):
            raise ContractError("invalid", "alternative selector")
    if schema == "CheckpointIntent":
        owner = {"expected_membership_epoch", "expected_membership_hash", "expected_export_generation", "generation", "policy_digest"}
        if v["authorization"] == "owner":
            if not owner <= v.keys() or v["generation"] != v["expected_export_generation"] + 1:
                raise ContractError("invalid", "checkpoint CAS")
        elif owner & v.keys() or v["operation"] == "activate":
            raise ContractError("invalid", "narrow-only checkpoint")
    if schema == "CheckpointReceipt" and v["acceptance_seq"] != v["effective_after_seq"]:
        raise ContractError("invalid", "checkpoint boundary")
    if schema == "MessageAcceptance":
        fields = {"message_envelope_hash", "acceptance_seq", "membership_epoch", "membership_hash", "exports", "signer", "signing_key_id"}
        if v["capture_status"] == "recorded":
            if not fields <= v.keys() or any(x["checkpoint_seq"] >= v["acceptance_seq"] for x in v["exports"]):
                raise ContractError("invalid", "capture boundary")
        elif fields & v.keys():
            raise ContractError("invalid", "legacy capture")
    if schema == "PresenceScope" and ((v["kind"] == "session") != ("session_id" in v)):
        raise ContractError("invalid", "presence scope")
    if schema in ("PresenceIntent", "PresenceBindingIntent") and ((v["authorization"] == "owner") != ("ownership_proof" in v)):
        raise ContractError("invalid", "presence authority proof")
    if schema == "PageResult" and (v["has_more"] != ("next_cursor" in v)):
        raise ContractError("invalid", "cursor")
    if schema == "Interval" and v["after_seq"] > v["through_seq"]:
        raise ContractError("invalid", "interval")
    if schema == "Capabilities":
        if set(v["enabled"]) - set(v["implemented"]) or set(v["enabled"]) & set(v["refused"]):
            raise ContractError("unsupported", "capability activation")
    if schema == "PreparedSend" and "sha256:" + hashlib.sha256(v["envelope"].encode()).hexdigest() != v["envelope_hash"]:
        raise ContractError("invalid", "envelope hash")
    if schema == "Refusal":
        retries = {"invalid": {"never"}, "unsupported": {"never"}, "forbidden": {"never"}, "consent_required": {"never"}, "stale": {"refresh"}, "replay_conflict": {"never"}, "not_found": {"never"}, "authority_unavailable": {"backoff"}, "native_unavailable": {"backoff", "reconcile"}, "outcome_unknown": {"reconcile"}, "limit_exceeded": {"backoff"}}
        if v["retry"] not in retries[v["code"]]:
            raise ContractError("invalid", "retry policy")
    if schema == "NativeV2Content" and v["kind"] == "mail" and "subject" not in v:
        raise ContractError("invalid", "mail subject")
    if schema == "PrepareRequest":
        managed = v["format"] == "managed_chat_plaintext"
        if ((not managed) != ("target" in v)) or managed != ("group_context" in v) or (managed and v["kind"] != "chat") or (v["kind"] == "mail" and v["author"]["kind"] != "native"):
            raise ContractError("invalid", "message profile")
        if managed and (v["group_context"]["author_ref"] != v["author"] or v["group_context"]["message_id"] != v["message_id"] or v.get("conversation_id") != v["group_context"]["session_id"]):
            raise ContractError("invalid", "message context")
    if schema == "NativeOperationRequest":
        decision = {"decision", "owner_authorization", "evidence_hash"}
        if v["operation"] == "resolve":
            if not decision <= v.keys():
                raise ContractError("invalid", "native resolution")
        elif {"decision", "owner_authorization"} & v.keys():
            raise ContractError("invalid", "native decision")
    if schema == "PolicyState" and v["authority_mode"] == "server_readable" and v["confidentiality"] == "end_to_end":
        raise ContractError("invalid", "server-readable authority")
    if schema == "PolicyState" and v["bridges"] and v["confidentiality"] != "bridge_readable":
        raise ContractError("invalid", "bridge-readable label")
    if schema == "ManagedPlaintext":
        if v["message_id"] != v["group_context"]["message_id"] or v["conversation_id"] != v["group_context"]["session_id"]:
            raise ContractError("invalid", "group context")
        author = v["group_context"]["author_ref"]
        if v["signer"] != author["did" if author["kind"] == "native" else "bridge"]:
            raise ContractError("invalid", "author signer")
    if schema == "AuthorProjection":
        guest = v["author"]["kind"] == "bridged"
        if guest and (v["author_assurance"] != "platform_attested" or v["trust_status"] != "external_untrusted" or v["verified"]):
            raise ContractError("invalid", "guest assurance")
        if not guest and (v["author_assurance"] != "native" or v["trust_status"] == "external_untrusted"):
            raise ContractError("invalid", "native assurance")


def decode_record(schema: str, raw: bytes) -> ContractRecord:
    if len(raw) > MAX_BYTES:
        raise ContractError("invalid", "size")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        _safe_json(value)
        _validate(schema, value)
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError("invalid") from error
    return ContractRecord(schema, value)


def canonical_record(record: ContractRecord) -> bytes:
    # Revalidate so mutation of a retained caller dictionary cannot bypass grammar.
    _safe_json(record.value)
    _validate(record.schema, record.value)
    raw = json.dumps(record.value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_BYTES:
        raise ContractError("invalid", "size")
    return raw


def require_capability(record: ContractRecord, capability: str) -> None:
    """Ignore unknown advertised tokens, but never select an unknown/deferred feature."""
    _validate("Capabilities", record.value)
    if capability not in PROFILE["capabilities"] or capability not in record.value["enabled"]:
        raise ContractError("unsupported", "capability")


def require_canonical_signed_payload(raw: bytes) -> None:
    """Require original new-profile signed bytes; never silently reserialize.

    This is a byte/JSON check, not a signature, typed-schema or authority check.
    Legacy native payloads retain their existing serialization rules.
    """
    if len(raw) > MAX_BYTES:
        raise ContractError("invalid", "signed payload size")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        _safe_json(value)
        if type(value) is not dict or raw != json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode():
            raise ContractError("invalid", "noncanonical signed payload")
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError("invalid", "signed payload") from error
