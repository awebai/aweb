"""Public-only ``aweb.log-key/1`` codec for the existing Go log-key record.

This builds signing bytes, never a key or signature. The caller independently
admits current controller authority and the exact human-approved operation.
"""

from typing import Any

from awid.did import public_key_from_did
from awid.e2ee_keys import decode_raw_standard_b64, encryption_key_id, raw_standard_b64
from awid.signing import canonical_json_bytes
from awid.team_ids import build_team_id, parse_team_id
from awid.utc_timestamps import parse_utc_seconds

LOG_KEY_PREFIX = b"aweb.log-key/1\n"
LOG_KEY_SUBJECT_FIELDS = frozenset({"team_id", "key_id", "public_key", "created_at"})
LOG_KEY_FIELDS = LOG_KEY_SUBJECT_FIELDS | {"v", "team_key_did"}


def validate_log_key_subject(subject: Any) -> dict:
    if type(subject) is not dict or set(subject) != LOG_KEY_SUBJECT_FIELDS:
        raise ValueError("invalid log-key subject")
    if not all(type(value) is str for value in subject.values()):
        raise ValueError("invalid log-key subject")
    team = subject["team_id"]
    if team.count(":") != 1 or build_team_id(*parse_team_id(team)) != team:
        raise ValueError("noncanonical log-key team")
    public = subject["public_key"]
    raw = decode_raw_standard_b64(public, field_name="public_key")
    if len(raw) != 32 or raw_standard_b64(raw) != public:
        raise ValueError("invalid log-key public key")
    if subject["key_id"] != encryption_key_id(public):
        raise ValueError("log-key id mismatch")
    parse_utc_seconds(subject["created_at"])
    return dict(subject)


def build_log_key_record(subject: Any, team_key_did: str) -> dict:
    if type(team_key_did) is not str:
        raise ValueError("invalid log-key team key")
    public_key_from_did(team_key_did)
    return {"v": 1, **validate_log_key_subject(subject), "team_key_did": team_key_did}


def log_key_record_signing_bytes(record: Any) -> bytes:
    if (
        type(record) is not dict
        or set(record) != LOG_KEY_FIELDS
        or type(record["v"]) is not int
        or record["v"] != 1
        or type(record["team_key_did"]) is not str
    ):
        raise ValueError("invalid log-key record")
    public_key_from_did(record["team_key_did"])
    validate_log_key_subject({name: record[name] for name in LOG_KEY_SUBJECT_FIELDS})
    return LOG_KEY_PREFIX + canonical_json_bytes(record)
