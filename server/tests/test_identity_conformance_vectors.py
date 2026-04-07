from __future__ import annotations

import hashlib
import json
from pathlib import Path

from awid.did import stable_id_from_did_key
from awid.log import log_entry_payload
from awid.signing import canonical_json_bytes, canonical_payload, sign_message
from awid.dns_verify import awid_txt_name, awid_txt_value


_SERVER_ROOT = Path(__file__).resolve().parents[1]
_VECTORS_DIR = _SERVER_ROOT / "docs" / "vectors"


def _load_json(name: str):
    return json.loads((_VECTORS_DIR / name).read_text(encoding="utf-8"))


def test_message_signing_vectors_match_current_signing_contract() -> None:
    vectors = _load_json("message-signing-v1.json")

    for case in vectors:
        payload = canonical_payload(case["message"])
        assert payload.decode("utf-8") == case["canonical_payload"]
        assert sign_message(bytes.fromhex(case["signing_seed_hex"]), payload) == case["signature_b64"]


def test_stable_id_vectors_match_current_derivation_contract() -> None:
    vectors = _load_json("stable-id-v1.json")

    for case in vectors:
        assert stable_id_from_did_key(case["did_key"]) == case["stable_id"]


def test_identity_log_vectors_match_current_audit_log_contract() -> None:
    vectors = _load_json("identity-log-v1.json")
    mapping = vectors["mapping"]
    seeds = vectors["key_seeds"]
    seed_by_did = {
        mapping["initial_did_key"]: bytes.fromhex(seeds["initial_seed_hex"]),
        mapping["rotated_did_key"]: bytes.fromhex(seeds["rotated_seed_hex"]),
    }

    for entry in vectors["entries"]:
        payload = log_entry_payload(
            did_aw=entry["entry_payload"]["did_aw"],
            seq=entry["entry_payload"]["seq"],
            operation=entry["entry_payload"]["operation"],
            previous_did_key=entry["entry_payload"]["previous_did_key"],
            new_did_key=entry["entry_payload"]["new_did_key"],
            prev_entry_hash=entry["entry_payload"]["prev_entry_hash"],
            state_hash=entry["entry_payload"]["state_hash"],
            authorized_by=entry["entry_payload"]["authorized_by"],
            timestamp=entry["entry_payload"]["timestamp"],
        )

        assert payload.decode("utf-8") == entry["canonical_entry_payload"]
        assert hashlib.sha256(payload).hexdigest() == entry["entry_hash"]
        assert (
            sign_message(seed_by_did[entry["entry_payload"]["authorized_by"]], payload)
            == entry["signature_b64"]
        )


def test_rotation_announcement_vectors_match_current_signing_contract() -> None:
    vectors = _load_json("rotation-announcements-v1.json")

    for case in vectors:
        for link in case["links"]:
            payload = canonical_json_bytes(
                {
                    "new_did": link["new_did_key"],
                    "old_did": link["old_did_key"],
                    "timestamp": link["timestamp"],
                }
            )
            assert payload.decode("utf-8") == link["canonical_payload"]
            assert sign_message(bytes.fromhex(link["old_seed_hex"]), payload) == link["signature_b64"]


def test_dns_txt_vectors_match_current_dns_contract() -> None:
    vectors = _load_json("dns-txt-v1.json")

    for case in vectors:
        assert awid_txt_name(case["domain"]) == case["dns_name"]
        assert awid_txt_value(case["controller_did"], case["registry_url"]) == case["dns_value"]
