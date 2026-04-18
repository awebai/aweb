from __future__ import annotations

import hashlib
import json
from pathlib import Path

from awid.did import stable_id_from_did_key
from awid.signing import canonical_json_bytes, canonical_payload, sign_message
from awid.dns_verify import awid_txt_name, awid_txt_value


_ROOT = Path(__file__).resolve().parents[2]
_VECTORS_DIR = _ROOT / "docs" / "vectors"


def _load_json(name: str):
    return json.loads((_VECTORS_DIR / name).read_text(encoding="utf-8"))


def test_awid_service_uses_the_same_conformance_vectors_as_aweb() -> None:
    message_vectors = _load_json("message-signing-v1.json")
    for case in message_vectors:
        payload = canonical_payload(case["message"])
        assert payload.decode("utf-8") == case["canonical_payload"]
        assert sign_message(bytes.fromhex(case["signing_seed_hex"]), payload) == case["signature_b64"]

    stable_vectors = _load_json("stable-id-v1.json")
    for case in stable_vectors:
        assert stable_id_from_did_key(case["did_key"]) == case["stable_id"]

    identity_vectors = _load_json("identity-log-v1.json")
    seeds = identity_vectors["key_seeds"]
    mapping = identity_vectors["mapping"]
    seed_by_did = {
        mapping["initial_did_key"]: bytes.fromhex(seeds["initial_seed_hex"]),
        mapping["rotated_did_key"]: bytes.fromhex(seeds["rotated_seed_hex"]),
    }
    previous_entry_hash = None
    forbidden_identity_fields = {"address", "handle", "server"}
    for entry in identity_vectors["entries"]:
        state_payload = canonical_json_bytes(entry["state_payload"])
        assert state_payload.decode("utf-8") == entry["canonical_state_payload"]
        assert hashlib.sha256(state_payload).hexdigest() == entry["state_hash"]
        assert forbidden_identity_fields.isdisjoint(entry["state_payload"])

        payload = canonical_json_bytes(entry["entry_payload"])
        assert forbidden_identity_fields.isdisjoint(entry["entry_payload"])
        assert payload.decode("utf-8") == entry["canonical_entry_payload"]
        assert hashlib.sha256(payload).hexdigest() == entry["entry_hash"]
        assert sign_message(seed_by_did[entry["entry_payload"]["authorized_by"]], payload) == entry["signature_b64"]
        assert entry["entry_payload"]["prev_entry_hash"] == previous_entry_hash
        previous_entry_hash = entry["entry_hash"]

    rotation_vectors = _load_json("rotation-announcements-v1.json")
    for case in rotation_vectors:
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

    dns_vectors = _load_json("dns-txt-v1.json")
    for case in dns_vectors:
        assert awid_txt_name(case["domain"]) == case["dns_name"]
        assert awid_txt_value(case["controller_did"], case["registry_url"]) == case["dns_value"]
