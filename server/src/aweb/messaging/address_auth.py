from __future__ import annotations

import json
from typing import Any, Mapping

from awid.signing import verify_did_key_signature


def local_recipient_visible_to_auth(row: Mapping[str, Any] | None, auth: Any) -> bool:
    row_team_id = str((row or {}).get("team_id") or "").strip()
    auth_team_id = str(getattr(auth, "team_id", None) or "").strip()
    return bool(row_team_id and auth_team_id and row_team_id == auth_team_id)


def requires_registry_address_binding(row: Mapping[str, Any] | None) -> bool:
    return str((row or {}).get("lifetime") or "").strip().lower() == "persistent"


def verified_signed_payload_json(
    *,
    signed_payload: str | None,
    signature: str | None,
    did_key: str | None,
) -> dict[str, Any] | None:
    if not signed_payload or not signature or not did_key:
        return None
    try:
        verify_did_key_signature(
            did_key=did_key,
            payload=signed_payload.encode("utf-8"),
            signature_b64=signature,
        )
        payload = json.loads(signed_payload)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None
