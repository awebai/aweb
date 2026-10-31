from __future__ import annotations

import json
import logging
from typing import Any, Mapping

from awid.federation_errors import FederationAuthorityError
from awid.log import canonical_server_origin
from awid.signing import verify_did_key_signature
from aweb.awid_error_handling import AWID_DEPENDENCY_ERRORS
from aweb.messaging.alias_targets import namespace_exists


def local_recipient_visible_to_auth(row: Mapping[str, Any] | None, auth: Any) -> bool:
    row_team_id = str((row or {}).get("team_id") or "").strip()
    auth_team_id = str(getattr(auth, "team_id", None) or "").strip()
    return bool(row_team_id and auth_team_id and row_team_id == auth_team_id)


def requires_registry_address_binding(row: Mapping[str, Any] | None) -> bool:
    return str((row or {}).get("identity_scope") or "").strip().lower() == "global"


def unreachable_address_refusal(address: str) -> str:
    """Why a full address reaches no one, in words that do not say whether a
    local identity holds that name."""
    return (
        f"{address} has no registered address. A local identity has no address and "
        "is reachable only from inside its own team, by alias; a global identity is "
        "reachable by address once one is assigned."
    )


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


async def namespace_uses_home_registry(db, registry_client, domain: str) -> bool:
    # A local team label alone is not authority. Use the configured registry
    # only when it is the selected origin and actually serves this namespace.
    if registry_client is None or not await namespace_exists(db, domain):
        return False
    try:
        if await registry_client.registry_audience(domain) != canonical_server_origin(registry_client.registry_url):
            return False
        namespace = await registry_client.get_namespace_fresh(domain)
    except AWID_DEPENDENCY_ERRORS as exc:
        logging.getLogger(__name__).warning("Messaging home namespace lookup unavailable for %s", domain, exc_info=True)
        raise FederationAuthorityError("sender_registry_unavailable") from exc
    return bool(
        namespace and namespace.domain == domain
        and namespace.verification_status == "verified" and namespace.controller_did
    )
