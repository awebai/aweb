from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from aweb.messaging.alias_targets import AmbiguousLocalAddressError, get_agent_by_namespace_alias
from aweb.messaging.conversations import (
    list_conversation_participants,
    require_active_conversation_participant,
)
from aweb.messaging.messages import get_agent_by_id
from aweb.messaging.verification import require_conversation_not_legacy_bound
from aweb.service_errors import ConflictError, ServiceError, ValidationError


@dataclass(frozen=True)
class MailContinuationContext:
    conversation: dict
    sender_participant: dict
    recipient_participant: dict
    participants: list[dict]


def participant_delivery_origin(participant: dict) -> str:
    origin = str(participant.get("delivery_origin") or "").strip()
    if origin:
        return origin
    transport_hint = str(participant.get("transport_hint") or "").strip()
    for prefix in ("federation:", "federated:"):
        if transport_hint.startswith(prefix):
            return transport_hint[len(prefix):].strip()
    return ""


def participant_is_remote(participant: dict) -> bool:
    return bool(participant_delivery_origin(participant))


def participant_recipient(participant: dict) -> dict:
    did = str(participant.get("did") or "").strip()
    return {
        "agent_id": participant.get("agent_id"),
        "team_id": None,
        "alias": participant.get("alias") or did,
        "address": participant.get("address"),
        "did_aw": did if did.startswith("did:aw:") else None,
        "did_key": did if did.startswith("did:key:") else None,
        "messaging_policy": None,
        "external": True,
    }


async def _local_recipient_from_address(db, *, address: str) -> dict | None:
    if "/" not in address:
        return None
    domain, name = address.split("/", 1)
    try:
        return await get_agent_by_namespace_alias(db, namespace=domain, alias=name)
    except AmbiguousLocalAddressError as exc:
        raise ConflictError(str(exc)) from exc


def with_requested_address(row: dict, address: str) -> dict:
    copied = dict(row)
    copied["address"] = (copied.get("address") or "").strip() or address
    return copied


async def recipient_for_conversation_participant(db, participant: dict) -> dict:
    address = str(participant.get("address") or "").strip()
    if participant.get("agent_id") is not None:
        local_recipient = await get_agent_by_id(db, agent_id=str(participant["agent_id"]))
        if local_recipient is not None:
            return with_requested_address(local_recipient, address) if address else local_recipient

    local_recipient = await _local_recipient_from_address(db, address=address)
    if local_recipient is not None:
        return with_requested_address(local_recipient, address)
    did = str(participant.get("did") or "").strip()
    if did.startswith("did:key:") and not participant_delivery_origin(participant):
        raise ValidationError("Local did:key recipient requires local resolution or learned return route")
    return participant_recipient(participant)


async def remote_recipient_from_participant(registry_client, participant: dict) -> dict:
    address = str(participant.get("address") or "").strip()
    delivery_origin = participant_delivery_origin(participant)
    participant_did = str(participant.get("did") or "").strip()
    did_aw = participant_did if participant_did.startswith("did:aw:") else ""
    if not did_aw:
        if participant_did.startswith("did:key:") and delivery_origin:
            return {
                "agent_id": None,
                "team_id": None,
                "alias": participant.get("alias") or participant_did,
                "address": address or participant_did,
                "did_aw": participant_did,
                "did_key": participant_did,
                "delivery_origin": delivery_origin,
                "reachability": "public",
                "messaging_policy": None,
                "external": True,
            }
        raise ValidationError("Remote mail recipient has no stored routable identity")
    current_did = str(participant.get("current_did_key") or participant.get("did_key") or "").strip()
    if not current_did:
        raise ValidationError("Remote mail recipient stored route is missing current did:key")
    if not current_did.startswith("did:key:"):
        raise ValidationError("Remote mail recipient stored route current did:key is invalid")
    if not delivery_origin:
        raise ValidationError("Remote mail recipient has no delivery origin")
    name = did_aw
    if "/" in address:
        _, name = address.split("/", 1)
    return {
        "agent_id": None,
        "team_id": None,
        "alias": participant.get("alias") or name,
        "address": address or did_aw,
        "did_aw": did_aw,
        "did_key": current_did,
        "delivery_origin": delivery_origin,
        "reachability": "public",
        "messaging_policy": None,
        "external": True,
    }


async def mail_continuation_context(
    db,
    *,
    conversation_id: str,
    sender_did: str,
    equivalent_dids: Iterable[str] = (),
) -> MailContinuationContext:
    auth_context = await require_active_conversation_participant(
        db,
        conversation_id=conversation_id,
        authenticated_did=sender_did,
        equivalent_dids=equivalent_dids,
    )
    await require_conversation_not_legacy_bound(
        db,
        conversation_id=conversation_id,
        conversation_type="mail",
    )
    participants = await list_conversation_participants(db, conversation_id=conversation_id)
    sender_participant_did = auth_context["participant"]["did"]
    recipients = [
        participant
        for participant in participants
        if participant["did"] != sender_participant_did
    ]
    if len(recipients) == 0 and len(participants) == 1:
        # Defensive self-loopback for a malformed historical conversation.
        recipient_participant = auth_context["participant"]
    elif len(recipients) == 1:
        recipient_participant = recipients[0]
    else:
        raise ValidationError("Mail conversation continuation requires exactly one recipient")
    return MailContinuationContext(
        conversation=auth_context["conversation"],
        sender_participant=auth_context["participant"],
        recipient_participant=recipient_participant,
        participants=participants,
    )


def explicit_mail_target_matches_participant(
    participant: dict,
    *,
    to_agent_id: str | None = None,
    to_alias: str | None = None,
    to_did: str | None = None,
    to_stable_id: str | None = None,
    to_address: str | None = None,
) -> bool:
    checks: list[bool] = []
    participant_agent_id = str(participant.get("agent_id") or "").strip()
    participant_alias = str(participant.get("alias") or "").strip()
    participant_did = str(participant.get("did") or "").strip()
    participant_address = str(participant.get("address") or "").strip()

    agent_id_matches = False
    stable_id_matches = False
    address_matches = False

    if to_agent_id is not None and str(to_agent_id).strip():
        agent_id_matches = participant_agent_id == str(to_agent_id).strip()
        checks.append(agent_id_matches)
    if to_alias is not None and str(to_alias).strip():
        checks.append(participant_alias == str(to_alias).strip())
    if to_stable_id is not None and str(to_stable_id).strip():
        stable_id_matches = participant_did == str(to_stable_id).strip()
        checks.append(stable_id_matches)
    if to_address is not None and str(to_address).strip():
        address_matches = participant_address.lower() == str(to_address).strip().lower()
        checks.append(address_matches)
    if to_did is not None and str(to_did).strip():
        did_matches = participant_did == str(to_did).strip()
        # Signed clients often include the recipient's current did:key as an
        # extra binding while the conversation participant stores the stable
        # did:aw. Accept that only when another stable participant field has
        # already identified the recorded recipient.
        checks.append(did_matches or stable_id_matches or address_matches or agent_id_matches)

    return bool(checks) and all(checks)
