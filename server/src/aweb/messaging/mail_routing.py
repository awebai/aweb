from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from aweb.messaging.address_auth import identity_recipient
from aweb.messaging.conversations import (
    list_conversation_participants,
    require_active_conversation_participant,
)
from aweb.messaging.messages import get_agent_by_id, resolve_agent_by_did
from aweb.messaging.verification import require_conversation_not_legacy_bound
from aweb.service_errors import ValidationError


class ParticipantRetiredError(ValidationError):
    status_code = 410

    def __init__(self, alias: str, team: str):
        super().__init__({
            "code": "participant_retired",
            "message": f"{alias} has moved; start a new mail to {alias} in {team}",
        })


async def _require_live_mail_participant(db, participant: dict, conversation: dict) -> None:
    did = participant["did"]
    rows = await db.get_manager("aweb").fetch_all(
        """SELECT deleted_at FROM {{tables.agents}}
           WHERE COALESCE(CASE WHEN did_aw_verified_key=did_key THEN NULLIF(did_aw,'') END, did_key)=$1""",
        did,
    )
    # Unknown/remote residence is not retirement. A deleted actor projection
    # cannot retire a DID that still has a live membership elsewhere.
    if rows and all(row["deleted_at"] is not None for row in rows):
        alias = str(participant.get("alias") or did)
        team = str(conversation.get("team_id") or "the original team")
        raise ParticipantRetiredError(alias, team)


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
        "external": True,
    }


async def recipient_for_conversation_participant(db, participant: dict) -> dict:
    did = str(participant.get("did") or "").strip()
    local = await resolve_agent_by_did(db, did)
    if local is not None:
        recipient = identity_recipient(local, str(participant.get("address") or "").strip())
        recipient["alias"] = participant.get("alias") or did
        return recipient
    if did.startswith("did:key:") and not participant_delivery_origin(participant):
        alias = str(participant.get("alias") or did)
        raise ValidationError(f'Conversation recipient "{alias}" has been retired and is unreachable. '
                              'Start a new conversation with an active recipient.')
    return participant_recipient({**participant, "agent_id": None})


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
                "address": None,
                "did_aw": None,
                "did_key": participant_did,
                "delivery_origin": delivery_origin,
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
    await _require_live_mail_participant(db, recipient_participant, auth_context["conversation"])
    await require_conversation_not_legacy_bound(
        db,
        conversation_id=conversation_id,
        conversation_type="mail",
    )
    return MailContinuationContext(
        conversation=auth_context["conversation"],
        sender_participant=auth_context["participant"],
        recipient_participant=recipient_participant,
        participants=participants,
    )


async def explicit_mail_target_matches_participant(
    db, participant: dict,
    *,
    to_agent_id: str | None = None,
    to_alias: str | None = None,
    to_did: str | None = None,
    to_stable_id: str | None = None,
    to_address: str | None = None,
) -> bool:
    checks: list[bool] = []
    participant_alias = str(participant.get("alias") or "").strip()
    participant_did = str(participant.get("did") or "").strip()
    participant_address = str(participant.get("address") or "").strip()

    selected_identity_matches = False
    stable_id_matches = False
    address_matches = False

    if to_agent_id is not None and str(to_agent_id).strip():
        selected = await get_agent_by_id(db, agent_id=str(to_agent_id).strip())
        selected_did = str((selected or {}).get("did_aw") or (selected or {}).get("did_key") or "")
        selected_identity_matches = selected_did == participant_did
        checks.append(selected_identity_matches)
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
        checks.append(did_matches or stable_id_matches or address_matches or selected_identity_matches)

    return bool(checks) and all(checks)
