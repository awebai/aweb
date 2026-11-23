"""Signed recipient claims shared by mail, chat and address resolution."""

from collections.abc import Mapping, Sequence
from typing import Any
from enum import Enum, StrEnum, auto


class RecipientSelectorField(StrEnum):
    AGENT_ID = "to_agent_id"
    ALIAS = "to_alias"
    DID = "to_did"
    STABLE_ID = "to_stable_id"
    ADDRESS = "to_address"


class RecipientBindingUse(Enum):
    SEND_CLAIMS = auto()
    ADDRESS_VISIBILITY = auto()


def signed_recipient_matches(
    payload: Mapping[str, Any],
    *,
    recipients: Sequence[Mapping[str, Any]],
    allowed_to: set[str],
    use: RecipientBindingUse = RecipientBindingUse.SEND_CLAIMS,
) -> bool:
    """Validate supplied claims; released plaintext envelopes may omit them.

    Implements Global And Local Identities (docs/identity-messaging-contract.md:124-142).

    Address resolution requires a DID claim before signed bytes can establish
    visibility. Group identity claims still require exactly one recipient.
    """
    signed_to = str(payload.get("to") or "").strip()
    if signed_to and signed_to not in allowed_to:
        return False
    signed_did = str(payload.get("to_did") or "").strip()
    signed_stable = str(payload.get("to_stable_id") or "").strip()
    if use is RecipientBindingUse.ADDRESS_VISIBILITY and not (
        signed_did or signed_stable
    ):
        return False
    if signed_did:
        if len(recipients) != 1:
            return False
        refs = {
            str(recipients[0].get(field) or "").strip()
            for field in ("did", "did_key", "did_aw")
        } - {""}
        if signed_did not in refs:
            return False
    if signed_stable and (
        len(recipients) != 1
        or signed_stable != str(recipients[0].get("did_aw") or "").strip()
    ):
        return False
    return True
