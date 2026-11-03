"""Stable serialization helpers for strict authority-core failures."""

from __future__ import annotations

from typing import Any

from awid.federation_errors import FederationAuthorityError


class RecipientNotResidentError(FederationAuthorityError):
    """An admitted address routes here but its exact identity is not resident."""

    detail = (
        "The recipient is not set up for messaging on the server this address points to. "
        "Ask the recipient or the person who manages that server to check the address "
        "and the recipient's messaging setup."
    )

    def __init__(self) -> None:
        super().__init__("recipient_identity_not_found")


class TeamRouteError(FederationAuthorityError):
    """The stable team-route refusal plus its supported recovery step."""

    def __init__(self, reason: str, *, team: str | None = None, domain: str | None = None) -> None:
        super().__init__(reason)
        team_label = f"Team {team}" if team else "This agent's team"
        details = {
            "local_sender_certificate_required": "This team-only agent's message did not carry its team certificate. Upgrade aw and resend.",
            "local_sender_certificate_invalid": "This agent's team certificate does not match it. Reinstall it with `aw id team fetch-cert` and resend.",
            "local_sender_certificate_revoked": f"This agent is no longer a member of {team or 'its team'}, so it cannot write outside it.",
            "local_sender_team_key_stale": f"{team_label} rotated its key. Its controller must reissue this agent's certificate.",
            "local_sender_team_server_missing": f"{team_label} has not published its server at AWID, so replies could not reach this agent. The team controller runs `aw id team set-server`; hosted teams publish automatically: contact support.",
            "local_sender_route_mismatch": "This agent's server does not match its team's published server. Check `aw id team show-server`.",
            "local_recipient_route_missing": "This agent can no longer receive replies here: its team membership or server changed. It can write to you again.",
            "recipient_policy_rejected": "The recipient accepts first messages only from its team and contacts. A team-only agent cannot be a contact; write from an agent with a public address (`aw init --global`).",
            "sender_registry_unavailable": "The server could not reach AWID. Retry shortly.",
            "federation_authority_coordination_unavailable": "The server could not reach AWID. Retry shortly.",
        }
        discovery = f"{domain or 'The team domain'} has no usable AWID record, so other servers cannot check this agent's team. Publish an `_awid` record for {domain or 'the team domain'}, or write from an agent with a public address (`aw init --global`)."
        self.detail = details.get(reason, discovery if reason.startswith("sender_registry_") else reason)


def authority_error_body(
    error: FederationAuthorityError,
    *,
    correlation_id: str,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "detail": getattr(error, "detail", error.reason),
        "reason": error.reason,
        "retryable": error.retryable,
        "correlation_id": correlation_id,
    }
    if error.did_aw is not None:
        body["did_aw"] = error.did_aw
    if error.observed_sequence is not None:
        body["observed_sequence"] = error.observed_sequence
    return body
