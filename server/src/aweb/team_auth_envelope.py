"""The shared AWID request envelope; existing server imports stay compatible."""

from awid.request_auth import (
    TEAM_AUTH_ENVELOPE_V2 as TEAM_AUTH_ENVELOPE_V2,
    TeamAuthEnvelope as TeamAuthEnvelope,
    canonical_audiences as canonical_audiences,
    compact_team_auth_payload as compact_team_auth_payload,
    decode_signed_payload_header as decode_signed_payload_header,
    identity_auth_signature_payload as identity_auth_signature_payload,
    raw_request_target as raw_request_target,
    team_auth_signature_payload as team_auth_signature_payload,
)
