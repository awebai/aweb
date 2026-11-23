"""An ended grant gives its holder a recovery action in the stream itself."""

import json

from aweb.grant_streams import grant_terminal_sse


def test_ended_grant_stream_explains_issuer_and_configured_oats_renewal():
    event = grant_terminal_sse("grant_issuer_revoked")
    assert event.startswith("event: grant_issuer_revoked\n")
    payload = json.loads(event.split("data: ", 1)[1])
    assert payload["type"] == "grant_issuer_revoked"
    assert (
        "This grant was issued from a certificate that is no longer current." in payload["detail"]
    )
    assert payload["detail"].endswith(
        "Ask the issuer for a new grant, or enable renewal on launch and restart the seat if you use OATS."
    )
