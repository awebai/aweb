from __future__ import annotations

from typing import Any

from fastapi import Request

ADDRESS_LOOKUP_AUTH_HEADER = "X-AWID-Address-Lookup-Authorization"
ADDRESS_LOOKUP_TIMESTAMP_HEADER = "X-AWID-Address-Lookup-Timestamp"
TEAM_CERTIFICATE_HEADER = "X-AWID-Team-Certificate"


def request_address_lookup_kwargs(request: Request) -> dict[str, str]:
    auth = (request.headers.get(ADDRESS_LOOKUP_AUTH_HEADER) or "").strip()
    timestamp = (request.headers.get(ADDRESS_LOOKUP_TIMESTAMP_HEADER) or "").strip()
    certificate = (request.headers.get(TEAM_CERTIFICATE_HEADER) or "").strip()
    if not (auth or timestamp):
        return {}
    return {
        "lookup_authorization": auth,
        "lookup_timestamp": timestamp,
        "team_certificate": certificate,
    }


def envelope_address_lookup_kwargs(envelope: Any) -> dict[str, str]:
    auth = (getattr(envelope, "target_address_lookup_authorization", None) or "").strip()
    timestamp = (getattr(envelope, "target_address_lookup_timestamp", None) or "").strip()
    certificate = ""
    cert = getattr(envelope, "sender_team_certificate", None)
    if cert is not None:
        import base64
        import json

        certificate = base64.b64encode(json.dumps(cert).encode()).decode()
    if not (auth or timestamp):
        return {}
    return {
        "lookup_authorization": auth,
        "lookup_timestamp": timestamp,
        "team_certificate": certificate,
    }
