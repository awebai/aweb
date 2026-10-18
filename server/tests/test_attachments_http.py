"""Attachment boundaries through the real app, PG and AWID authority fixtures."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

import pytest

from aweb.e2ee_messages import _inner_payload_map
from test_dashboard_privacy import _request, privacy_app  # noqa: F401


def descriptor():
    return {"id": str(uuid4()), "filename": "report.pdf", "media_type": "application/pdf",
            "size": 9, "sha256": sha256(b"filebytes").hexdigest(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat().replace("+00:00", "Z")}


def test_attachment_inner_content_is_preserved_without_changing_header():
    old = {"inner_version": 2, "kind": "mail", "message_id": str(uuid4()),
           "conversation_id": str(uuid4()), "created_at": "2026-10-18T00:00:00Z",
           "from": {}, "recipients": [], "subject": "text", "body": "text"}
    attached = {**old, "attachments": [descriptor()]}
    assert _inner_payload_map(attached, include_content=True)["attachments"] == attached["attachments"]
    assert _inner_payload_map(attached, include_content=False) == _inner_payload_map(old, include_content=False)
    assert "attachments" not in _inner_payload_map(old, include_content=True)


@pytest.mark.asyncio
async def test_attachment_ref_send_without_backend_fails_closed(privacy_app):
    # The app must recognize the optional interface before refusing its missing
    # configured backend; an unrecognized request shape is not this boundary.
    d = descriptor()
    response = await _request(privacy_app, "alice", "POST", "/v1/messages", {
        "to_did": privacy_app.actors["bob"].did, "body": "text",
        "attachment_refs": [{"id": d["id"], "size": d["size"], "descriptor_sha256": "0" * 64}],
    })
    assert response.status_code == 422
    assert response.json()["detail"] == {"code": "request_invalid"}


@pytest.mark.asyncio
async def test_legacy_attachments_refused_without_echoing_filename(privacy_app):
    response = await _request(privacy_app, "alice", "POST", "/v1/messages", {
        "to_did": privacy_app.actors["bob"].did, "body": "text", "attachments": [descriptor()],
    })
    assert response.status_code == 422
    assert response.json()["detail"] == {"code": "request_invalid"}
    assert "report.pdf" not in response.text
