from __future__ import annotations

import uuid

import httpx
import pytest

from .harness import AwebOtherTarget, AwebTarget


def _bad_auth_client(base_url: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=base_url,
        headers={"Authorization": "Bearer definitely-invalid-token"},
        timeout=10.0,
    )


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_invalid_bearer_token_is_rejected(aweb_target: AwebTarget) -> None:
    async with _bad_auth_client(aweb_target.base_url) as client:
        resp = await client.get("/v1/chat/pending")
        assert resp.status_code == 401, resp.text


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_cross_project_mail_send_is_rejected(
    aweb_client, aweb_target: AwebTarget, aweb_other_target: AwebOtherTarget | None
) -> None:
    if aweb_other_target is None:
        pytest.skip("Missing AWEB_OTHER_* env vars")

    resp = await aweb_client.post(
        "/v1/messages",
        json={
            "to_agent_id": aweb_other_target.agent.agent_id,
            "subject": "cross-project",
            "body": "should not deliver",
            "priority": "normal",
            "thread_id": None,
        },
    )
    assert resp.status_code in (403, 404), resp.text


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_cross_project_chat_alias_resolution_is_rejected(
    aweb_client, aweb_target: AwebTarget, aweb_other_target: AwebOtherTarget | None
) -> None:
    if aweb_other_target is None:
        pytest.skip("Missing AWEB_OTHER_* env vars")

    resp = await aweb_client.post(
        "/v1/chat/sessions",
        json={
            "to_aliases": [aweb_other_target.agent.alias],
            "message": "cross-project should fail",
            "leaving": False,
        },
    )
    assert resp.status_code in (403, 404), resp.text


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_cross_project_reservation_acquire_is_rejected(
    aweb_client, aweb_other_client, aweb_target: AwebTarget, aweb_other_target: AwebOtherTarget | None
) -> None:
    if aweb_other_target is None:
        pytest.skip("Missing AWEB_OTHER_* env vars")

    resource_key = f"conformance:{uuid.uuid4().hex}"

    acquire_a = await aweb_client.post(
        "/v1/reservations",
        json={
            "resource_key": resource_key,
            "ttl_seconds": 60,
            "metadata": {},
        },
    )
    assert acquire_a.status_code in (200, 201), acquire_a.text

    # Another project should not see/use the same resource key as a global keyspace.
    # Acquiring in a different project MUST succeed (isolated namespaces).
    acquire_b = await aweb_other_client.post(
        "/v1/reservations",
        json={
            "resource_key": resource_key,
            "ttl_seconds": 60,
            "metadata": {},
        },
    )
    assert acquire_b.status_code in (200, 201), acquire_b.text


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_write_requests_must_not_accept_project_selector_fields(aweb_client, aweb_target: AwebTarget) -> None:
    # These endpoints MUST reject client-provided project selectors (clean-start).
    fake_project_id = str(uuid.uuid4())

    mail = await aweb_client.post(
        "/v1/messages",
        json={
            "project_id": fake_project_id,
            "to_agent_id": aweb_target.agent_2.agent_id,
            "subject": "should reject selectors",
            "body": "should reject selectors",
            "priority": "normal",
            "thread_id": None,
        },
    )
    assert mail.status_code in (400, 422), mail.text

    chat = await aweb_client.post(
        "/v1/chat/sessions",
        json={
            "project_id": fake_project_id,
            "to_aliases": [aweb_target.agent_2.alias],
            "message": "should reject selectors",
            "leaving": False,
        },
    )
    assert chat.status_code in (400, 422), chat.text

    res = await aweb_client.post(
        "/v1/reservations",
        json={
            "project_id": fake_project_id,
            "resource_key": f"conformance:{uuid.uuid4().hex}",
            "ttl_seconds": 60,
            "metadata": {},
        },
    )
    assert res.status_code in (400, 422), res.text
