from __future__ import annotations

import uuid

import pytest

from .harness import AwebTarget


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_reservation_acquire_conflict_release_cycle(
    aweb_client, aweb_client_2, aweb_target: AwebTarget
) -> None:
    resource_key = f"conformance:{uuid.uuid4().hex}"

    acquire_1 = await aweb_client.post(
        "/v1/reservations",
        json={
            "resource_key": resource_key,
            "ttl_seconds": 60,
            "metadata": {"purpose": "conformance"},
        },
    )
    assert acquire_1.status_code in (200, 201), acquire_1.text

    acquire_2 = await aweb_client_2.post(
        "/v1/reservations",
        json={
            "resource_key": resource_key,
            "ttl_seconds": 60,
            "metadata": {"purpose": "conformance"},
        },
    )
    assert acquire_2.status_code == 409, acquire_2.text
    conflict = acquire_2.json()
    # Conflict payload shape is implementation-defined, but must identify holder.
    # Prefer canonical keys when present.
    holder_alias = conflict.get("holder_alias") or conflict.get("alias") or ""
    assert holder_alias == aweb_target.agent_1.alias

    release_wrong = await aweb_client_2.post(
        "/v1/reservations/release",
        json={
            "resource_key": resource_key,
        },
    )
    assert release_wrong.status_code == 409, release_wrong.text

    release_right = await aweb_client.post(
        "/v1/reservations/release",
        json={
            "resource_key": resource_key,
        },
    )
    assert release_right.status_code in (200, 204), release_right.text

    acquire_2_after = await aweb_client_2.post(
        "/v1/reservations",
        json={
            "resource_key": resource_key,
            "ttl_seconds": 60,
            "metadata": {"purpose": "conformance"},
        },
    )
    assert acquire_2_after.status_code in (200, 201), acquire_2_after.text


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_reservation_renew_requires_ownership(
    aweb_client, aweb_client_2, aweb_target: AwebTarget
) -> None:
    resource_key = f"conformance:{uuid.uuid4().hex}"

    acquire = await aweb_client.post(
        "/v1/reservations",
        json={
            "resource_key": resource_key,
            "ttl_seconds": 60,
            "metadata": {},
        },
    )
    assert acquire.status_code in (200, 201), acquire.text

    renew_wrong = await aweb_client_2.post(
        "/v1/reservations/renew",
        json={
            "resource_key": resource_key,
            "ttl_seconds": 60,
        },
    )
    assert renew_wrong.status_code == 409, renew_wrong.text

    renew_right = await aweb_client.post(
        "/v1/reservations/renew",
        json={
            "resource_key": resource_key,
            "ttl_seconds": 60,
        },
    )
    assert renew_right.status_code in (200, 204), renew_right.text


@pytest.mark.aweb_conformance
@pytest.mark.asyncio
async def test_reservations_list_can_filter_by_prefix(aweb_client, aweb_target: AwebTarget) -> None:
    prefix = f"conformance:{uuid.uuid4().hex}:"
    key_in = prefix + "a"
    key_out = f"conformance:{uuid.uuid4().hex}:b"

    for key in (key_in, key_out):
        resp = await aweb_client.post(
            "/v1/reservations",
            json={
                "resource_key": key,
                "ttl_seconds": 60,
                "metadata": {},
            },
        )
        assert resp.status_code in (200, 201), resp.text

    listed = await aweb_client.get("/v1/reservations", params={"prefix": prefix})
    assert listed.status_code == 200, listed.text
    data = listed.json()
    items = data.get("reservations")
    if items is None:
        # Some implementations may return a bare list.
        items = data if isinstance(data, list) else []

    resource_keys = [i.get("resource_key") for i in items if isinstance(i, dict)]
    assert key_in in resource_keys
    assert key_out not in resource_keys
