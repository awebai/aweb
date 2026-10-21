"""The exchange over HTTP: POST /v1/links/{link_id}/session (docs/page-links.md §2)."""

from __future__ import annotations

import httpx
from fastapi import FastAPI
from pgdbm import AsyncDatabaseManager

from aweb_naapp.runtime.capability_links.routes import mount_link_exchange

from .conftest import T0, mint_link, proof_for
from .test_exchange import body

LINK_HEADERS = {"cache-control": "no-store", "referrer-policy": "no-referrer"}


def _client(db, authority) -> httpx.AsyncClient:
    app = FastAPI()

    async def check_current_member(creator):
        return proof_for(certificate_id=creator.certificate_id)

    mount_link_exchange(
        app,
        db=db,
        authority=authority,
        check_current_member=check_current_member,
        client_address=lambda request: request.headers.get("x-test-client", "203.0.113.7"),
        clock=lambda: T0,
    )
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://pages.example.com"
    )


def _has_link_headers(response: httpx.Response) -> bool:
    return all(response.headers.get(name) == value for name, value in LINK_HEADERS.items())


async def test_a_holder_exchanges_the_secret_over_http(db: AsyncDatabaseManager, authority) -> None:
    minted = await mint_link(db, authority)
    async with _client(db, authority) as client:
        response = await client.post(
            f"/v1/links/{minted.link_id}/session", content=body(minted.secret)
        )
    assert response.status_code == 200
    assert _has_link_headers(response)
    payload = response.json()
    assert set(payload) == {"session_id", "csrf_token", "expires_at", "link"}
    assert payload["expires_at"] == "2026-10-20T12:15:00Z"
    assert payload["link"] == {"page_id": "pg_4hd2", "mode": "live", "actions": ["mark-cleaned"]}
    assert minted.secret not in response.text


async def test_refusals_carry_the_contract_code_and_no_detail(
    db: AsyncDatabaseManager, authority
) -> None:
    minted = await mint_link(db, authority)
    async with _client(db, authority) as client:
        wrong = await client.post(f"/v1/links/{minted.link_id}/session", content=body("wrong"))
        unknown = await client.post("/v1/links/lnk_unknown/session", content=body(minted.secret))
        malformed = await client.post(f"/v1/links/{minted.link_id}/session", content=b"{}")
    for response in (wrong, unknown):
        assert response.status_code == 404
        assert response.json() == {"detail": {"code": "link_unavailable"}}
        assert _has_link_headers(response)
    assert wrong.text == unknown.text
    assert malformed.status_code == 422
    assert malformed.json() == {"detail": {"code": "schema_invalid"}}


async def test_a_flooding_client_gets_retry_after(db: AsyncDatabaseManager, authority) -> None:
    minted = await mint_link(db, authority)
    async with _client(db, authority) as client:
        for _ in range(30):
            await client.post(
                f"/v1/links/{minted.link_id}/session",
                content=body("wrong"),
                headers={"x-test-client": "attacker"},
            )
        limited = await client.post(
            f"/v1/links/{minted.link_id}/session",
            content=body("wrong"),
            headers={"x-test-client": "attacker"},
        )
        holder = await client.post(
            f"/v1/links/{minted.link_id}/session", content=body(minted.secret)
        )
    assert limited.status_code == 429
    assert limited.json() == {"detail": {"code": "safety_rate_limited"}}
    assert int(limited.headers["retry-after"]) >= 1
    assert _has_link_headers(limited)
    assert holder.status_code == 200
