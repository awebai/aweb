"""Session boundary over real migrated PostgreSQL and production HTTP routes."""

from __future__ import annotations

import asyncio
import hashlib
import re
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from aweb_naapp.runtime.app import NaappRuntime
from playwright.async_api import expect
from test_live_refresh import live_browser, live_world
from test_present_privacy import OWNER, assert_private, mint, present_world

__all__ = ["live_browser", "live_world", "present_world"]
HEADER = "X-Folio-Edit-Session"


def target(link):
    parts = urlsplit(link["url"])
    return parts.path, parse_qs(parts.fragment).get("k", [link["token"]])[0]


async def exchange(client, link):
    path, opener = target(link)
    response = await client.post(path + "/session", json={"opener": opener})
    assert response.status_code == 200
    assert_private(response)
    return path, response.json()["session_secret"]


@pytest.fixture
async def session_http(present_world):
    app, _, _ = present_world
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://folio.test"
    ) as client:
        yield client


async def test_fragment_opener_get_is_inert_and_double_exchange_is_atomic(
    present_world, session_http
):
    link = await mint(present_world)
    path, opener = target(link)
    assert urlsplit(link["url"]).fragment.startswith("k=")
    assert opener not in path and opener != link["token"]
    assert re.fullmatch(r"[A-Za-z0-9_-]{22}", link["token"])
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", opener)
    shell = await session_http.get(path)
    assert shell.status_code == 200
    assert "script-src 'nonce-" in shell.headers["content-security-policy"]
    assert "Original" not in shell.text
    responses = await asyncio.gather(
        *[session_http.post(path + "/session", json={"opener": opener}) for _ in range(2)]
    )
    assert sorted(r.status_code for r in responses) == [200, 404]
    _, db, _ = present_world
    row = await db.fetch_one("SELECT COUNT(*) AS n FROM {{tables.edit_sessions}}")
    assert row["n"] == 1
    winner = next(r.json() for r in responses if r.status_code == 200)
    stored = await db.fetch_one("SELECT credential_hash FROM {{tables.edit_sessions}}")
    assert (
        bytes(stored["credential_hash"])
        == hashlib.sha256(winner["session_secret"].encode()).digest()
    )


async def test_session_outlives_opener_and_revoke_still_ends_it(present_world, session_http):
    link = await mint(present_world)
    path, secret = await exchange(session_http, link)
    _, db, _ = present_world
    await db.execute(
        "UPDATE {{tables.presentation_links}} SET created_at=NOW()-interval '340 seconds', expires_at=NOW()-interval '40 seconds' WHERE token=$1",
        link["token"],
    )
    headers = {HEADER: secret}
    state = await session_http.get(path + "/state?after_version=1", headers=headers)
    assert state.status_code == 200
    saved = await session_http.post(
        path + "/edit", headers=headers, json={"body": "After 340 seconds", "base_version": 1}
    )
    assert saved.status_code == 200
    from folio.repository import revoke_presentation_link

    await revoke_presentation_link(db, principal=OWNER, token=link["token"])
    assert (await session_http.get(path + "/state", headers=headers)).status_code == 404
    assert (
        await session_http.post(
            path + "/edit", headers=headers, json={"body": "No", "base_version": 2}
        )
    ).status_code == 404


@pytest.mark.parametrize("checked_at", [452.090299787, 964.597241499])
async def test_session_keeps_valid_full_ttl_membership_at_ci_clock_values(
    present_world, session_http, monkeypatch, checked_at
):
    from dataclasses import replace
    from types import SimpleNamespace

    from folio import edit_sessions

    original = NaappRuntime.check_current_member

    async def current(self, *args, **kwargs):
        proof = await original(self, *args, **kwargs)
        return replace(proof, checked_at=checked_at, fresh_until=checked_at + 60)

    monkeypatch.setattr(NaappRuntime, "check_current_member", current)
    monkeypatch.setattr(
        edit_sessions, "time", SimpleNamespace(monotonic=lambda: checked_at + 1)
    )
    link = await mint(present_world)
    path, secret = await exchange(session_http, link)
    headers = {HEADER: secret}
    state = await session_http.get(path + "/state", headers=headers)
    assert state.status_code == 200
    assert state.json()["body"] == "Original"
    saved = await session_http.post(
        path + "/edit", headers=headers, json={"body": "Still editable", "base_version": 1}
    )
    assert saved.status_code == 200


async def test_session_is_header_only_and_bound_to_document(present_world, session_http):
    link = await mint(present_world)
    path, secret = await exchange(session_http, link)
    other = await mint(present_world)
    other_path, _ = target(other)
    for suffix, kwargs in [
        ("/state?session_secret=" + secret, {}),
        ("/state", {"headers": {"cookie": "session_secret=" + secret}}),
    ]:
        assert (await session_http.get(path + suffix, **kwargs)).status_code == 404
    assert (
        await session_http.get(other_path + "/state", headers={HEADER: secret})
    ).status_code == 404
    _, db, _ = present_world
    await db.execute("DELETE FROM {{tables.documents}} WHERE slug='draft'")
    assert (await session_http.get(path + "/state", headers={HEADER: secret})).status_code == 404


async def test_session_preview_sanitizes_and_resume_survives_another_app(
    present_world, session_http
):
    from folio.api import create_app

    link = await mint(present_world)
    path, secret = await exchange(session_http, link)
    preview = await session_http.post(
        path + "/preview",
        headers={HEADER: secret},
        json={"body": "# Heading\n\n**bold** <script>alert(1)</script>"},
    )
    assert preview.status_code == 200
    assert "<h1>Heading</h1>" in preview.text and "<strong>bold</strong>" in preview.text
    assert "<script" not in preview.text and "alert(" not in preview.text
    _, db, settings = present_world
    # A fresh process/runtime would have only this migrated DB, not session memory.
    restarted = create_app(settings)
    for route in restarted.routes:
        for dependency in getattr(getattr(route, "dependant", None), "dependencies", ()):
            if dependency.name == "database":
                restarted.dependency_overrides[dependency.call] = lambda: db
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=restarted), base_url="http://folio.test"
    ) as client:
        response = await client.get(path + "/state", headers={HEADER: secret})
    assert response.status_code == 200
    assert response.json()["body"] == "Original"
    assert "session_secret" not in response.json()


async def test_real_server_refusal_and_exception_do_not_log_credentials(
    live_world, live_browser, monkeypatch, caplog
):
    import logging

    from folio import api

    origin, _ = live_browser
    link = await mint(live_world)
    path, opener = target(link)
    with caplog.at_level(logging.DEBUG):
        async with httpx.AsyncClient(base_url=origin) as client:
            _, secret = await exchange(client, link)
            replay = await client.post(path + "/session", json={"opener": opener})
            assert replay.status_code == 404

            def broken_renderer(*args, **kwargs):
                raise RuntimeError("Synthetic rendering failure")

            monkeypatch.setattr(api, "render_presented_markdown", broken_renderer)
            failed = await client.post(
                path + "/preview", headers={HEADER: secret}, json={"body": "Draft"}
            )
            assert failed.status_code == 500
            _, db, _ = live_world
            await db.execute(
                "UPDATE {{tables.presentation_links}} SET revoked_at=NOW() WHERE token=$1",
                link["token"],
            )
            refused = await client.get(path + "/state", headers={HEADER: secret})
            assert refused.status_code == 404
    assert not any(value in caplog.text for value in (opener, secret))


@pytest.mark.parametrize("status", [403, 503])
async def test_membership_loss_is_terminal_but_registry_outage_is_retryable(
    present_world, session_http, monkeypatch, status
):
    from fastapi import HTTPException

    link = await mint(present_world)
    path, secret = await exchange(session_http, link)
    original = NaappRuntime.check_current_member

    async def refuse(*args, **kwargs):
        raise HTTPException(status_code=status, detail="Registry refusal")

    monkeypatch.setattr(NaappRuntime, "check_current_member", refuse)
    response = await session_http.get(path + "/state", headers={HEADER: secret})
    assert response.status_code == (404 if status == 403 else 503)
    monkeypatch.setattr(NaappRuntime, "check_current_member", original)
    resumed = await session_http.get(path + "/state", headers={HEADER: secret})
    assert resumed.status_code == (404 if status == 403 else 200)


async def test_browser_background_reload_and_revoke_keep_the_draft(live_world, live_browser):
    origin, browser = live_browser
    link = await mint(live_world)
    parts = urlsplit(link["url"])
    page = await browser.new_page(viewport={"width": 375, "height": 812})
    await page.goto(origin + parts.path + "#" + parts.fragment)
    await expect(page.locator("#body")).to_have_value("Original")
    assert urlsplit(page.url).fragment == ""
    assert await page.evaluate("Object.keys(sessionStorage)") == [
        "folio.editSession:" + link["token"]
    ]
    await page.locator("#body").fill("Retained draft")
    await page.evaluate(
        "Object.defineProperty(document, 'hidden', {configurable:true, value:true}); document.dispatchEvent(new Event('visibilitychange'))"
    )
    _, db, _ = live_world
    await db.execute(
        "UPDATE {{tables.presentation_links}} SET created_at=NOW()-interval '340 seconds', expires_at=NOW()-interval '40 seconds' WHERE token=$1",
        link["token"],
    )
    await page.evaluate(
        "Object.defineProperty(document, 'hidden', {configurable:true, value:false}); document.dispatchEvent(new Event('visibilitychange'))"
    )
    async with page.expect_response(lambda r: r.url.endswith("/edit")) as saved:
        await page.locator("#save").click()
    assert (await saved.value).status == 200
    await page.reload()
    await expect(page.locator("#body")).to_have_value("Retained draft")
    other = await browser.new_page()
    await other.goto(origin + parts.path + "#" + parts.fragment)
    await expect(other.locator("#link-recovery")).to_be_visible()
    await page.locator("#body").fill("Unsaved after reload")
    await db.execute(
        "UPDATE {{tables.presentation_links}} SET revoked_at=NOW() WHERE token=$1", link["token"]
    )
    await expect(page.locator("#link-recovery")).to_be_visible(timeout=10000)
    await expect(page.locator("#body")).to_have_value("Unsaved after reload")
    await expect(page.locator("#copy-draft")).to_be_visible()
    await expect(page.locator("#save")).to_be_disabled()


async def test_session_bootstrap_retains_team_theme(present_world, session_http):
    _, db, _ = present_world
    await db.execute(
        "INSERT INTO {{tables.themes}} (team_id,tokens,header,footer) VALUES ($1,$2::jsonb,$3,$4)",
        OWNER.team_id,
        '{"colors":{"background":"#123456"}}',
        "Team header",
        "Team footer",
    )
    link = await mint(present_world)
    path, secret = await exchange(session_http, link)
    resumed = await session_http.get(path + "/state", headers={HEADER: secret})
    theme = resumed.json()["theme"]
    assert "#123456" in theme["css"]
    assert theme["header"] == "Team header"
    assert theme["footer"] == "Team footer"


@pytest.mark.parametrize("resume", [False, True], ids=["exchange", "resume"])
async def test_phone_bootstrap_reports_wait_and_retry_before_enabling_editor(
    live_world, live_browser, monkeypatch, resume
):
    from fastapi import HTTPException

    origin, browser = live_browser
    app, _, _ = live_world
    link = await mint(live_world)
    parts = urlsplit(link["url"])
    held, release = asyncio.Event(), asyncio.Event()
    armed = False
    healthy = True
    original = NaappRuntime.check_current_member

    async def registry(self, *args, **kwargs):
        if not healthy:
            raise HTTPException(status_code=503, detail="Registry unavailable")
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(NaappRuntime, "check_current_member", registry)

    def is_bootstrap(path, query=""):
        if resume:
            return path.endswith("/state") and not query
        return path.endswith("/session")

    @app.middleware("http")
    async def hold_bootstrap(request, call_next):
        nonlocal armed
        if armed and is_bootstrap(request.url.path, request.url.query):
            armed = False
            held.set()
            await release.wait()
        return await call_next(request)

    page = await browser.new_page(viewport={"width": 375, "height": 812})
    if resume:
        await page.goto(origin + parts.path + "#" + parts.fragment)
        await expect(page.locator("#body")).to_have_value("Original")
    armed = True
    healthy = False
    if resume:
        await page.reload()
    else:
        await page.goto(origin + parts.path + "#" + parts.fragment)
    notice = page.locator("#bootstrap-status")

    async def assert_in_view():
        await expect(notice).to_be_visible()
        box = await notice.bounding_box()
        assert box is not None
        assert 0 <= box["x"] and 0 <= box["y"]
        assert box["x"] + box["width"] <= 375
        assert box["y"] + box["height"] <= 812
        await expect(notice).to_have_attribute("role", "status")
        await expect(page.locator("#body")).to_be_disabled()
        assert not await page.locator("#body").get_attribute("placeholder")
        assert await page.locator("#status").text_content() == ""

    try:
        await asyncio.wait_for(held.wait(), timeout=10)
        await assert_in_view()
        await expect(notice).to_have_attribute("data-state", "loading")
        async with page.expect_response(
            lambda r: is_bootstrap(urlsplit(r.url).path, urlsplit(r.url).query) and r.status == 503
        ):
            release.set()
        await expect(notice).to_have_attribute("data-state", "retry")
        await assert_in_view()
        await page.locator("#tab-preview").click()
        await assert_in_view()
        healthy = True
        await expect(page.locator("#body")).to_be_enabled(timeout=10000)
        await expect(page.locator("#body")).to_have_value("Original")
        await expect(page.locator("#body")).to_be_focused()
        await expect(page.locator("#tab-edit")).to_have_attribute("aria-selected", "true")
        await expect(notice).to_be_hidden()
    finally:
        release.set()
