"""Real aw/AWID/PostgreSQL and two Chromium editors, without adapter stubs."""
from __future__ import annotations

import pytest
from playwright.sync_api import expect, sync_playwright
from test_e2e_present import _mint_present
from test_e2e_smoke import (
    _append_version,
    _create_document,
    _provision_team,
    aw_workspace_factory,
    folio,
)

__all__ = ["folio", "aw_workspace_factory"]

pytestmark = pytest.mark.e2e


def test_live_views_follow_cli_and_human_saves_without_losing_a_draft(folio, aw_workspace_factory, tmp_path):
    team = _provision_team(aw_workspace_factory("live-refresh"), alias="writer")
    _create_document(folio, team, slug="live", title="Live document", body="# First version")
    edit = _mint_present(folio, team, slug="live", editable=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            clean, dirty, other = [browser.new_page() for _ in range(3)]
            for page, link in [(clean, edit), (dirty, _mint_present(folio, team, slug="live", editable=True)), (other, _mint_present(folio, team, slug="live", editable=True))]:
                page.goto(link["url"])
            dirty.locator("#body").fill("Retained local draft")
            _append_version(folio, team, slug="live", body="# CLI second version", tmp_path=tmp_path)
            expect(clean.locator("#body")).to_have_value("# CLI second version", timeout=12000)
            expect(other.locator("#body")).to_have_value("# CLI second version", timeout=12000)
            expect(dirty.locator("#load-latest")).to_be_visible(timeout=12000)
            expect(dirty.locator("#body")).to_have_value("Retained local draft")
            other.locator("#body").fill("# Human third version")
            other.locator("#save").click()
            expect(other.locator("#save")).to_be_disabled()
            expect(clean.locator("#body")).to_have_value("# Human third version", timeout=12000)
            expect(dirty.locator("#body")).to_have_value("Retained local draft")
            dirty.locator("#load-latest").click()
            dirty.locator("#load-confirm").click()
            expect(dirty.locator("#body")).to_have_value("# Human third version")
            expect(dirty.locator("#save")).to_be_disabled()
        finally:
            browser.close()
