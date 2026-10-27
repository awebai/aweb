"""Measure the production editor after the records journey's save/add/delete.

The host fixture uses real signatures, registry checks, SQL and HTTP, with an
explicit installation grant fixture. The installed-stack journey stays separate.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
import uvicorn
from playwright.async_api import async_playwright, expect
from test_record_collections import VALUE
from test_record_host import linked, listener
from test_widget_authorization import authors, signed
from test_widget_records_session import with_table

from folio.record_collections import DISCOVERY_SCHEMA

__all__ = ["authors", "linked", "listener"]


async def capture_layout(page, destination):
    # Reset any horizontal scroll caused by bringing an overflowing control into
    # view. Bounds are measured from the viewport's ordinary left edge.
    await page.evaluate("window.scrollTo(0, 0)")
    report = await page.evaluate("""() => {
      const viewport = innerWidth;
      const identify = el => {
        if (el.id) return '#' + el.id;
        return el.tagName.toLowerCase() + (el.classList.length ? '.' + [...el.classList].join('.') : '');
      };
      const measure = el => {
        const rect = el.getBoundingClientRect();
        const css = getComputedStyle(el);
        const containers = [];
        for (let parent = el.parentElement; parent; parent = parent.parentElement) {
          const overflow = getComputedStyle(parent).overflowX;
          if (overflow !== 'visible') containers.push({element: identify(parent), overflow});
        }
        return {element: identify(el), left: rect.left, right: rect.right, width: rect.width,
          clientWidth: el.clientWidth, scrollWidth: el.scrollWidth,
          display: css.display, overflowX: css.overflowX, containers};
      };
      const elements = [...document.querySelectorAll('body *')].map(measure);
      return {viewport, documentWidth: document.documentElement.scrollWidth,
        widerThanViewport: elements.filter(el => el.width > viewport),
        outsideViewport: elements.filter(el => el.width && (el.left < -0.5 || el.right > viewport + 0.5)),
        internallyOverflowing: elements.filter(el => el.scrollWidth > el.clientWidth),
        bar: [...document.querySelectorAll('.bar, .brand, .tabs, .actions, #status, #editor-name, #discard, #save')].map(measure)};
    }""")
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "geometry.json").write_text(json.dumps(report, indent=2) + "\n")
    (destination / "editor.aria.yml").write_text(await page.locator("body").aria_snapshot())
    await page.screenshot(path=str(destination / "editor.png"), full_page=True)
    return report


@pytest.mark.parametrize("width", [1280, 375])
async def test_editor_chrome_stays_within_viewport_after_prose_and_rows(authors, width, tmp_path):
    world, _ = await with_table(authors)
    minted = await signed(
        world, world.member, "POST", "/v1/present",
        payload={"slug": "ordinary", "editable": True},
    )
    assert minted.status_code == 200, minted.text
    world.listener.listen()
    server = uvicorn.Server(
        uvicorn.Config(world.app, lifespan="off", log_config=None, ws="none")
    )
    serving = asyncio.create_task(server.serve(sockets=[world.listener]))
    output = Path(os.environ.get("FOLIO_EDITOR_LAYOUT_EVIDENCE", str(tmp_path))) / str(width)
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if serving.done():
                    await serving
                await asyncio.sleep(0.01)
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                page = await browser.new_page(viewport={"width": width, "height": 800})
                try:
                    await page.goto(minted.json()["url"])
                    editor = page.locator('#pane-edit [data-folio-widget="research"]')
                    await expect(editor.get_by_role("table")).to_be_visible()
                    prose = page.get_by_role("textbox", name="Document text 1", exact=True)
                    await expect(page.locator("#save")).to_have_text("Saved")
                    await prose.fill(f"Saved prose at {width}px\n\n")
                    await page.locator("#save").click()
                    await expect(page.locator("#status")).to_contain_text("Saved version")
                    await page.reload()
                    await expect(prose).to_have_value(f"Saved prose at {width}px\n\n")
                    await expect(editor.get_by_role("table")).to_be_visible()
                    await editor.get_by_role("button", name="Add row", exact=True).click()
                    added = {**VALUE, "finding": f"Browser added {width}", "status": "added"}
                    for field, value in added.items():
                        schema = DISCOVERY_SCHEMA["properties"][field]
                        choices = schema.get("enum")
                        control = editor.get_by_role(
                            "combobox" if choices else "textbox",
                            name=schema.get("title", field), exact=True,
                        )
                        if choices:
                            await control.select_option(str(choices.index(value)))
                        else:
                            await control.fill(value)
                    await editor.get_by_role("button", name="Save row", exact=True).click()
                    row = editor.locator("tbody tr").filter(has_text=added["finding"])
                    await expect(row).to_be_visible()
                    await row.get_by_role("button", name="Delete row ").click()
                    await page.get_by_role("dialog").get_by_role(
                        "button", name="Delete row", exact=True
                    ).click()
                    await expect(row).to_have_count(0)
                    await expect(page.locator("#save")).to_have_text("Saved")
                    report = await capture_layout(page, output)
                    assert report["documentWidth"] <= width, json.dumps(report, indent=2)
                    # The existing split view has no tabs on desktop; phone tabs
                    # and both save/discard controls must remain in the viewport.
                    for control in (page.locator("#discard"), page.locator("#save")):
                        await expect(control).to_be_visible()
                        bounds = await control.bounding_box()
                        assert 0 <= bounds["x"] and bounds["x"] + bounds["width"] <= width
                        assert await control.inner_text()
                    if width == 375:
                        await page.get_by_role("tab", name="Preview", exact=True).click()
                        await expect(page.locator("#pane-preview")).to_be_visible()
                        await page.get_by_role("tab", name="Write", exact=True).click()
                    else:
                        await expect(page.get_by_role("tablist")).not_to_be_visible()
                        await expect(page.locator("#pane-preview")).to_be_visible()
                    await expect(page.locator("#pane-edit")).to_be_visible()
                    await prose.fill(f"Unsaved draft at {width}px\n\n")
                    await page.get_by_role("button", name="Discard changes", exact=True).click()
                    await expect(page.get_by_role("dialog", name="Discard unsaved changes?")).to_be_visible()
                    await page.get_by_role("button", name="Keep editing", exact=True).click()
                    await expect(prose).to_have_value(f"Unsaved draft at {width}px\n\n")
                except BaseException:
                    await capture_layout(page, output)
                    raise
            finally:
                await browser.close()
    finally:
        server.should_exit = True
        await asyncio.wait_for(serving, timeout=10)
