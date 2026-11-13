"""Times a console page renders in UTC read in the viewer's own zone."""

from importlib.resources import files

from playwright.async_api import expect

from tests.console.test_console_shell_browser import browser as browser  # noqa: F401

SCRIPT = files("aweb_naapp.console.browser").joinpath("console.js").read_text()


async def test_a_marked_time_reads_in_the_viewers_zone_and_keeps_utc_without_script(browser):  # noqa: F811
    context = await browser.new_context(timezone_id="America/New_York", locale="en-US")
    page = await context.new_page()
    await page.set_content(
        '<body data-console-csrf-key="k"><main>'
        '<p>Expires <time id="marked" datetime="2026-11-13T15:30:00Z" data-local>2026-11-13 15:30 UTC</time></p>'
        '<p><time id="plain" datetime="2026-11-13T15:30:00Z">2026-11-13 15:30 UTC</time></p>'
        "</main></body>"
    )
    await expect(page.locator("#marked")).to_have_text("2026-11-13 15:30 UTC")
    await page.add_script_tag(content=SCRIPT)
    await expect(page.locator("#marked")).to_have_text("Nov 13, 2026, 10:30 AM EST")
    # Only marked times change; a page without script keeps its UTC text.
    await expect(page.locator("#plain")).to_have_text("2026-11-13 15:30 UTC")
    await context.close()
