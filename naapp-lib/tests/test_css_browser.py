"""Contrast of the shared status component after Chromium resolves the CSS."""

import re

import pytest
from playwright.async_api import async_playwright

from aweb_naapp import aweb_css


def _luminance(rgb: list[float]) -> float:
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return sum(c * weight for c, weight in zip(linear, (0.2126, 0.7152, 0.0722), strict=True))


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("surface", ["bg", "surface", "surface-2"])
async def test_wait_pill_small_text_contrast(theme: str, surface: str) -> None:
    async with async_playwright() as playwright:
        # Use the locked Playwright browser, also installed in the candidate gate.
        browser = await playwright.chromium.launch()
        try:
            page = await browser.new_page(color_scheme=theme)
            await page.set_content(
                f'<html data-theme="{theme}"><body>'
                f'<div style="background: var(--{surface})">'
                '<span class="pill wait">Pending</span></div></body></html>'
            )
            await page.add_style_tag(content=aweb_css())
            colours = await page.locator(".pill.wait").evaluate("""pill => {
                const backgrounds = [];
                for (let element = pill; element; element = element.parentElement) {
                    backgrounds.unshift(getComputedStyle(element).backgroundColor);
                }
                return {foreground: getComputedStyle(pill).color, backgrounds};
            }""")
        finally:
            await browser.close()

    # Resolve the translucent pill over its actual ancestor backgrounds, rather
    # than comparing the text against the uncomposited --wait-soft RGB channels.
    background = [1.0, 1.0, 1.0]
    for colour in colours["backgrounds"]:
        channels = [float(value) for value in re.findall(r"[\d.]+", colour)]
        alpha = channels[3] if len(channels) == 4 else 1.0
        background = [
            channel / 255 * alpha + behind * (1 - alpha)
            for channel, behind in zip(channels[:3], background, strict=True)
        ]
    foreground = [float(value) / 255 for value in re.findall(r"[\d.]+", colours["foreground"])[:3]]
    light, dark = sorted((_luminance(foreground), _luminance(background)), reverse=True)
    contrast = (light + 0.05) / (dark + 0.05)
    assert contrast >= 4.5, f"{theme}/{surface}: wait pill contrast {contrast:.3f}:1 < 4.5:1"
