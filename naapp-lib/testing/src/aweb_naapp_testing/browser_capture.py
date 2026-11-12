"""Settled, keyboard-focused captures for callers already running Playwright."""

import asyncio
import json
from pathlib import Path

from playwright.async_api import Locator, Page, expect


async def capture_enabled_control(page: Page, control: Locator, path: Path) -> None:
    """Capture the actual enabled styles without disabling animations or changing CSS."""
    await expect(control).to_be_enabled()
    await control.focus()
    # Reach it with the keyboard, so :focus-visible is real rather than forced.
    await page.keyboard.press("Shift+Tab")
    await page.keyboard.press("Tab")
    await expect(control).to_be_focused()
    async with asyncio.timeout(5):
        styles = await control.evaluate(
            """async element => {
              await new Promise(requestAnimationFrame);
              await Promise.all(element.getAnimations().filter(animation =>
                Number.isFinite(animation.effect.getComputedTiming().endTime)
              ).map(animation => animation.finished));
              const style = getComputedStyle(element);
              return {
                label: element.textContent.trim(),
                state: document.body.dataset.handoffState,
                disabled: element.disabled,
                focused: element === document.activeElement,
                focus_visible: element.matches(':focus-visible'),
                color: style.color,
                background: style.backgroundColor,
                opacity: style.opacity,
                filter: style.filter,
                outline_color: style.outlineColor,
                outline_style: style.outlineStyle,
                outline_width: style.outlineWidth,
                outline_offset: style.outlineOffset,
                box_shadow: style.boxShadow
              };
            }"""
        )
    assert styles["focused"] and styles["focus_visible"] and not styles["disabled"]
    path.with_suffix(".json").write_text(json.dumps(styles, indent=2) + "\n")
    await page.screenshot(path=path, full_page=True)
