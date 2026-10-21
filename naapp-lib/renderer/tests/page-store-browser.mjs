import assert from "node:assert/strict";
import { chromium, expect } from "@playwright/test";

const browser = await chromium.launch();
try {
  const page = await browser.newPage({
    viewport: { width: 1000, height: 650 },
  });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(process.argv[2]);
  const table = page.locator('[data-widget="items"]');
  await expect(table).toContainText("Verify fixture inventory");
  const note = page.getByLabel("Note (required)", { exact: true });
  await expect(note).toHaveValue("Original note");
  const draft = "Keep this unsaved browser draft";
  await note.fill(draft);
  await note.focus();
  await note.evaluate((input) => input.setSelectionRange(5, 12));
  const before = await note.evaluate((input) => ({
    scroll: [scrollX, scrollY],
    selection: [input.selectionStart, input.selectionEnd],
  }));
  assert(before.scroll[1] > 0, "The test must exercise a scrolled page");
  await page.keyboard.press("Alt+u");
  // This proves the update reached both PostgreSQL and the renderer's host.read.
  await expect(table).toContainText("Updated through PostgreSQL");
  await expect(note).toHaveValue(draft);
  await expect(note).toBeFocused();
  const after = await note.evaluate((input) => ({
    scroll: [scrollX, scrollY],
    selection: [input.selectionStart, input.selectionEnd],
  }));
  assert.deepEqual(after, before, "Refresh must preserve selection and scroll");
  assert.deepEqual(errors, []);
  console.log(
    "Real PostgreSQL refresh preserves draft, focus, selection and scroll.",
  );
} finally {
  await browser.close();
}
