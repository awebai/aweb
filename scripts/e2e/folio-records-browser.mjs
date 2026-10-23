import assert from "node:assert/strict";
import { chromium, expect } from "@playwright/test";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const { url, values } = JSON.parse(input);
const browser = await chromium.launch();
try {
  for (const width of [1280, 375]) {
    const context = await browser.newContext({
      viewport: { width, height: 800 },
      ignoreHTTPSErrors: true,
    });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const response = await page.goto(url);
    assert.equal(response.headers()["cache-control"], "no-store");
    assert.equal(response.headers()["referrer-policy"], "no-referrer");
    const table = page.locator('[data-widget="records"]');
    await expect(table).toBeVisible();
    await expect(table.locator("tbody tr")).toHaveCount(values.length);
    for (const value of values) {
      const row = table.locator("tbody tr").filter({ hasText: value.finding });
      await expect(row).toHaveCount(1);
      for (const field of ["finding", "why_relevant", "status", "kind"]) {
        await expect(row).toContainText(value[field]);
      }
      await row.getByRole("link").click();
      await expect(page.getByRole("dialog")).toContainText(value.source_url);
      await page.getByRole("button", { name: "Cancel", exact: true }).click();
    }
    assert.equal(new URL(page.url()).hash, "");
    assert.deepEqual(
      await page.evaluate(() => [localStorage.length, sessionStorage.length]),
      [0, 0],
    );
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    // Reload must discard the capability; the host clears the former table.
    await page.reload();
    await expect(page.getByRole("alert")).toBeVisible();
    await expect(page.getByRole("table")).toHaveCount(0);
    assert.deepEqual(errors, []);
    await context.close();
  }
} finally {
  await browser.close();
}
