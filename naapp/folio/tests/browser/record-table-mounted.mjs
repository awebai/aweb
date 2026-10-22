import assert from "node:assert/strict";
import {
  chromium,
  expect,
} from "../../../../naapp-lib/renderer/node_modules/@playwright/test/index.mjs";

const browser = await chromium.launch();
try {
  const context = await browser.newContext({
    viewport: { width: 375, height: 800 },
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const response = await page.goto(process.argv[2]);
  assert.equal(response.headers()["cache-control"], "no-store");
  assert.equal(response.headers()["referrer-policy"], "no-referrer");
  await expect(page.locator('[data-widget="records"]')).toContainText(
    "A useful discussion",
  );
  await expect(page.locator("#identity")).toContainText("Live, read-only");
  await expect(
    page.getByRole("heading", {
      name: "Discoveries and conversations",
      exact: true,
    }),
  ).toHaveCount(1);
  const source = page.getByRole("link", {
    name: "https://example.test/research?topic=pages",
    exact: true,
  });
  await source.click();
  await expect(page.getByRole("dialog")).toContainText(
    "https://example.test/research?topic=pages",
  );
  await expect(
    page.getByRole("button", { name: "Cancel", exact: true }),
  ).toBeFocused();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  assert.equal(new URL(page.url()).hash, "");
  assert.deepEqual(
    await page.evaluate(() => [localStorage.length, sessionStorage.length]),
    [0, 0],
  );
  assert(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  );
  await page.getByRole("button", { name: "Refresh table" }).click();
  await expect(page.locator('[data-widget="records"]')).toContainText(
    "A useful discussion",
  );
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Open the link again" }),
  ).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("dashboard Documents");
  await expect(page.getByRole("table")).toHaveCount(0);
  assert.deepEqual(errors, []);
} finally {
  await browser.close();
}
