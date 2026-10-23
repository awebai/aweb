import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

async function source(page, id = "property-0") {
  const bind = encodeURIComponent(JSON.stringify({ collection: "properties" }));
  const projection = await page.request
    .get(`/api/widget?case=table-urls&bind=${bind}`)
    .then((response) => response.json());
  return projection.records.find((record) => record.id === id).value.source_url;
}

test("a URL cell uses the existing host confirmation and explicit new-tab Open", async ({
  page,
}) => {
  await page.addInitScript(() => {
    window.open = (...args) => {
      window.opened = args;
      return null;
    };
  });
  await page.goto("/?case=table-urls");
  const href = new URL(await source(page)).href;
  const host = new URL(href).host;
  const cell = page.locator(
    '[data-widget="property-table"] [data-record="property-0"] td',
  );
  const link = cell.getByRole("link");
  await expect(link).toHaveAccessibleName(href);
  await expect(link.locator("bdi")).toHaveText(host);
  await expect(page.locator("#page [href]")).toHaveCount(0);
  await link.click({ button: "middle" });
  expect(await page.evaluate(() => window.opened)).toBeUndefined();
  await link.click({ modifiers: ["Control"] });
  expect(await page.evaluate(() => window.opened)).toBeUndefined();
  await page.keyboard.press("Escape");
  await link.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("heading")).toHaveText(host);
  expect(await page.evaluate(() => window.opened)).toBeUndefined();
  await dialog
    .getByRole("button", { name: `Open ${host}`, exact: true })
    .click();
  expect(await page.evaluate(() => window.opened)).toEqual([
    href,
    "_blank",
    "noopener,noreferrer",
  ]);
  await expect(link).toBeFocused();
});

test("long accepted and refused URLs never overflow the phone page", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto("/?case=table-urls");
  const table = page.locator('[data-widget="property-table"]');
  await expect(table.locator("tbody tr")).toHaveCount(3);
  const accepted = await source(page);
  const refused = await source(page, "property-1");
  expect(accepted.length).toBeGreaterThan(2000);
  expect(refused.length).toBeGreaterThan(2000);
  const inert = table.locator('[data-record="property-1"] td');
  await expect(inert.locator("bdi")).toHaveText(refused);
  await expect(inert.getByRole("link")).toHaveCount(0);
  const width = await table.locator(".table-scroll").evaluate((region) => ({
    content: region.scrollWidth,
    available: region.clientWidth,
  }));
  expect(width.content).toBeLessThanOrEqual(width.available);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
});

test("URL projections retain the destination index across paging and revision updates", async ({
  page,
}) => {
  await page.goto("/?case=table-urls&paged=1");
  const table = page.locator('[data-widget="property-table"]');
  await expect(
    table.locator('[data-record="property-0"] [role="link"]'),
  ).toBeVisible();
  await table.getByRole("button", { name: "Next", exact: true }).click();
  await expect(table.locator('[data-record="property-1"]')).toBeVisible();
  await table.getByRole("button", { name: "Next", exact: true }).click();
  await expect(
    table.locator('[data-record="property-2"] [role="link"]'),
  ).toBeVisible();
  await page.keyboard.press("Alt+u");
  await expect(
    table.locator('[data-record="property-0"] [role="link"]'),
  ).toBeVisible();
  await expect(page.locator("#destinations")).toContainText(
    new URL(await source(page)).host,
  );
});
