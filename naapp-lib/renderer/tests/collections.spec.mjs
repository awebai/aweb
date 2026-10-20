import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("collection widgets show stable records, sorted pages and accessible chart alternatives", async ({
  page,
}) => {
  await page.goto("/");
  const table = page.locator('[data-widget="property-table"]');
  await expect(
    table.getByRole("columnheader", { name: "Property" }),
  ).toBeVisible();
  await expect(table.locator("tbody tr")).toHaveCount(2);
  await expect(table.locator("tbody tr").first()).toContainText("Maple House");
  await table.getByRole("button", { name: "Next" }).click();
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table.locator("tbody tr")).toContainText("Riverside");
  await table.getByRole("button", { name: "Previous" }).click();
  await table.getByRole("button", { name: "Occupancy" }).click();
  await expect(table.locator("tbody tr").first()).toContainText("Maple House");
  await table.getByRole("button", { name: "Occupancy" }).click();
  await expect(table.locator("tbody tr").first()).toContainText("Riverside");
  await expect(
    page.locator('[data-widget="property-cards"] [data-record]'),
  ).toHaveCount(3);
  await expect(
    page.locator('[data-widget="property-list"] [data-record]'),
  ).toHaveCount(3);
  await expect(
    page.locator('[data-widget="activity"] [data-record]'),
  ).toHaveCount(3);
  for (const kind of ["bar", "line", "pie"]) {
    const chart = page.locator(`[data-widget="chart-${kind}"]`);
    await expect(chart.locator("svg")).toBeVisible();
    await expect(chart.getByRole("table")).toBeVisible();
    await expect(chart.getByRole("table")).toContainText("Maple House");
  }
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("bound values use bidi isolation and filters return only matching authorized snapshot rows", async ({
  page,
}) => {
  await page.goto("/?vector=record-value-bidi-and-homoglyph");
  const value = page.locator('[data-widget="items"] tbody bdi').first();
  await expect(value).toContainText("pаy");
  expect(
    await value.evaluate((node) => getComputedStyle(node).unicodeBidi),
  ).toBe("isolate");
  await page.goto("/");
  const table = page.locator('[data-widget="property-table"]');
  await expect(table.locator("tbody tr")).toHaveCount(2);
  await expect(table.locator("input, select")).toHaveCount(0);
});

test("pager retains keyboard focus at the last page and announces the range", async ({
  page,
}) => {
  await page.goto("/");
  const table = page.locator('[data-widget="property-table"]');
  const next = table.getByRole("button", { name: "Next" });
  await next.focus();
  await page.keyboard.press("Enter");
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table.getByRole("button", { name: "Previous" })).toBeFocused();
  await expect(page.locator("#announcements")).toContainText("Showing 3 of 3");
  await expect(
    page.locator('[data-widget="property-cards"] .pagination'),
  ).not.toBeVisible();
});

test("a dense phone table scrolls as a table and calendar dates retain their day", async ({
  browser,
  baseURL,
}) => {
  const context = await browser.newContext({
    viewport: { width: 375, height: 812 },
    timezoneId: "America/Los_Angeles",
    ignoreHTTPSErrors: true,
  });
  const page = await context.newPage();
  await page.goto(baseURL + "/?case=dense-table");
  const table = page.locator('[data-widget="property-table"]');
  await expect(table.locator("tbody tr")).toHaveCount(2);
  await expect(table).toContainText("Oct 20, 2026");
  await expect(table).toContainText("€12,345.67");
  const sizes = await table.locator(".table-scroll").evaluate((node) => ({
    scroll: node.scrollWidth,
    width: node.clientWidth,
    body: document.body.scrollWidth,
    viewport: innerWidth,
    cells: [...node.querySelectorAll("td")].map(
      (cell) => getComputedStyle(cell).overflowWrap,
    ),
    compact: [...node.querySelectorAll(".cell-compact")].map(
      (cell) => getComputedStyle(cell).whiteSpace,
    ),
  }));
  expect(sizes.scroll).toBeGreaterThan(sizes.width);
  expect(sizes.body).toBeLessThanOrEqual(sizes.viewport);
  expect(sizes.cells.every((value) => value === "normal")).toBe(true);
  expect(sizes.compact.every((value) => value === "nowrap")).toBe(true);
  await context.close();
});
test("empty collections have one quiet message, and charts and timelines carry readable labels", async ({
  page,
}) => {
  await page.goto("/?case=empty");
  const table = page.locator('[data-widget="property-table"]');
  await expect(table).toContainText("Nothing here yet.");
  await expect(table.locator(".pagination")).not.toBeVisible();
  await expect(table.locator("input,select,table")).toHaveCount(0);
  await page.goto("/");
  await expect(
    page.locator('[data-widget="chart-pie"] .chart-labels'),
  ).toContainText("Maple House: 62");
  await expect(page.locator('[data-widget="chart-pie"] th').first()).toHaveText(
    "Property",
  );
  await expect(
    page.locator('[data-widget="activity"] time').first(),
  ).toContainText(/\d:\d\d (AM|PM)/);
});
test("pie slices have visible gaps, direct category/value labels and matching legend tints", async ({
  page,
}) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/");
  const pie = page.locator('[data-widget="chart-pie"]');
  await expect(pie.locator(".pie-direct-label")).toHaveCount(3);
  await expect(pie.locator(".pie-direct-label").first()).toContainText(
    "Maple House62",
  );
  const geometry = await pie.evaluate((node) => {
    const circles = [...node.querySelectorAll("circle[stroke-dasharray]")];
    const labels = [...node.querySelectorAll(".chart-swatch")];
    return {
      gap: 6 * circles[0].getScreenCTM().a,
      matching: circles.every(
        (circle, i) =>
          getComputedStyle(circle).stroke ===
          getComputedStyle(labels[i]).backgroundColor,
      ),
    };
  });
  expect(geometry.gap).toBeGreaterThanOrEqual(2);
  expect(geometry.matching).toBe(true);
});
