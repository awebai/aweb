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
  await table.getByLabel("Filter field").selectOption("name");
  await table.getByLabel("Filter value").fill("Riverside");
  await table.getByRole("button", { name: "Apply filter" }).click();
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table.locator("tbody tr")).toContainText("Riverside");
});
