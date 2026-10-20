import { test, expect } from "@playwright/test";

test("outbound links need a host confirmation, preserve focus, and cannot navigate by modifiers", async ({
  page,
}) => {
  await page.goto("/?vector=markdown-domain-spoof-text");
  const link = page.locator('[data-widget="t1"]').getByRole("link");
  await expect(link).not.toHaveAttribute("href");
  const popups = [];
  page.on("popup", (popup) => popups.push(popup));
  await link.click({ button: "middle" });
  expect(popups).toHaveLength(0);
  await link.click({ modifiers: ["Control"] });
  expect(popups).toHaveLength(0);
  await page.keyboard.press("Escape");
  await link.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("heading")).toHaveText("evil.example");
  await expect(dialog).toContainText("https://evil.example/login");
  await expect(
    dialog.getByRole("button", { name: "Cancel", exact: true }),
  ).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(link).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  expect(popups).toHaveLength(0);
  await expect(dialog).not.toBeVisible();
});

test("same-page state refresh preserves the focused node and announces once", async ({
  page,
}) => {
  await page.goto("/");
  const link = page.locator('[data-widget="intro"]').getByRole("link");
  await link.focus();
  // The gallery's host refresh control changes only state and revision through
  // its ordinary fetch/update path, not a mocked renderer callback.
  await page.keyboard.press("Alt+u");
  await expect(link).toBeFocused();
  await expect(page.locator("#announcements")).toContainText(
    "Projection updated",
  );
  await page.keyboard.press("Alt+u");
  await expect(link).toBeFocused();
});

test("two bound stats on one collection use their independent authorized filters", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.locator('[data-widget="bound-one"] .stat-value'),
  ).toHaveText("62");
  await expect(
    page.locator('[data-widget="bound-two"] .stat-value'),
  ).toHaveText("95");
});

test("phone metric cards occupy a single column, stat figures never wrap", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const positions = await page
    .locator('[data-widget="metrics"] > .widget')
    .evaluateAll((nodes) =>
      nodes.map((n) => ({
        left: n.getBoundingClientRect().left,
        top: n.getBoundingClientRect().top,
      })),
    );
  expect(new Set(positions.map((p) => p.left)).size).toBe(1);
  expect(positions[0].top).toBeLessThan(positions[1].top);
  expect(positions[1].top).toBeLessThan(positions[2].top);
  expect(
    await page
      .locator(".stat-value")
      .first()
      .evaluate((n) => getComputedStyle(n).whiteSpace),
  ).toBe("nowrap");
});

test("hostile page markup cannot hide, remove or auto-trigger host confirmation", async ({
  page,
}) => {
  await page.goto("/?case=dialog-hostile");
  const link = page.locator('[data-widget="hostile"]').getByRole("link");
  await expect(link).toBeVisible();
  await expect(
    page.locator("#page dialog, #page style, #page script"),
  ).toHaveCount(0);
  await link.evaluate((node) => node.click());
  await expect(page.locator("#link-confirmation")).not.toBeVisible();
  await link.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByRole("dialog").getByRole("heading")).toHaveText(
    "example.com",
  );
});

test("dark mode preserves contrast and English chrome", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/");
  await expect(
    page.locator('[data-widget="bound-two"] .stat-value'),
  ).toHaveText("95");
  const background = await page.evaluate(
    () => getComputedStyle(document.documentElement).backgroundColor,
  );
  expect(background).toBe("rgb(11, 10, 9)");
  const { default: AxeBuilder } = await import("@axe-core/playwright");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("large stat values and their units remain on one line at tablet and desktop widths", async ({
  page,
}) => {
  for (const width of [768, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/?case=wide-stats");
    await expect(
      page.locator('[data-widget="decimal-display"] .stat-value'),
    ).toHaveText("1234567.50");
    await expect(
      page.locator('[data-widget="occupancy"] .stat-value'),
    ).toHaveText("1,234,567");
    for (const figure of await page
      .locator('[data-widget="metrics"] .stat-figure')
      .all()) {
      const geometry = await figure.evaluate((node) => ({
        fits: node.scrollWidth <= node.clientWidth + 1,
        children: [...node.children].map(
          (n) => n.getBoundingClientRect().bottom,
        ),
      }));
      expect(geometry.fits).toBe(true);
      expect(
        Math.max(...geometry.children) - Math.min(...geometry.children),
      ).toBeLessThan(12);
    }
  }
});
