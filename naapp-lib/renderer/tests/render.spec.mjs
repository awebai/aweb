import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("gallery renders semantic widgets, state and safe Markdown under enforced CSP", async ({
  page,
}) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Property overview" }),
  ).toBeVisible();
  await expect(page.locator('[data-widget="occupancy"]')).toContainText("82");
  await expect(
    page.locator('[data-widget="occupancy"] progress'),
  ).toHaveAttribute("value", "40");
  await expect(page.locator('[data-widget="future"]')).toContainText(
    "A future widget",
  );
  await expect(page.locator('[data-widget="intro"] strong')).toContainText(
    "clear",
  );
  await expect(page.locator("#destinations")).toContainText("example.com");
  await expect(
    page.locator("#page script, #page style, #page iframe"),
  ).toHaveCount(0);
  expect(
    await page.evaluate(() => {
      try {
        document.createElement("div").innerHTML = "<img src=x>";
        return false;
      } catch {
        return true;
      }
    }),
  ).toBe(true);
  expect(errors).toEqual([]);
});

test("gallery supports phone layout and accessible English chrome", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.locator("#destinations")).toContainText(
    "Link destinations",
  );
  await expect(page.locator('[data-widget="future"]')).toContainText(
    "This part of the page can't be shown here.",
  );
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  const result = await new AxeBuilder({ page }).analyze();
  expect(result.violations).toEqual([]);
});

test("unknown major format gives a safe whole-page fallback", async ({
  page,
}) => {
  await page.goto("/?case=unsupported");
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.locator("#page [data-widget]")).toHaveCount(0);
});

// Read the canonical corpus directly: no copied vectors and no intercepted
// HTTP calls. The fixture host validates and serves each real snapshot.
import { readFileSync } from "node:fs";
const vectors = JSON.parse(
  readFileSync(
    new URL("../../../docs/vectors/page-format-v1.json", import.meta.url),
  ),
);
for (const vector of vectors.cases.filter((c) => c.render)) {
  test(`C1 ${vector.name}: ${vector.render}`, async ({ page }) => {
    const requests = [];
    page.on("request", (request) => requests.push(request.url()));
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.goto(`/?vector=${encodeURIComponent(vector.name)}`);
    await expect(page.locator("[data-widget]")).not.toHaveCount(0);
    const textWidget = page.locator('[data-widget="t1"]');
    if (vector.render === "link_inert")
      await expect(
        textWidget.locator("[href],img,script,iframe,svg"),
      ).toHaveCount(0);
    if (vector.render === "html_inert") {
      await expect(textWidget.locator("img,svg,script")).toHaveCount(0);
      await expect(textWidget).toContainText("<");
    }
    if (vector.render === "destination_domain_shown") {
      await textWidget.getByRole("link").click();
      const host = new URL(
        vector.input.patch[0].value.props.markdown.match(/\]\((https[^)]+)/)[1],
      ).host;
      await expect(page.getByRole("dialog").getByRole("heading")).toHaveText(
        host,
      );
      await expect(page.locator("#destinations")).toContainText(host);
    }
    if (vector.render === "text_escaped")
      await expect(
        page.getByRole("heading", {
          name: vector.input.patch[0].value,
          exact: true,
        }),
      ).toBeVisible();
    const assetOrigin = `https://127.0.0.1:${Number(new URL(page.url()).port) + 1}`;
    if (vector.render === "asset_origin_only") {
      const image = page.locator('[data-widget="img"] img');
      await image.scrollIntoViewIfNeeded();
      await expect(image).toHaveAttribute(
        "src",
        new RegExp("^" + assetOrigin.replaceAll(".", "\\.") + "/"),
      );
      await expect(
        page.locator("#page svg,#page object,#page iframe"),
      ).toHaveCount(0);
    }
    if (vector.render === "bidi_isolated") {
      const value = page.locator('[data-widget="items"] tbody bdi').first();
      await expect(value).toContainText(vector.input.patch[0].value);
      expect(await value.evaluate((n) => getComputedStyle(n).unicodeBidi)).toBe(
        "isolate",
      );
    }
    if (["table_url_link", "table_url_inert"].includes(vector.render)) {
      const expected = vector.render_expected;
      const snapshot = await page.request
        .get(`/api/page?vector=${encodeURIComponent(vector.name)}`)
        .then((r) => r.json());
      const widget = snapshot.layout.find((w) => w.id === expected.widget_id);
      const column = widget.props.columns.findIndex(
        (c) => c.field === expected.field,
      );
      const cell = page
        .locator(
          `[data-widget="${expected.widget_id}"] [data-record="${expected.record_id}"] td`,
        )
        .nth(column);
      if (vector.render === "table_url_link") {
        const link = cell.getByRole("link", {
          name: expected.href,
          exact: true,
        });
        await expect(link.locator("bdi")).toHaveText(expected.text);
        await expect(page.locator("#page [href]")).toHaveCount(0);
        expect(
          await link.evaluate((node) =>
            [...node.attributes].some((attr) => attr.value.includes("://")),
          ),
        ).toBe(false);
        await expect(page.locator("#destinations")).toContainText(
          expected.host,
        );
        await link.press("Enter");
        const dialog = page.getByRole("dialog");
        await expect(dialog.getByRole("heading")).toHaveText(expected.host);
        await expect(dialog).toContainText(expected.href);
        await expect(
          dialog.getByRole("button", { name: "Cancel", exact: true }),
        ).toBeFocused();
        await page.keyboard.press("Escape");
      } else {
        await expect(cell.locator("bdi")).toHaveText(expected.text);
        await expect(cell.getByRole("link")).toHaveCount(0);
        await expect(cell.locator("[href],button,script,img")).toHaveCount(0);
      }
    }
    expect(
      requests.every(
        (url) =>
          url.startsWith(new URL(page.url()).origin + "/") ||
          (vector.render === "asset_origin_only" &&
            url.startsWith(assetOrigin + "/")),
      ),
    ).toBe(true);
    expect(errors).toEqual([]);
  });
}
