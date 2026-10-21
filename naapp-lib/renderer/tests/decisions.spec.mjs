import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
test("decision cards show the exact proposal, advisory recommendation and no preselected choice", async ({
  page,
}) => {
  await page.goto("/");
  const card = page.locator('[data-widget="price-decision"]');
  await expect(card).toContainText("Review the proposed nightly price");
  await expect(card).toContainText("€120.00");
  await expect(card).toContainText("The agent recommends Approve.");
  await expect(card.getByRole("radio", { checked: true })).toHaveCount(0);
  await expect(card.locator('button[type="submit"]')).toBeDisabled();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});
test("recording a decision uses the separate host answer seam, exact stage binding and CSRF", async ({
  page,
}) => {
  await page.goto("/");
  const card = page.locator('[data-widget="price-decision"]');
  await card.getByRole("radio", { name: "Approve", exact: true }).check();
  const sent = page.waitForRequest(
    (r) => new URL(r.url()).pathname === "/api/answer",
  );
  await card.locator('button[type="submit"]').click();
  const request = await sent;
  expect(request.headers()["x-csrf-token"]).toBeTruthy();
  const body = request.postDataJSON();
  expect(body).toMatchObject({
    task_id: "task-price",
    action_id: "answer-price",
    stage: {
      expected_task_rev: 1,
      choice: "approve",
      input: {},
      proposal_rev: 1,
    },
  });
  expect(body.stage).not.toHaveProperty("expected_page_rev");
  expect(body.stage.answer_key).toMatch(/^[A-Za-z0-9._-]{1,128}$/);
  await expect(card).toContainText(
    "You approved this. The agent will apply it.",
  );
  await expect(card.locator(".decision-status")).toBeFocused();
  await expect(card.getByRole("radio")).toHaveCount(0);
  await expect(card.locator(".recorded-choice")).toBeVisible();
  await page.reload();
  await expect(page.locator('[data-widget="price-decision"]')).toContainText(
    "You approved this. The agent will apply it.",
  );
});
for (const fault of [
  "task",
  "options",
  "missing-field",
  "missing-currency",
  "record",
  "digest",
  "operation",
  "source",
  "expired",
  "denied",
  "input",
  "display",
  "item",
]) {
  test(`decision ${fault} mismatch refuses an answerable control`, async ({
    page,
  }) => {
    const dispatches = [];
    page.on("request", (r) => {
      if (new URL(r.url()).pathname === "/api/answer") dispatches.push(r);
    });
    await page.goto("/?case=decision-" + fault);
    const card = page.locator(
      `[data-widget="${fault === "item" ? "bundle-decision" : "price-decision"}"]`,
    );
    await expect(card.locator(".decision-status")).not.toHaveText(
      "Checking decision…",
    );
    await expect(card.locator('button[type="submit"]')).toBeDisabled();
    for (const option of await card.getByRole("radio").all())
      await expect(option).toBeDisabled();
    await card.locator('button[type="submit"]').press("Enter");
    expect(await card.getByRole("radio", { checked: true }).count()).toBe(0);
    expect(dispatches).toHaveLength(0);
  });
}
test("a bundle presents every item and records one all-or-nothing answer", async ({
  page,
}) => {
  await page.goto("/");
  const card = page.locator('[data-widget="bundle-decision"]');
  await expect(card.locator(".bundle-item")).toHaveCount(2);
  await expect(card).toContainText("One decision covers both items.");
  await card.getByRole("radio", { name: "Reject", exact: true }).check();
  const sent = page.waitForRequest(
    (r) => new URL(r.url()).pathname === "/api/answer",
  );
  await card.locator('button[type="submit"]').click();
  expect((await sent).postDataJSON()).toMatchObject({
    task_id: "task-bundle",
    stage: { choice: "reject" },
  });
  await expect(card).toContainText(
    "You rejected this. The agent will be told.",
  );
});
test("page widget_state cannot grant decision authority and missing CSRF blocks answers", async ({
  page,
}) => {
  await page.goto("/?case=decision-denied");
  const card = page.locator('[data-widget="price-decision"]');
  await expect(card).not.toContainText("Approved by page data");
  await expect(card.locator("progress, .widget-state")).toHaveCount(0);
  await expect(card.locator('button[type="submit"]')).toBeDisabled();
  await page.goto("/?case=no-csrf");
  const noToken = page.locator('[data-widget="price-decision"]');
  await expect(noToken.locator(".decision-status")).not.toHaveText(
    "Checking decision…",
  );
  for (const option of await noToken.getByRole("radio").all())
    await expect(option).toBeDisabled();
  await expect(noToken.locator(".decision-status")).toContainText(
    "The host could not verify",
  );
  await expect(
    page
      .locator('[data-widget="price-decision"]')
      .locator('button[type="submit"]'),
  ).toBeDisabled();
});

for (const [scenario, text, answerable] of [
  ["superseded", "Earlier answer: Approve · superseded.", false],
  ["reopened", "Earlier answer: Approve · superseded.", true],
  ["passkey-pending", "Decision verification is pending.", false],
  ["approved", "You approved this. The agent will apply it.", false],
  ["rejected", "You rejected this. The agent will be told.", false],
  ["closed", "This decision is closed.", false],
  ["applied", "Applied.", false],
  ["apply-failed", "It could not be applied.", false],
]) {
  test(`gallery exposes decision ${scenario} for product review`, async ({
    page,
  }) => {
    await page.goto("/?case=decision-" + scenario);
    const card = page.locator('[data-widget="price-decision"]');
    await expect(card).toContainText(text);
    const approve = card.getByRole("radio", { name: "Approve", exact: true });
    if (answerable) await expect(approve).toBeEnabled();
    else if (
      ["approved", "rejected", "applied", "apply-failed"].includes(scenario)
    ) {
      await expect(card.getByRole("radio")).toHaveCount(0);
      await expect(card.locator(".recorded-choice")).toBeVisible();
    } else await expect(approve).toBeDisabled();
  });
}

test("decision money uses the trusted Nightly price field and currency scale", async ({
  page,
}) => {
  await page.goto("/");
  const card = page.locator('[data-widget="price-decision"]');
  await expect(card.locator(".decision-proposal")).toContainText(
    "Nightly price",
  );
  await expect(card.locator(".decision-proposal")).toContainText("€120.00");
  await expect(card.locator(".decision-proposal")).not.toContainText(
    "minor currency units",
  );
  await page.goto("/?case=decision-jpy");
  await expect(
    page.locator('[data-widget="price-decision"] .decision-proposal'),
  ).toContainText("¥12,000");
});

for (const theme of ["light", "dark"]) {
  test(`decision cards support phone keyboard use and ${theme} accessibility`, async ({
    page,
  }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.emulateMedia({ colorScheme: theme });
    await page.goto("/");
    const card = page.locator('[data-widget="bundle-decision"]');
    const approve = card.getByRole("radio", { name: "Approve", exact: true });
    await expect(approve).toBeEnabled();
    await expect(card.locator(".decision-proposal")).toContainText("€135.00");
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await approve.focus();
    await approve.press("Space");
    await card.locator('button[type="submit"]').press("Enter");
    await expect(card).toContainText(
      "You approved this. The agent will apply it.",
    );
    await expect(card.locator(".decision-status")).toBeFocused();
  });
}
