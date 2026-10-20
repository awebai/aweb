import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
test("decision cards show the exact proposal, advisory recommendation and no preselected choice", async ({
  page,
}) => {
  await page.goto("/");
  const card = page.locator('[data-widget="price-decision"]');
  await expect(card).toContainText("Review the proposed nightly price");
  await expect(card).toContainText("12,000");
  await expect(card).toContainText("Agent recommendation: Approve");
  await expect(card.getByRole("radio", { checked: true })).toHaveCount(0);
  await expect(
    card.getByRole("button", { name: "Record decision" }),
  ).toBeDisabled();
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
  await card.getByRole("button", { name: "Record decision" }).click();
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
  await expect(card).toContainText("Decision recorded: Approve");
  await expect(card.locator(".decision-status")).toBeFocused();
  await expect(
    card.getByRole("radio", { name: "Reject", exact: true }),
  ).toBeDisabled();
  await page.reload();
  await expect(page.locator('[data-widget="price-decision"]')).toContainText(
    "Decision recorded: Approve",
  );
});
for (const fault of [
  "task",
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
    await page.goto("/?case=decision-" + fault);
    const card = page.locator(
      `[data-widget="${fault === "item" ? "bundle-decision" : "price-decision"}"]`,
    );
    await expect(card.locator(".decision-status")).not.toHaveText(
      "Checking decision…",
    );
    await expect(
      card.getByRole("button", { name: "Record decision" }),
    ).toBeDisabled();
    expect(await card.getByRole("radio", { checked: true }).count()).toBe(0);
  });
}
test("a bundle presents every item and records one all-or-nothing answer", async ({
  page,
}) => {
  await page.goto("/");
  const card = page.locator('[data-widget="bundle-decision"]');
  await expect(card.locator(".bundle-item")).toHaveCount(2);
  await expect(card).toContainText("All items together");
  await card.getByRole("radio", { name: "Reject", exact: true }).check();
  const sent = page.waitForRequest(
    (r) => new URL(r.url()).pathname === "/api/answer",
  );
  await card.getByRole("button", { name: "Record decision" }).click();
  expect((await sent).postDataJSON()).toMatchObject({
    task_id: "task-bundle",
    stage: { choice: "reject" },
  });
  await expect(card).toContainText("Decision recorded: Reject");
});
test("page widget_state cannot grant decision authority and missing CSRF blocks answers", async ({
  page,
}) => {
  await page.goto("/?case=decision-denied");
  const card = page.locator('[data-widget="price-decision"]');
  await expect(card).toContainText("Approved by page data");
  await expect(
    card.getByRole("button", { name: "Record decision" }),
  ).toBeDisabled();
  await page.goto("/?case=no-csrf");
  await expect(
    page
      .locator('[data-widget="price-decision"]')
      .getByRole("button", { name: "Record decision" }),
  ).toBeDisabled();
});
