import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chromium, expect } from "@playwright/test";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const { url, values, edit_urls, schema, collection, cli_binary, cli_home } = JSON.parse(input);
function tool(name, body) {
  const args = ["folio", name];
  for (const [key, value] of Object.entries(body))
    args.push("--" + key, typeof value === "object" ? JSON.stringify(value) : String(value));
  const result = spawnSync(cli_binary, args, { cwd: cli_home, encoding: "utf8" });
  assert.equal(result.status, 0, "Synthetic member CLI operation failed: " + result.stderr);
  return JSON.parse(result.stdout);
}
const browser = await chromium.launch();
try {
  for (const [iteration, width] of [1280, 375].entries()) {
    const currentValues = values.length ? tool("record-query", { collection_id: collection }).records.map(row => row.value) : [];
    const context = await browser.newContext({ viewport: { width, height: 800 }, ignoreHTTPSErrors: true });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    const response = await page.goto(url);
    assert.equal(response.headers()["cache-control"], "no-store");
    assert.equal(response.headers()["referrer-policy"], "no-referrer");
    const table = page.locator('[data-folio-widget="research"]');
    if (currentValues.length) await expect(table.getByRole("table")).toBeVisible();
    else await expect(table.getByText("No records", { exact: true })).toBeVisible();
    await expect(table.locator("tbody tr")).toHaveCount(currentValues.length);
    for (const value of currentValues) {
      const row = table.locator("tbody tr").filter({ hasText: value.finding });
      await expect(row).toHaveCount(1);
      for (const field of ["finding", "why_relevant", "status", "kind"])
        await expect(row).toContainText(value[field]);
      await row.getByRole("link").click();
      await expect(page.getByRole("dialog")).toContainText(value.source_url);
      await page.getByRole("button", { name: "Cancel", exact: true }).click();
    }
    assert.equal(new URL(page.url()).hash, "");
    assert.deepEqual(await page.evaluate(() => [localStorage.length, sessionStorage.length]), [0, 0]);
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    // Read-only document links retain their ordinary valid-link reload behavior.
    await page.reload();
    await expect(table.locator("tbody tr")).toHaveCount(currentValues.length);
    if (edit_urls.length) {
      await page.goto(edit_urls[iteration]);
      const editor = page.locator('#pane-edit [data-folio-widget="research"]');
      await expect(editor.getByRole("table")).toBeVisible();
      const prose = page.getByRole("textbox", { name: "Document text 1", exact: true });
      await prose.fill("Unsaved prose remains while a row is saved\n\n");
      const source = tool("record-query", { collection_id: collection }).records[0];
      await editor.getByRole("button", { name: "Edit row " + source.id, exact: true }).click();
      const status = editor.getByLabel(schema.properties.status.title || "status", { exact: true });
      await status.fill("Browser draft " + width);
      // Real installed CLI writes first, producing the same observed-row conflict.
      tool("record-update", { collection_id: collection, record_id: source.id,
        expected_rev: source.rev, patch: { status: "Agent won " + width }, request_id: "browser-agent-race-" + width });
      await editor.getByRole("button", { name: "Save row", exact: true }).click();
      await expect(editor.getByRole("button", { name: "Keep my changes", exact: true })).toBeVisible();
      await expect(status).toHaveValue("Browser draft " + width);
      await expect(prose).toHaveValue("Unsaved prose remains while a row is saved\n\n");
      await editor.getByRole("button", { name: "Keep my changes", exact: true }).click();
      await editor.getByRole("button", { name: "Save row", exact: true }).click();
      await expect(editor.locator("tbody")).toContainText("Browser draft " + width);
      await expect(prose).toHaveValue("Unsaved prose remains while a row is saved\n\n");
      const committed = tool("record-query", { collection_id: collection }).records.find(row => row.id === source.id);
      assert.equal(committed.rev, source.rev + 2);
      assert.equal(committed.value.status, "Browser draft " + width);
      // Explicit prose save preserves the widget definition; a reload reuses the session.
      await page.locator("#save").click();
      await expect(page.locator("#status")).toContainText("Saved version");
      await page.reload();
      await expect(prose).toHaveValue("Unsaved prose remains while a row is saved\n\n");
      await expect(editor.locator("tbody")).toContainText("Browser draft " + width);
      await editor.getByRole("button", { name: "Add row", exact: true }).click();
      const added = { ...values[0], finding: "Browser added " + width, status: "added" };
      for (const [field, value] of Object.entries(added)) {
        const control = editor.getByLabel(schema.properties[field].title || field, { exact: true });
        if (Array.isArray(schema.properties[field].enum))
          await control.selectOption(String(schema.properties[field].enum.indexOf(value)));
        else await control.fill(String(value));
      }
      await editor.getByRole("button", { name: "Save row", exact: true }).click();
      await expect(editor.locator("tbody")).toContainText(added.finding);
      const addedRow = tool("record-query", { collection_id: collection }).records.find(row => row.value.finding === added.finding);
      assert(addedRow);
      await editor.getByRole("button", { name: "Delete row " + addedRow.id, exact: true }).click();
      await page.getByRole("dialog").getByRole("button", { name: "Delete row", exact: true }).click();
      await expect(editor.locator("tbody")).not.toContainText(added.finding);
      assert(!tool("record-query", { collection_id: collection }).records.some(row => row.id === addedRow.id));
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      assert.equal(new URL(page.url()).hash, "");
    }
    assert.deepEqual(errors, []);
    await context.close();
  }
} finally {
  await browser.close();
}
