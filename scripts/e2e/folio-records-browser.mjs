import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { chromium, expect } from "@playwright/test";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const { url, values, edit_urls, schema, collection, cli_binary, cli_home, legacy } = JSON.parse(input);
function tool(name, body) {
  const args = ["folio", name];
  for (const [key, value] of Object.entries(body))
    args.push("--" + key, typeof value === "object" ? JSON.stringify(value) : String(value));
  const result = spawnSync(cli_binary, args, { cwd: cli_home, encoding: "utf8" });
  assert.equal(result.status, 0, "Synthetic member CLI operation failed: " + result.stderr);
  return JSON.parse(result.stdout);
}
const evidenceDirectory = process.env.FOLIO_RECORDS_BROWSER_EVIDENCE;
assert(evidenceDirectory, "The journey must retain browser failure evidence");
async function retainFailure(page, width, error) {
  await mkdir(evidenceDirectory, { recursive: true });
  const stem = join(evidenceDirectory, `records-failure-${width || "unknown"}`);
  const editor = page.locator("#pane-edit");
  const root = await editor.count() ? editor : page.locator("body");
  const captures = await Promise.allSettled([
    root.ariaSnapshot({ timeout: 5000 }).then(snapshot => writeFile(stem + ".aria.yml", snapshot)),
    page.screenshot({ path: stem + ".png", fullPage: true, timeout: 5000 }),
  ]);
  await writeFile(stem + ".json", JSON.stringify({
    viewport: width, failure: { name: error.name, message: error.message },
    aria: captures[0].status, screenshot: captures[1].status,
  }, null, 2));
  console.error(`Browser failure evidence retained under ${stem}`);
}
let failurePage, failureWidth;
const browser = await chromium.launch();
try {
  for (const [iteration, width] of [1280, 375].entries()) {
    const currentValues = values.length ? tool("record-query", { collection_id: collection }).records.map(row => row.value) : [];
    const context = await browser.newContext({ viewport: { width, height: 800 }, ignoreHTTPSErrors: true });
    const page = await context.newPage();
    failurePage = page; failureWidth = width;
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    const response = await page.goto(url);
    assert.equal(response.headers()["cache-control"], "no-store");
    assert.equal(response.headers()["referrer-policy"], "no-referrer");
    const table = page.locator('[data-folio-widget="research"]');
    if (currentValues.length) await expect(table.getByRole("table")).toBeVisible();
    else {
      // The served renderer bundle is built from collections.mjs. Read its
      // authoritative empty-state text instead of maintaining another copy.
      const shared = await context.request.get(new URL("/present/widgets/assets/renderer.js", url).href);
      assert(shared.ok());
      const match = (await shared.text()).match(/if \(!visible\.length\)\s+region\.append\(chrome\("p", ("(?:\\.|[^"\\])*"), "field-description"\)\)/);
      assert(match, "Shared renderer empty-state source must be identifiable");
      await expect(table.getByText(JSON.parse(match[1]), { exact: true })).toBeVisible();
    }
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
    console.log(`PASS records ${currentValues.length ? "populated" : "empty"} readonly table at ${width}px`);
    // Read-only document links retain their ordinary valid-link reload behavior.
    await page.reload();
    await expect(table.locator("tbody tr")).toHaveCount(currentValues.length);
    if (edit_urls.length) {
      await page.goto(edit_urls[iteration]);
      const editor = page.locator('#pane-edit [data-folio-widget="research"]');
      await expect(editor.getByRole("table")).toBeVisible();
      const prose = page.getByRole("textbox", { name: "Document text 1", exact: true });
      const proseSave = page.locator("#save");
      await expect(proseSave).toBeDisabled();
      await expect(proseSave).toHaveText("Saved");
      const proseDraft = `Unsaved prose remains while a row is saved at ${width}px\n\n`;
      await prose.fill(proseDraft);
      await expect(proseSave).toBeEnabled();
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
      await expect(prose).toHaveValue(proseDraft);
      await editor.getByRole("button", { name: "Keep my changes", exact: true }).click();
      await editor.getByRole("button", { name: "Save row", exact: true }).click();
      await expect(editor.locator("tbody")).toContainText("Browser draft " + width);
      await expect(prose).toHaveValue(proseDraft);
      const committed = tool("record-query", { collection_id: collection }).records.find(row => row.id === source.id);
      assert.equal(committed.rev, source.rev + 2);
      assert.equal(committed.value.status, "Browser draft " + width);
      console.log(`PASS records browser conflict keeps row and prose drafts, explicit rebase at ${width}px`);
      // Explicit prose save preserves the widget definition; a reload reuses the session.
      await proseSave.click();
      await expect(page.locator("#status")).toContainText("Saved version");
      await page.reload();
      await expect(prose).toHaveValue(proseDraft);
      await expect(editor.locator("tbody")).toContainText("Browser draft " + width);
      await editor.getByRole("button", { name: "Add row", exact: true }).click();
      const added = { ...values[0], finding: "Browser added " + width, status: "added" };
      for (const [field, value] of Object.entries(added)) {
        const isEnum = Array.isArray(schema.properties[field].enum);
        const control = editor.getByRole(isEnum ? "combobox" : "textbox", {
          name: schema.properties[field].title || field, exact: true,
        });
        if (isEnum)
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
      console.log(`PASS records browser add/delete, separate prose save and session reload at ${width}px`);
    }
    assert.deepEqual(errors, []);
    await context.close();
    failurePage = undefined;
  }
  if (legacy) {
    const context = await browser.newContext({ viewport: { width: 375, height: 800 }, ignoreHTTPSErrors: true });
    const page = await context.newPage();
    failurePage = page; failureWidth = 375;
    const view = new URL(legacy.view_url);
    const viewState = page.waitForResponse(response => new URL(response.url()).pathname === view.pathname + "/widgets");
    await page.goto(view.href);
    const state = await (await viewState).json();
    assert.deepEqual(state.widgets.research, { state: "records_identity_required", reopen: "new_link_from_sharer" });
    const table = page.locator('[data-folio-widget="research"]');
    await expect(table.locator(".row-status")).toBeVisible();
    await expect(table.getByRole("table")).toHaveCount(0);
    const refusedView = await context.request.get(new URL(view.pathname + "/widgets/research/records", view.origin).href);
    assert.equal(refusedView.status(), 409);
    assert.deepEqual(await refusedView.json(), { detail: { code: "records_identity_required" } });
    const edit = new URL(legacy.edit_url);
    const exchanged = page.waitForResponse(response => new URL(response.url()).pathname === edit.pathname + "/session");
    await page.goto(edit.href);
    const opened = await (await exchanged).json();
    assert.deepEqual(opened.widgets.research, { state: "records_identity_required", reopen: "edit" });
    const editor = page.locator('#pane-edit [data-folio-widget="research"]');
    await expect(editor.locator(".row-status")).toBeVisible();
    await expect(editor.getByRole("table")).toHaveCount(0);
    const headers = { "X-Folio-Edit-Session": opened.session_secret };
    const endpoint = new URL(edit.pathname + "/widgets/research/records", edit.origin).href;
    const refusedEdit = await context.request.get(endpoint, { headers });
    assert.equal(refusedEdit.status(), 409);
    assert.deepEqual(await refusedEdit.json(), { detail: { code: "records_identity_required" } });
    const refusedWrite = await context.request.post(endpoint + "/update", { headers,
      data: { record_id: "unavailable", expected_rev: 1, patch: { finding: "refused" }, request_id: "legacy-write" } });
    assert.equal(refusedWrite.status(), 409);
    assert.deepEqual(await refusedWrite.json(), { detail: { code: "records_identity_required" } });
    const prose = page.getByRole("textbox", { name: "Document text 1", exact: true });
    await prose.fill("Legacy prose remains editable\n\n");
    await page.locator("#save").click();
    await expect(page.locator("#status")).toContainText("Saved version");
    console.log("PASS records legacy readonly/edit links disclose no rows or receipts; prose save still works");
    await context.close();
    failurePage = undefined;
  }
} catch (error) {
  if (failurePage) {
    try { await retainFailure(failurePage, failureWidth, error); }
    catch { console.error("Browser failure evidence capture failed"); }
  }
  throw error;
} finally {
  await browser.close();
}
