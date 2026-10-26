// Renderer component proof only. Final Folio acceptance uses real session/store
// routes; these bounded host functions isolate the shared DOM and draft logic.
import { test, expect } from "@playwright/test";

async function open(page, { conflict = false, readonly = false } = {}) {
  await page.goto("/");
  await page.evaluate(
    async ({ conflict, readonly }) => {
      const { mountTableWidget, createActionConfirmation } =
        await import("/assets/page-renderer.js");
      const root = document.createElement("section");
      root.id = "editable-table-test";
      document.body.append(root);
      const dialog = document.createElement("dialog");
      document.body.append(dialog);
      const confirm = createActionConfirmation(dialog);
      let rows = [{ id: "r1", rev: 1, value: { finding: "Before", count: 2 } }];
      let revision = 1;
      window.tableRequests = [];
      const query = () => ({
        records: structuredClone(rows),
        count: rows.length,
        next_cursor: null,
        snapshot_rev: revision,
      });
      const widget = {
        id: "research",
        type: "table",
        props: {
          columns: [
            { field: "finding", label: "Finding", format: "text" },
            { field: "count", label: "Count", format: "number" },
          ],
        },
        bind: { collection: "notes", limit: 20 },
      };
      const state = {
        state: "ready",
        data_mode: "live",
        query: query(),
        edit: readonly
          ? {
              add: false,
              patch_fields: [],
              delete: false,
              reopen_to_edit: true,
            }
          : {
              add: true,
              patch_fields: ["finding", "count"],
              delete: true,
              reopen_to_edit: false,
            },
        page: {
          page_format: "aweb.page/1",
          page_id: "notes",
          rev: 1,
          title: "Research",
          locale: "en",
          layout: [widget],
          collections: [
            {
              id: "notes",
              schema: {
                type: "object",
                properties: {
                  finding: { type: "string", minLength: 1 },
                  count: { type: "integer" },
                },
                required: ["finding"],
                additionalProperties: false,
              },
              records: rows,
            },
          ],
        },
      };
      window.tableEditor = mountTableWidget({
        root,
        widgetId: "research",
        state,
        host: {
          query: async () => query(),
          patch: async (request) => {
            window.tableRequests.push(structuredClone(request));
            if (conflict) {
              conflict = false;
              rows[0] = {
                id: "r1",
                rev: 2,
                value: { finding: "Agent input", count: 3 },
              };
              revision++;
              throw { code: "revision_conflict", status: 409 };
            }
            rows[0] = {
              id: "r1",
              rev: rows[0].rev + 1,
              value: { ...rows[0].value, ...request.patch },
            };
            revision++;
            return { record: structuredClone(rows[0]), snapshot_rev: revision };
          },
          add: async (request) => {
            window.tableRequests.push(structuredClone(request));
            rows.push({ id: "r2", rev: 1, value: request.values });
            revision++;
            return {
              record: structuredClone(rows.at(-1)),
              snapshot_rev: revision,
            };
          },
          delete: async (request) => {
            window.tableRequests.push(structuredClone(request));
            rows = rows.filter((row) => row.id !== request.record_id);
            revision++;
            return {
              record_id: request.record_id,
              rev: request.expected_rev + 1,
              deleted: true,
              snapshot_rev: revision,
            };
          },
          confirmDelete: (record, event) =>
            confirm(
              { label: "Delete row", description: "Delete this row?" },
              event,
            ),
        },
      });
    },
    { conflict, readonly },
  );
  return page.locator("#editable-table-test");
}

test("editing a cell sends only its typed patch and the observed row revision", async ({
  page,
}) => {
  const table = await open(page);
  await table.getByRole("button", { name: "Edit row r1", exact: true }).click();
  await table.getByLabel("Finding", { exact: true }).fill("My finding");
  await table.getByRole("button", { name: "Save row", exact: true }).click();
  await expect(table.locator("tbody")).toContainText("My finding");
  const [request] = await page.evaluate(() => window.tableRequests);
  expect(request.patch).toEqual({ finding: "My finding" });
  expect(request.expected_rev).toBe(1);
});

test("a conflict keeps the input and needs a deliberate rebase before another save", async ({
  page,
}) => {
  const table = await open(page, { conflict: true });
  await table.getByRole("button", { name: "Edit row r1", exact: true }).click();
  await table.getByLabel("Finding", { exact: true }).fill("Keep this draft");
  await table.getByRole("button", { name: "Save row", exact: true }).click();
  await expect(table.getByLabel("Finding", { exact: true })).toHaveValue(
    "Keep this draft",
  );
  await expect(
    table.getByRole("button", { name: "Keep my changes", exact: true }),
  ).toBeVisible();
  expect(await page.evaluate(() => window.tableRequests.length)).toBe(1);
  await table
    .getByRole("button", { name: "Keep my changes", exact: true })
    .click();
  await table.getByRole("button", { name: "Save row", exact: true }).click();
  await expect(table.locator("tbody")).toContainText("Keep this draft");
  const requests = await page.evaluate(() => window.tableRequests);
  expect(requests[1].expected_rev).toBe(2);
  expect(requests[1].request_id).not.toBe(requests[0].request_id);
});

test("adding and explicitly confirmed deletion use row operations", async ({
  page,
}) => {
  const table = await open(page);
  await table.getByRole("button", { name: "Add row", exact: true }).click();
  await table.getByLabel("Finding", { exact: true }).fill("New row");
  await table.getByRole("button", { name: "Save row", exact: true }).click();
  await expect(table.locator("tbody tr")).toHaveCount(2);
  await table
    .getByRole("button", { name: "Delete row r2", exact: true })
    .click();
  expect(await page.evaluate(() => window.tableRequests.length)).toBe(1);
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Delete row", exact: true })
    .click();
  await expect(table.locator("tbody tr")).toHaveCount(1);
  const requests = await page.evaluate(() => window.tableRequests);
  expect(requests[1].record_id).toBe("r2");
  expect(requests[1].expected_rev).toBe(1);
});

test("a later-added read-only table shows rows with no write controls", async ({
  page,
}) => {
  const table = await open(page, { readonly: true });
  await expect(table.locator("tbody")).toContainText("Before");
  await expect(
    table.getByRole("button", { name: /Edit row|Delete row|Add row/ }),
  ).toHaveCount(0);
  await expect(table.locator("[data-reopen-to-edit]")).toBeVisible();
});
